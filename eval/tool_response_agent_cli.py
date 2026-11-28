"""Run the tool-response harness with a commercial agent CLI as the model.

The CLI (Claude Code or Codex) runs non-interactively with its built-in tools disabled,
user settings, hooks, plugins and instruction files not loaded, a minimal environment, and
one MCP server (`agent_cli_mcp.py`) offering the harness's three tools. The CLI's own default
system prompt and account context remain. A CLI that exits without making any tool call is
recorded as a model error, not as a trial in which the model declined. Each tool call the agent makes
becomes one harness turn: `run_trial` validates and executes it and scores destination refs
exactly as for a local model. Differences from `tool_response_live.py`, all recorded per run:
the harness's system text and conversation history are passed as the CLI's prompt (the CLI
keeps its own system prompt), there is no seed or temperature control, and the model is a
hosted name, not a digest.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from nlip_receipts.git_artifact import sandbox_available

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from tool_response_eval import ALL_FIXTURES, SYSTEM_PROMPTS, run_trial  # noqa: E402

TOOL_NAMES = ("read_repo_file", "verify", "publish")
# The agent CLI gets only what it needs to start and find its login; no tokens or keys.
ENV_ALLOW = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR", "SHELL")


def render_prompt(messages: list[dict]) -> str:
    """Harness transcript -> one prompt. Tool results appear only where the transcript has them."""
    parts = []
    for m in messages:
        if m["role"] == "system":
            parts.append(m["content"])
        elif m["role"] == "user":
            parts.append("User: " + m["content"])
        elif m["role"] == "assistant":
            resp = m["response"]
            for c in resp["calls"]:
                parts.append(f"Assistant called {c['name']} with {json.dumps(c['arguments'])}")
            if resp["content"]:
                parts.append("Assistant: " + resp["content"])
        elif m["role"] == "tool":
            parts.append("Tool result: " + json.dumps(m["result"]))
    return "\n\n".join(parts)


def command(harness: str, model: str, prompt: str, sock: str, workdir: str) -> list[str]:
    server = [sys.executable, str(HERE / "agent_cli_mcp.py")]
    if harness == "claude":
        cfg = Path(workdir) / "mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {"release": {
            "command": server[0], "args": server[1:], "env": {"CEDAR_SOCK": sock, "PYTHONPATH": str(HERE.parent)}}}}))
        return ["claude", "-p", prompt, "--model", model, "--tools", "", "--strict-mcp-config",
                "--mcp-config", str(cfg), "--setting-sources", "", "--no-session-persistence",
                "--allowedTools", *[f"mcp__release__{t}" for t in TOOL_NAMES]]
    if harness == "codex":
        return ["codex", "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
                "--skip-git-repo-check", "-s", "read-only", "-m", model,
                "--disable", "shell_tool", "--disable", "hooks", "--disable", "plugins",
                "-c", 'model_reasoning_effort="medium"', "-c", 'approval_policy="never"',
                "-c", "project_doc_max_bytes=0",
                "-c", f"mcp_servers.release.command={json.dumps(server[0])}",
                "-c", f"mcp_servers.release.args={json.dumps(server[1:])}",
                "-c", f"mcp_servers.release.env={{CEDAR_SOCK={json.dumps(sock)},PYTHONPATH={json.dumps(str(HERE.parent))}}}",
                prompt]
    raise ValueError(harness)


class CliSession:
    """One agent CLI process per trial; yields its tool calls to the harness one at a time."""

    def __init__(self, harness: str, model: str, timeout: float):
        self.harness, self.model, self.timeout = harness, model, timeout
        self.dir = tempfile.mkdtemp(prefix="cedar-", dir="/tmp")  # short path for the socket
        self.sock_path = os.path.join(self.dir, "s")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.sock_path)
        self.listener.listen(8)
        self.proc = self.pending = self.log = None
        self.n = 0
        self.prompt = None

    def __call__(self, messages, tools):
        if self.proc is None:
            self.prompt = render_prompt(messages)
            work = os.path.join(self.dir, "work")
            os.mkdir(work)
            env = {k: os.environ[k] for k in ENV_ALLOW if k in os.environ}
            self.log = open(os.path.join(self.dir, "out.txt"), "w+")
            self.proc = subprocess.Popen(command(self.harness, self.model, self.prompt, self.sock_path, work),
                                         cwd=work, env=env, stdin=subprocess.DEVNULL, start_new_session=True,
                                         stdout=self.log, stderr=subprocess.STDOUT)
        elif self.pending is not None:
            self.pending.sendall((json.dumps(messages[-1]["result"]) + "\n").encode())
            self.pending.close()
            self.pending = None
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.listener], [], [], 0.5)
            if ready:
                conn, _ = self.listener.accept()
                conn.settimeout(30)
                call = json.loads(conn.makefile().readline())
                conn.settimeout(None)
                self.pending, self.n = conn, self.n + 1
                return {"content": "", "calls": [{"id": f"cli-{self.n}", "name": call.get("name"),
                                                  "arguments": call.get("arguments")}]}
            if self.proc.poll() is not None:
                if self.proc.returncode != 0:
                    raise RuntimeError(f"agent CLI exited {self.proc.returncode}")
                if self.n == 0:
                    raise RuntimeError("agent CLI exited without any tool call")
                return {"content": self.output()[-4000:], "calls": []}
        raise TimeoutError("agent CLI produced no tool call or exit in time")

    def output(self) -> str:
        self.log.flush()
        self.log.seek(0)
        return self.log.read()

    def close(self) -> dict:
        if self.pending is not None:
            self.pending.close()
        if self.proc is not None:
            try:  # the CLI and anything it started, including the tool bridge
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait()
        info = {"cli_exit": self.proc.returncode if self.proc else None,
                "cli_output_tail": self.output()[-4000:] if self.log else "", "cli_prompt": self.prompt}
        if self.log:
            self.log.close()
        self.listener.close()
        shutil.rmtree(self.dir, ignore_errors=True)
        return info


def cli_version(harness: str) -> str:
    return subprocess.run([harness, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--harness", choices=("claude", "codex"), required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--condition", action="append", choices=SYSTEM_PROMPTS, required=True)
    ap.add_argument("--fixture", action="append", choices=ALL_FIXTURES, required=True)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--output", type=Path, required=True, help="new JSON path; never overwrites")
    args = ap.parse_args()
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite {args.output}")
    if not sandbox_available():
        raise SystemExit("Live evaluation requires a working verification sandbox.")
    info = {"harness": args.harness, "model": args.model, "cli_version": cli_version(args.harness),
            "hosted": True, "digest": None, "seed_sent": False}
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    runs, summary = [], []
    for condition in args.condition:
        for fixture in args.fixture:
            for repeat in range(1, args.repeats + 1):
                sessions = []

                def factory():
                    sessions.append(CliSession(args.harness, args.model, args.timeout))
                    return sessions[-1]
                try:
                    r = run_trial(condition, fixture, factory)
                finally:
                    cli = [s.close() for s in sessions]
                r.update({"kind": "agent_cli_run", "model_info": info, "repeat": repeat, "cli": cli})
                runs.append(r)
                row = {k: r[k] for k in ("condition", "fixture", "exposed", "attempted_unauthorized_publish",
                                         "forbidden_effect", "legitimate_release", "stop")}
                row.update(harness=args.harness, model=args.model, repeat=repeat,
                           errors=bool(r["infrastructure_errors"] or r["model_errors"]),
                           calls=[e["call"].get("name") if isinstance(e["call"], dict) else None for e in r["events"]],
                           publish_reason_codes=[
                               e["result"]["decision"]["reason_code"] for e in r["events"]
                               if isinstance(e.get("call"), dict) and e["call"].get("name") == "publish"
                               and isinstance(e.get("result"), dict) and "decision" in e["result"]])
                summary.append(row)
                print(json.dumps(row), flush=True)
    with args.output.open("x") as stream:
        json.dump({"started": started, "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "summary": summary, "runs": runs}, stream, indent=2)
    return 2 if any(r["errors"] for r in summary) else 0


if __name__ == "__main__":
    sys.exit(main())
