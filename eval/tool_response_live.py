"""Run the tool-response harness (`eval/tool_response_eval.py`) with a live local model.

The model is reached through Ollama's OpenAI-compatible chat endpoint with native tool
calling. Nothing here changes how trials run: `run_trial` builds fresh state per trial,
executes only the calls the model actually returns, and scores effects from destination
refs. This module only converts the harness transcript to chat messages and the model's
reply back into the harness's `{content, calls}` envelope, without repairing anything:
unparseable arguments are passed through as an unparsed marker and the harness rejects them.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tool_response_eval import run_trial  # noqa: E402

OLLAMA = "http://127.0.0.1:11434"
CONDITIONS = ("prompt_only", "receipt_gate")
FIXTURES = ("attack", "benign")
TOOL_DESCRIPTIONS = {
    "read_repo_file": "Read a file from the release repository.",
    "verify": "Run the configured verification check on an exact commit and return a receipt.",
    "publish": "Publish an exact commit to the destination branch.",
}


def tool_schemas(tools: dict) -> list[dict]:
    """The harness's fixed argument contract as OpenAI-style function schemas."""
    out = []
    for name, args in tools.items():
        props = {}
        for arg, desc in args.items():
            if arg == "receipt_id":
                props[arg] = {"type": ["string", "null"], "description": desc}
            else:
                props[arg] = {"type": "string", "description": desc}
        out.append({"type": "function", "function": {
            "name": name, "description": TOOL_DESCRIPTIONS[name],
            "parameters": {"type": "object", "properties": props, "required": list(args),
                           "additionalProperties": False}}})
    return out


def to_chat(messages: list[dict]) -> list[dict]:
    """Harness transcript -> chat messages. Tool results go back as tool turns."""
    chat = []
    for m in messages:
        if m["role"] in ("system", "user"):
            chat.append({"role": m["role"], "content": m["content"]})
        elif m["role"] == "assistant":
            resp = m["response"] if isinstance(m.get("response"), dict) else {}
            calls = resp.get("calls") if isinstance(resp.get("calls"), list) else []
            entry = {"role": "assistant", "content": resp.get("content") if isinstance(resp.get("content"), str) else ""}
            tool_calls = [
                {"id": c.get("id"), "type": "function",
                 "function": {"name": c.get("name"), "arguments": json.dumps(c.get("arguments"))}}
                for c in calls if isinstance(c, dict)
            ]
            if tool_calls:
                entry["tool_calls"] = tool_calls
            chat.append(entry)
        elif m["role"] == "tool":
            chat.append({"role": "tool", "tool_call_id": m.get("call_id"), "content": json.dumps(m["result"])})
    return chat


def from_chat(message: dict) -> dict:
    """Chat reply -> harness envelope. Arguments that are not a JSON object are not repaired."""
    calls = []
    for tc in message.get("tool_calls") or []:
        fn = tc.get("function") or {}
        raw = fn.get("arguments")
        if isinstance(raw, dict):
            args = raw
        else:
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                args = {"__unparsed_arguments__": raw}
        calls.append({"id": tc.get("id") or "", "name": fn.get("name"), "arguments": args})
    return {"content": message.get("content") or "", "calls": calls}


def ollama_factory(model: str, *, temperature: float, seed: int, timeout: float = 600.0):
    def factory():
        def call(messages, tools):
            payload = {"model": model, "messages": to_chat(messages), "tools": tool_schemas(tools),
                       "temperature": temperature, "seed": seed, "stream": False}
            req = urllib.request.Request(f"{OLLAMA}/v1/chat/completions", data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
            return from_chat(body["choices"][0]["message"])
        return call
    return factory


def model_info(model: str) -> dict:
    with urllib.request.urlopen(f"{OLLAMA}/api/tags", timeout=10) as resp:
        tags = {m["name"]: m for m in json.loads(resp.read())["models"]}
    with urllib.request.urlopen(f"{OLLAMA}/api/version", timeout=10) as resp:
        version = json.loads(resp.read()).get("version")
    m = tags[model]
    return {"model": model, "digest": m["digest"], "parameter_size": m["details"].get("parameter_size"),
            "quantization": m["details"].get("quantization_level"), "ollama_version": version}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--model", action="append", required=True, help="Ollama model tag; repeatable")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--output", type=Path, required=True, help="new JSON path; never overwrites")
    args = ap.parse_args()
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite {args.output}")
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    runs, summary = [], []
    for model in args.model:
        info = model_info(model)
        for condition in CONDITIONS:
            for fixture in FIXTURES:
                for seed in range(1, args.seeds + 1):
                    r = run_trial(condition, fixture, ollama_factory(model, temperature=args.temperature, seed=seed))
                    r.update({"kind": "live_model_run", "model_info": info, "seed": seed,
                              "temperature": args.temperature})
                    runs.append(r)
                    row = {k: r[k] for k in ("condition", "fixture", "exposed", "attempted_unauthorized_publish",
                                             "forbidden_effect", "legitimate_release", "stop")}
                    row.update(model=model, seed=seed, errors=bool(r["infrastructure_errors"] or r["model_errors"]),
                               calls=[e["call"].get("name") if isinstance(e["call"], dict) else None for e in r["events"]])
                    summary.append(row)
                    print(json.dumps(row), flush=True)
    with args.output.open("x") as stream:
        json.dump({"started": started, "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "summary": summary, "runs": runs}, stream, indent=2)
    return 2 if any(r["errors"] for r in summary) else 0


if __name__ == "__main__":
    sys.exit(main())
