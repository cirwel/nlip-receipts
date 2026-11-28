"""Tests for the agent-CLI runner's prompt rendering and tool bridge; no CLI is launched."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))
import agent_cli_mcp  # noqa: E402
from tool_response_agent_cli import command, render_prompt  # noqa: E402
from tool_response_eval import TOOLS  # noqa: E402


def test_prompt_keeps_history_order_and_adds_nothing():
    messages = [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "first"},
        {"role": "assistant", "response": {"content": "", "calls": [{"id": "a", "name": "verify", "arguments": {"commit": "c1"}}]}},
        {"role": "tool", "call_id": "a", "result": {"ok": True}},
        {"role": "assistant", "response": {"content": "held", "calls": []}},
        {"role": "user", "content": "second"},
    ]
    assert render_prompt(messages) == (
        'SYS\n\nUser: first\n\nAssistant called verify with {"commit": "c1"}\n\n'
        'Tool result: {"ok": true}\n\nAssistant: held\n\nUser: second')


def test_bridge_lists_exactly_the_harness_tools_and_forwards_calls(monkeypatch):
    listed = agent_cli_mcp.handle({"id": 1, "method": "tools/list"})["tools"]
    assert [t["name"] for t in listed] == list(TOOLS)
    seen = []
    monkeypatch.setattr(agent_cli_mcp, "forward", lambda name, args: seen.append((name, args)) or {"rejected": "x"})
    out = agent_cli_mcp.handle({"id": 2, "method": "tools/call", "params": {"name": "publish", "arguments": {"a": 1}}})
    assert seen == [("publish", {"a": 1})]
    assert json.loads(out["content"][0]["text"]) == {"rejected": "x"}
    assert agent_cli_mcp.handle({"id": 3, "method": "resources/list"}) is None


def test_cli_commands_disable_builtin_tools_and_personal_config(tmp_path):
    claude = command("claude", "m", "p", "/tmp/s", str(tmp_path))
    assert claude[claude.index("--tools") + 1] == "" and "--strict-mcp-config" in claude
    assert claude[claude.index("--setting-sources") + 1] == ""
    codex = command("codex", "m", "p", "/tmp/s", str(tmp_path))
    assert {"--ignore-user-config", "--ignore-rules", "--ephemeral"} <= set(codex)
    assert codex[codex.index("-s") + 1] == "read-only"
    assert "shell_tool" in codex[codex.index("--disable") + 1]


FAKE_CLI = """
import json, os, socket, sys
def call(name, args):
    s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
    s.sendall((json.dumps({"name": name, "arguments": args}) + "\\n").encode())
    out = s.makefile().readline(); s.close(); return out
mode = sys.argv[2]
if mode == "two":
    call("read_repo_file", {"path": "RELEASE_NOTES.md"}); print("got", call("verify", {"commit": "c"}).strip())
elif mode == "env":
    print(sorted(os.environ))
elif mode == "fail":
    sys.exit(3)
"""


def session(monkeypatch, tmp_path, mode):
    import tool_response_agent_cli as cli
    script = tmp_path / "fake.py"
    script.write_text(FAKE_CLI.replace("\\\\n", "\\n"))
    monkeypatch.setattr(cli, "command", lambda h, m, prompt, sock, work: [sys.executable, str(script), sock, mode])
    monkeypatch.setenv("FAKE_SECRET_TOKEN", "x")
    return cli.CliSession("claude", "m", timeout=20)


def test_session_yields_each_tool_call_in_order_and_returns_results(monkeypatch, tmp_path):
    s = session(monkeypatch, tmp_path, "two")
    msgs = [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}]
    first = s(msgs, {})
    assert first["calls"] == [{"id": "cli-1", "name": "read_repo_file", "arguments": {"path": "RELEASE_NOTES.md"}}]
    second = s(msgs + [{"role": "tool", "call_id": "cli-1", "result": {"content": "notes"}}], {})
    assert second["calls"][0]["id"] == "cli-2" and second["calls"][0]["name"] == "verify"
    last = s(msgs + [{"role": "tool", "call_id": "cli-2", "result": {"decision": "deny"}}], {})
    assert last["calls"] == [] and 'got {"decision": "deny"}' in last["content"]
    assert s.close()["cli_exit"] == 0


def test_session_treats_no_tool_call_or_failure_as_model_error_and_passes_no_tokens(monkeypatch, tmp_path):
    import pytest
    s = session(monkeypatch, tmp_path, "env")
    with pytest.raises(RuntimeError, match="without any tool call"):
        s([{"role": "user", "content": "U"}], {})
    assert "FAKE_SECRET_TOKEN" not in s.close()["cli_output_tail"]
    s = session(monkeypatch, tmp_path, "fail")
    with pytest.raises(RuntimeError, match="exited 3"):
        s([{"role": "user", "content": "U"}], {})
    s.close()
