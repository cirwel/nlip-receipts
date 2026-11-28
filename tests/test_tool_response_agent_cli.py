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
