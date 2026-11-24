"""Conversion tests for the live-model adapter; no model is contacted."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))

import tool_response_live as live  # noqa: E402
from tool_response_eval import SYSTEM_PROMPTS, TOOLS, digest  # noqa: E402
from tool_response_live import from_chat, to_chat, tool_schemas  # noqa: E402


def test_schemas_cover_exactly_the_harness_contract():
    schemas = {s["function"]["name"]: s["function"]["parameters"] for s in tool_schemas(TOOLS)}
    assert set(schemas) == set(TOOLS)
    for name, params in schemas.items():
        assert set(params["properties"]) == set(TOOLS[name]) == set(params["required"])
        assert params["additionalProperties"] is False


def test_transcript_round_trips_calls_and_tool_results():
    messages = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u"},
        {"role": "assistant", "response": {"content": "", "calls": [
            {"id": "c1", "name": "read_repo_file", "arguments": {"path": "RELEASE_NOTES.md"}}]}},
        {"role": "tool", "call_id": "c1", "result": {"content": "notes"}},
    ]
    chat = to_chat(messages)
    assert [m["role"] for m in chat] == ["system", "user", "assistant", "tool"]
    assert chat[2]["tool_calls"][0]["function"]["name"] == "read_repo_file"
    assert chat[3] == {"role": "tool", "tool_call_id": "c1", "content": json.dumps({"content": "notes"})}


def test_reply_conversion_does_not_repair_calls():
    reply = {"content": None, "tool_calls": [
        {"id": "a", "function": {"name": "publish", "arguments": "{not json"}},
        {"function": {"name": "verify", "arguments": {"commit": "x"}}},
    ]}
    env = from_chat(reply)
    assert env["content"] == ""
    assert env["calls"][0]["arguments"] == {"__unparsed_arguments__": "{not json"}
    assert env["calls"][1]["id"] == ""  # missing id stays missing; the harness rejects it
    assert from_chat({"content": "done"}) == {"content": "done", "calls": []}


@pytest.mark.parametrize(("options", "conditions"), [
    ([], ["prompt_only", "receipt_gate"]),
    (["--condition", "no_gate"], ["no_gate"]),
])
def test_live_matrix_selection(tmp_path, monkeypatch, options, conditions):
    output = tmp_path / "run.json"
    monkeypatch.setattr(sys, "argv", ["live", "--model", "stub", "--seeds", "1", "--output", str(output), *options])
    monkeypatch.setattr(live, "sandbox_available", lambda: True)
    monkeypatch.setattr(live, "model_info", lambda model: {"model": model})
    seen_system = []
    def no_calls(messages, tools):
        seen_system.append(messages[0]["content"])
        return {"content": "", "calls": []}
    monkeypatch.setattr(live, "ollama_factory", lambda *a, **kw: lambda: no_calls)
    assert live.main() == 0
    report = json.loads(output.read_text())
    expected = [(c, f, 1) for c in conditions for f in ("attack", "benign")]
    for rows in (report["runs"], report["summary"]):
        assert [(r["condition"], r["fixture"], r["seed"]) for r in rows] == expected
    assert seen_system == [SYSTEM_PROMPTS[c] for c, _, _ in expected]
    assert [r["system_sha256"] for r in report["runs"]] == [digest(SYSTEM_PROMPTS[c]) for c, _, _ in expected]


def test_live_aborts_before_inference_without_a_sandbox(tmp_path, monkeypatch):
    output = tmp_path / "run.json"
    monkeypatch.setattr(sys, "argv", ["live", "--model", "stub", "--condition", "no_gate", "--output", str(output)])
    monkeypatch.setattr(live, "sandbox_available", lambda: False)
    monkeypatch.setattr(live, "model_info", lambda _: pytest.fail("contacted Ollama"))
    with pytest.raises(SystemExit, match="working verification sandbox"):
        live.main()
    assert not output.exists()
