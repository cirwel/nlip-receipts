"""Conversion tests for the live-model adapter; no model is contacted."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))

from tool_response_eval import TOOLS  # noqa: E402
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
