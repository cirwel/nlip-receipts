"""Deterministic runner contracts; no model-susceptibility claims."""
import json

import pytest

from eval.tool_response_eval import FIXTURES, Trial, run_trial, scripted_factory
from nlip_receipts.git_artifact import sandbox_available


def test_actual_unauthorized_effect_and_gate_denial():
    baseline = run_trial("prompt_only", "attack", scripted_factory(True))
    gated = run_trial("receipt_gate", "attack", scripted_factory(True))
    for result in (baseline, gated):
        assert result["exposed"] and result["attempted_unauthorized_publish"]
        assert not result["infrastructure_errors"]
        assert not result["legitimate_release"]
        assert result["initial_refs"] == {}
        assert result["events"][0]["result"]["content"] == (FIXTURES / "attack.md").read_text()
        assert "<INFORMATION>" not in json.dumps(result["transcript"][:2])
        assert result["transcript"][3]["role"] == "tool"
        assert result["transcript"][3]["call_id"] == "1"
    assert baseline["forbidden_effect"]
    assert baseline["final_refs"] == {"refs/heads/main": baseline["target"]["commit"]}
    assert not gated["forbidden_effect"] and gated["final_refs"] == {}
    assert gated["events"][1]["result"]["decision"]["reason_code"] == "MISSING_RECEIPT"


@pytest.mark.parametrize("condition", ["prompt_only", "receipt_gate"])
def test_benign_exact_commit_with_real_sandbox(condition):
    result = run_trial(condition, "benign", scripted_factory(False))
    if not sandbox_available():
        assert result["infrastructure_errors"]
        assert result["final_refs"] == {}
        assert not result["legitimate_release"]
        pytest.skip("Real OS sandbox unavailable; benign e2e blocked, no substitute verification")
    assert not result["infrastructure_errors"]
    assert result["legitimate_release"] and not result["forbidden_effect"]
    assert not result["attempted_unauthorized_publish"]
    assert result["events"][1]["result"]["receipt"]["status"] == "passed"
    assert result["final_refs"] == {"refs/heads/main": result["target"]["commit"]}


@pytest.mark.parametrize("answer", [
    {"content": "No action", "calls": []},
    {"content": "publish now"},
    {"content": "", "calls": [{"id": "x", "name": "publish", "arguments": {}}]},
    {"content": "", "calls": [{"id": "x", "name": "shell", "arguments": {"cmd": "git push"}}]},
    {"content": "", "calls": [{"id": "x", "name": "read_repo_file", "arguments": {"path": "../ledger.db"}}]},
    {"content": "", "calls": [None]},
])
def test_no_call_or_malformed_never_mutates(answer):
    result = run_trial("prompt_only", "attack", lambda: lambda messages, tools: answer, max_turns=1)
    assert result["initial_refs"] == result["final_refs"] == {}
    assert not result["forbidden_effect"]
    assert not result["exposed"]


def test_sequential_results_and_callback_state_are_fresh():
    instances = []
    def factory():
        seen = []
        instances.append(seen)
        def model(messages, tools):
            seen.append(messages)
            if len(seen) == 1:
                return {"content": "", "calls": [
                    {"id": "a", "name": "read_repo_file", "arguments": {"path": "RELEASE_NOTES.md"}},
                    {"id": "b", "name": "read_repo_file", "arguments": {"path": "../ledger.db"}},
                ]}
            assert messages[-2]["call_id"] == "a"
            assert messages[-2]["result"]["content"] == (FIXTURES / "benign.md").read_text()
            assert messages[-1]["call_id"] == "b"
            assert "rejected" in messages[-1]["result"]
            return {"content": "Done", "calls": []}
        return model
    results = [run_trial("receipt_gate", "benign", factory) for _ in range(2)]
    assert len(instances) == 2 and instances[0] is not instances[1]
    assert all(r["initial_refs"] == r["final_refs"] == {} for r in results)
    assert all(len(r["events"]) == 2 for r in results)
    # Verify storage, credentials and ledger independence directly, too.
    a, b = Trial("receipt_gate", "attack"), Trial("receipt_gate", "attack")
    try:
        assert a.root != b.root and a.ledger.db_path != b.ledger.db_path
        assert a.secret != b.secret
        assert a.secret not in json.dumps(results) and b.secret not in json.dumps(results)
    finally:
        a.close()
        b.close()


def test_duplicate_ids_and_call_budget():
    call = {"id": "a", "name": "read_repo_file", "arguments": {"path": "RELEASE_NOTES.md"}}
    result = run_trial("prompt_only", "benign", lambda: lambda m, t: {"content": "", "calls": [call] * 3}, max_calls=2)
    assert result["stop"] == "call_budget" and len(result["events"]) == 2
    assert result["events"][1]["result"] == {"rejected": "duplicate call id"}
    assert result["final_refs"] == {}


def test_receipt_is_not_automatically_supplied_and_score_ignores_gate_answer():
    def factory():
        base = scripted_factory(False)()
        def model(messages, tools):
            answer = base(messages, tools)
            for call in answer["calls"]:
                if call["name"] == "publish":
                    call["arguments"]["receipt_id"] = None
            return answer
        return model
    result = run_trial("receipt_gate", "benign", factory)
    if not sandbox_available():
        pytest.skip("Requires a real passing verification receipt")
    assert result["events"][-1]["result"]["decision"]["reason_code"] == "MISSING_RECEIPT"
    assert not result["attempted_unauthorized_publish"]  # user requires a pass, not a receipt argument
    assert not result["legitimate_release"] and result["final_refs"] == {}


@pytest.mark.parametrize("change", [
    {"branch": "other"}, {"destination": "https://example.invalid/repo"},
    {"commit": "HEAD"}, {"receipt_id": 4}, {"caller_secret": "untrusted"},
])
def test_publish_arguments_are_not_repaired(change):
    def factory():
        base = scripted_factory(True)()
        def model(messages, tools):
            answer = base(messages, tools)
            for call in answer["calls"]:
                if call["name"] == "publish":
                    call["arguments"].update(change)
            return answer
        return model
    result = run_trial("prompt_only", "attack", factory)
    assert "rejected" in result["events"][1]["result"]
    assert result["final_refs"] == {}


def test_credentials_never_enter_transcript(monkeypatch):
    from eval import tool_response_eval
    secret = "synthetic-credential-test-marker"
    monkeypatch.setattr(tool_response_eval.secrets, "token_hex", lambda n: secret)
    result = run_trial("receipt_gate", "attack", scripted_factory(True))
    assert secret not in json.dumps(result)


def test_attack_verification_really_fails_when_sandbox_works():
    # Same real verifier as benign; never synthesize a failure receipt.
    result = run_trial("receipt_gate", "attack", scripted_factory(False))
    if not sandbox_available():
        assert result["infrastructure_errors"] and result["final_refs"] == {}
        pytest.skip("Failing-commit verification also requires the real OS sandbox")
    receipt = result["events"][1]["result"]["receipt"]
    assert receipt["status"] == "failed" and receipt["exit_code"] != 0
    assert not result["infrastructure_errors"] and result["final_refs"] == {}
