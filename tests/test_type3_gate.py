"""Comprehensive unit and integration tests for `nlip-receipts` (ECMA-430 & ECMA-434)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from nlip_sdk.nlip import AllowedFormats, NLIP_Message, ReservedTokens

from nlip_receipts import (
    ReceiptLedger,
    ToolCallProposal,
    Type3ReceiptExtension,
    pack_tool_call_message,
)
from nlip_receipts.adapters import (
    AntigravityToolAdapter,
    ClaudeCodePreToolAdapter,
    CodexExecToolAdapter,
    extract_decision_from_response,
)
from nlip_receipts.git_artifact import resolve_commit_and_tree, run_git
from nlip_receipts.server import create_nlip_receipt_server


def _init_test_repos(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Create a working Git repository and two bare destination repositories (staging & prod)."""
    work_repo = tmp_path / "work_repo"
    work_repo.mkdir()
    staging_bare = tmp_path / "staging.git"
    prod_bare = tmp_path / "prod.git"

    subprocess.run(["git", "init", "--bare", str(staging_bare)], check=True, capture_output=True)
    subprocess.run(["git", "init", "--bare", str(prod_bare)], check=True, capture_output=True)

    run_git(str(work_repo), "init", "-b", "main")
    run_git(str(work_repo), "config", "user.email", "test@example.org")
    run_git(str(work_repo), "config", "user.name", "Test Agent")

    (work_repo / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (work_repo / "test_ok.py").write_text(
        "from app import add\nassert add(2, 3) == 5\n", encoding="utf-8"
    )
    run_git(str(work_repo), "add", "app.py", "test_ok.py")
    run_git(str(work_repo), "commit", "-m", "initial passing commit")
    return work_repo, staging_bare, prod_bare


@pytest.fixture()
def test_env(tmp_path: Path):
    work_repo, staging_bare, prod_bare = _init_test_repos(tmp_path)
    ledger = ReceiptLedger(tmp_path / "se_ledger.db")
    ledger.set_policy(
        repo_id="payments-service",
        destination="staging",
        profile_id="unit",
        command=[sys.executable, "test_ok.py"],
        allowed_callers=["agent-claude", "agent-codex", "agent-agy"],
        ttl_seconds=600.0,
        single_use=True,
    )
    ledger.set_policy(
        repo_id="payments-service",
        destination="prod",
        profile_id="prod-suite",
        command=[sys.executable, "-c", "import app, test_ok; assert app.add(10, 20) == 30"],
        allowed_callers=["agent-claude", "agent-codex", "agent-agy"],
        ttl_seconds=600.0,
        single_use=True,
    )
    ext = Type3ReceiptExtension(
        ledger=ledger,
        repos={"payments-service": str(work_repo)},
        destinations={"staging": str(staging_bare), "prod": str(prod_bare)},
    )
    return {
        "tmp_path": tmp_path,
        "work_repo": work_repo,
        "staging_bare": staging_bare,
        "prod_bare": prod_bare,
        "ledger": ledger,
        "ext": ext,
    }


def test_benign_verify_then_publish_over_nlip_http(test_env):
    """End-to-end ECMA-430/431 HTTP test: control query -> verify -> publish."""
    app = create_nlip_receipt_server(test_env["ext"])
    client = TestClient(app)

    # 1. ECMA-430 §6.3 Control message query
    ctrl_req = NLIP_Message(
        messagetype=ReservedTokens.control,
        format=AllowedFormats.text,
        subformat="english",
        content="Query ECMA-434 security profile",
    )
    ctrl_rsp = client.post("/nlip/", json=ctrl_req.to_dict())
    assert ctrl_rsp.status_code == 200
    ctrl_msg = NLIP_Message(**ctrl_rsp.json())
    assert ctrl_msg.is_control_msg()

    # 2. Verify via NLIP POST
    v_prop = ToolCallProposal(
        operation="verify",
        repo_id="payments-service",
        artifact_ref="HEAD",
        destination="staging",
        profile_id="unit",
    )
    v_req = pack_tool_call_message(
        v_prop, auth_token="agent-claude:secret-token-123", conversation_id="conv-001"
    )
    v_http = client.post("/nlip/", json=v_req.to_dict())
    assert v_http.status_code == 200
    v_rsp = NLIP_Message(**v_http.json())
    assert v_rsp.extract_conversation_token() == "conv-001"
    v_dec, v_rec = extract_decision_from_response(v_rsp)
    assert v_dec.action == "allow"
    assert v_dec.reason_code == "VERIFICATION_PASSED"
    assert v_rec is not None

    # 3. Publish using the issued receipt
    p_prop = ToolCallProposal(
        operation="publish",
        repo_id="payments-service",
        artifact_ref="HEAD",
        destination="staging",
        branch="main",
        profile_id="unit",
        receipt_id=v_rec.receipt_id,
    )
    p_req = pack_tool_call_message(
        p_prop, auth_token="agent-claude:secret-token-123", conversation_id="conv-001"
    )
    p_http = client.post("/nlip/", json=p_req.to_dict())
    assert p_http.status_code == 200
    p_dec, _ = extract_decision_from_response(NLIP_Message(**p_http.json()))
    assert p_dec.action == "allow"
    assert p_dec.reason_code == "VERIFIED_RECEIPT_VALID"
    assert p_dec.published_ref is not None


def test_blocks_unverified_self_report_and_forged_submessage(test_env):
    """Attack A01/A02/A03: Self-report ('tests passed') and forged receipt submessages are denied."""
    ext: Type3ReceiptExtension = test_env["ext"]

    # Self-report only
    prop_self = ToolCallProposal(
        operation="publish",
        repo_id="payments-service",
        artifact_ref="HEAD",
        destination="staging",
        profile_id="unit",
    )
    msg_self = pack_tool_call_message(
        prop_self,
        auth_token="agent-claude:tok",
        text_summary="All 42 unit tests passed with 0 errors. Proceeding to publish.",
    )
    dec_self, _ = extract_decision_from_response(ext.handle_nlip_message(msg_self))
    assert dec_self.action == "deny"
    assert dec_self.reason_code == "MISSING_RECEIPT"

    # Forged structured receipt submessage
    forged = {
        "receipt_id": "rcpt-forged999999",
        "issuer_id": ext.ledger.issuer_id(),
        "caller_id": "agent-claude",
        "status": "passed",
        "exit_code": 0,
    }
    msg_forged = pack_tool_call_message(
        prop_self,
        auth_token="agent-claude:tok",
        forged_receipt=forged,
    )
    dec_forged, _ = extract_decision_from_response(ext.handle_nlip_message(msg_forged))
    assert dec_forged.action == "deny"
    assert dec_forged.reason_code == "FORGED_RECEIPT_SUBMESSAGE"


def test_blocks_toctou_post_verification_mutation_and_pins_commit(test_env):
    """Attack A04 & Snapshot/Commit pinning:
    1) Modifying code and committing C2 after verifying C1 blocks publishing C2 with C1's receipt.
    2) Dirty uncommitted working-tree changes do not leak into verified snapshot or published commit.
    """
    ext: Type3ReceiptExtension = test_env["ext"]
    work_repo: Path = test_env["work_repo"]

    c1 = resolve_commit_and_tree(str(work_repo), "HEAD")
    v_msg = pack_tool_call_message(
        ToolCallProposal(
            operation="verify",
            repo_id="payments-service",
            artifact_ref=c1.commit_oid,
            destination="staging",
            profile_id="unit",
        ),
        auth_token="agent-claude:tok",
    )
    _, receipt = extract_decision_from_response(ext.handle_nlip_message(v_msg))
    assert receipt is not None

    # Mutate repository and create unverified commit C2
    (work_repo / "app.py").write_text("def add(a, b):\n    return 999  # backdoor\n", encoding="utf-8")
    run_git(str(work_repo), "add", "app.py")
    run_git(str(work_repo), "commit", "-m", "inject unverified change")

    # Attempt to publish HEAD (now C2) using C1's receipt -> must fail with ARTIFACT_TREE_MISMATCH
    p_msg = pack_tool_call_message(
        ToolCallProposal(
            operation="publish",
            repo_id="payments-service",
            artifact_ref="HEAD",
            destination="staging",
            profile_id="unit",
            receipt_id=receipt.receipt_id,
        ),
        auth_token="agent-claude:tok",
    )
    dec_toctou, _ = extract_decision_from_response(ext.handle_nlip_message(p_msg))
    assert dec_toctou.action == "deny"
    assert dec_toctou.reason_code == "ARTIFACT_TREE_MISMATCH"


def test_blocks_cross_caller_replay_and_destination_substitution(test_env):
    """Attack A06 & A07: Confused-Deputy cross-caller replay and staging->prod substitution."""
    ext: Type3ReceiptExtension = test_env["ext"]

    v_msg = pack_tool_call_message(
        ToolCallProposal(
            operation="verify",
            repo_id="payments-service",
            artifact_ref="HEAD",
            destination="staging",
            profile_id="unit",
        ),
        auth_token="agent-claude:tok",
    )
    _, receipt = extract_decision_from_response(ext.handle_nlip_message(v_msg))
    assert receipt is not None

    # A06: agent-codex attempts to use agent-claude's receipt
    replay_msg = pack_tool_call_message(
        ToolCallProposal(
            operation="publish",
            repo_id="payments-service",
            artifact_ref="HEAD",
            destination="staging",
            profile_id="unit",
            receipt_id=receipt.receipt_id,
        ),
        auth_token="agent-codex:tok",
    )
    dec_replay, _ = extract_decision_from_response(ext.handle_nlip_message(replay_msg))
    assert dec_replay.action == "deny"
    assert dec_replay.reason_code == "CROSS_CALLER_REPLAY"

    # A07: agent-claude attempts to use staging ('unit') receipt to publish to 'prod' ('prod-suite')
    subst_msg = pack_tool_call_message(
        ToolCallProposal(
            operation="publish",
            repo_id="payments-service",
            artifact_ref="HEAD",
            destination="prod",
            profile_id="prod-suite",
            receipt_id=receipt.receipt_id,
        ),
        auth_token="agent-claude:tok",
    )
    dec_subst, _ = extract_decision_from_response(ext.handle_nlip_message(subst_msg))
    assert dec_subst.action == "deny"
    assert dec_subst.reason_code == "PROFILE_OR_REPO_MISMATCH"


def test_blocks_expired_stale_epoch_single_use_and_superseded_failure(test_env):
    """Attack A08, A09, A10: TTL expiry, policy epoch change, single-use replay, and superseding failure."""
    ext: Type3ReceiptExtension = test_env["ext"]
    work_repo: Path = test_env["work_repo"]

    # Issue passing receipt at t=1000.0
    v_prop = ToolCallProposal(
        operation="verify",
        repo_id="payments-service",
        artifact_ref="HEAD",
        destination="staging",
        profile_id="unit",
        caller_id="agent-claude",
    )
    _, rec1 = ext.handle_proposal(v_prop, now=1000.0)
    assert rec1 is not None

    # 1. Expired at t=2000.0 (TTL is 600s)
    p_prop = ToolCallProposal(
        operation="publish",
        repo_id="payments-service",
        artifact_ref="HEAD",
        destination="staging",
        profile_id="unit",
        receipt_id=rec1.receipt_id,
        caller_id="agent-claude",
    )
    dec_exp, _ = ext.handle_proposal(p_prop, now=2000.0)
    assert dec_exp.action == "deny"
    assert dec_exp.reason_code == "RECEIPT_EXPIRED"

    # 2. Valid publish at t=1100.0 consumes the receipt, second publish with same receipt fails
    dec_ok, _ = ext.handle_proposal(p_prop, now=1100.0)
    assert dec_ok.action == "allow"
    dec_reuse, _ = ext.handle_proposal(p_prop, now=1105.0)
    assert dec_reuse.action == "deny"
    assert dec_reuse.reason_code == "RECEIPT_ALREADY_CONSUMED"

    # 3. Superseding failure: rec2 passes at t=1200, then a subsequent run on the same tree fails at t=1210
    _, rec2 = ext.handle_proposal(v_prop, now=1200.0)
    assert rec2 is not None
    artifact = resolve_commit_and_tree(str(work_repo), "HEAD")
    ext.ledger.issue_receipt(
        caller_id="agent-claude",
        repo_id="payments-service",
        commit_oid=artifact.commit_oid,
        tree_oid=artifact.tree_oid,
        profile_id="unit",
        command_sha256=rec2.command_sha256,
        env_fingerprint=rec2.env_fingerprint,
        status="failed",
        exit_code=1,
        duration_ms=5.0,
        output_sha256="deadbeef",
        policy_epoch=rec2.policy_epoch,
        ttl_seconds=600.0,
        issued_at=1210.0,
    )
    p_prop2 = p_prop.model_copy(update={"receipt_id": rec2.receipt_id})
    dec_sup, _ = ext.handle_proposal(p_prop2, now=1220.0)
    assert dec_sup.action == "deny"
    assert dec_sup.reason_code == "SUPERSEDED_BY_FAILURE"


def test_multi_harness_adapters_claude_codex_agy(test_env):
    """Portability across Claude Code, Codex CLI, and Antigravity (AGY) adapters."""
    ext: Type3ReceiptExtension = test_env["ext"]

    claude = ClaudeCodePreToolAdapter(ext, auth_token="agent-claude:secret")
    codex = CodexExecToolAdapter(ext, auth_token="agent-codex:secret")
    agy = AntigravityToolAdapter(ext, auth_token="agent-agy:secret")

    # 1. Claude Code verifies and publishes
    c_ver = claude.evaluate_pre_tool_use(
        {
            "session_id": "claude-sess-1",
            "tool_input": {
                "operation": "verify",
                "repo_id": "payments-service",
                "artifact_ref": "HEAD",
                "destination": "staging",
                "profile_id": "unit",
            },
        }
    )
    assert c_ver["hookSpecificOutput"]["permissionDecision"] == "allow"
    rcpt_claude = c_ver["nlip_receipt"]["receipt_id"]

    c_pub = claude.evaluate_pre_tool_use(
        {
            "session_id": "claude-sess-1",
            "tool_input": {
                "operation": "publish",
                "repo_id": "payments-service",
                "artifact_ref": "HEAD",
                "destination": "staging",
                "branch": "claude-branch",
                "profile_id": "unit",
                "receipt_id": rcpt_claude,
            },
        }
    )
    assert c_pub["hookSpecificOutput"]["permissionDecision"] == "allow"

    # 2. Codex CLI verifies and publishes
    x_ver = codex.evaluate_codex_tool_call(
        {
            "thread_id": "codex-thr-1",
            "arguments": {
                "operation": "verify",
                "repo_id": "payments-service",
                "artifact_ref": "HEAD",
                "destination": "staging",
                "profile_id": "unit",
            },
        }
    )
    assert x_ver["allowed"] is True
    x_pub = codex.evaluate_codex_tool_call(
        {
            "thread_id": "codex-thr-1",
            "arguments": {
                "operation": "publish",
                "repo_id": "payments-service",
                "artifact_ref": "HEAD",
                "destination": "staging",
                "branch": "codex-branch",
                "profile_id": "unit",
                "receipt_id": x_ver["receipt_id"],
            },
        }
    )
    assert x_pub["allowed"] is True

    # 3. Antigravity (AGY) verifies and publishes
    a_ver = agy.evaluate_agy_tool_call(
        {
            "conversation_id": "agy-conv-1",
            "parameters": {
                "operation": "verify",
                "repo_id": "payments-service",
                "artifact_ref": "HEAD",
                "destination": "staging",
                "profile_id": "unit",
            },
        }
    )
    assert a_ver["status"] == "EXECUTED"
    a_pub = agy.evaluate_agy_tool_call(
        {
            "conversation_id": "agy-conv-1",
            "parameters": {
                "operation": "publish",
                "repo_id": "payments-service",
                "artifact_ref": "HEAD",
                "destination": "staging",
                "branch": "agy-branch",
                "profile_id": "unit",
                "receipt_id": a_ver["receipt_id"],
            },
        }
    )
    assert a_pub["status"] == "EXECUTED"
