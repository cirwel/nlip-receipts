"""End-to-End Runnable Demonstration of the NLIP Type-3 Verification Receipt Gate (`make demo`).

Demonstrates:
1. ECMA-430 §6.3 `control` handshake advertising ECMA-434 Security Profile & SCOs.
2. Blocking agent self-report ("tests passed") and forged NLIP receipt submessages.
3. Snapshot-isolated Type-3 `verify` execution (`git archive`) and HMAC receipt issuance.
4. Blocking post-verification TOCTOU mutations (`ARTIFACT_TREE_MISMATCH`).
5. Blocking Confused-Deputy cross-caller receipt replay (`CROSS_CALLER_REPLAY`).
6. Authorized publication (`publish`) across Claude Code, Codex CLI, and Antigravity (AGY)
   adapters to a bare Git destination repository, with hash-chained audit log inspection.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

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
    NLIPTransportError,
    extract_decision_from_response,
    http_nlip_transport,
)
from nlip_receipts.git_artifact import resolve_commit_and_tree, run_git
from nlip_receipts.server import create_nlip_receipt_server

REPO_ROOT = Path(__file__).resolve().parent
HOOK_SCRIPT = REPO_ROOT / "hooks" / "claude_pretool_nlip.py"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _banner(title: str) -> None:
    print(f"\n{'=' * 78}\n  {title}\n{'=' * 78}")


def run_demo(*, use_http: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix="nlip-se-demo-") as tmp:
        base = Path(tmp)
        work = base / "payments-service"
        work.mkdir()
        staging = base / "staging.git"
        se_dir = base / "se-state"
        se_dir.mkdir()
        subprocess.run(["git", "init", "--bare", str(staging)], check=True, capture_output=True)

        run_git(str(work), "init", "-b", "main")
        run_git(str(work), "config", "user.email", "demo@safeose.org")
        run_git(str(work), "config", "user.name", "SafeOSE Demo")

        (work / "ledger_calc.py").write_text(
            "def settle(amount: int, fee: int) -> int:\n    return amount - fee\n",
            encoding="utf-8",
        )
        (work / "test_settle.py").write_text(
            "from ledger_calc import settle\nassert settle(100, 3) == 97\n",
            encoding="utf-8",
        )
        run_git(str(work), "add", "ledger_calc.py", "test_settle.py")
        run_git(str(work), "commit", "-m", "C1: initial settlement logic")
        c1 = resolve_commit_and_tree(str(work), "HEAD")

        ledger_path = se_dir / "se_ledger.db"
        server_proc: subprocess.Popen | None = None
        server_url = ""
        ext: Type3ReceiptExtension | None = None

        if use_http:
            port = _free_port()
            server_url = f"http://127.0.0.1:{port}"
            cfg_path = se_dir / "server_config.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "ledger_path": str(ledger_path),
                        "repos": {"payments-service": str(work)},
                        "destinations": {"staging": str(staging)},
                        "caller_secrets_env": {
                            "agent-claude": "DEMO_CLAUDE_SECRET",
                            "agent-codex": "DEMO_CODEX_SECRET",
                            "agent-agy": "DEMO_AGY_SECRET",
                        },
                        "policies": [
                            {
                                "repo_id": "payments-service",
                                "destination": "staging",
                                "profile_id": "unit-suite",
                                "command": [sys.executable, "test_settle.py"],
                                "allowed_callers": ["agent-claude", "agent-codex", "agent-agy"],
                                "allowed_branches": [
                                    "main",
                                    "mcp-verified",
                                    "codex-verified",
                                    "agy-verified",
                                ],
                                "ttl_seconds": 600.0,
                                "single_use": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(cfg_path, 0o600)
            srv_env = {
                **os.environ,
                "PYTHONPATH": str(REPO_ROOT),
                "DEMO_CLAUDE_SECRET": "session-token",
                "DEMO_CODEX_SECRET": "session-token",
                "DEMO_AGY_SECRET": "session-token",
            }
            server_proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "nlip_receipts.server",
                    "--config",
                    str(cfg_path),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=str(REPO_ROOT),
                env=srv_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            send: Callable[[NLIP_Message], NLIP_Message] = http_nlip_transport(
                server_url, timeout=10.0
            )
            probe = NLIP_Message(
                messagetype=ReservedTokens.control,
                format=AllowedFormats.text,
                subformat="english",
                content="probe",
            )
            for _ in range(60):
                try:
                    if send(probe).is_control_msg():
                        break
                except NLIPTransportError:
                    time.sleep(0.1)
            else:
                server_proc.terminate()
                raise RuntimeError("nlip_server failed to start in --http demo mode")
        else:
            ledger = ReceiptLedger(ledger_path)
            for caller in ("agent-claude", "agent-codex", "agent-agy"):
                ledger.register_caller_secret(caller, "session-token")
            ledger.set_policy(
                repo_id="payments-service",
                destination="staging",
                profile_id="unit-suite",
                command=[sys.executable, "test_settle.py"],
                allowed_callers=["agent-claude", "agent-codex", "agent-agy"],
                allowed_branches=["main", "codex-verified", "agy-verified"],
                ttl_seconds=600.0,
                single_use=True,
            )
            ext = Type3ReceiptExtension(
                ledger=ledger,
                repos={"payments-service": str(work)},
                destinations={"staging": str(staging)},
            )
            app = create_nlip_receipt_server(ext)
            client = TestClient(app)
            send = lambda m: NLIP_Message(**client.post("/nlip/", json=m.to_dict()).json())

        try:
            mode_label = f"LIVE HTTP ({server_url})" if use_http else "IN-PROCESS TestClient"
            _banner(f"STEP 1: ECMA-430 Control Handshake & Profile Discovery [{mode_label}]")
            ctrl_req = NLIP_Message(
                messagetype=ReservedTokens.control,
                format=AllowedFormats.text,
                subformat="english",
                content="Query endpoint ECMA-434 security profile",
            )
            ctrl_rsp = send(ctrl_req)
            print(f"Control Response: {ctrl_rsp.content}")
            print(f"Structured Profile: {ctrl_rsp.submessages[0].content}")

            _banner("STEP 2: Attack Blocked — Self-Report & Forged NLIP Submessage")
            forged_msg = pack_tool_call_message(
                ToolCallProposal(
                    operation="publish",
                    repo_id="payments-service",
                    artifact_ref=c1.commit_oid,
                    destination="staging",
                    profile_id="unit-suite",
                ),
                auth_token="agent-claude:session-token",
                text_summary="All unit tests passed locally! Publishing now.",
                forged_receipt={
                    "receipt_id": "rcpt-fake999",
                    "status": "passed",
                    "exit_code": 0,
                    "tree_oid": c1.tree_oid,
                },
            )
            dec_forged, _ = extract_decision_from_response(send(forged_msg))
            print(f"Action:      {dec_forged.action.upper()}")
            print(f"Reason Code: {dec_forged.reason_code}")
            print(f"Message:     {dec_forged.message}")
            print(f"ECMA-434:    {dec_forged.sco_refs}")

            _banner("STEP 3: Trusted Type-3 Snapshot Verification (`verify`)")
            verify_msg = pack_tool_call_message(
                ToolCallProposal(
                    operation="verify",
                    repo_id="payments-service",
                    artifact_ref=c1.commit_oid,
                    destination="staging",
                    profile_id="unit-suite",
                ),
                auth_token="agent-claude:session-token",
                conversation_id="conv-demo-01",
            )
            dec_ver, rec_c1 = extract_decision_from_response(send(verify_msg))
            assert rec_c1 is not None
            print(f"Action:      {dec_ver.action.upper()} ({dec_ver.reason_code})")
            print(f"Receipt ID:  {rec_c1.receipt_id}")
            print(f"Bound Tree:  {rec_c1.tree_oid}")
            print(f"Bound Caller:{rec_c1.caller_id} | Duration: {rec_c1.duration_ms:.2f} ms")

            _banner("STEP 4: Attack Blocked — Post-Verification TOCTOU Code Mutation")
            (work / "ledger_calc.py").write_text(
                "def settle(amount: int, fee: int) -> int:\n    return 0  # unauthorized drain\n",
                encoding="utf-8",
            )
            run_git(str(work), "add", "ledger_calc.py")
            run_git(str(work), "commit", "-m", "C2: unverified post-check edit")
            c2 = resolve_commit_and_tree(str(work), "HEAD")

            toctou_msg = pack_tool_call_message(
                ToolCallProposal(
                    operation="publish",
                    repo_id="payments-service",
                    artifact_ref=c2.commit_oid,
                    destination="staging",
                    profile_id="unit-suite",
                    receipt_id=rec_c1.receipt_id,
                ),
                auth_token="agent-claude:session-token",
            )
            dec_toctou, _ = extract_decision_from_response(send(toctou_msg))
            print(f"Action:      {dec_toctou.action.upper()}")
            print(f"Reason Code: {dec_toctou.reason_code}")
            print(f"Message:     {dec_toctou.message}")

            _banner("STEP 5: Attack Blocked — Confused-Deputy Cross-Caller Receipt Replay")
            replay_msg = pack_tool_call_message(
                ToolCallProposal(
                    operation="publish",
                    repo_id="payments-service",
                    artifact_ref=c1.commit_oid,
                    destination="staging",
                    profile_id="unit-suite",
                    receipt_id=rec_c1.receipt_id,
                ),
                auth_token="agent-codex:session-token",
            )
            dec_replay, _ = extract_decision_from_response(send(replay_msg))
            print(f"Action:      {dec_replay.action.upper()}")
            print(f"Reason Code: {dec_replay.reason_code}")
            print(f"Message:     {dec_replay.message}")

            if use_http:
                _banner("STEP 5b: Live Claude PreToolUse Guardrail + MCP Stdio Bridge")
                hook_proc = subprocess.run(
                    [sys.executable, str(HOOK_SCRIPT)],
                    input=json.dumps(
                        {"tool_name": "Bash", "tool_input": {"command": "git push staging HEAD:main"}}
                    ),
                    capture_output=True,
                    text=True,
                    check=True,
                )
                hook_out = json.loads(hook_proc.stdout)["hookSpecificOutput"]
                print(
                    f"[Claude PreToolUse Hook] Bash `git push` -> {hook_out['permissionDecision'].upper()} "
                    f"({hook_out['permissionDecisionReason']})"
                )

                mcp_input = "\n".join(
                    [
                        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                        json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": 2,
                                "method": "tools/call",
                                "params": {
                                    "name": "nlip_verify",
                                    "arguments": {
                                        "repo_id": "payments-service",
                                        "artifact_ref": c1.commit_oid,
                                        "destination": "staging",
                                        "profile_id": "unit-suite",
                                    },
                                },
                            }
                        ),
                    ]
                ) + "\n"
                mcp_env = {
                    **os.environ,
                    "PYTHONPATH": str(REPO_ROOT),
                    "NLIP_SERVER_URL": server_url,
                    "NLIP_CALLER_TOKEN": "agent-claude:session-token",
                }
                mcp_ver_proc = subprocess.run(
                    [sys.executable, "-m", "nlip_receipts.mcp_stdio"],
                    input=mcp_input,
                    env=mcp_env,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                mcp_ver_lines = [json.loads(ln) for ln in mcp_ver_proc.stdout.splitlines() if ln.strip()]
                mcp_rcpt = json.loads(mcp_ver_lines[1]["result"]["content"][0]["text"])["receipt"][
                    "receipt_id"
                ]
                mcp_pub_proc = subprocess.run(
                    [sys.executable, "-m", "nlip_receipts.mcp_stdio"],
                    input=json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {
                                "name": "nlip_publish",
                                "arguments": {
                                    "repo_id": "payments-service",
                                    "artifact_ref": c1.commit_oid,
                                    "destination": "staging",
                                    "branch": "mcp-verified",
                                    "profile_id": "unit-suite",
                                    "receipt_id": mcp_rcpt,
                                },
                            },
                        }
                    )
                    + "\n",
                    env=mcp_env,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                mcp_pub = json.loads(
                    json.loads(mcp_pub_proc.stdout.splitlines()[0])["result"]["content"][0]["text"]
                )["decision"]
                print(
                    f"[MCP Stdio -> HTTP]    decision={mcp_pub['action']} | ref={mcp_pub['published_ref']}"
                )

            _banner("STEP 6: Authorized Multi-Harness Publication (Claude, Codex, Antigravity)")
            adapter_transport = send if use_http else None
            # Claude publishes C1 using its valid receipt (even though working tree HEAD is currently C2!)
            claude_adapter = ClaudeCodePreToolAdapter(
                ext, auth_token="agent-claude:session-token", transport=adapter_transport
            )
            claude_res = claude_adapter.evaluate_pre_tool_use(
                {
                    "session_id": "claude-demo",
                    "tool_input": {
                        "operation": "publish",
                        "repo_id": "payments-service",
                        "artifact_ref": c1.commit_oid,
                        "destination": "staging",
                        "branch": "main",
                        "profile_id": "unit-suite",
                        "receipt_id": rec_c1.receipt_id,
                    },
                }
            )
            print(
                f"[Claude Code Adapter]  decision={claude_res['hookSpecificOutput']['permissionDecision']} "
                f"| ref={claude_res['nlip_decision']['published_ref']}"
            )

            # Codex verifies and publishes C1 to codex-verified branch
            codex_adapter = CodexExecToolAdapter(
                ext, auth_token="agent-codex:session-token", transport=adapter_transport
            )
            codex_ver = codex_adapter.evaluate_codex_tool_call(
                {
                    "thread_id": "codex-demo",
                    "arguments": {
                        "operation": "verify",
                        "repo_id": "payments-service",
                        "artifact_ref": c1.commit_oid,
                        "destination": "staging",
                        "profile_id": "unit-suite",
                    },
                }
            )
            codex_pub = codex_adapter.evaluate_codex_tool_call(
                {
                    "thread_id": "codex-demo",
                    "arguments": {
                        "operation": "publish",
                        "repo_id": "payments-service",
                        "artifact_ref": c1.commit_oid,
                        "destination": "staging",
                        "branch": "codex-verified",
                        "profile_id": "unit-suite",
                        "receipt_id": codex_ver["receipt_id"],
                    },
                }
            )
            print(
                f"[Codex CLI Adapter]    allowed={codex_pub['allowed']} "
                f"| ref={codex_pub['published_ref']}"
            )

            # Antigravity (AGY) verifies and publishes C1 to agy-verified branch
            agy_adapter = AntigravityToolAdapter(
                ext, auth_token="agent-agy:session-token", transport=adapter_transport
            )
            agy_ver = agy_adapter.evaluate_agy_tool_call(
                {
                    "conversation_id": "agy-demo",
                    "parameters": {
                        "operation": "verify",
                        "repo_id": "payments-service",
                        "artifact_ref": c1.commit_oid,
                        "destination": "staging",
                        "profile_id": "unit-suite",
                    },
                }
            )
            agy_pub = agy_adapter.evaluate_agy_tool_call(
                {
                    "conversation_id": "agy-demo",
                    "parameters": {
                        "operation": "publish",
                        "repo_id": "payments-service",
                        "artifact_ref": c1.commit_oid,
                        "destination": "staging",
                        "branch": "agy-verified",
                        "profile_id": "unit-suite",
                        "receipt_id": agy_ver["receipt_id"],
                    },
                }
            )
            print(
                f"[Antigravity Adapter]  status={agy_pub['status']} "
                f"| ref={agy_pub['published_ref']}"
            )
        finally:
            if server_proc is not None:
                server_proc.terminate()
                server_proc.wait(timeout=5)

        _banner("STEP 7: Hash-Chained Audit Trail Inspection (ECMA-434 §7.2.4)")
        audit_ledger = (
            ReceiptLedger(ledger_path, hmac_key=(se_dir / "se_ledger.db.hmac").read_bytes())
            if use_http
            else ext.ledger  # type: ignore[union-attr]
        )
        decisions = audit_ledger.list_decisions(limit=25)
        for row in reversed(decisions):
            print(
                f"seq={row['seq']:02d} | {row['action'].upper():5s} | {row['reason_code']:26s} "
                f"| caller={row['caller_id']:12s} | hash={row['entry_hash'][:12]}..."
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--http",
        action="store_true",
        help="Run against a live uvicorn nlip_server subprocess, MCP stdio bridge, and Claude PreToolUse hook.",
    )
    cli_args = parser.parse_args()
    run_demo(use_http=cli_args.http)
