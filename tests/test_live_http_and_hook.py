"""Live out-of-process HTTP server, MCP stdio bridge, and Claude `PreToolUse` hook tests."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from nlip_sdk.nlip import AllowedFormats, NLIP_Message, ReservedTokens

from nlip_receipts import ReceiptLedger, ToolCallProposal, Type3ReceiptExtension, pack_tool_call_message
from nlip_receipts.adapters import (
    AntigravityToolAdapter,
    ClaudeCodePreToolAdapter,
    CodexExecToolAdapter,
    NLIPTransportError,
    extract_decision_from_response,
    http_nlip_transport,
)
from nlip_receipts.git_artifact import resolve_commit_and_tree, run_git
from nlip_receipts.server import (
    build_extension_from_config,
    create_nlip_receipt_server,
    load_or_create_hmac_key,
    main as server_main,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK_SCRIPT = REPO_ROOT / "hooks" / "claude_pretool_nlip.py"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _init_sample_repo(base: Path) -> tuple[Path, Path, str, str]:
    from nlip_receipts.git_artifact import _safe_git_env

    fixed_env = {
        **_safe_git_env(),
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000",
    }
    work = base / "svc"
    work.mkdir()
    dest = base / "staging.git"
    dest.mkdir()
    run_git(str(dest), "init", "-q", "--bare", "--template=", "--object-format=sha1")
    run_git(str(work), "init", "-q", "--template=", "--object-format=sha1", "-b", "main")
    run_git(str(work), "config", "user.email", "test@example.invalid")
    run_git(str(work), "config", "user.name", "Test")
    (work / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (work / "check.py").write_text("from app import add\nassert add(2, 3) == 5\n", encoding="utf-8")
    run_git(str(work), "add", ".")
    subprocess.run(
        ["git", "-c", f"core.hooksPath={os.devnull}", "-C", str(work), "commit", "-qm", "C1"],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        env=fixed_env,
    )
    c1 = resolve_commit_and_tree(str(work), "HEAD").commit_oid

    (work / "app.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    run_git(str(work), "add", "app.py")
    subprocess.run(
        ["git", "-c", f"core.hooksPath={os.devnull}", "-C", str(work), "commit", "-qm", "C2 broken"],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        env=fixed_env,
    )
    c2 = resolve_commit_and_tree(str(work), "HEAD").commit_oid
    return work, dest, c1, c2


def _dest_refs(dest: Path) -> dict[str, str]:
    out = run_git(str(dest), "for-each-ref", "--format=%(refname) %(objectname)").decode()
    return dict(line.split() for line in out.splitlines())


def _start_http_server(config_path: Path, port: int, extra_env: dict[str, str] | None = None) -> subprocess.Popen:
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT), **(extra_env or {})}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "nlip_receipts.server",
            "--config",
            str(config_path),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    url = f"http://127.0.0.1:{port}"
    transport = http_nlip_transport(url, timeout=2.0)
    ctrl = NLIP_Message(
        messagetype=ReservedTokens.control,
        format=AllowedFormats.text,
        subformat="english",
        content="ready-probe",
    )
    for _ in range(60):
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=5)
            raise RuntimeError(f"nlip_server exited early ({proc.returncode}): {out}\n{err}")
        try:
            rsp = transport(ctrl)
            if rsp.is_control_msg():
                return proc
        except NLIPTransportError:
            pass
        import time

        time.sleep(0.1)
    proc.terminate()
    proc.wait(timeout=5)
    raise TimeoutError("nlip_server did not become ready within 6s")


def _write_server_config(
    path: Path,
    *,
    ledger_path: Path,
    work: Path,
    dest: Path,
    branches: list[str] | None = None,
) -> Path:
    cfg = {
        "ledger_path": str(ledger_path),
        "repos": {"svc": str(work)},
        "destinations": {"staging": str(dest)},
        "caller_secrets_env": {
            "agent-claude": "TEST_CLAUDE_SECRET",
            "agent-codex": "TEST_CODEX_SECRET",
            "agent-agy": "TEST_AGY_SECRET",
        },
        "policies": [
            {
                "repo_id": "svc",
                "destination": "staging",
                "profile_id": "unit",
                "command": [sys.executable, "check.py"],
                "allowed_callers": ["agent-claude", "agent-codex", "agent-agy"],
                "allowed_branches": branches or ["main", "codex-branch", "agy-branch"],
                "ttl_seconds": 600.0,
                "single_use": True,
            }
        ],
    }
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def test_inprocess_and_live_http_adapter_parity(tmp_path: Path) -> None:
    """In-process TestClient and live uvicorn HTTP transport produce identical decisions, audit
    reason sequences, and destination refs across all three harness adapters."""
    secrets_env = {
        "TEST_CLAUDE_SECRET": "sec-claude",
        "TEST_CODEX_SECRET": "sec-codex",
        "TEST_AGY_SECRET": "sec-agy",
    }

    def run_sequence(mode: str) -> tuple[list[tuple[str, str]], dict[str, str], list[str]]:
        sub = tmp_path / mode
        sub.mkdir()
        se_dir = sub / "se-state"
        se_dir.mkdir()
        work, dest, c1, c2 = _init_sample_repo(sub)
        cfg_path = _write_server_config(
            se_dir / "server.json", ledger_path=se_dir / "ledger.db", work=work, dest=dest
        )

        proc = None
        if mode == "inprocess":
            old = {k: os.environ.get(k) for k in secrets_env}
            os.environ.update(secrets_env)
            try:
                ext = build_extension_from_config(cfg_path)
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            tc = TestClient(create_nlip_receipt_server(ext))
            transport = lambda m: NLIP_Message(**tc.post("/nlip/", json=m.to_dict()).json())
        else:
            port = _free_port()
            proc = _start_http_server(cfg_path, port, extra_env=secrets_env)
            transport = http_nlip_transport(f"http://127.0.0.1:{port}")

        try:
            claude = ClaudeCodePreToolAdapter(
                None, auth_token="agent-claude:sec-claude", transport=transport
            )
            codex = CodexExecToolAdapter(
                None, auth_token="agent-codex:sec-codex", transport=transport
            )
            agy = AntigravityToolAdapter(
                None, auth_token="agent-agy:sec-agy", transport=transport
            )

            outcomes: list[tuple[str, str]] = []

            # 1. Unverified publish denied
            r1 = claude.evaluate_pre_tool_use(
                {
                    "session_id": "s1",
                    "tool_input": {
                        "operation": "publish",
                        "repo_id": "svc",
                        "artifact_ref": c1,
                        "destination": "staging",
                        "branch": "main",
                        "profile_id": "unit",
                    },
                }
            )
            outcomes.append(
                (r1["hookSpecificOutput"]["permissionDecision"], r1["nlip_decision"]["reason_code"])
            )

            # 2. Verify C1 succeeds
            v1 = claude.evaluate_pre_tool_use(
                {
                    "session_id": "s1",
                    "tool_input": {
                        "operation": "verify",
                        "repo_id": "svc",
                        "artifact_ref": c1,
                        "destination": "staging",
                        "profile_id": "unit",
                    },
                }
            )
            rcpt_c1 = v1["nlip_receipt"]["receipt_id"]
            outcomes.append(
                (v1["hookSpecificOutput"]["permissionDecision"], v1["nlip_decision"]["reason_code"])
            )

            # 3. TOCTOU publish C2 with C1's receipt denied
            r_toctou = claude.evaluate_pre_tool_use(
                {
                    "session_id": "s1",
                    "tool_input": {
                        "operation": "publish",
                        "repo_id": "svc",
                        "artifact_ref": c2,
                        "destination": "staging",
                        "branch": "main",
                        "profile_id": "unit",
                        "receipt_id": rcpt_c1,
                    },
                }
            )
            outcomes.append(
                (
                    r_toctou["hookSpecificOutput"]["permissionDecision"],
                    r_toctou["nlip_decision"]["reason_code"],
                )
            )

            # 4. Cross-caller replay by codex denied
            r_replay = codex.evaluate_codex_tool_call(
                {
                    "thread_id": "t1",
                    "arguments": {
                        "operation": "publish",
                        "repo_id": "svc",
                        "artifact_ref": c1,
                        "destination": "staging",
                        "branch": "codex-branch",
                        "profile_id": "unit",
                        "receipt_id": rcpt_c1,
                    },
                }
            )
            outcomes.append(("allow" if r_replay["allowed"] else "deny", r_replay["reason_code"]))

            # 5. Authorized Claude publish C1 succeeds
            r_pub = claude.evaluate_pre_tool_use(
                {
                    "session_id": "s1",
                    "tool_input": {
                        "operation": "publish",
                        "repo_id": "svc",
                        "artifact_ref": c1,
                        "destination": "staging",
                        "branch": "main",
                        "profile_id": "unit",
                        "receipt_id": rcpt_c1,
                    },
                }
            )
            outcomes.append(
                (
                    r_pub["hookSpecificOutput"]["permissionDecision"],
                    r_pub["nlip_decision"]["reason_code"],
                )
            )

            # 6. Antigravity verify + publish over same transport
            v_agy = agy.evaluate_agy_tool_call(
                {
                    "conversation_id": "a1",
                    "parameters": {
                        "operation": "verify",
                        "repo_id": "svc",
                        "artifact_ref": c1,
                        "destination": "staging",
                        "profile_id": "unit",
                    },
                }
            )
            p_agy = agy.evaluate_agy_tool_call(
                {
                    "conversation_id": "a1",
                    "parameters": {
                        "operation": "publish",
                        "repo_id": "svc",
                        "artifact_ref": c1,
                        "destination": "staging",
                        "branch": "agy-branch",
                        "profile_id": "unit",
                        "receipt_id": v_agy["receipt_id"],
                    },
                }
            )
            outcomes.append((p_agy["status"], p_agy["reason_code"]))
        finally:
            if proc is not None:
                proc.terminate()
                proc.wait(timeout=5)

        ro_ledger = ReceiptLedger(se_dir / "ledger.db", hmac_key=(se_dir / "ledger.db.hmac").read_bytes())
        audit_reasons = [row["reason_code"] for row in reversed(ro_ledger.list_decisions(limit=50))]
        return outcomes, _dest_refs(dest), audit_reasons

    inproc_outcomes, inproc_refs, inproc_audit = run_sequence("inprocess")
    live_outcomes, live_refs, live_audit = run_sequence("live_http")

    assert inproc_outcomes == live_outcomes == [
        ("deny", "MISSING_RECEIPT"),
        ("allow", "VERIFICATION_PASSED"),
        ("deny", "ARTIFACT_TREE_MISMATCH"),
        ("deny", "CROSS_CALLER_REPLAY"),
        ("allow", "VERIFIED_RECEIPT_VALID"),
        ("EXECUTED", "VERIFIED_RECEIPT_VALID"),
    ]
    assert inproc_refs == live_refs
    assert set(live_refs) == {"refs/heads/main", "refs/heads/agy-branch"}
    assert inproc_audit == live_audit


def test_server_restart_preserves_receipts_and_rotates_on_policy_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_CLAUDE_SECRET", "sec-claude")
    monkeypatch.setenv("TEST_CODEX_SECRET", "sec-codex")
    monkeypatch.setenv("TEST_AGY_SECRET", "sec-agy")

    se_dir = tmp_path / "se"
    se_dir.mkdir()
    work, dest, c1, _ = _init_sample_repo(tmp_path)
    cfg_path = _write_server_config(
        se_dir / "server.json", ledger_path=se_dir / "ledger.db", work=work, dest=dest
    )

    ext1 = build_extension_from_config(cfg_path)
    v1_msg = pack_tool_call_message(
        ToolCallProposal(
            operation="verify",
            repo_id="svc",
            artifact_ref=c1,
            destination="staging",
            profile_id="unit",
        ),
        auth_token="agent-claude:sec-claude",
    )
    _, rec1 = extract_decision_from_response(ext1.handle_nlip_message(v1_msg))
    assert rec1 is not None

    # Restart 1 with identical config: HMAC key & policy_epoch preserved, receipt stays spendable.
    ext2 = build_extension_from_config(cfg_path)
    pub_msg = pack_tool_call_message(
        ToolCallProposal(
            operation="publish",
            repo_id="svc",
            artifact_ref=c1,
            destination="staging",
            branch="main",
            profile_id="unit",
            receipt_id=rec1.receipt_id,
        ),
        auth_token="agent-claude:sec-claude",
    )
    dec2, _ = extract_decision_from_response(ext2.handle_nlip_message(pub_msg))
    assert dec2.action == "allow" and dec2.reason_code == "VERIFIED_RECEIPT_VALID"

    # Mint second receipt, then change allowed_branches in config and restart -> POLICY_EPOCH_STALE.
    _, rec2 = extract_decision_from_response(ext2.handle_nlip_message(v1_msg))
    assert rec2 is not None
    _write_server_config(
        cfg_path,
        ledger_path=se_dir / "ledger.db",
        work=work,
        dest=dest,
        branches=["main"],
    )
    ext3 = build_extension_from_config(cfg_path)
    pub_stale = pack_tool_call_message(
        ToolCallProposal(
            operation="publish",
            repo_id="svc",
            artifact_ref=c1,
            destination="staging",
            branch="main",
            profile_id="unit",
            receipt_id=rec2.receipt_id,
        ),
        auth_token="agent-claude:sec-claude",
    )
    dec3, _ = extract_decision_from_response(ext3.handle_nlip_message(pub_stale))
    assert dec3.action == "deny" and dec3.reason_code == "POLICY_EPOCH_STALE"


def test_server_refuses_non_loopback_and_transport_classifies_errors(tmp_path: Path) -> None:
    assert server_main(["--config", str(tmp_path / "missing.json"), "--host", "0.0.0.0"]) == 2

    dead_port = _free_port()
    dead_transport = http_nlip_transport(f"http://127.0.0.1:{dead_port}", timeout=0.5)
    ctrl = NLIP_Message(
        messagetype=ReservedTokens.control,
        format=AllowedFormats.text,
        subformat="english",
        content="probe",
    )
    with pytest.raises(NLIPTransportError, match="NLIP HTTP transport failed"):
        dead_transport(ctrl)

    def _bad_status(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "boom"})

    with httpx.Client(transport=httpx.MockTransport(_bad_status)) as mock_client:
        t500 = http_nlip_transport("http://nlip.local", client=mock_client)
        with pytest.raises(NLIPTransportError, match="500"):
            t500(ctrl)


def test_mcp_stdio_bridge_over_live_http_server(tmp_path: Path) -> None:
    se_dir = tmp_path / "se"
    se_dir.mkdir()
    work, dest, c1, c2 = _init_sample_repo(tmp_path)
    cfg_path = _write_server_config(
        se_dir / "server.json", ledger_path=se_dir / "ledger.db", work=work, dest=dest
    )
    secrets_env = {
        "TEST_CLAUDE_SECRET": "sec-claude",
        "TEST_CODEX_SECRET": "sec-codex",
        "TEST_AGY_SECRET": "sec-agy",
    }
    port = _free_port()
    srv = _start_http_server(cfg_path, port, extra_env=secrets_env)
    try:
        mcp_env = {
            **os.environ,
            "PYTHONPATH": str(REPO_ROOT),
            "NLIP_SERVER_URL": f"http://127.0.0.1:{port}",
            "NLIP_CALLER_TOKEN": "agent-claude:sec-claude",
        }
        mcp = subprocess.Popen(
            [sys.executable, "-m", "nlip_receipts.mcp_stdio"],
            cwd=str(REPO_ROOT),
            env=mcp_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert mcp.stdin is not None and mcp.stdout is not None

            def rpc(msg: dict[str, Any], *, framed: bool = False) -> dict[str, Any]:
                raw = json.dumps(msg).encode("utf-8")
                if framed:
                    mcp.stdin.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
                else:
                    mcp.stdin.write(raw + b"\n")
                mcp.stdin.flush()
                if framed:
                    hdr = mcp.stdout.readline().decode("ascii")
                    assert hdr.lower().startswith("content-length:")
                    n = int(hdr.split(":", 1)[1].strip())
                    assert mcp.stdout.readline() == b"\r\n"
                    return json.loads(mcp.stdout.read(n).decode("utf-8"))
                return json.loads(mcp.stdout.readline().decode("utf-8"))

            init_rsp = rpc(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}
            )
            assert init_rsp["result"]["serverInfo"]["name"] == "nlip-receipts-mcp"
            assert init_rsp["result"]["protocolVersion"] == "2024-11-05"

            fallback_init = rpc(
                {"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}
            )
            assert fallback_init["result"]["protocolVersion"] == "2024-11-05"

            # Notification produces no response
            mcp.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
            mcp.stdin.flush()

            tools_rsp = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, framed=True)
            names = {t["name"] for t in tools_rsp["result"]["tools"]}
            assert names == {"nlip_verify", "nlip_publish", "nlip_control"}

            ver_rsp = rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "nlip_verify",
                        "arguments": {
                            "repo_id": "svc",
                            "artifact_ref": c1,
                            "destination": "staging",
                            "profile_id": "unit",
                        },
                    },
                }
            )
            assert ver_rsp["result"]["isError"] is False
            ver_body = json.loads(ver_rsp["result"]["content"][0]["text"])
            assert "hmac_tag" not in json.dumps(ver_body)
            rcpt_id = ver_body["receipt"]["receipt_id"]

            # Mismatched C2 publish denied over MCP -> HTTP
            bad_pub = rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "nlip_publish",
                        "arguments": {
                            "repo_id": "svc",
                            "artifact_ref": c2,
                            "destination": "staging",
                            "branch": "main",
                            "profile_id": "unit",
                            "receipt_id": rcpt_id,
                        },
                    },
                }
            )
            assert bad_pub["result"]["isError"] is True
            assert (
                json.loads(bad_pub["result"]["content"][0]["text"])["decision"]["reason_code"]
                == "ARTIFACT_TREE_MISMATCH"
            )
            assert _dest_refs(dest) == {}

            # Matching C1 publish succeeds and updates bare destination
            ok_pub = rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "nlip_publish",
                        "arguments": {
                            "repo_id": "svc",
                            "artifact_ref": c1,
                            "destination": "staging",
                            "branch": "main",
                            "profile_id": "unit",
                            "receipt_id": rcpt_id,
                        },
                    },
                }
            )
            assert ok_pub["result"]["isError"] is False
            assert _dest_refs(dest) == {"refs/heads/main": c1}
        finally:
            mcp.terminate()
            mcp.wait(timeout=5)
    finally:
        srv.terminate()
        srv.wait(timeout=5)


@pytest.mark.parametrize(
    ("stdin_payload", "expected_decision", "extra_env"),
    [
        # Fail-closed malformed inputs
        ("", "deny", None),
        ("{not-json", "deny", None),
        ("[]", "deny", None),
        (json.dumps({"tool_name": "Bash"}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": 123}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo 'unclosed"}}), "deny", None),
        (json.dumps({"tool_name": "Write", "tool_input": {}}), "deny", None),
        # Blocked Bash direct-publish vectors (including newlines, mid-word #, continuations, wrappers)
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "pytest -q\ngit push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo a#; git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git \\\npush origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git 2>&1 >/dev/null push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git -C /tmp/r -c a=b push staging HEAD:main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "pytest -q && git --git-dir=/tmp/r push"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "/usr/bin/env FOO=1 git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "env -S 'git push origin main'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "env --split-string='git push origin main'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "sudo -u root git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "sudo -iu root git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "sudo -uroot git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "sudo --user root git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "command git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "nohup git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "exec git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "time git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "nice -n 5 git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "xargs git push"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo x | xargs --replace git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "((git push origin main))"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "((true) ); cat <<'EOF'\n'\nEOF\ngit push origin main\n#'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo \"$(((true) ); cat <<'EOF'\n'\nEOF\ngit push origin main\n#')\""}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "{ git push origin main; }"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "if true; then git push origin main; fi"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "eval git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "coproc git push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "function f { git push origin main; }; f"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "$'git' push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "$'\\x67it' push origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "{git,push,origin,main}"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git {push,status}"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git -c alias.x=push x origin main"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "sh -c 'git -C repo push origin main'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "bash --norc -c 'git push origin main'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "bash --rcfile /tmp/rc -c 'git push origin main'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "bash -o pipefail -c 'git push origin main'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "bash -eo pipefail -c 'git push origin main'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "bash -oc pipefail 'git push origin main'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "bash -c -- 'git push origin main'"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "bash <<'EOF'\ngit push origin main\nEOF"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "cat <<EOF\n$(git push origin main)\nEOF"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo ${FOO:-$(git push origin main)}"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "gh pr {merge,view} 12"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo $(git push origin main)"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": 'echo "$( (:); git push origin main)"'}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo `(:); git push origin main`"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": 'echo "$(case a in a) git push origin main;; esac)"'}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git send-pack /tmp/dest HEAD"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "gh pr merge 12 --merge"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "gh pr -R o/r merge 12"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "gh api -X PUT repos/o/r/pulls/1/merge"}}), "deny", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "gh api -X POST repos/o/r/merges"}}), "deny", None),
        # Blocked protected config/hook writes (including $CLAUDE_PROJECT_DIR, ../hooks, APFS case, worktrees)
        (json.dumps({"cwd": "/repo", "tool_name": "Write", "tool_input": {"file_path": ".claude/settings.json"}}), "deny", None),
        (json.dumps({"cwd": "/repo", "tool_name": "Write", "tool_input": {"file_path": ".CLAUDE/settings.json"}}), "deny", None),
        (json.dumps({"cwd": "/repo", "tool_name": "Edit", "tool_input": {"file_path": "hooks/claude_pretool_nlip.py"}}), "deny", None),
        (
            json.dumps({"cwd": "/proj/sub", "tool_name": "Edit", "tool_input": {"file_path": "../hooks/claude_pretool_nlip.py"}}),
            "deny",
            {"CLAUDE_PROJECT_DIR": "/proj"},
        ),
        (
            json.dumps({"cwd": "/tmp", "tool_name": "Write", "tool_input": {"file_path": "/proj/hooks/guard.py"}}),
            "deny",
            {"CLAUDE_PROJECT_DIR": "/proj"},
        ),
        (json.dumps({"cwd": "/repo", "tool_name": "MultiEdit", "tool_input": {"edits": [{"file_path": ".git/config"}]}}), "deny", None),
        (json.dumps({"cwd": "/repo", "tool_name": "Write", "tool_input": {"file_path": ".git/hooks/pre-push"}}), "deny", None),
        (json.dumps({"cwd": "/repo", "tool_name": "Write", "tool_input": {"file_path": ".git/worktrees/wt1/config"}}), "deny", None),
        (json.dumps({"cwd": "/repo", "tool_name": "Write", "tool_input": {"file_path": ".git/worktrees/wt1/hooks/pre-push"}}), "deny", None),
        # Allowed normal operations emit empty stdout ("silent") so Claude Code prompts normally
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": 'git commit -m "fix git push bug"'}}), "silent", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git commit -m \"$(cat <<'EOF'\nDon't break X\nEOF\n)\""}}), "silent", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "gh pr create --title t --body \"$(cat <<'EOF'\nFixes bug (see #12)\nEOF\n)\""}}), "silent", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "cat > notes.md <<'EOF'\nit's fine (see #12)\nEOF"}}), "silent", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git add src/{a,b}.py && git mv src/foo.{js,ts} && git rm -r {build,dist}"}}), "silent", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status x${a},${b}"}}), "silent", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": 'echo "$(cat <<< hi)" && echo $((1 << 4)) && (( x << 2 )) && echo "${MSG:-don\'t know}"'}}), "silent", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "# git push comment\npytest -q"}}), "silent", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": 'echo "$(echo case /tmp/case/foo)" && cp src/{a,b}.py dst/'}}), "silent", None),
        (json.dumps({"tool_name": "Bash", "tool_input": {"command": "pytest -q"}}), "silent", None),
        (json.dumps({"cwd": "/repo", "tool_name": "Write", "tool_input": {"file_path": "src/app.py"}}), "silent", None),
        (json.dumps({"tool_name": "mcp__nlip__nlip_verify", "tool_input": {"repo_id": "svc"}}), "silent", None),
        (json.dumps({"tool_name": "mcp__nlip__nlip_publish", "tool_input": {"repo_id": "svc"}}), "silent", None),
    ],
)
def test_claude_pretool_hook_fails_closed_and_guards_bypasses(
    stdin_payload: str, expected_decision: str, extra_env: dict[str, str] | None
) -> None:
    env = {**os.environ, **(extra_env or {})}
    proc = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=stdin_payload,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, f"hook must exit 0 (got {proc.returncode}): {proc.stderr}"
    if expected_decision == "silent":
        assert proc.stdout == "", f"deny-only hook must stay silent when not blocking: {proc.stdout!r}"
        return
    body = json.loads(proc.stdout)
    assert set(body) == {"hookSpecificOutput"}
    hso = body["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == expected_decision
    assert isinstance(hso["permissionDecisionReason"], str) and hso["permissionDecisionReason"]


def test_server_config_removal_revokes_callers_and_policies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_CLAUDE_SECRET", "sec-claude")
    monkeypatch.setenv("TEST_CODEX_SECRET", "sec-codex")
    monkeypatch.setenv("TEST_AGY_SECRET", "sec-agy")

    se_dir = tmp_path / "se"
    se_dir.mkdir()
    work, dest, c1, _ = _init_sample_repo(tmp_path)
    cfg_path = se_dir / "server.json"
    cfg = {
        "ledger_path": str(se_dir / "ledger.db"),
        "repos": {"svc": str(work)},
        "destinations": {"staging": str(dest)},
        "caller_secrets_env": {
            "agent-claude": "TEST_CLAUDE_SECRET",
            "agent-codex": "TEST_CODEX_SECRET",
        },
        "policies": [
            {
                "repo_id": "svc",
                "destination": "staging",
                "profile_id": "unit",
                "command": [sys.executable, "check.py"],
                "allowed_callers": ["agent-claude", "agent-codex"],
                "allowed_branches": ["main"],
                "ttl_seconds": 600.0,
                "single_use": True,
            },
            {
                "repo_id": "svc",
                "destination": "staging",
                "profile_id": "canary",
                "command": [sys.executable, "check.py"],
                "allowed_callers": ["agent-claude"],
                "allowed_branches": ["main"],
                "ttl_seconds": 600.0,
                "single_use": True,
            },
        ],
    }
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(cfg_path, 0o600)

    ext1 = build_extension_from_config(cfg_path)
    _, canary_rcpt = extract_decision_from_response(
        ext1.handle_nlip_message(
            pack_tool_call_message(
                ToolCallProposal(
                    operation="verify",
                    repo_id="svc",
                    artifact_ref=c1,
                    destination="staging",
                    profile_id="canary",
                ),
                auth_token="agent-claude:sec-claude",
            )
        )
    )
    assert canary_rcpt is not None

    # Remove agent-codex AND the canary policy from config and rebuild.
    cfg["caller_secrets_env"] = {"agent-claude": "TEST_CLAUDE_SECRET"}
    cfg["policies"] = [cfg["policies"][0]]
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    ext2 = build_extension_from_config(cfg_path)

    dec_removed_caller, _ = extract_decision_from_response(
        ext2.handle_nlip_message(
            pack_tool_call_message(
                ToolCallProposal(
                    operation="verify",
                    repo_id="svc",
                    artifact_ref=c1,
                    destination="staging",
                    profile_id="unit",
                ),
                auth_token="agent-codex:sec-codex",
            )
        )
    )
    assert dec_removed_caller.action == "deny"
    assert dec_removed_caller.reason_code == "CALLER_AUTH_INVALID"

    dec_removed_policy, _ = extract_decision_from_response(
        ext2.handle_nlip_message(
            pack_tool_call_message(
                ToolCallProposal(
                    operation="publish",
                    repo_id="svc",
                    artifact_ref=c1,
                    destination="staging",
                    branch="main",
                    profile_id="canary",
                    receipt_id=canary_rcpt.receipt_id,
                ),
                auth_token="agent-claude:sec-claude",
            )
        )
    )
    assert dec_removed_policy.action == "deny"
    assert dec_removed_policy.reason_code == "POLICY_NOT_FOUND"

    # Even with strict_caller_auth=False, a previously registered caller that was removed from
    # config remains explicitly revoked rather than reverting to an open unprovisioned identity.
    cfg["strict_caller_auth"] = False
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    ext3 = build_extension_from_config(cfg_path)
    for asserted_tok in ("agent-codex", "agent-codex:sec-codex"):
        dec_revoked_nonstrict, _ = extract_decision_from_response(
            ext3.handle_nlip_message(
                pack_tool_call_message(
                    ToolCallProposal(
                        operation="verify",
                        repo_id="svc",
                        artifact_ref=c1,
                        destination="staging",
                        profile_id="unit",
                    ),
                    auth_token=asserted_tok,
                )
            )
        )
        assert dec_revoked_nonstrict.action == "deny"
        assert dec_revoked_nonstrict.reason_code == "CALLER_AUTH_INVALID"


def test_load_or_create_hmac_key_enforces_mode_owner_and_length(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "ledger.hmac"
    key = load_or_create_hmac_key(key_path)
    assert len(key) == 32
    assert (key_path.stat().st_mode & 0o777) == 0o600

    # Key owned by a different UID is rejected.
    if hasattr(os, "getuid"):
        real_uid = os.getuid()
        monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
        with pytest.raises(PermissionError, match="owned by uid"):
            load_or_create_hmac_key(key_path)
        monkeypatch.undo()

    # Group/world-readable key is tightened to 0600 on load when chmod succeeds.
    os.chmod(key_path, 0o644)
    assert load_or_create_hmac_key(key_path) == key
    assert (key_path.stat().st_mode & 0o777) == 0o600

    # Group/world-readable key fails closed if chmod raises OSError.
    os.chmod(key_path, 0o644)
    def _fail_chmod(_p: Any, _m: int) -> None:
        raise OSError("chmod denied")

    monkeypatch.setattr(os, "chmod", _fail_chmod)
    with pytest.raises(PermissionError, match="0600"):
        load_or_create_hmac_key(key_path)
    monkeypatch.undo()
    os.chmod(key_path, 0o600)

    # Short (<32-byte) key is rejected.
    short_path = tmp_path / "short.hmac"
    short_path.write_bytes(b"x" * 16)
    os.chmod(short_path, 0o600)
    with pytest.raises(ValueError, match="at least 32 bytes"):
        load_or_create_hmac_key(short_path)

    # Inline-secret config with group/world-readable permissions is rejected.
    work, dest, _, _ = _init_sample_repo(tmp_path)
    inline_cfg = tmp_path / "inline.json"
    inline_cfg.write_text(
        json.dumps(
            {
                "ledger_path": str(tmp_path / "l.db"),
                "repos": {"svc": str(work)},
                "destinations": {"staging": str(dest)},
                "callers": {"agent-a": "inline-secret"},
                "policies": [],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(inline_cfg, 0o644)
    with pytest.raises(PermissionError, match="0600"):
        build_extension_from_config(inline_cfg)
