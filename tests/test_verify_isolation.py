"""Regression tests for verify-time isolation, caller authentication, and branch binding.

Each attack here succeeded against 3f3bae8 (before the verify sandbox, strict caller auth by
default, and the policy branch allowlist). The tests assert the attack is now blocked.
"""

from __future__ import annotations

import hashlib
import socket
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from nlip_receipts import ReceiptLedger, ToolCallProposal, Type3ReceiptExtension, pack_tool_call_message
from nlip_receipts import git_artifact
from nlip_receipts.git_artifact import run_git
from nlip_receipts.schemas import unpack_tool_call_message

SECRETS = {"alice": "alice-secret", "mallory": "mallory-secret"}


def _env(tmp: Path, *, pin: bool = False) -> dict:
    work = tmp / "work"
    work.mkdir()
    prod = tmp / "prod.git"
    subprocess.run(["git", "init", "-q", "--bare", str(prod)], check=True)
    run_git(str(work), "init", "-b", "main")
    run_git(str(work), "config", "user.email", "t@example.org")
    run_git(str(work), "config", "user.name", "t")
    (work / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (work / "test_ok.py").write_text("from app import add\nassert add(2, 3) == 5\n")
    run_git(str(work), "add", ".")
    run_git(str(work), "commit", "-qm", "init")
    ledger = ReceiptLedger(tmp / "ledger.db")
    for caller, secret in SECRETS.items():
        ledger.register_caller_secret(caller, secret)
    pins = {"test_ok.py": hashlib.sha256((work / "test_ok.py").read_bytes()).hexdigest()} if pin else None
    ledger.set_policy(
        repo_id="svc",
        destination="prod",
        profile_id="p",
        command=[sys.executable, "test_ok.py"],
        allowed_callers=list(SECRETS),
        pinned_file_sha256=pins,
    )
    ext = Type3ReceiptExtension(ledger=ledger, repos={"svc": str(work)}, destinations={"prod": str(prod)})
    return {"work": work, "prod": prod, "ledger": ledger, "ext": ext, "db": tmp / "ledger.db"}


def _commit(work: Path, files: dict[str, str]) -> None:
    for name, body in files.items():
        (work / name).write_text(body)
    run_git(str(work), "add", ".")
    run_git(str(work), "commit", "-qm", "change")


def _prop(op: str, caller: str, **kw) -> ToolCallProposal:
    kw.setdefault("artifact_ref", "HEAD")
    return ToolCallProposal(
        operation=op,
        repo_id="svc",
        destination="prod",
        profile_id="p",
        caller_id=caller,
        caller_secret=SECRETS.get(caller),
        **kw,
    )


def _prod_main(prod: Path):
    try:
        return run_git(str(prod), "rev-parse", "refs/heads/main").decode().strip()
    except git_artifact.ArtifactError:
        return None


def test_verify_code_cannot_push_to_destination(tmp_path):
    """Code imported by the verify command must not be able to publish by pushing directly."""
    e = _env(tmp_path, pin=True)
    _commit(
        e["work"],
        {
            "app.py": textwrap.dedent(
                f"""
                import subprocess
                subprocess.run(["git", "-C", {str(e['work'])!r}, "push", "-q", {str(e['prod'])!r},
                                "HEAD:refs/heads/main"])
                def add(a, b):
                    return -999
                """
            )
        },
    )
    dec, _ = e["ext"].handle_proposal(_prop("verify", "mallory"))
    assert dec.reason_code == "VERIFICATION_CHECK_FAILED"
    assert _prod_main(e["prod"]) is None


def test_verify_code_cannot_rewrite_ledger(tmp_path):
    """Code run by verify must not be able to un-consume a single-use receipt in the ledger."""
    e = _env(tmp_path)
    ext = e["ext"]
    _, rec = ext.handle_proposal(_prop("verify", "alice"))
    assert ext.handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id))[0].action == "allow"
    old_head = run_git(str(e["work"]), "rev-parse", "HEAD").decode().strip()
    _commit(
        e["work"],
        {
            "test_ok.py": (
                f"import sqlite3\nc = sqlite3.connect({str(e['db'])!r})\n"
                "c.execute('update receipts set consumed = 0'); c.commit()\n"
            )
        },
    )
    ext.handle_proposal(_prop("verify", "mallory"))
    replay, _ = ext.handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id, artifact_ref=old_head))
    assert replay.action == "deny"
    assert replay.reason_code == "RECEIPT_ALREADY_CONSUMED"


def test_verify_code_has_no_network(tmp_path):
    """Code run by verify must not reach a listener on the host (no exfiltration or local RPC)."""
    e = _env(tmp_path)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(0.1)
    port = srv.getsockname()[1]
    hits: list[bool] = []
    done = threading.Event()

    def _accept() -> None:
        while not done.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            hits.append(True)
            conn.close()

    t = threading.Thread(target=_accept, daemon=True)
    t.start()
    _commit(
        e["work"],
        {"app.py": f"import socket\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=2)\nexcept OSError:\n    pass\ndef add(a, b):\n    return a + b\n"},
    )
    dec, _ = e["ext"].handle_proposal(_prop("verify", "alice"))
    assert dec.reason_code == "VERIFICATION_PASSED"  # the payload ran and the test still passed
    done.set()
    t.join(timeout=2.0)
    srv.close()
    assert hits == []


def test_verify_code_cannot_connect_to_host_unix_socket(tmp_path):
    """Filesystem Unix sockets (docker, ssh-agent, local services) must be unreachable from verify.
    The socket lives under the current working directory, not /tmp, so a sandbox that merely
    hides /tmp would not pass."""
    import os
    import tempfile

    e = _env(tmp_path)
    sock_dir = tempfile.mkdtemp(dir=os.getcwd(), prefix=".s-")
    path = os.path.join(sock_dir, "s")
    srv = socket.socket(socket.AF_UNIX)
    try:
        srv.bind(path)
        srv.listen(1)
        srv.settimeout(0.1)
        _commit(
            e["work"],
            {"app.py": f"import socket\ntry:\n    socket.socket(socket.AF_UNIX).connect({path!r})\nexcept OSError:\n    pass\ndef add(a, b):\n    return a + b\n"},
        )
        dec, _ = e["ext"].handle_proposal(_prop("verify", "alice"))
        assert dec.reason_code == "VERIFICATION_PASSED"
        try:
            conn, _ = srv.accept()
            conn.close()
            connected = True
        except (socket.timeout, OSError):
            connected = False
        assert connected is False
    finally:
        srv.close()
        os.unlink(path)
        os.rmdir(sock_dir)


def test_verify_fails_closed_without_sandbox(tmp_path, monkeypatch):
    e = _env(tmp_path)
    monkeypatch.setattr(git_artifact, "sandbox_available", lambda: False)
    dec, rec = e["ext"].handle_proposal(_prop("verify", "alice"))
    assert dec.action == "deny"
    assert dec.reason_code == "SANDBOX_UNAVAILABLE"
    assert rec is None


def test_receipt_from_unsandboxed_verify_cannot_satisfy_sandboxed_gate(tmp_path):
    e = _env(tmp_path)
    unsandboxed = Type3ReceiptExtension(
        ledger=e["ledger"],
        repos={"svc": str(e["work"])},
        destinations={"prod": str(e["prod"])},
        verify_sandbox="off",
    )
    _, rec = unsandboxed.handle_proposal(_prop("verify", "alice"))
    assert rec.status == "passed"
    dec, _ = e["ext"].handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id))
    assert dec.action == "deny"
    assert dec.reason_code == "PROFILE_OR_REPO_MISMATCH"


def test_legacy_ledger_migration_retires_existing_receipts(tmp_path):
    import sqlite3

    e = _env(tmp_path)
    _, rec = e["ext"].handle_proposal(_prop("verify", "alice"))
    with sqlite3.connect(e["db"]) as conn:  # simulate a ledger created before this change
        conn.execute("ALTER TABLE policies DROP COLUMN allowed_branches_json")
    upgraded = ReceiptLedger(e["db"], hmac_key=e["ledger"]._hmac_key)
    ext = Type3ReceiptExtension(ledger=upgraded, repos={"svc": str(e["work"])}, destinations={"prod": str(e["prod"])})
    dec, _ = ext.handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id))
    assert dec.reason_code == "POLICY_EPOCH_STALE"
    assert _prod_main(e["prod"]) is None


def test_unprovisioned_caller_cannot_impersonate(tmp_path):
    """Holding another caller's receipt id and asserting their name, without their secret, is denied."""
    e = _env(tmp_path)
    _, rec = e["ext"].handle_proposal(_prop("verify", "alice"))
    msg = pack_tool_call_message(
        _prop("publish", "mallory", receipt_id=rec.receipt_id), auth_token="alice:not-alices-secret"
    )
    prop, _ = unpack_tool_call_message(msg)
    dec, _ = e["ext"].handle_proposal(prop)
    assert dec.action == "deny"
    assert dec.reason_code == "CALLER_AUTH_INVALID"
    assert _prod_main(e["prod"]) is None


def test_publish_branch_must_be_allowed_by_policy(tmp_path):
    e = _env(tmp_path)
    _, rec = e["ext"].handle_proposal(_prop("verify", "alice"))
    dec, _ = e["ext"].handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id, branch="release"))
    assert dec.action == "deny"
    assert dec.reason_code == "BRANCH_NOT_ALLOWED"
    ok, _ = e["ext"].handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id, branch="main"))
    assert ok.action == "allow"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Documented limitation (SECURITY.md): a receipt attests that the policy command exited 0 "
        "over the tree, not that the code is correct. Code imported by the test can control the "
        "exit status even when the test file itself is pinned."
    ),
)
def test_code_under_test_cannot_force_passing_exit(tmp_path):
    e = _env(tmp_path, pin=True)
    _commit(e["work"], {"app.py": "import os\nos._exit(0)\ndef add(a, b):\n    return -999\n"})
    dec, _ = e["ext"].handle_proposal(_prop("verify", "mallory"))
    assert dec.reason_code != "VERIFICATION_PASSED"
