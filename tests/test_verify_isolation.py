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


@pytest.fixture()
def host_dir():
    """A scratch directory under the current working directory instead of /tmp.

    The Linux sandbox mounts an empty tmpfs over /tmp, so fixtures under pytest's tmp_path would be
    invisible to sandboxed code whatever the sandbox's other rules were. Placing them under the
    checkout makes the isolation tests fail if the sandbox ever exposes or writes the host tree.
    """
    import shutil
    import tempfile

    path = Path(tempfile.mkdtemp(dir=Path.cwd(), prefix=".iso-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


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


def test_verify_code_cannot_push_to_destination(host_dir):
    """Code imported by the verify command must not be able to publish by pushing directly."""
    e = _env(host_dir, pin=True)
    _commit(
        e["work"],
        {
            "app.py": textwrap.dedent(
                f"""
                import subprocess
                import subprocess
                r = subprocess.run(["git", "-C", {str(e['work'])!r}, "push", "-q", {str(e['prod'])!r},
                                    "HEAD:refs/heads/main"])
                raise SystemExit(7 if r.returncode != 0 else 8)  # 7: push attempted and refused
                """
            )
        },
    )
    dec, rec = e["ext"].handle_proposal(_prop("verify", "mallory"))
    assert dec.reason_code == "VERIFICATION_CHECK_FAILED"
    assert rec.exit_code == 7  # the payload ran, attempted the push, and git failed
    assert _prod_main(e["prod"]) is None


def test_verify_code_cannot_rewrite_ledger(host_dir):
    """Code run by verify must not be able to un-consume a single-use receipt in the ledger."""
    e = _env(host_dir)
    ext = e["ext"]
    _, rec = ext.handle_proposal(_prop("verify", "alice"))
    assert ext.handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id))[0].action == "allow"
    old_head = run_git(str(e["work"]), "rev-parse", "HEAD").decode().strip()
    _commit(
        e["work"],
        {
            "test_ok.py": (
                f"import sqlite3\ntry:\n    c = sqlite3.connect({str(e['db'])!r})\n"
                "    c.execute('update receipts set consumed = 0'); c.commit()\n"
                "except sqlite3.Error:\n    raise SystemExit(7)\nraise SystemExit(8)\n"
            )
        },
    )
    _, tamper = ext.handle_proposal(_prop("verify", "mallory"))
    assert tamper.exit_code == 7  # the payload ran and its ledger write failed
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


def test_protected_paths_stay_hidden_inside_an_exposed_prefix(host_dir):
    """A ledger or repository inside an interpreter prefix (e.g. a virtualenv at a repo root)
    must stay unreadable even though the rest of the prefix is exposed."""
    import os

    e = _env(host_dir)
    prefix = host_dir / "py"
    (prefix / "bin").mkdir(parents=True)
    os.symlink(os.path.realpath(sys.executable), prefix / "bin" / "python")
    (prefix / "visible.txt").write_text("V")  # ord 86
    secret = prefix / "ledger-copy.db"
    secret.write_text("S")  # ord 83
    ext = Type3ReceiptExtension(ledger=e["ledger"], repos={"svc": str(e["work"])}, destinations={"prod": str(e["prod"])})
    ext._protected_paths = lambda: [str(secret)]  # type: ignore[method-assign]
    script = (
        f"import sys\ntry:\n    sys.exit(ord(open({str(secret)!r}).read(1)))\nexcept OSError:\n    pass\n"
        f"sys.exit(ord(open({str(prefix / 'visible.txt')!r}).read(1)))\n"
    )
    e["ledger"].set_policy(repo_id="svc", destination="prod", profile_id="p",
                           command=[str(prefix / "bin" / "python"), "-c", script], allowed_callers=list(SECRETS))
    _, rec = ext.handle_proposal(_prop("verify", "alice"))
    assert rec.exit_code == 86  # prefix mounted, protected file inside it hidden


def test_home_directory_prefix_is_refused(host_dir, monkeypatch):
    import os

    e = _env(host_dir)
    (host_dir / "bin").mkdir()
    os.symlink(os.path.realpath(sys.executable), host_dir / "bin" / "python")
    monkeypatch.setenv("HOME", str(host_dir))
    e["ledger"].set_policy(repo_id="svc", destination="prod", profile_id="p",
                           command=[str(host_dir / "bin" / "python"), "test_ok.py"], allowed_callers=list(SECRETS))
    dec, rec = e["ext"].handle_proposal(_prop("verify", "alice"))
    assert dec.reason_code == "SANDBOX_UNAVAILABLE"
    assert rec is None


def test_existing_world_writable_ledger_is_restricted(tmp_path):
    import os
    import stat

    db = tmp_path / "old.db"
    ReceiptLedger(db)
    os.chmod(db, 0o666)
    ReceiptLedger(db)
    assert stat.S_IMODE(os.stat(db).st_mode) == 0o600


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


def test_verify_code_cannot_read_host_files(host_dir):
    """Files outside the snapshot and interpreter prefix (ledger, keys, other repos) are unreadable,
    so the verify exit code cannot be used to leak them a byte at a time."""
    e = _env(host_dir)
    secret = host_dir / "secret.txt"
    secret.write_text("A")  # ord("A") == 65
    _commit(
        e["work"],
        {"app.py": f"try:\n    raise SystemExit(ord(open({str(secret)!r}).read(1)))\nexcept OSError:\n    pass\ndef add(a, b):\n    return a + b\n"},
    )
    dec, rec = e["ext"].handle_proposal(_prop("verify", "alice"))
    assert dec.reason_code == "VERIFICATION_PASSED"
    assert rec.exit_code != 65


def test_verify_code_cannot_probe_host_file_existence(host_dir):
    """Even metadata (does this file exist?) must not leak through the exit status."""
    e = _env(host_dir)
    probe = host_dir / "exists.txt"
    probe.write_text("x")
    _commit(
        e["work"],
        {"app.py": f"import os\nif os.path.exists({str(probe)!r}):\n    raise SystemExit(9)\ndef add(a, b):\n    return a + b\n"},
    )
    dec, rec = e["ext"].handle_proposal(_prop("verify", "alice"))
    assert dec.reason_code == "VERIFICATION_PASSED"
    assert rec.exit_code == 0


def test_unregistered_caller_name_is_refused_by_default(tmp_path):
    """The original bypass: any token naming an unregistered caller authenticated as that caller."""
    e = _env(tmp_path)
    e["ledger"].set_policy(repo_id="svc", destination="prod", profile_id="p", command=[sys.executable, "test_ok.py"],
                           allowed_callers=[*SECRETS, "eve"])
    msg = pack_tool_call_message(_prop("verify", "mallory"), auth_token="eve:anything")
    prop, _ = unpack_tool_call_message(msg)
    dec, _ = e["ext"].handle_proposal(prop)
    assert dec.action == "deny"
    assert dec.reason_code == "CALLER_AUTH_INVALID"


def test_invalid_branch_denied_before_receipt_is_consumed(tmp_path):
    e = _env(tmp_path)
    e["ledger"].set_policy(repo_id="svc", destination="prod", profile_id="p", command=[sys.executable, "test_ok.py"],
                           allowed_callers=list(SECRETS), allowed_branches=["main", "bench-*"])
    _, rec = e["ext"].handle_proposal(_prop("verify", "alice"))
    bad, _ = e["ext"].handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id, branch="bench-.."))
    assert bad.reason_code == "BRANCH_NOT_ALLOWED"
    ok, _ = e["ext"].handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id, branch="main"))
    assert ok.action == "allow"


def test_gate_defaults_to_unauthenticated():
    import inspect

    from nlip_receipts import evaluate_type3_gate

    assert inspect.signature(evaluate_type3_gate).parameters["caller_authenticated"].default is False


def test_wrong_secret_for_registered_caller_cannot_impersonate(tmp_path):
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


def test_revoke_disable_and_clear_repo_fail_closed(tmp_path):
    """ETHICS.md off-switches: revoked policies and purged repos deny verify and publish."""
    e = _env(tmp_path)
    ext, ledger = e["ext"], e["ledger"]
    _, rec = ext.handle_proposal(_prop("verify", "alice"))
    assert ledger.revoke_policy("svc", "prod", "p") is True
    dec, _ = ext.handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id))
    assert dec.reason_code == "POLICY_NOT_FOUND"
    assert _prod_main(e["prod"]) is None

    ledger.set_policy(repo_id="svc", destination="prod", profile_id="p", command=[sys.executable, "test_ok.py"],
                      allowed_callers=list(SECRETS))
    assert ledger.disable_destination("prod") == 1
    assert ext.handle_proposal(_prop("verify", "alice"))[0].reason_code == "POLICY_NOT_FOUND"

    ledger.set_policy(repo_id="svc", destination="prod", profile_id="p", command=[sys.executable, "test_ok.py"],
                      allowed_callers=list(SECRETS))
    _, rec2 = ext.handle_proposal(_prop("verify", "alice"))
    assert ledger.clear_repo("svc") == (1, 2)
    assert ledger.get_receipt(rec2.receipt_id) is None


def test_recreating_a_revoked_policy_does_not_revive_old_receipts(tmp_path):
    e = _env(tmp_path)
    ext, ledger = e["ext"], e["ledger"]
    _, rec = ext.handle_proposal(_prop("verify", "alice"))
    assert ledger.revoke_policy("svc", "prod", "p") is True
    ledger.set_policy(repo_id="svc", destination="prod", profile_id="p", command=[sys.executable, "test_ok.py"],
                      allowed_callers=list(SECRETS))
    dec, _ = ext.handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id))
    assert dec.reason_code == "POLICY_EPOCH_STALE"
    assert _prod_main(e["prod"]) is None


def test_decision_log_records_nlip_conversation_id(tmp_path):
    e = _env(tmp_path)
    msg = pack_tool_call_message(_prop("verify", "alice"), auth_token="alice:alice-secret", conversation_id="conv-42")
    e["ext"].handle_nlip_message(msg)
    assert e["ledger"].list_decisions(limit=1)[0]["conversation_id"] == "conv-42"
