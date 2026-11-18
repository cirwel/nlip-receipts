"""Regressions for operation dispatch and Linux exposed-root masking."""
import shutil
import subprocess
import sys

import pytest

from nlip_receipts import git_artifact
import nlip_receipts.gate as gate
from nlip_receipts.git_artifact import SandboxUnavailable
from test_verify_isolation import _env, _prop, _prod_main


def test_status_cannot_publish_or_consume_valid_receipt(tmp_path, monkeypatch):
    e = _env(tmp_path)
    # Dispatch is independent of OS isolation. Use real verification and publication,
    # with isolation off so this regression also runs on hosts without namespaces.
    e["ext"].verify_sandbox = "off"
    dec, rec = e["ext"].handle_proposal(_prop("verify", "alice"))
    assert dec.action == "allow"
    assert rec is not None and rec.status == "passed"
    assert e["ledger"].verify_receipt_hmac(rec)
    push = gate.push_immutable_commit
    pushes = []

    def track_push(*args, **kwargs):
        pushes.append(args)
        return push(*args, **kwargs)

    monkeypatch.setattr(gate, "push_immutable_commit", track_push)
    dec, returned = e["ext"].handle_proposal(_prop("status", "alice", receipt_id=rec.receipt_id))
    assert (dec.action, dec.reason_code, dec.operation) == ("deny", "UNSUPPORTED_OPERATION", "status")
    assert returned is None and dec.published_ref is None
    assert pushes == [] and _prod_main(e["prod"]) is None
    assert not e["ledger"].get_receipt(rec.receipt_id).consumed

    dec, _ = e["ext"].handle_proposal(_prop("publish", "alice", receipt_id=rec.receipt_id))
    assert dec.action == "allow" and dec.published_ref
    assert len(pushes) == 1
    assert _prod_main(e["prod"]) == rec.commit_oid
    assert e["ledger"].get_receipt(rec.receipt_id).consumed


def _layout(tmp_path, monkeypatch):
    root = tmp_path / "system"
    prefix = root / "venv"
    nested = prefix / "repository"
    nested.mkdir(parents=True)
    secret = prefix / "ledger.db"
    secret.write_text("ledger secret")
    (nested / "private.txt").write_text("repo secret")
    (prefix / "visible.txt").write_text("visible")
    alias = tmp_path / "alias"
    alias.symlink_to(prefix, target_is_directory=True)
    child_alias = tmp_path / "child-alias"
    child_alias.symlink_to(nested, target_is_directory=True)
    snap = tmp_path / "snapshot"
    snap.mkdir()
    monkeypatch.setattr(git_artifact, "_interpreter_mounts", lambda _: [
        (str(prefix), str(alias)), (str(nested), str(child_alias)),
    ])
    return root, prefix, nested, secret, alias, child_alias, snap


@pytest.mark.parametrize("protected_alias", [False, True])
def test_linux_masks_system_roots_and_all_interpreter_aliases(tmp_path, monkeypatch, protected_alias):
    root, prefix, nested, secret, alias, child_alias, snap = _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/bwrap")
    monkeypatch.setattr(git_artifact, "_LINUX_SYSTEM_DIRS", (str(root),))
    protected = [alias / secret.name, child_alias] if protected_alias else [secret, nested]
    argv = git_artifact._sandbox_argv(["/bin/true"], str(snap), [str(p) for p in protected])
    for path in (secret, alias / secret.name):
        assert ["--ro-bind", "/dev/null", str(path)] in [argv[j:j+3] for j in range(len(argv))]
    for path in (nested, alias / nested.name, child_alias):
        assert ["--tmpfs", str(path)] in [argv[j:j+2] for j in range(len(argv))]
    last_exposure = max(j for j in range(len(argv)-2) if argv[j] == "--ro-bind" and argv[j+1] != "/dev/null")
    assert all(argv.index(str(path), last_exposure + 3) > last_exposure for path in (secret, nested, child_alias))


def test_linux_system_root_masks_without_interpreter_mounts(tmp_path, monkeypatch):
    root, prefix, nested, secret, alias, child_alias, snap = _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/bwrap")
    monkeypatch.setattr(git_artifact, "_LINUX_SYSTEM_DIRS", (str(root),))
    monkeypatch.setattr(git_artifact, "_interpreter_mounts", lambda _: [])
    argv = git_artifact._sandbox_argv(["/bin/true"], str(snap), [str(secret), str(nested)])
    assert ["--ro-bind", "/dev/null", str(secret)] in [argv[j:j+3] for j in range(len(argv))]
    assert ["--tmpfs", str(nested)] in [argv[j:j+2] for j in range(len(argv))]


@pytest.mark.parametrize("protect_parent", [False, True])
def test_linux_rejects_protected_snapshot_overlap(tmp_path, monkeypatch, protect_parent):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/bwrap")
    monkeypatch.setattr(git_artifact, "_interpreter_mounts", lambda _: [])
    snap = tmp_path / "snapshot"
    snap.mkdir()
    protected = tmp_path if protect_parent else snap / "secret"
    with pytest.raises(SandboxUnavailable, match="overlaps"):
        git_artifact._sandbox_argv(["/bin/true"], str(snap), [str(protected)])


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux bubblewrap runtime regression")
@pytest.mark.parametrize("interpreter_aliases", [False, True])
def test_linux_masks_runtime(tmp_path, monkeypatch, interpreter_aliases):
    if not git_artifact.sandbox_available():
        pytest.skip("bubblewrap cannot start namespaces on this host")
    root, prefix, nested, secret, alias, child_alias, snap = _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(git_artifact, "_LINUX_SYSTEM_DIRS", (*git_artifact._LINUX_SYSTEM_DIRS, str(root)))
    if not interpreter_aliases:
        monkeypatch.setattr(git_artifact, "_interpreter_mounts", lambda _: [])
    prefixes = (prefix, alias) if interpreter_aliases else (prefix,)
    secrets = (secret, alias / secret.name) if interpreter_aliases else (secret,)
    repos = (nested, alias / nested.name, child_alias) if interpreter_aliases else (nested,)
    script = "\n".join([
        "from pathlib import Path",
        "def assert_masked(path):",
        "    try:",
        "        data = Path(path).read_bytes()",
        "    except (PermissionError, FileNotFoundError):",
        "        return",
        "    assert data == b''",
        *[f"assert Path({str(p / 'visible.txt')!r}).read_text() == 'visible'" for p in prefixes],
        *[f"assert_masked({str(p)!r})" for p in secrets],
        *[f"assert not Path({str(p / 'private.txt')!r}).exists()" for p in repos],
        "print('masked')",
    ])
    argv = git_artifact._sandbox_argv([sys._base_executable, "-c", script], str(snap), [str(secret), str(nested)])
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "masked"


def _ledger_under_exposed_root(tmp_path, command=None):
    """Repositories under `tmp_path/repos`, the ledger alone in `tmp_path/system/state`."""
    from nlip_receipts import ReceiptLedger, Type3ReceiptExtension
    from test_verify_isolation import SECRETS

    (tmp_path / "repos").mkdir()
    e = _env(tmp_path / "repos")
    root = tmp_path / "system"
    state = root / "state"
    ledger = ReceiptLedger(state / "ledger.db")
    (root / "visible.txt").write_text("visible")
    for caller, secret in SECRETS.items():
        ledger.register_caller_secret(caller, secret)
    ledger.set_policy(repo_id="svc", destination="prod", profile_id="p",
                      command=command or [sys.executable, "test_ok.py"], allowed_callers=list(SECRETS))
    ext = gate.Type3ReceiptExtension(ledger=ledger, repos={"svc": str(e["work"])},
                                     destinations={"prod": str(e["prod"])})
    return e, root, state, ledger, ext


def test_ledger_directory_is_protected():
    """SQLite sidecar files are covered by the ledger's directory, not named one by one."""
    import os
    import tempfile
    from pathlib import Path

    from nlip_receipts import ReceiptLedger

    with tempfile.TemporaryDirectory() as tmp:
        ledger = ReceiptLedger(Path(tmp) / "state" / "ledger.db")
        ext = gate.Type3ReceiptExtension(ledger=ledger, repos={}, destinations={})
        paths = ext._protected_paths()
        state = os.path.realpath(os.path.join(tmp, "state"))
        assert state in paths
        assert not any(p.endswith(("-wal", "-shm", "-journal")) for p in paths)


def test_linux_argv_hides_ledger_directory_inside_exposed_root(tmp_path, monkeypatch):
    """With the real protected set, a ledger under an exposed root is hidden by a tmpfs over its
    directory. No /dev/null bind may target a path that does not exist: bwrap cannot create a
    mount point inside a read-only bind and the verify would fail."""
    import os

    e, root, state, ledger, ext = _ledger_under_exposed_root(tmp_path)
    snap = tmp_path / "snapshot"
    snap.mkdir()
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/bwrap")
    monkeypatch.setattr(git_artifact, "_LINUX_SYSTEM_DIRS", (str(root),))
    monkeypatch.setattr(git_artifact, "_interpreter_mounts", lambda _: [])
    argv = git_artifact._sandbox_argv(["/bin/true"], str(snap), ext._protected_paths())
    windows = [argv[j:j + 2] for j in range(len(argv))]
    assert ["--tmpfs", os.path.realpath(state)] in windows
    assert argv.index(os.path.realpath(state)) > argv.index(str(root))  # mask after the bind
    dev_null_targets = [argv[j + 2] for j in range(len(argv) - 2) if argv[j:j + 2] == ["--ro-bind", "/dev/null"]]
    assert all(os.path.exists(p) for p in dev_null_targets)
    assert not any(a.endswith(("-wal", "-shm", "-journal")) for a in argv)


@pytest.mark.parametrize("alias", [False, True])
def test_interpreter_inside_protected_directory_is_refused(tmp_path, monkeypatch, alias):
    """Masking the ledger directory would hide an interpreter installed under it, and the run
    would fail as though the tree were bad. The sandbox refuses instead."""
    e, root, state, ledger, ext = _ledger_under_exposed_root(tmp_path)
    venv = tmp_path / "venv"
    venv.mkdir()
    inside = state / "venv"
    if alias:
        inside.symlink_to(venv, target_is_directory=True)
        mount = (str(venv), str(inside))
    else:
        inside.mkdir()
        mount = (str(inside), str(inside))
    snap = tmp_path / "snapshot"
    snap.mkdir()
    monkeypatch.setattr(git_artifact, "_interpreter_mounts", lambda _: [mount])
    for platform in ("linux", "darwin"):
        monkeypatch.setattr(sys, "platform", platform)
        monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/sandbox")
        with pytest.raises(SandboxUnavailable, match="inside a protected path"):
            git_artifact._sandbox_argv(["/bin/true"], str(snap), ext._protected_paths())


def test_refused_sandbox_does_not_supersede_a_pass(tmp_path, monkeypatch):
    if not git_artifact.sandbox_available():
        pytest.skip("no working OS sandbox on this host")
    e, root, state, ledger, ext = _ledger_under_exposed_root(tmp_path)
    dec, passed = ext.handle_proposal(_prop("verify", "alice"))
    assert dec.reason_code == "VERIFICATION_PASSED", dec.message
    inside = state / "venv"
    inside.mkdir()
    real_mounts = git_artifact._interpreter_mounts
    monkeypatch.setattr(git_artifact, "_interpreter_mounts",
                        lambda cmd: [*real_mounts(cmd), (str(inside), str(inside))])
    dec, rec = ext.handle_proposal(_prop("verify", "alice"))
    assert (dec.reason_code, rec) == ("SANDBOX_UNAVAILABLE", None)
    latest = ledger.latest_receipt_for_tree("svc", passed.tree_oid, "p", "prod")
    assert latest.receipt_id == passed.receipt_id and latest.status == "passed"


def test_verify_passes_with_ledger_under_exposed_root(tmp_path, monkeypatch):
    """Runtime check with the real protected set. On Linux the ledger directory sits under an
    exposed root; before the directory mask, bwrap aborted on the missing `-journal` file and the
    verify recorded a failed receipt."""
    if not git_artifact.sandbox_available():
        pytest.skip("no working OS sandbox on this host")
    ledger_path = tmp_path / "system" / "state" / "ledger.db"
    script = "\n".join([
        "import os, sys",
        "from pathlib import Path",
        "try:",
        f"    data = Path({str(ledger_path)!r}).read_bytes()",
        "except OSError:",
        "    data = b''",
        "if data: sys.exit(3)",
        "try:",
        f"    names = os.listdir({str(ledger_path.parent)!r})",
        "except OSError:",
        "    names = []",
        "if names: sys.exit(4)",
        "if sys.platform.startswith('linux'):",
        f"    sys.exit(0 if Path({str(tmp_path / 'system' / 'visible.txt')!r}).read_text() == 'visible' else 5)",
    ])
    monkeypatch.setattr(git_artifact, "_LINUX_SYSTEM_DIRS",
                        (*git_artifact._LINUX_SYSTEM_DIRS, str(tmp_path / "system")))
    e, root, state, ledger, ext = _ledger_under_exposed_root(tmp_path, [sys.executable, "-c", script])
    dec, rec = ext.handle_proposal(_prop("verify", "alice"))
    assert dec.reason_code == "VERIFICATION_PASSED", (dec.message, rec and rec.exit_code)
