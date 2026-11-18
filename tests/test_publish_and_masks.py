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
        *[f"assert Path({str(p / 'visible.txt')!r}).read_text() == 'visible'" for p in prefixes],
        *[f"assert Path({str(p)!r}).read_bytes() == b''" for p in secrets],
        *[f"assert not Path({str(p / 'private.txt')!r}).exists()" for p in repos],
        "print('masked')",
    ])
    argv = git_artifact._sandbox_argv([sys._base_executable, "-c", script], str(snap), [str(secret), str(nested)])
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "masked"
