"""Immutable Git artifact resolution, isolated snapshot verification, and commit-pinned publication.

Builds on the content-addressed repository fingerprinting concepts from `hermes-receipts`,
extending them with:
- `--no-replace-objects`, `GIT_CONFIG_NOSYSTEM=1`, and `GIT_CONFIG_GLOBAL=/dev/null`
- Snapshot-isolated verification (`git archive --worktree-attributes <tree_oid>`) with full
  manifest verification against `git ls-tree -r <tree_oid>` (blocking `.gitattributes`
  `export-ignore` / `export-subst` and submodule gitlink attacks)
- Optional policy-pinned test file digest verification (blocking adaptive test-tampering attacks)
- Commit-pinned publication (`git push --no-verify --no-follow-tags -- <dest> <commit_oid>:refs/heads/<branch>`)
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass

_SAFE_REF_RE = re.compile(r"^(HEAD|[0-9a-fA-F]{7,64}|refs/[A-Za-z0-9._/-]+|[A-Za-z0-9._/-]+)$")


class ArtifactError(RuntimeError):
    """Raised when a Git repository or immutable artifact cannot be resolved, verified, or exported."""


class SandboxUnavailable(ArtifactError):
    """Raised when `verify` requires an OS sandbox and none is usable on this host."""


# ── Verification sandbox ──────────────────────────────────────────────────────
# `verify` executes code from the untrusted tree (the test command imports it). Without OS
# isolation that code runs with the SE's own privileges and can push to destinations or rewrite
# the ledger directly, bypassing the gate. The sandbox denies network access and every
# filesystem write outside the snapshot directory.
SANDBOX_MODES = ("required", "off")

_DARWIN_PROFILE = """(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write*
  (subpath {snap})
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/tty")
  (literal "/dev/dtracehelper")
  (regex #"^/dev/fd/"))
"""

_sandbox_probe_cache: dict[str, bool] = {}


def _sbpl_string(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sandbox_argv(command: list[str], snap_dir: str) -> list[str] | None:
    """Wrap `command` in the host's OS sandbox, or return None if no backend is installed."""
    snap = os.path.realpath(snap_dir)
    if sys.platform == "darwin":
        exe = shutil.which("sandbox-exec")
        if exe:
            return [exe, "-p", _DARWIN_PROFILE.format(snap=_sbpl_string(snap)), "--", *command]
        return None
    if sys.platform.startswith("linux"):
        exe = shutil.which("bwrap")
        if exe:
            return [
                exe,
                "--ro-bind", "/", "/",
                "--dev", "/dev",
                "--proc", "/proc",
                "--tmpfs", "/tmp",
                "--bind", snap, snap,
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--chdir", snap,
                "--",
                *command,
            ]
    return None


def sandbox_available() -> bool:
    """Return True if the host sandbox backend exists and can actually start a process."""
    key = sys.platform
    if key not in _sandbox_probe_cache:
        with tempfile.TemporaryDirectory(prefix="nlip-se-probe-") as probe_dir:
            argv = _sandbox_argv(["/bin/sh", "-c", "exit 0"], probe_dir)
            ok = False
            if argv is not None:
                try:
                    ok = (
                        subprocess.run(
                            argv,
                            cwd=probe_dir,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=10.0,
                            check=False,
                        ).returncode
                        == 0
                    )
                except (OSError, subprocess.TimeoutExpired):
                    ok = False
            _sandbox_probe_cache[key] = ok
    return _sandbox_probe_cache[key]


@dataclass(frozen=True)
class ResolvedArtifact:
    repo_path: str
    commit_oid: str
    tree_oid: str


def _safe_git_env() -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("GIT_") and k in ("PATH", "HOME", "USER", "TMPDIR")
    }
    env.update(
        GIT_TERMINAL_PROMPT="0",
        GIT_OPTIONAL_LOCKS="0",
        GIT_NO_LAZY_FETCH="1",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_ATTR_NOSYSTEM="1",
        LC_ALL="C",
    )
    return env


def run_git(repo_path: str, *args: str, timeout: float = 5.0) -> bytes:
    cmd = [
        "git",
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=always",
        "-C",
        repo_path,
        *args,
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=_safe_git_env(),
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ArtifactError(f"git command timed out: {args[:2]}") from exc
    except OSError as exc:
        raise ArtifactError(f"git binary unavailable: {exc}") from exc

    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace").strip()
        raise ArtifactError(err or f"git {args[0]} failed with exit {proc.returncode}")
    return proc.stdout


def resolve_commit_and_tree(repo_path: str, ref: str, timeout: float = 5.0) -> ResolvedArtifact:
    """Resolve `ref` in `repo_path` to its exact immutable `(commit_oid, tree_oid)`.

    Rejects revision-search expressions (`:/...`), reflog syntax (`@{...}`), and range syntax (`..`).
    """
    if (
        not ref
        or not isinstance(ref, str)
        or ref.startswith("-")
        or ".." in ref
        or "@{" in ref
        or ":" in ref
        or "~" in ref
        or "^" in ref
        or not _SAFE_REF_RE.fullmatch(ref)
    ):
        raise ArtifactError(f"invalid or disallowed artifact reference syntax: {ref!r}")
    real_repo = os.path.realpath(repo_path)
    commit_oid = (
        run_git(
            real_repo,
            "rev-parse",
            "--verify",
            "-q",
            "--end-of-options",
            f"{ref}^{{commit}}",
            timeout=timeout,
        )
        .decode()
        .strip()
    )
    tree_oid = (
        run_git(
            real_repo,
            "rev-parse",
            "--verify",
            "-q",
            "--end-of-options",
            f"{commit_oid}^{{tree}}",
            timeout=timeout,
        )
        .decode()
        .strip()
    )
    return ResolvedArtifact(repo_path=real_repo, commit_oid=commit_oid, tree_oid=tree_oid)


def list_tree_manifest(repo_path: str, tree_oid: str, timeout: float = 5.0) -> dict[str, tuple[str, str]]:
    """Return `{rel_path: (mode, blob_oid)}` for every entry in `tree_oid`.
    Rejects trees containing submodule gitlinks (`160000`).
    """
    out = run_git(repo_path, "ls-tree", "-r", "-z", "--full-tree", tree_oid, timeout=timeout)
    manifest: dict[str, tuple[str, str]] = {}
    for entry in out.split(b"\0"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        mode, kind, oid = meta.decode().split()
        rel_path = os.fsdecode(raw_path)
        if mode == "160000" or kind == "commit":
            raise ArtifactError(f"submodules/gitlinks are not permitted in verified trees: {rel_path}")
        if mode == "120000":
            raise ArtifactError(f"symlinks are not permitted in verified trees: {rel_path}")
        manifest[rel_path] = (mode, oid)
    return manifest


def _git_blob_oid(data: bytes, obj_format: str = "sha1") -> str:
    h = hashlib.sha256() if obj_format == "sha256" else hashlib.sha1()
    h.update(b"blob " + str(len(data)).encode("ascii") + b"\0" + data)
    return h.hexdigest()


def export_isolated_snapshot(
    repo_path: str,
    tree_oid: str,
    snapshot_dir: str,
    *,
    pinned_file_sha256: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> None:
    """Export the exact immutable `tree_oid` into `snapshot_dir` and verify 1-to-1 manifest
    equivalence against `git ls-tree -r <tree_oid>`.

    Blocks `.gitattributes` `export-ignore` / `export-subst` discrepancies and verifies any
    operator-pinned test file SHA-256 digests (`pinned_file_sha256`).
    """
    manifest = list_tree_manifest(repo_path, tree_oid, timeout=timeout)
    tar_bytes = run_git(
        repo_path, "archive", "--format=tar", tree_oid, timeout=timeout
    )
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
            tf.extractall(path=snapshot_dir, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise ArtifactError(f"failed to extract archive snapshot: {exc}") from exc

    # Verify exact 1-to-1 file set (no extra or missing files) and blob OID + executable mode match
    extracted_files: set[str] = set()
    for root_dir, _dirs, files in os.walk(snapshot_dir):
        for fname in files:
            full = os.path.join(root_dir, fname)
            rel = os.path.relpath(full, snapshot_dir).replace(os.sep, "/")
            extracted_files.add(rel)

    if extracted_files != set(manifest.keys()):
        missing = sorted(set(manifest.keys()) - extracted_files)
        extra = sorted(extracted_files - set(manifest.keys()))
        raise ArtifactError(
            f"snapshot export 1-to-1 manifest mismatch: missing={missing[:5]}, extra={extra[:5]}"
        )

    for rel_path, (mode, expected_oid) in manifest.items():
        full_path = os.path.join(snapshot_dir, rel_path)
        st = os.lstat(full_path)
        is_exec = bool(st.st_mode & 0o100)
        if (mode == "100755" and not is_exec) or (mode == "100644" and is_exec):
            raise ArtifactError(f"snapshot file mode mismatch on {rel_path!r}: expected {mode}")
        with open(full_path, "rb") as f:
            content = f.read()
        obj_fmt = "sha256" if len(expected_oid) == 64 else "sha1"
        actual_oid = _git_blob_oid(content, obj_fmt)
        if actual_oid != expected_oid:
            raise ArtifactError(
                f"snapshot export integrity failure (possible export-subst/filter) on {rel_path!r}"
            )

    if pinned_file_sha256:
        for rel_path, expected_sha256 in pinned_file_sha256.items():
            if rel_path not in manifest:
                raise ArtifactError(f"protected test file missing from tree manifest: {rel_path!r}")
            full_path = os.path.join(snapshot_dir, rel_path)
            with open(full_path, "rb") as f:
                actual_sha256 = hashlib.sha256(f.read()).hexdigest()
            if actual_sha256 != expected_sha256:
                raise ArtifactError(
                    f"protected verification file {rel_path!r} was modified by untrusted commit"
                )


def compute_env_fingerprint(
    command: list[str], pinned_file_sha256: dict[str, str] | None = None
) -> tuple[str, str]:
    """Return `(command_sha256, env_fingerprint)` using unambiguous length-prefixed encoding."""
    parts = [f"{len(arg)}:{arg}" for arg in command]
    if pinned_file_sha256:
        for k, v in sorted(pinned_file_sha256.items()):
            parts.append(f"pin:{len(k)}:{k}={v}")
    cmd_canon = "|".join(parts).encode("utf-8")
    command_sha256 = hashlib.sha256(cmd_canon).hexdigest()
    env_meta = f"py={sys.version_info.major}.{sys.version_info.minor}|platform={sys.platform}".encode(
        "utf-8"
    )
    env_fingerprint = hashlib.sha256(env_meta).hexdigest()[:16]
    return command_sha256, env_fingerprint


def run_verification_in_snapshot(
    repo_path: str,
    tree_oid: str,
    command: list[str],
    *,
    pinned_file_sha256: dict[str, str] | None = None,
    timeout: float = 15.0,
    sandbox: str = "required",
) -> tuple[int, float, str, str, str]:
    """Run `command` inside a manifest-verified isolated temporary snapshot of `tree_oid`.

    With `sandbox="required"` (the default) the command runs under the host OS sandbox
    (`sandbox-exec` on macOS, `bwrap` on Linux) with no network and no filesystem writes outside
    the snapshot; if no working sandbox exists, `SandboxUnavailable` is raised (fail closed).
    `sandbox="off"` runs the untrusted tree with the SE's own privileges and is only safe when the
    caller provides equivalent isolation itself.

    Returns `(exit_code, duration_ms, output_sha256, command_sha256, env_fingerprint)`.
    """
    if not command or not all(isinstance(part, str) and part for part in command):
        raise ArtifactError("verification command must be a non-empty argument vector")
    if sandbox not in SANDBOX_MODES:
        raise ArtifactError(f"unknown sandbox mode: {sandbox!r}")
    if sandbox == "required" and not sandbox_available():
        raise SandboxUnavailable(
            "no working OS sandbox (sandbox-exec on macOS, bwrap on Linux); refusing to run "
            "untrusted verification code with Security Extension privileges"
        )

    command_sha256, env_fingerprint = compute_env_fingerprint(command, pinned_file_sha256)
    with tempfile.TemporaryDirectory(prefix="nlip-se-verify-") as snap_dir:
        export_isolated_snapshot(
            repo_path,
            tree_oid,
            snap_dir,
            pinned_file_sha256=pinned_file_sha256,
            timeout=min(5.0, timeout),
        )
        clean_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": snap_dir,
            "TMPDIR": snap_dir,
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
        }
        argv = command
        if sandbox == "required":
            wrapped = _sandbox_argv(command, snap_dir)
            if wrapped is None:
                raise SandboxUnavailable("OS sandbox backend disappeared after probe")
            argv = wrapped
        t0 = time.perf_counter()
        proc = subprocess.Popen(
            argv,
            cwd=snap_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=clean_env,
            shell=False,
            start_new_session=True,
        )
        try:
            out_bytes, _ = proc.communicate(timeout=timeout)
            exit_code = int(proc.returncode)
            output_bytes = out_bytes or b""
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            proc.wait(timeout=2.0)
            exit_code = 124
            output_bytes = b"verification timed out"
        finally:
            # Reap anything the command left running in its session (backgrounded children).
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
        duration_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    output_sha256 = hashlib.sha256(output_bytes).hexdigest()
    return exit_code, duration_ms, output_sha256, command_sha256, env_fingerprint


def push_immutable_commit(
    repo_path: str,
    commit_oid: str,
    dest_path: str,
    branch: str = "main",
    timeout: float = 10.0,
) -> str:
    """Push the exact verified `commit_oid` to `refs/heads/<branch>` in `dest_path`."""
    if not branch or "/" in branch or ".." in branch or branch.startswith("-"):
        raise ArtifactError(f"invalid target branch name: {branch!r}")
    if not re.fullmatch(r"[0-9a-fA-F]{40}([0-9a-fA-F]{24})?", commit_oid):
        raise ArtifactError(f"invalid commit_oid format: {commit_oid!r}")
    real_dest = os.path.realpath(dest_path)
    if not os.path.isabs(real_dest) or not os.path.isdir(real_dest):
        raise ArtifactError(f"destination repository does not exist: {dest_path!r}")
    refspec = f"{commit_oid}:refs/heads/{branch}"
    run_git(
        repo_path,
        "push",
        "--no-verify",
        "--no-follow-tags",
        "--porcelain",
        "--",
        real_dest,
        refspec,
        timeout=timeout,
    )
    pushed_head = (
        run_git(real_dest, "rev-parse", "--verify", f"refs/heads/{branch}", timeout=timeout)
        .decode()
        .strip()
    )
    if pushed_head != commit_oid:
        raise ArtifactError(f"destination ref mismatch: expected {commit_oid}, got {pushed_head}")
    return f"refs/heads/{branch}@{pushed_head}"
