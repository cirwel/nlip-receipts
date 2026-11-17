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
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass

_SAFE_REF_RE = re.compile(r"^(HEAD|[0-9a-fA-F]{7,64}|refs/[A-Za-z0-9._/-]+|[A-Za-z0-9._/-]+)$")


class ArtifactError(RuntimeError):
    """Raised when a Git repository or immutable artifact cannot be resolved, verified, or exported."""


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
    # --worktree-attributes prevents in-tree .gitattributes from applying export-ignore/export-subst
    tar_bytes = run_git(
        repo_path, "archive", "--format=tar", "--worktree-attributes", tree_oid, timeout=timeout
    )
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        tf.extractall(path=snapshot_dir, filter="data")

    # Verify every blob in `git ls-tree` exists in `snapshot_dir` with the exact git blob OID
    for rel_path, (mode, expected_oid) in manifest.items():
        full_path = os.path.join(snapshot_dir, rel_path)
        if mode == "120000":
            raise ArtifactError(f"symlinks are not permitted in verified trees: {rel_path}")
        if not os.path.isfile(full_path):
            raise ArtifactError(
                f"snapshot export integrity failure (possible export-ignore): missing {rel_path!r}"
            )
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
            full_path = os.path.join(snapshot_dir, rel_path)
            if not os.path.isfile(full_path):
                raise ArtifactError(f"protected test file missing from tree: {rel_path!r}")
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
) -> tuple[int, float, str, str, str]:
    """Run `command` inside a manifest-verified isolated temporary snapshot of `tree_oid`.

    Returns `(exit_code, duration_ms, output_sha256, command_sha256, env_fingerprint)`.
    """
    if not command or not all(isinstance(part, str) and part for part in command):
        raise ArtifactError("verification command must be a non-empty argument vector")

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
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                command,
                cwd=snap_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=clean_env,
                timeout=timeout,
                shell=False,
                check=False,
            )
            exit_code = int(proc.returncode)
            output_bytes = proc.stdout or b""
        except subprocess.TimeoutExpired:
            exit_code = 124
            output_bytes = b"verification timed out"
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
    refspec = f"{commit_oid}:refs/heads/{branch}"
    run_git(
        repo_path,
        "push",
        "--no-verify",
        "--no-follow-tags",
        "--porcelain",
        "--",
        dest_path,
        refspec,
        timeout=timeout,
    )
    pushed_head = (
        run_git(dest_path, "rev-parse", "--verify", f"refs/heads/{branch}", timeout=timeout)
        .decode()
        .strip()
    )
    if pushed_head != commit_oid:
        raise ArtifactError(f"destination ref mismatch: expected {commit_oid}, got {pushed_head}")
    return f"refs/heads/{branch}@{pushed_head}"
