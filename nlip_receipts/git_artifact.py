"""Immutable Git artifact resolution, isolated snapshot verification, and commit-pinned publication.

Builds on the content-addressed repository fingerprinting concepts from `hermes-receipts`,
extending them with snapshot-isolated verification (`git archive <tree_oid>`) and
commit-pinned publication (`git push <dest> <commit_oid>:refs/heads/<branch>`) to eliminate
mid-run working-tree race conditions and post-verification TOCTOU gaps.
"""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass


class ArtifactError(RuntimeError):
    """Raised when a Git repository or immutable artifact cannot be resolved or exported."""


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
        LC_ALL="C",
    )
    return env


def run_git(repo_path: str, *args: str, timeout: float = 5.0) -> bytes:
    cmd = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
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
    """Resolve `ref` in `repo_path` to its exact immutable `(commit_oid, tree_oid)`."""
    if not ref or not isinstance(ref, str) or ref.startswith("-"):
        raise ArtifactError(f"invalid artifact reference: {ref!r}")
    real_repo = os.path.realpath(repo_path)
    commit_oid = (
        run_git(real_repo, "rev-parse", "--verify", "-q", "--end-of-options", f"{ref}^{{commit}}", timeout=timeout)
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


def export_isolated_snapshot(repo_path: str, tree_oid: str, snapshot_dir: str, timeout: float = 5.0) -> None:
    """Export the exact immutable `tree_oid` into `snapshot_dir` via `git archive`."""
    tar_bytes = run_git(repo_path, "archive", "--format=tar", tree_oid, timeout=timeout)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        # Use data filter on Python 3.12+ to prevent path traversal / symlink escapes
        tf.extractall(path=snapshot_dir, filter="data")


def compute_env_fingerprint(command: list[str]) -> tuple[str, str]:
    """Return `(command_sha256, env_fingerprint)` for the verification execution profile."""
    cmd_canon = "\0".join(command).encode("utf-8")
    command_sha256 = hashlib.sha256(cmd_canon).hexdigest()
    env_meta = f"py={sys.version_info.major}.{sys.version_info.minor}|platform={sys.platform}".encode("utf-8")
    env_fingerprint = hashlib.sha256(env_meta).hexdigest()[:16]
    return command_sha256, env_fingerprint


def run_verification_in_snapshot(
    repo_path: str,
    tree_oid: str,
    command: list[str],
    timeout: float = 15.0,
) -> tuple[int, float, str, str, str]:
    """Run `command` inside an isolated temporary snapshot of `tree_oid`.

    Returns `(exit_code, duration_ms, output_sha256, command_sha256, env_fingerprint)`.
    Because the check runs on an exported snapshot of `tree_oid` rather than the live
    working tree, concurrent edits to the working tree during execution cannot race or
    alter the verified content.
    """
    if not command or not all(isinstance(part, str) and part for part in command):
        raise ArtifactError("verification command must be a non-empty argument vector")

    command_sha256, env_fingerprint = compute_env_fingerprint(command)
    with tempfile.TemporaryDirectory(prefix="nlip-se-verify-") as snap_dir:
        export_isolated_snapshot(repo_path, tree_oid, snap_dir, timeout=min(5.0, timeout))
        clean_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": snap_dir,
            "TMPDIR": snap_dir,
            "PYTHONDONTWRITEBYTECODE": "1",
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
    """Push the exact verified `commit_oid` to `refs/heads/<branch>` in `dest_path`.

    Pushing `<commit_oid>:refs/heads/<branch>` instead of a mutable ref name ensures
    that even if `HEAD` moved after verification, only the verified commit is published.
    """
    if not branch or "/" in branch or ".." in branch or branch.startswith("-"):
        raise ArtifactError(f"invalid target branch name: {branch!r}")
    refspec = f"{commit_oid}:refs/heads/{branch}"
    run_git(
        repo_path,
        "push",
        "--no-verify",
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
