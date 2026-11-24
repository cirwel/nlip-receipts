#!/usr/bin/env python3
"""Fail-closed, deny-only Claude Code `PreToolUse` guardrail hook for `nlip-receipts`.

Architectural role & security boundary:
- This hook NEVER executes `publish`, consumes a single-use receipt, or emits `permissionDecision:
  "allow"` (which in Claude Code skips normal user permission prompts). When a call is not blocked,
  the hook prints nothing and exits 0 so Claude Code's standard permission flow runs unchanged.
- Actual `verify` and `publish` calls run through the MCP stdio bridge (`nlip_receipts.mcp_stdio`)
  over HTTP `POST /nlip/` to the Type-3 `nlip_server`.
- Cooperative client-side guardrails enforced here:
  1. Blocks direct `Bash` remote-publication commands (`git push`, `git send-pack`, `git receive-pack`,
     `gh pr merge`, GitHub `/pulls/.../merge` and `/merges` API calls, including multi-line scripts,
     wrapper prefixes like `env`/`sudo`/`command`/`exec`/`nohup`/`time`/`nice`/`xargs`, `sh -c`, and
     command substitutions), directing the agent to `nlip_verify` / `nlip_publish`.
  2. Blocks file-edit tools (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) targeting `.claude/`,
     `hooks/` (anchored at `$CLAUDE_PROJECT_DIR`, repo root, git root, and `cwd`), `.git/hooks/`,
     `.git/config`, or `.git/worktrees/*/config` (case-insensitively for macOS APFS compatibility).
  3. Fails closed (`permissionDecision: "deny"`, exit 0) on any malformed stdin JSON or unexpected
     exception, since non-0/non-2 hook exit codes fail open in Claude Code.
- Defense-in-depth note: client-side `Bash` inspection is NOT a privilege boundary against an
  unconfined local shell. As documented in `SECURITY.md`, production deployments must run
  `nlip_server` under a separate OS user, container, or host that exclusively holds destination
  write access and ledger/HMAC secrets.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_HOOK_REPO_ROOT = Path(__file__).resolve().parents[1]
_GIT_WRITE_SUBCOMMANDS = frozenset({"push", "send-pack", "receive-pack"})
_GIT_ARG_FLAGS = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
)
_SHELL_BINARIES = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_SHELL_PREFIX_KEYWORDS = frozenset(
    {"!", "{", "}", "if", "then", "elif", "else", "do", "while", "until"}
)
_WRAPPER_ARG_FLAGS: dict[str, frozenset[str]] = {
    "env": frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}),
    "sudo": frozenset({"-u", "-g", "-C", "-D", "-R", "-T", "-h", "-p", "-r", "-t"}),
    "command": frozenset(),
    "exec": frozenset({"-a"}),
    "nohup": frozenset(),
    "time": frozenset({"-o", "-f"}),
    "nice": frozenset({"-n"}),
    "xargs": frozenset({"-I", "-J", "-L", "-n", "-P", "-s", "-d", "-E", "-a"}),
}
_EDIT_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})

_SUBST_BYPASS_RE = re.compile(
    r"(?:\$\(|`)\s*[^`)]*\b(?:git\b[^`)]*\b(?:push|send-pack|receive-pack)|"
    r"git-(?:send-pack|receive-pack)|gh\s+pr\s+merge|gh\s+api\b[^`)]*\/(?:pulls/\d+/merge|merges)\b)"
)
_GH_MERGE_API_RE = re.compile(r"(?:^|/)(?:pulls/\d+/merge|merges)(?:$|[?#])")


def _emit_deny(reason: str) -> int:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()
    return 0


def _git_subcommand(tokens: list[str]) -> str | None:
    """Extract the primary git subcommand from a command segment starting with `git`."""
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--":
            idx += 1
            break
        if tok in _GIT_ARG_FLAGS:
            idx += 2
            continue
        if any(tok.startswith(f"{flag}=") for flag in _GIT_ARG_FLAGS if flag.startswith("--")):
            idx += 1
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        return tok
    return tokens[idx] if idx < len(tokens) else None


def _split_segments(command: str) -> list[list[str]]:
    """Tokenize a shell command into simple-command segments separated by unquoted control
    operators (`;`, `&`, `|`, `(`, `)`, `\\n`), respecting POSIX quoting, backslash-newline
    continuations, and token-start-only `#` comments (`echo a#; git push` does NOT start a comment).
    Raises `ValueError` on unclosed quotes or trailing backslash so callers fail closed.
    """
    segments: list[list[str]] = []
    current: list[str] = []
    buf: list[str] = []
    word_open = False
    i = 0
    n = len(command)

    def flush_word() -> None:
        nonlocal word_open
        if word_open:
            current.append("".join(buf))
            buf.clear()
            word_open = False

    def flush_segment() -> None:
        flush_word()
        if current:
            segments.append(list(current))
            current.clear()

    while i < n:
        ch = command[i]
        if ch in (" ", "\t", "\r"):
            flush_word()
            i += 1
            continue
        if ch in (";", "&", "|", "(", ")", "\n"):
            flush_segment()
            i += 1
            continue
        if ch == "#" and not word_open:
            flush_segment()
            while i < n and command[i] != "\n":
                i += 1
            continue
        if ch == "'":
            word_open = True
            i += 1
            end = command.find("'", i)
            if end == -1:
                raise ValueError("unclosed single quote")
            buf.append(command[i:end])
            i = end + 1
            continue
        if ch == '"':
            word_open = True
            i += 1
            while i < n and command[i] != '"':
                if command[i] == "\\":
                    if i + 1 >= n:
                        raise ValueError("trailing backslash in double quotes")
                    nxt = command[i + 1]
                    if nxt == "\n":
                        i += 2
                        continue
                    if nxt in ('"', "\\", "$", "`"):
                        buf.append(nxt)
                        i += 2
                        continue
                buf.append(command[i])
                i += 1
            if i >= n:
                raise ValueError("unclosed double quote")
            i += 1
            continue
        if ch == "\\":
            if i + 1 >= n:
                raise ValueError("trailing backslash")
            if command[i + 1] == "\n":
                i += 2
                continue
            word_open = True
            buf.append(command[i + 1])
            i += 2
            continue
        word_open = True
        buf.append(ch)
        i += 1

    flush_segment()
    return segments


def _strip_wrappers(seg: list[str]) -> list[str]:
    """Strip leading shell compound keywords, `VAR=val` assignments, and command-prefix wrappers
    (`env`, `sudo`, `command`, `exec`, `nohup`, `time`, `nice`, `xargs`, including path-qualified
    forms like `/usr/bin/env`)."""
    idx = 0
    while idx < len(seg):
        tok = seg[idx]
        if tok in _SHELL_PREFIX_KEYWORDS:
            idx += 1
            continue
        if "=" in tok and not tok.startswith("=") and tok.split("=", 1)[0].isidentifier():
            idx += 1
            continue
        base = os.path.basename(tok)
        if base in _WRAPPER_ARG_FLAGS:
            arg_flags = _WRAPPER_ARG_FLAGS[base]
            idx += 1
            while idx < len(seg):
                sub_tok = seg[idx]
                if sub_tok == "--":
                    idx += 1
                    break
                if base == "env" and "=" in sub_tok and not sub_tok.startswith("="):
                    idx += 1
                    continue
                if sub_tok in arg_flags:
                    idx += 2
                    continue
                if any(
                    sub_tok.startswith(f"{flag}=") for flag in arg_flags if flag.startswith("--")
                ):
                    idx += 1
                    continue
                if sub_tok.startswith("-"):
                    idx += 1
                    continue
                break
            continue
        break
    return seg[idx:]


def _check_bash_command(command: str, *, _depth: int = 0) -> str | None:
    """Return a denial reason if `command` invokes a direct publication path, else `None`."""
    if _depth > 4:
        return "Nested shell wrapper depth exceeded; failing closed under NLIP Type-3 guardrail."

    if _SUBST_BYPASS_RE.search(command):
        return (
            "Command-substitution publication from Bash is blocked by the NLIP Type-3 guardrail. "
            "Use `nlip_verify` and `nlip_publish`."
        )

    try:
        segments = _split_segments(command)
    except ValueError:
        return (
            "Unparseable shell quoting in Bash command; failing closed under NLIP Type-3 guardrail."
        )

    for raw_seg in segments:
        seg = _strip_wrappers(raw_seg)
        if not seg:
            continue
        base = os.path.basename(seg[0])

        if base in _SHELL_BINARIES:
            for i in range(1, len(seg) - 1):
                flag = seg[i]
                if flag.startswith("-") and "c" in flag[1:]:
                    nested = _check_bash_command(seg[i + 1], _depth=_depth + 1)
                    if nested:
                        return nested
                    break

        if base == "git":
            sub = _git_subcommand(seg)
            if sub in _GIT_WRITE_SUBCOMMANDS:
                return (
                    f"Direct `git {sub}` from Bash is blocked by the NLIP Type-3 guardrail. "
                    "Verify the commit with `nlip_verify` and publish with `nlip_publish`."
                )
        elif base in ("git-receive-pack", "git-send-pack"):
            return f"Direct `{base}` is blocked; publish via `nlip_publish`."
        elif base == "gh":
            non_flags = [t for t in seg[1:] if not t.startswith("-")]
            if len(non_flags) >= 2 and non_flags[0] == "pr" and non_flags[1] == "merge":
                return "Direct `gh pr merge` from Bash is blocked by the NLIP Type-3 guardrail."
            if non_flags and non_flags[0] == "api" and any(
                _GH_MERGE_API_RE.search(t) for t in seg[1:]
            ):
                return "Direct GitHub merge API call from Bash is blocked by the NLIP Type-3 guardrail."

    return None


def _project_roots(cwd: str) -> list[Path]:
    roots: list[Path] = [_HOOK_REPO_ROOT]
    env_proj = os.environ.get("CLAUDE_PROJECT_DIR")
    if env_proj:
        roots.append(Path(env_proj).resolve(strict=False))
    cwd_path = Path(cwd).resolve(strict=False)
    roots.append(cwd_path)
    for anc in cwd_path.parents:
        if (anc / ".git").exists():
            roots.append(anc)
            break
    return roots


def _is_protected_path(raw_path: str, cwd: str) -> bool:
    cand = Path(raw_path)
    resolved = (
        (Path(cwd) / cand).resolve(strict=False)
        if not cand.is_absolute()
        else cand.resolve(strict=False)
    )
    lower_parts = [p.lower() for p in resolved.parts]
    for i, part in enumerate(lower_parts):
        if part == ".claude":
            return True
        if part == ".git":
            tail = lower_parts[i + 1 :]
            if tail and tail[0] in ("config", "hooks"):
                return True
            if len(tail) >= 3 and tail[0] == "worktrees" and tail[2] in ("config", "hooks"):
                return True

    for root in _project_roots(cwd):
        try:
            rel = resolved.relative_to(root)
        except ValueError:
            rel_lower_root = [p.lower() for p in root.parts]
            if len(lower_parts) > len(rel_lower_root) and lower_parts[: len(rel_lower_root)] == rel_lower_root:
                if lower_parts[len(rel_lower_root)] == "hooks":
                    return True
            continue
        if rel.parts and rel.parts[0].lower() == "hooks":
            return True
    return False


def evaluate_hook_stdin(stdin_text: str) -> str | None:
    """Return a denial reason string if blocked, or `None` to remain silent (`exit 0`, deferring
    to Claude Code's normal permission flow). Fails closed on malformed input."""
    if not stdin_text or not stdin_text.strip():
        return "NLIP PreToolUse guardrail failed closed: empty hook payload."
    try:
        event = json.loads(stdin_text)
    except ValueError as exc:
        return f"NLIP PreToolUse guardrail failed closed: invalid JSON ({exc})."

    if not isinstance(event, dict):
        return "NLIP PreToolUse guardrail failed closed: hook payload must be a JSON object."

    tool_name = event.get("tool_name")
    tool_input = event.get("tool_input")
    if not isinstance(tool_name, str) or not tool_name or not isinstance(tool_input, dict):
        return "NLIP PreToolUse guardrail failed closed: missing tool_name or tool_input."

    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) and event.get("cwd") else os.getcwd()

    if tool_name == "Bash":
        command = tool_input.get("command")
        if not isinstance(command, str):
            return "NLIP PreToolUse guardrail failed closed: Bash tool_input.command must be a string."
        return _check_bash_command(command)

    if tool_name in _EDIT_TOOLS:
        candidates: list[Any] = [
            tool_input.get("file_path"),
            tool_input.get("path"),
            tool_input.get("notebook_path"),
        ]
        edits = tool_input.get("edits")
        if isinstance(edits, list):
            for entry in edits:
                if isinstance(entry, dict):
                    candidates.append(entry.get("file_path"))
                    candidates.append(entry.get("path"))
        if any(not isinstance(p, str) for p in candidates if p is not None):
            return "NLIP PreToolUse guardrail failed closed: non-string path in edit tool."
        paths = [p for p in candidates if isinstance(p, str) and p]
        if not paths:
            return f"NLIP PreToolUse guardrail failed closed: {tool_name} missing target path."
        for p in paths:
            if _is_protected_path(p, cwd):
                return f"Modifying protected hook/git configuration path ({p!r}) is blocked."
        return None

    return None


def main() -> int:
    try:
        raw = sys.stdin.read()
        denial = evaluate_hook_stdin(raw)
        if denial is not None:
            return _emit_deny(denial)
        return 0
    except BaseException as exc:  # pragma: no cover - defensive fail-closed catch-all
        return _emit_deny(
            f"NLIP PreToolUse guardrail failed closed on internal error: {type(exc).__name__}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
