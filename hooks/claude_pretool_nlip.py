#!/usr/bin/env python3
"""Fail-closed, deny-only Claude Code `PreToolUse` guardrail hook for `nlip-receipts`.

Architectural role & security boundary:
- This hook NEVER executes `publish` or consumes a single-use receipt (which would desynchronize
  repository state if another hook or user prompt later denied the tool or if the hook timed out).
  Actual `verify` and `publish` calls run through the MCP stdio bridge (`nlip_receipts.mcp_stdio`)
  over HTTP `POST /nlip/` to the Type-3 `nlip_server`.
- Instead, this hook enforces cooperative client-side guardrails:
  1. Blocks direct `Bash` remote-publication commands (`git push`, `git send-pack`, `git receive-pack`,
     `gh pr merge`, GitHub merge API calls, including nested `sh -c` / command-substitution forms),
     directing the agent to `nlip_verify` / `nlip_publish`.
  2. Blocks file-edit tools (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) targeting `.claude/`,
     `hooks/`, `.git/hooks/`, or `.git/config`.
  3. Fails closed (`permissionDecision: "deny"`, exit 0) on any malformed stdin JSON or unexpected
     exception, since non-0/non-2 hook exit codes fail open in Claude Code.
- Defense-in-depth note: client-side `Bash` pattern matching is NOT a privilege boundary against an
  unconfined local shell. As documented in `SECURITY.md`, production deployments must run
  `nlip_server` under a separate OS user, container, or host that exclusively holds destination
  write access and ledger/HMAC secrets.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

_GIT_WRITE_SUBCOMMANDS = frozenset({"push", "send-pack", "receive-pack"})
_GIT_ARG_FLAGS = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
)
_SHELL_BINARIES = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_OPERATOR_TOKENS = frozenset({";", "&", "&&", "|", "||", "(", ")"})
_EDIT_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})

# Catch command substitutions (`$(...)` or `` `...` ``) that embed a publication command inside
# a double-quoted token where shlex keeps the substitution attached to surrounding text.
_SUBST_BYPASS_RE = re.compile(
    r"(?:\$\(|`)\s*[^`)]*\b(?:git\b[^`)]*\b(?:push|send-pack|receive-pack)|gh\s+pr\s+merge)\b"
)


def _emit_decision(decision: str, reason: str) -> int:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
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
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = False
    lexer.commenters = "#"
    segments: list[list[str]] = []
    current: list[str] = []
    for tok in lexer:
        if tok in _OPERATOR_TOKENS or "\n" in tok:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


def _strip_env_assignments(seg: list[str]) -> list[str]:
    idx = 0
    while idx < len(seg):
        tok = seg[idx]
        if tok == "env":
            idx += 1
            while idx < len(seg) and (seg[idx].startswith("-") or "=" in seg[idx]):
                idx += 1
            break
        if "=" in tok and not tok.startswith("=") and tok.split("=", 1)[0].isidentifier():
            idx += 1
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
        seg = _strip_env_assignments(raw_seg)
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
            if non_flags and non_flags[0] == "api" and any("/merges" in t for t in seg[1:]):
                return "Direct GitHub merge API call from Bash is blocked by the NLIP Type-3 guardrail."

    return None


def _is_protected_path(raw_path: str, cwd: str) -> bool:
    cand = Path(raw_path)
    resolved = (
        (Path(cwd) / cand).resolve(strict=False) if not cand.is_absolute() else cand.resolve(strict=False)
    )
    parts = resolved.parts
    for i, part in enumerate(parts):
        if part == ".claude":
            return True
        if part == ".git" and i + 1 < len(parts) and parts[i + 1] in ("config", "hooks"):
            return True
    try:
        rel = resolved.relative_to(Path(cwd).resolve(strict=False))
        if rel.parts and rel.parts[0] == "hooks":
            return True
    except ValueError:
        pass
    return False


def evaluate_hook_stdin(stdin_text: str) -> tuple[str, str]:
    """Pure evaluator returning `('allow' | 'deny', reason)`; fails closed on malformed input."""
    if not stdin_text or not stdin_text.strip():
        return "deny", "NLIP PreToolUse guardrail failed closed: empty hook payload."
    try:
        event = json.loads(stdin_text)
    except ValueError as exc:
        return "deny", f"NLIP PreToolUse guardrail failed closed: invalid JSON ({exc})."

    if not isinstance(event, dict):
        return "deny", "NLIP PreToolUse guardrail failed closed: hook payload must be a JSON object."

    tool_name = event.get("tool_name")
    tool_input = event.get("tool_input")
    if not isinstance(tool_name, str) or not tool_name or not isinstance(tool_input, dict):
        return "deny", "NLIP PreToolUse guardrail failed closed: missing tool_name or tool_input."

    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) and event.get("cwd") else os.getcwd()

    if tool_name == "Bash":
        command = tool_input.get("command")
        if not isinstance(command, str):
            return "deny", "NLIP PreToolUse guardrail failed closed: Bash tool_input.command must be a string."
        denial = _check_bash_command(command)
        if denial:
            return "deny", denial
        return "allow", "Permitted non-publication Bash command."

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
            return "deny", "NLIP PreToolUse guardrail failed closed: non-string path in edit tool."
        paths = [p for p in candidates if isinstance(p, str) and p]
        if not paths:
            return "deny", f"NLIP PreToolUse guardrail failed closed: {tool_name} missing target path."
        for p in paths:
            if _is_protected_path(p, cwd):
                return (
                    "deny",
                    f"Modifying protected hook/git configuration path ({p!r}) is blocked.",
                )
        return "allow", "Permitted file edit."

    return "allow", f"Tool {tool_name} permitted."


def main() -> int:
    try:
        raw = sys.stdin.read()
        decision, reason = evaluate_hook_stdin(raw)
        return _emit_decision(decision, reason)
    except BaseException as exc:  # pragma: no cover - defensive fail-closed catch-all
        return _emit_decision(
            "deny", f"NLIP PreToolUse guardrail failed closed on internal error: {type(exc).__name__}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
