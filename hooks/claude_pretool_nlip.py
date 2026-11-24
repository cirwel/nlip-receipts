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
_SHELL_ARG_LONG_FLAGS = frozenset({"--rcfile", "--init-file", "-o", "+o", "-O", "+O"})
_SHELL_PREFIX_KEYWORDS = frozenset(
    {"!", "{", "}", "if", "then", "elif", "else", "do", "while", "until", "coproc", "function"}
)
_WRAPPER_ARG_FLAGS: dict[str, frozenset[str]] = {
    "env": frozenset({"-u", "-C", "--unset", "--chdir"}),
    "sudo": frozenset(
        {
            "-u",
            "-g",
            "-C",
            "-D",
            "-R",
            "-T",
            "-h",
            "-p",
            "-r",
            "-t",
            "-U",
            "--user",
            "--group",
            "--close-from",
            "--chdir",
            "--chroot",
            "--command-timeout",
            "--host",
            "--prompt",
            "--role",
            "--type",
            "--other-user",
        }
    ),
    "command": frozenset(),
    "exec": frozenset({"-a"}),
    "nohup": frozenset(),
    "time": frozenset({"-o", "-f", "--output", "--format"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "xargs": frozenset(
        {
            "-I",
            "-J",
            "-L",
            "-n",
            "-P",
            "-s",
            "-d",
            "-E",
            "-a",
            "--replace",
            "--max-lines",
            "--max-args",
            "--max-procs",
            "--max-chars",
            "--delimiter",
            "--eof",
            "--arg-file",
        }
    ),
}
_EDIT_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
_FIND_EXEC_FLAGS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})

_GH_MERGE_API_RE = re.compile(r"(?:^|/)(?:pulls/\d+/merge|merges)(?:$|[?#])")
_ANSI_C_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
}


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


def _git_has_alias_override(tokens: list[str]) -> bool:
    """Return True if a `git` invocation defines an inline `alias.*` config override."""
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--":
            return False
        low = tok.lower()
        if tok in ("-c", "--config-env"):
            if idx + 1 < len(tokens) and tokens[idx + 1].lstrip().lower().startswith("alias."):
                return True
            idx += 2
            continue
        if low.startswith("-calias.") or low.startswith("--config-env=alias."):
            return True
        if tok in _GIT_ARG_FLAGS:
            idx += 2
            continue
        if any(tok.startswith(f"{flag}=") for flag in _GIT_ARG_FLAGS if flag.startswith("--")):
            idx += 1
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        return False
    return False


def _git_subcommand_index(tokens: list[str]) -> int | None:
    """Return the index of the primary git subcommand in `tokens`, or `None`."""
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
        return idx
    return idx if idx < len(tokens) else None


def _git_subcommand(tokens: list[str]) -> str | None:
    """Extract the primary git subcommand from a command segment starting with `git`."""
    idx = _git_subcommand_index(tokens)
    return tokens[idx] if idx is not None else None


def _scan_ansi_c_quote(command: str, start: int) -> tuple[str, int]:
    """Parse `$'...'` starting after `$'` at index `start`; return `(decoded, next_index)`."""
    out: list[str] = []
    i = start
    n = len(command)
    while i < n:
        ch = command[i]
        if ch == "'":
            return "".join(out), i + 1
        if ch == "\\":
            i += 1
            if i >= n:
                raise ValueError("trailing backslash in $'...' quote")
            esc = command[i]
            if esc == "x" and i + 1 < n:
                j = i + 1
                while j < min(i + 3, n) and command[j] in "0123456789abcdefABCDEF":
                    j += 1
                if j > i + 1:
                    out.append(chr(int(command[i + 1 : j], 16)))
                    i = j
                    continue
            if esc in "01234567":
                j = i
                while j < min(i + 3, n) and command[j] in "01234567":
                    j += 1
                out.append(chr(int(command[i:j], 8) & 0xFF))
                i = j
                continue
            if esc in ("u", "U"):
                width = 4 if esc == "u" else 8
                j = i + 1
                while j < min(i + 1 + width, n) and command[j] in "0123456789abcdefABCDEF":
                    j += 1
                if j > i + 1:
                    out.append(chr(int(command[i + 1 : j], 16)))
                    i = j
                    continue
            out.append(_ANSI_C_ESCAPES.get(esc, esc))
            i += 1
            continue
        out.append(ch)
        i += 1
    raise ValueError("unclosed $'...' quote")


def _scan_backtick(
    command: str, open_idx: int, *, in_double: bool, subs_out: list[str]
) -> tuple[str, int]:
    """Scan `` `...` `` starting at `open_idx`; append inner script to `subs_out`."""
    j = open_idx + 1
    n = len(command)
    inner: list[str] = []
    while j < n and command[j] != "`":
        if command[j] == "\\" and j + 1 < n:
            nxt = command[j + 1]
            if nxt in ("\\", "`", "$") or (in_double and nxt == '"'):
                inner.append(nxt)
                j += 2
                continue
        inner.append(command[j])
        j += 1
    if j >= n:
        raise ValueError("unclosed backtick substitution")
    subs_out.append("".join(inner))
    return command[open_idx : j + 1], j + 1


def _scan_dollar_brace(
    command: str, dollar_idx: int, subs_out: list[str]
) -> tuple[str, int]:
    """Scan `${...}` parameter expansion starting at `dollar_idx`, extracting nested substitutions
    without treating `${a},${b}` as brace expansion."""
    j = dollar_idx + 2
    n = len(command)
    depth = 1
    while j < n and depth > 0:
        c = command[j]
        if c == "\\":
            if j + 1 >= n:
                raise ValueError("trailing backslash in ${...}")
            j += 2
            continue
        if c == "$" and j + 1 < n and command[j + 1] == "'":
            _, j = _scan_ansi_c_quote(command, j + 2)
            continue
        if c == "$" and j + 1 < n and command[j + 1] == "(":
            _, j = _scan_dollar_paren(command, j, subs_out)
            continue
        if c == "$" and j + 1 < n and command[j + 1] == "{":
            _, j = _scan_dollar_brace(command, j, subs_out)
            continue
        if c == "'":
            end = command.find("'", j + 1)
            if end == -1:
                raise ValueError("unclosed single quote in ${...}")
            j = end + 1
            continue
        if c == '"':
            _, j = _scan_double_quoted(command, j + 1, subs_out)
            continue
        if c == "`":
            _, j = _scan_backtick(command, j, in_double=False, subs_out=subs_out)
            continue
        if c == "{":
            depth += 1
            j += 1
            continue
        if c == "}":
            depth -= 1
            if depth == 0:
                return command[dollar_idx : j + 1], j + 1
            j += 1
            continue
        j += 1
    raise ValueError("unclosed ${...} expansion")


def _parse_heredoc_op(command: str, lt_idx: int) -> tuple[tuple[str, bool, bool], int]:
    """Parse `<<` or `<<-` starting at `lt_idx`; return `((delim, quoted, strip_tabs), next_idx)`."""
    n = len(command)
    k = lt_idx + 2
    strip_tabs = False
    if k < n and command[k] == "-":
        strip_tabs = True
        k += 1
    while k < n and command[k] in (" ", "\t"):
        k += 1
    delim_chars: list[str] = []
    delim_quoted = False
    while k < n and command[k] not in (" ", "\t", "\r", "\n", ";", "&", "|", "(", ")", "<", ">"):
        ch = command[k]
        if ch == "\\":
            if k + 1 >= n:
                raise ValueError("trailing backslash in heredoc delimiter")
            if command[k + 1] == "\n":
                k += 2
                continue
            delim_quoted = True
            delim_chars.append(command[k + 1])
            k += 2
            continue
        if ch == "$" and k + 1 < n and command[k + 1] == "'":
            delim_quoted = True
            decoded, k = _scan_ansi_c_quote(command, k + 2)
            delim_chars.append(decoded)
            continue
        if ch == "$" and k + 1 < n and command[k + 1] == '"':
            delim_quoted = True
            k += 1
            ch = '"'
        if ch == "'":
            delim_quoted = True
            end = command.find("'", k + 1)
            if end == -1:
                raise ValueError("unclosed single quote in heredoc delimiter")
            delim_chars.append(command[k + 1 : end])
            k = end + 1
            continue
        if ch == '"':
            delim_quoted = True
            k += 1
            while k < n and command[k] != '"':
                if command[k] == "\\" and k + 1 < n and command[k + 1] in ('"', "\\", "$", "`"):
                    delim_chars.append(command[k + 1])
                    k += 2
                    continue
                delim_chars.append(command[k])
                k += 1
            if k >= n:
                raise ValueError("unclosed double quote in heredoc delimiter")
            k += 1
            continue
        delim_chars.append(ch)
        k += 1
    if not delim_chars:
        raise ValueError("empty heredoc delimiter")
    return ("".join(delim_chars), delim_quoted, strip_tabs), k


def _scan_unquoted_heredoc_subs(body: str, subs_out: list[str]) -> None:
    """In an unquoted heredoc body, quotes/`#`/`()` are literal; only `$(...)`, `${...}`, and
    backticks expand."""
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "$" and i + 1 < n and body[i + 1] == "(":
            _, i = _scan_dollar_paren(body, i, subs_out)
            continue
        if ch == "$" and i + 1 < n and body[i + 1] == "{":
            _, i = _scan_dollar_brace(body, i, subs_out)
            continue
        if ch == "`":
            _, i = _scan_backtick(body, i, in_double=False, subs_out=subs_out)
            continue
        i += 1


def _consume_heredocs(
    command: str,
    pos_after_nl: int,
    pending: list[tuple[str, bool, bool]],
    subs_out: list[str],
) -> tuple[int, list[str]]:
    """Consume queued heredoc bodies starting at `pos_after_nl`; return `(next_pos, bodies)`."""
    bodies: list[str] = []
    pos = pos_after_nl
    n = len(command)
    for delim, delim_quoted, strip_tabs in pending:
        body_start = pos
        matched = False
        while pos <= n:
            nl = command.find("\n", pos)
            line_end = nl if nl != -1 else n
            raw_line = command[pos:line_end]
            cmp_line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
            if strip_tabs:
                cmp_line = cmp_line.lstrip("\t")
            if cmp_line == delim:
                body_text = command[body_start:pos]
                bodies.append(body_text)
                if not delim_quoted:
                    _scan_unquoted_heredoc_subs(body_text, subs_out)
                pos = nl + 1 if nl != -1 else n
                matched = True
                break
            if nl == -1:
                break
            pos = nl + 1
        if not matched:
            raise ValueError(f"unterminated heredoc ({delim!r})")
    pending.clear()
    return pos, bodies


def _scan_double_quoted(
    command: str, start: int, subs_out: list[str]
) -> tuple[str, int]:
    """Scan `"..."` starting after opening `"` at `start`, extracting nested `$(...)` / `` `...` ``."""
    out: list[str] = []
    i = start
    n = len(command)
    while i < n and command[i] != '"':
        ch = command[i]
        if ch == "\\":
            if i + 1 >= n:
                raise ValueError("trailing backslash in double quotes")
            nxt = command[i + 1]
            if nxt == "\n":
                i += 2
                continue
            if nxt in ('"', "\\", "$", "`"):
                out.append(nxt)
                i += 2
                continue
            out.append(ch)
            i += 1
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == "(":
            raw_sub, i = _scan_dollar_paren(command, i, subs_out)
            out.append(raw_sub)
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == "{":
            raw_brace, i = _scan_dollar_brace(command, i, subs_out)
            out.append(raw_brace)
            continue
        if ch == "`":
            raw_bt, i = _scan_backtick(command, i, in_double=True, subs_out=subs_out)
            out.append(raw_bt)
            continue
        out.append(ch)
        i += 1
    if i >= n:
        raise ValueError("unclosed double quote")
    return "".join(out), i + 1


def _scan_dollar_paren(
    command: str, dollar_idx: int, subs_out: list[str]
) -> tuple[str, int]:
    """Scan `$(...)` starting at `dollar_idx`, respecting nested quotes, heredocs, substitutions,
    and command-position `case ... esac` pattern `)` delimiters. Appends inner body to `subs_out`."""
    j = dollar_idx + 2
    n = len(command)
    depth = 1
    case_depth = 0
    at_cmd_pos = True
    cur_word: list[str] = []
    pending_heredocs: list[tuple[str, bool, bool]] = []
    _DELIMS = frozenset(
        {" ", "\t", "\r", "\n", ";", "&", "|", "(", ")", "'", '"', "`", "\\", "#", "<", ">"}
    )
    _CMD_FOLLOW_KW = frozenset({"!", "{", "if", "then", "elif", "else", "do", "while", "until"})

    def flush_kw() -> None:
        nonlocal case_depth, at_cmd_pos
        if cur_word:
            w = "".join(cur_word)
            cur_word.clear()
            if at_cmd_pos and w == "case":
                case_depth += 1
                at_cmd_pos = False
            elif at_cmd_pos and w == "esac" and case_depth > 0:
                case_depth -= 1
                at_cmd_pos = False
            elif at_cmd_pos and w in _CMD_FOLLOW_KW:
                at_cmd_pos = True
            else:
                at_cmd_pos = False

    while j < n and depth > 0:
        c = command[j]
        if c not in _DELIMS and not (
            c == "$" and j + 1 < n and command[j + 1] in ("(", "{", "'", '"')
        ):
            cur_word.append(c)
            j += 1
            continue
        flush_kw()
        if (
            c == "<"
            and j + 1 < n
            and command[j + 1] == "<"
            and not (j + 2 < n and command[j + 2] == "<")
        ):
            spec, j = _parse_heredoc_op(command, j)
            pending_heredocs.append(spec)
            continue
        if c == "\n":
            at_cmd_pos = True
            j += 1
            if pending_heredocs:
                j, _ = _consume_heredocs(command, j, pending_heredocs, subs_out)
            continue
        if c == "#":
            if j == dollar_idx + 2 or command[j - 1] in (
                " ",
                "\t",
                "\r",
                "\n",
                ";",
                "&",
                "|",
                "(",
                ")",
            ):
                while j < n and command[j] != "\n":
                    j += 1
                continue
        if c == "\\":
            if j + 1 >= n:
                raise ValueError("trailing backslash in $(...)")
            if command[j + 1] != "\n":
                at_cmd_pos = False
            j += 2
            continue
        if c == "$" and j + 1 < n and command[j + 1] == "'":
            _, j = _scan_ansi_c_quote(command, j + 2)
            at_cmd_pos = False
            continue
        if c == "$" and j + 1 < n and command[j + 1] == "(":
            _, j = _scan_dollar_paren(command, j, subs_out)
            at_cmd_pos = False
            continue
        if c == "$" and j + 1 < n and command[j + 1] == "{":
            _, j = _scan_dollar_brace(command, j, subs_out)
            at_cmd_pos = False
            continue
        if c == "'":
            end = command.find("'", j + 1)
            if end == -1:
                raise ValueError("unclosed single quote in $(...)")
            j = end + 1
            at_cmd_pos = False
            continue
        if c == '"':
            _, j = _scan_double_quoted(command, j + 1, subs_out)
            at_cmd_pos = False
            continue
        if c == "`":
            _, j = _scan_backtick(command, j, in_double=False, subs_out=subs_out)
            at_cmd_pos = False
            continue
        if c in (";", "&", "|"):
            at_cmd_pos = True
            j += 1
            continue
        if c == "(":
            depth += 1
            at_cmd_pos = True
            j += 1
            continue
        if c == ")":
            if case_depth > 0 and depth == 1:
                at_cmd_pos = True
                j += 1
                continue
            depth -= 1
            if depth == 0:
                if pending_heredocs:
                    raise ValueError("unterminated heredoc in $(...)")
                subs_out.append(command[dollar_idx + 2 : j])
                return command[dollar_idx : j + 1], j + 1
            at_cmd_pos = False
            j += 1
            continue
        j += 1
    raise ValueError("unclosed $(...) substitution")


def _tokenize_shell(
    command: str,
) -> tuple[list[tuple[list[tuple[str, bool]], list[str]]], list[str]]:
    """Tokenize `command` into `([(segment_tokens, heredoc_bodies), ...], command_substitutions)`,
    where each segment token is `(text, has_unquoted_brace_expansion)`.
    """
    segments: list[tuple[list[tuple[str, bool]], list[str]]] = []
    subs: list[str] = []
    current: list[tuple[str, bool]] = []
    buf: list[str] = []
    word_open = False
    brace_stack: list[bool] = []  # per open unquoted `{`: True once an unquoted `,` appeared at depth
    has_brace_exp = False
    skip_next_word = False
    pending_heredocs: list[tuple[str, bool, bool]] = []
    line_seg_indices: list[int] = []
    i = 0
    n = len(command)

    def discard_io_number_or_flush() -> None:
        nonlocal word_open, has_brace_exp
        if word_open and "".join(buf).isdigit() and not has_brace_exp and not skip_next_word:
            buf.clear()
            word_open = False
            brace_stack.clear()
        else:
            flush_word()

    def flush_word() -> None:
        nonlocal word_open, has_brace_exp, skip_next_word
        if word_open:
            if not skip_next_word:
                current.append(("".join(buf), has_brace_exp))
            skip_next_word = False
            buf.clear()
            word_open = False
            brace_stack.clear()
            has_brace_exp = False

    def flush_segment() -> None:
        nonlocal skip_next_word
        flush_word()
        skip_next_word = False
        if current:
            line_seg_indices.append(len(segments))
            segments.append((list(current), []))
            current.clear()

    while i < n:
        ch = command[i]
        if ch in (" ", "\t", "\r"):
            flush_word()
            i += 1
            continue
        if (
            ch == "<"
            and i + 1 < n
            and command[i + 1] == "<"
            and not (i + 2 < n and command[i + 2] == "<")
        ):
            discard_io_number_or_flush()
            spec, i = _parse_heredoc_op(command, i)
            pending_heredocs.append(spec)
            continue
        if ch == "\n":
            flush_segment()
            i += 1
            if pending_heredocs:
                i, bodies = _consume_heredocs(command, i, pending_heredocs, subs)
                for seg_idx in line_seg_indices:
                    segments[seg_idx][1].extend(bodies)
            line_seg_indices.clear()
            continue
        if ch == "&" and i + 1 < n and command[i + 1] == ">":
            flush_word()
            i += 3 if (i + 2 < n and command[i + 2] == ">") else 2
            skip_next_word = True
            continue
        if ch in (";", "&", "|", "(", ")"):
            flush_segment()
            i += 1
            continue
        if ch in ("<", ">"):
            discard_io_number_or_flush()
            if ch == "<" and i + 2 < n and command[i : i + 3] == "<<<":
                i += 3
            elif i + 1 < n and command[i : i + 2] in (">>", ">|", "<>", ">&", "<&"):
                i += 2
            else:
                i += 1
            skip_next_word = True
            continue
        if ch == "#" and not word_open:
            flush_segment()
            while i < n and command[i] != "\n":
                i += 1
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == "'":
            word_open = True
            decoded, i = _scan_ansi_c_quote(command, i + 2)
            buf.append(decoded)
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == '"':
            word_open = True
            decoded, i = _scan_double_quoted(command, i + 2, subs)
            buf.append(decoded)
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == "(":
            word_open = True
            raw_sub, i = _scan_dollar_paren(command, i, subs)
            buf.append(raw_sub)
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == "{":
            word_open = True
            raw_brace, i = _scan_dollar_brace(command, i, subs)
            buf.append(raw_brace)
            continue
        if ch == "'":
            word_open = True
            end = command.find("'", i + 1)
            if end == -1:
                raise ValueError("unclosed single quote")
            buf.append(command[i + 1 : end])
            i = end + 1
            continue
        if ch == '"':
            word_open = True
            decoded, i = _scan_double_quoted(command, i + 1, subs)
            buf.append(decoded)
            continue
        if ch == "`":
            word_open = True
            raw_bt, i = _scan_backtick(command, i, in_double=False, subs_out=subs)
            buf.append(raw_bt)
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
        if ch == "{":
            brace_stack.append(False)
        elif ch == "," and brace_stack:
            brace_stack[-1] = True
        elif ch == "}" and brace_stack:
            if brace_stack.pop():
                has_brace_exp = True
        buf.append(ch)
        i += 1

    flush_segment()
    if pending_heredocs:
        raise ValueError("unterminated heredoc at end of command")
    return segments, subs


def _unwrap_segment(
    raw_seg: list[tuple[str, bool]],
) -> tuple[list[tuple[str, bool]], list[str]]:
    """Strip leading shell compound keywords, `VAR=val` assignments, and command-prefix wrappers,
    returning `(remaining_tokens, nested_shell_strings)` (e.g. from `env -S` / `--split-string`).
    Handles clustered short flags such as `sudo -iu root` or `sudo -uroot`.
    """
    nested: list[str] = []
    idx = 0
    n = len(raw_seg)
    while idx < n:
        tok, has_brace = raw_seg[idx]
        if has_brace:
            break
        if tok in ("function", "coproc"):
            idx += 1
            if idx + 1 < n and raw_seg[idx + 1][0] == "{":
                idx += 2
            continue
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
            while idx < n:
                sub_tok, sub_brace = raw_seg[idx]
                if sub_brace:
                    break
                if sub_tok == "--":
                    idx += 1
                    break
                if base == "env":
                    if sub_tok in ("-S", "--split-string"):
                        if idx + 1 < n:
                            nested.append(raw_seg[idx + 1][0])
                        idx += 2
                        continue
                    if sub_tok.startswith("--split-string="):
                        nested.append(sub_tok.split("=", 1)[1])
                        idx += 1
                        continue
                    if "=" in sub_tok and not sub_tok.startswith("="):
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
                if sub_tok.startswith("--"):
                    idx += 1
                    continue
                if sub_tok.startswith("-") and len(sub_tok) > 1:
                    advanced = False
                    for k in range(1, len(sub_tok)):
                        short_flag = f"-{sub_tok[k]}"
                        if base == "env" and short_flag == "-S":
                            if k == len(sub_tok) - 1:
                                if idx + 1 < n:
                                    nested.append(raw_seg[idx + 1][0])
                                idx += 2
                            else:
                                nested.append(sub_tok[k + 1 :])
                                idx += 1
                            advanced = True
                            break
                        if short_flag in arg_flags:
                            idx += 2 if k == len(sub_tok) - 1 else 1
                            advanced = True
                            break
                    if not advanced:
                        idx += 1
                    continue
                break
            continue
        break
    return raw_seg[idx:], nested


def _shell_dash_c_arg(tokens: list[str]) -> str | None:
    """Extract the command-string operand of `sh`/`bash` `-c` (supporting `--norc -c`, `--rcfile x -c`,
    `-o pipefail -c`, `-eo pipefail -c`, `-lc`, and `-c -- 'cmd'`)."""
    has_c = False
    j = 1
    n = len(tokens)
    while j < n:
        tok = tokens[j]
        if tok == "--":
            j += 1
            break
        if tok in _SHELL_ARG_LONG_FLAGS:
            j += 2
            continue
        if tok.startswith("--"):
            j += 1
            continue
        if (tok.startswith("-") or tok.startswith("+")) and len(tok) > 1:
            if tok.startswith("-") and "c" in tok[1:]:
                has_c = True
            consumed_next = False
            for k in range(1, len(tok)):
                if tok[k] in ("o", "O"):
                    consumed_next = k == len(tok) - 1
                    break
            j += 2 if consumed_next else 1
            continue
        break
    if has_c and j < n:
        return tokens[j]
    return None


def _gh_subcommand_limit(tokens: list[str]) -> int:
    """Return slice upper bound covering `gh` plus its first two non-flag subcommand words."""
    seen = 0
    for idx in range(1, len(tokens)):
        if not tokens[idx].startswith("-"):
            seen += 1
            if seen == 2:
                return idx + 1
    return len(tokens)


def _check_bash_command(command: str, *, _depth: int = 0) -> str | None:
    """Return a denial reason if `command` invokes a direct publication path, else `None`."""
    if _depth > 5:
        return "Nested shell wrapper depth exceeded; failing closed under NLIP Type-3 guardrail."

    try:
        segments, subst_bodies = _tokenize_shell(command)
    except ValueError:
        return (
            "Unparseable shell quoting in Bash command; failing closed under NLIP Type-3 guardrail."
        )

    for sub_cmd in subst_bodies:
        nested_sub = _check_bash_command(sub_cmd, _depth=_depth + 1)
        if nested_sub:
            return nested_sub

    for raw_seg, heredoc_bodies in segments:
        unwrapped, wrapper_nested = _unwrap_segment(raw_seg)
        for wn in wrapper_nested:
            res = _check_bash_command(wn, _depth=_depth + 1)
            if res:
                return res
        if not unwrapped:
            continue
        if unwrapped[0][1]:
            return (
                "Unquoted brace expansion in Bash command position is blocked by the NLIP Type-3 "
                "guardrail."
            )

        seg = [t for t, _ in unwrapped]
        base = os.path.basename(seg[0])

        if base == "eval":
            if len(seg) > 1:
                nested_eval = _check_bash_command(" ".join(seg[1:]), _depth=_depth + 1)
                if nested_eval:
                    return nested_eval
            for hb in heredoc_bodies:
                nested_hb = _check_bash_command(hb, _depth=_depth + 1)
                if nested_hb:
                    return nested_hb
            continue

        if base == "find":
            for k, tok in enumerate(seg[1:], start=1):
                if tok in _FIND_EXEC_FLAGS:
                    end_k = k + 1
                    while end_k < len(seg) and seg[end_k] not in (";", "+"):
                        end_k += 1
                    if end_k > k + 1:
                        res = _check_bash_command(" ".join(seg[k + 1 : end_k]), _depth=_depth + 1)
                        if res:
                            return res

        if base in _SHELL_BINARIES:
            dash_c = _shell_dash_c_arg(seg)
            if dash_c is not None:
                nested = _check_bash_command(dash_c, _depth=_depth + 1)
                if nested:
                    return nested
            for hb in heredoc_bodies:
                nested_hb = _check_bash_command(hb, _depth=_depth + 1)
                if nested_hb:
                    return nested_hb

        if base == "git":
            if _git_has_alias_override(seg):
                return (
                    "Inline `git -c alias.*` configuration from Bash is blocked by the NLIP Type-3 "
                    "guardrail."
                )
            sub_idx = _git_subcommand_index(seg)
            brace_limit = (sub_idx + 1) if sub_idx is not None else len(unwrapped)
            if any(has_b for _, has_b in unwrapped[:brace_limit]):
                return (
                    "Unquoted brace expansion in `git` subcommand/options is blocked by the NLIP "
                    "Type-3 guardrail."
                )
            sub = seg[sub_idx] if sub_idx is not None else None
            if sub in _GIT_WRITE_SUBCOMMANDS:
                return (
                    f"Direct `git {sub}` from Bash is blocked by the NLIP Type-3 guardrail. "
                    "Verify the commit with `nlip_verify` and publish with `nlip_publish`."
                )
        elif base in ("git-receive-pack", "git-send-pack"):
            return f"Direct `{base}` is blocked; publish via `nlip_publish`."
        elif base == "gh":
            non_flags = [t for t in seg[1:] if not t.startswith("-")]
            gh_limit = (
                len(unwrapped)
                if (non_flags and non_flags[0] == "api")
                else _gh_subcommand_limit(seg)
            )
            if any(has_b for _, has_b in unwrapped[:gh_limit]):
                return (
                    "Unquoted brace expansion in `gh` subcommand/API endpoint is blocked by the "
                    "NLIP Type-3 guardrail."
                )
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
