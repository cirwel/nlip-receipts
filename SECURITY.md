# Security Compliance Statement (ECMA-434 Annex A)

This repository conforms to the **Natural Language Interaction Protocol (NLIP)** security guidelines (**ECMA-434**, 1st Edition, December 2025) and follows NIST's *Recommended Criteria for Cybersecurity Labeling of Consumer Software* (CSWP 02042022-1).

## Descriptive Claims
- **Claimant:** CIRWEL (`cirwel`)
- **Label Scope:** `nlip-receipts` v0.1.0 (Python 3.10+, `nlip_sdk` / `nlip_server` Type-3 Security Extension)
- **Claim Date:** 2026-11
- **Security Update Status:** Supported
- **Update Method:** GitHub releases and git tags
- **Vulnerability Disclosure Policy:** Report vulnerabilities via GitHub Security Advisories on the repository.

## ECMA-434 Security Countermeasures and Objectives (SCO) Mapping
- **7.2.2 Runtime & Behaviour: NLIP Client Authorization** — Enforces per-caller, per-destination authorization at the Type-3 tool boundary before side-effecting publication executes.
- **7.2.3 Runtime & Behaviour: Privilege Misuse Prevention** — Prevents Confused-Deputy and cross-caller receipt replay by binding verification receipts to `(caller_id, repo_id, tree_oid, profile_id, policy_epoch)`.
- **7.2.4 Observability & Audit: Agent Behaviours** — Records an append-only, structured decision and verification audit trail (`decisions` and `receipts` tables) traceable by NLIP conversation correlator and caller identity.
- **7.2.7 Agent Lifecycle: Secure-by-Design Disclosure** — Provided via this `SECURITY.md` disclosure.
- **7.3.2 Runtime Agent Behaviour Controls** — Enforces deterministic, zero-LLM-call runtime validation at the Type-3 tool boundary (`verify` / `publish`), ensuring agent self-reports (`"tests passed"`) or forged NLIP submessages cannot authorize side effects.
- **Proposed SCO 7.3.4 (Execution-Attested Side-Effect Gating):** Requires side-effecting tool invocations across an NLIP boundary to present a non-forgeable reference to a passing verification run executed by a trusted supervisor over the exact immutable artifact digest being published.

## Secure Development Practices
- [x] Secure coding practices aligned with NIST SSDF (SP 800-218).
- [x] No hard-coded secrets; HMAC ledger keys are ephemeral or operator-supplied at startup.
- [x] Cryptography uses HMAC-SHA256 and SHA-256 content/output digests; production transport requires TLS 1.3 per ECMA-434 §7.1.1.
- [x] Subprocess execution uses argument vectors (`shell=False` for Git operations) and isolated snapshot directories (`git archive`) with sanitized environments.

## Threat Model and Limitations

**Trusted:** the Security Extension process, its ledger file and HMAC key, the operator's policies, and the destination repositories. **Untrusted:** the agent, every NLIP message it sends, and the contents of the tree it asks to verify or publish.

The gate is only meaningful if the agent's sole route to a destination is the SE's `publish` operation. An agent that holds its own push credentials or runs as the SE's OS user can bypass any tool-boundary gate. In out-of-process deployments (`python -m nlip_receipts.server` paired with `python -m nlip_receipts.mcp_stdio`), run the HTTP server under a separate OS user, container, or host that exclusively owns the SQLite ledger, `.hmac` key file, and destination write credentials; the server CLI refuses non-loopback plain-HTTP binds unless `--allow-non-loopback` is explicitly set behind a TLS proxy. The included Claude Code `PreToolUse` script (`hooks/claude_pretool_nlip.py`) is a fail-closed, deny-only cooperative harness guardrail (blocking accidental `Bash` `git push` / `gh pr merge` calls and edits to `.claude/`, `hooks/`, or `.git/config`, without consuming receipts or executing pushes inside `PreToolUse`), not a substitute for OS-level separation.

Defaults that this relies on:

- **`verify` runs in an OS sandbox.** The verification command imports code from the untrusted tree. It runs under `sandbox-exec` (macOS) or `bwrap` (Linux) so that this code cannot push to a destination, rewrite or read the ledger, or ask a host service (Docker, D-Bus, an SSH agent, launchd) to act for it:
  - no network access. On macOS Unix-socket connections are denied. On Linux the network namespace isolates abstract sockets and only read-only system directories, the interpreter prefix and the snapshot are mounted, so host sockets elsewhere (`/run`, home directories) are unreachable; a pathname socket inside one of the mounted read-only directories remains connectable;
  - no writes to the host filesystem outside the snapshot (Linux gives the process a private, empty `/tmp` and `/dev`; macOS allows writes only to the snapshot and `/dev/null`-style devices);
  - reads limited to system directories, the snapshot, and the interpreter's install prefix: on Linux nothing else is mounted, and on macOS reads under `/Users`, `/Volumes`, `/private/tmp` and `/private/var/folders` are denied, including metadata (so sandboxed code cannot test whether a file exists) except for the directories leading to allowed paths. The ledger's directory, source repositories and destinations stay hidden even if they sit inside an exposed system directory or interpreter prefix, under every alias that mounts them. An interpreter prefix that would expose a home directory or a top-level directory, or an interpreter or verify executable inside a protected path, is refused (`SANDBOX_UNAVAILABLE`); run the verify command from a dedicated interpreter or virtualenv. On Linux, a protected path that does not exist under an exposed directory is also refused, because its mask cannot be installed;
  - macOS only: Mach service lookups other than logging, notifications and user lookup are denied, and signals to processes outside the sandbox are refused. Linux runs the command in its own PID namespace, so anything it starts dies with it; on macOS a child that detaches with `setsid` can outlive the run, but it stays inside the sandbox.

  The sandbox is probed before every `verify`, and this run's exact sandbox configuration is started once with a no-op that only finds the verify executable. If either fails, `verify` is denied with `SANDBOX_UNAVAILABLE` and issues no receipt, instead of recording a failed run that would supersede an earlier pass. `Type3ReceiptExtension(verify_sandbox="off")` disables all of this and is safe only inside equivalent external isolation (a separate container or OS user). The isolation mode is bound into each receipt's `command_sha256`, so a receipt minted with the sandbox off cannot be spent at a gate that requires it, and opening a ledger created before this change advances every policy epoch, retiring receipts that were verified unsandboxed.
- **Callers must authenticate.** `ReceiptLedger(strict_caller_auth=True)` is the default: a caller with no registered secret (`register_caller_secret`) is denied. With `strict_caller_auth=False`, the `caller_id` is taken as asserted, so binding a receipt to its caller (Confused-Deputy protection) becomes advisory.
- **Publish targets are allowlisted.** A policy's `allowed_branches` (fnmatch globs, default `["main"]`) limits which branch `publish` may write in the destination. Branch names must be a single safe ref component; invalid names are refused before a single-use receipt is consumed.
- **The decision function fails closed.** `evaluate_type3_gate(caller_authenticated=...)` defaults to `False`; callers must pass the result of `ReceiptLedger.verify_caller_secret`.
- **Ledger file access.** The ledger file is created with mode `0600` (an existing ledger with group or world bits is tightened to `0600` on open, and refused if it is writable by others and cannot be) and must be writable only by the SE's OS user. The receipt HMAC prevents anyone without the key from minting or altering a receipt. It does not protect the `consumed` flag, policy rows, or the decision chain against deletion or rollback by someone who can write the file.

Known limitations:

- **A receipt attests that the policy command exited 0 over that exact tree, not that the code is correct.** The test command imports the code under test, so that code can control the exit status (for example, `os._exit(0)` at import), even when the test files themselves are pinned with `pinned_file_sha256`. Pins detect mismatches in the exported files before execution only. The snapshot remains writable, so tested code can weaken a pinned check before it is read; no post-run integrity check is performed. This is mutation inside the sandbox, not a sandbox escape or modification of the Git object selected for publication. Mitigations are outside this extension: a verifier whose result does not depend on the untrusted process's exit status, or human review of what is being published. `tests/test_verify_isolation.py::test_code_under_test_cannot_force_passing_exit` (forced exit) and `tests/test_pinned_file_runtime_limit.py` (pinned check rewritten inside the snapshot) record these as expected failures.
- **The decision log is hash-chained, not signed.** Someone with write access to the ledger can rewrite the whole chain consistently. Export it to an append-only store if tamper evidence is required.
- **Type-3 attests artifact verification, not Type-1 user-intent commit selection.** A valid unconsumed receipt for commit `C1` authorizes publishing `C1` under `(caller_id, repo_id, destination, profile_id, policy_epoch)`. It blocks replaying `C1`'s receipt onto a modified commit `C2` (`ARTIFACT_TREE_MISMATCH`), but if an agent holds an unconsumed receipt for `C1` and asks `publish` to ship `C1` when the user asked for `C2`, the Type-3 boundary allows `C1` (observed in 1 of 10 gated `receipt_reuse` trials in the 24 November run, and in 0 of 100 in the 27–28 November run). Preventing rollback or target substitution across already-verified commits requires binding the user's requested target OID at the Type-1 boundary or scoping policies/ephemeral profiles per release request.
