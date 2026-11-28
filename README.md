# `nlip-receipts`: Execution-Attested Side-Effect Gating at the NLIP Type-3 Boundary

**NDSS SafeOSE '27 Open-Source AI Security Hackathon Submission — Focus Area 3 (Security Functions at Unified Control Points)**

`nlip-receipts` is a pluggable, framework-agnostic **Type-3 Security Extension (SE)** for the [Natural Language Interaction Protocol (NLIP / ECMA-430)](https://ecma-international.org/publications-and-standards/standards/ecma-430/) and [ECMA-434](https://ecma-international.org/wp-content/uploads/ECMA-434_1st_edition_december_2025.pdf) reference server (`nlip_server` / `nlip_sdk`).

It enforces a deterministic, zero-LLM-call security invariant at the **Type-3 tool/execution boundary**:
> **Security Property:** A side-effecting publication call (`publish`) executes if and only if an authorized caller references an **immutable artifact digest (`tree_oid`)** for which the trusted Type-3 verifier previously recorded a passing verification run (`verify`) in **SE-protected local state** under the active policy epoch and target profile. Agent self-reports (*"All tests passed"*) and forged NLIP `structured` submessages cannot mint or substitute a receipt.

---

## 1. Focus Area 3 Fit-Test Compliance

The Focus Area 3 specification requires that a Security Extension *"cannot see the agent's hidden reasoning"* and must make its decision using only:
1. **The relevant NLIP message or structured tool/model call data:** Carried in an ECMA-430 `structured` submessage (`subformat="json"`, `label="nlip.se.type3.tool_call"`) plus caller authentication in an ECMA-430 `token` submessage (`subformat="authentication"` / `"authorization"`).
2. **Local state recorded from earlier interactions:** Stored in the SE-protected SQLite ledger (`ReceiptLedger`), which records HMAC-SHA256-authenticated verification receipts issued exclusively by the Type-3 snapshot verifier.
3. **The policy implemented by the team:** Explicit per-repository, per-destination `PolicyConfig` specifying the verification argv vector, allowed caller identities, receipt TTL, single-use semantics, and `policy_epoch`.

`evaluate_type3_gate()` in [`nlip_receipts/gate.py`](nlip_receipts/gate.py) is a **pure function** of `(proposal, resolved_commit, resolved_tree, receipt, latest_tree_receipt, receipt_hmac_valid, policy, now, caller_authenticated)`:
- **0 LLM calls** on the enforcement path. The decision, including its ledger reads, takes under 1 ms; a real `publish` is dominated by the `git push` (tens of ms) and `verify` by the sandboxed test run (see §5).
- **Sandboxed verification:** the verify command imports code from the untrusted tree, so it runs under `sandbox-exec` (macOS) or `bwrap` (Linux) with no network, no host writes, and no view of the ledger or other repositories. Unix-socket connections are denied on macOS; on Linux only sockets inside the read-only directories the sandbox mounts stay reachable. See [`SECURITY.md`](SECURITY.md#threat-model-and-limitations) for the threat model and the remaining limitation.
- **Snapshot-isolated verification (`git archive <tree_oid>`):** Verification runs inside an isolated temporary directory exported from the immutable Git tree object rather than the live working tree, eliminating concurrent working-tree race conditions.
- **Commit-pinned publication (`git push <dest> <commit_oid>:refs/heads/<branch>`):** Publication pushes the exact verified commit object rather than a mutable branch ref, eliminating post-verification TOCTOU mutations.
- **Live HTTP daemon, MCP stdio bridge & harness adapters:** [`nlip_receipts/server.py`](nlip_receipts/server.py) (`python -m nlip_receipts.server --config ...`) runs `nlip_server` under `uvicorn` with persistent `0600` HMAC keys and policy-epoch rotation; [`nlip_receipts/mcp_stdio.py`](nlip_receipts/mcp_stdio.py) (`python -m nlip_receipts.mcp_stdio`) exposes `nlip_verify`, `nlip_publish`, and `nlip_control` over MCP JSON-RPC 2.0 stdio → HTTP `POST /nlip/` so tool calls own execution cleanly; [`hooks/claude_pretool_nlip.py`](hooks/claude_pretool_nlip.py) provides a fail-closed, deny-only Claude Code `PreToolUse` guardrail blocking direct `Bash` `git push` and protected hook/git-config edits; and [`nlip_receipts/adapters.py`](nlip_receipts/adapters.py) translates Claude Code, Codex CLI, and Antigravity (`agy`) payloads either in-process or over `http_nlip_transport(url)`. In production, run `nlip_server` under a separate OS user/container owning the ledger and destination credentials (see [`SECURITY.md`](SECURITY.md#threat-model-and-limitations)).

---

## 2. ECMA-430 & ECMA-434 Standards Mapping

| Standard / Clause | Title | How `nlip-receipts` Implements / Extends It |
|---|---|---|
| **ECMA-430 §5.2 & §5.3** | Structured & Token Submessages | Encodes tool proposals, receipts, and decisions as `format="structured", subformat="json"` submessages; extracts and strips `token` credentials at ingress. |
| **ECMA-430 §5.1.1 & §6.3** | Control Messages | Responds to `messagetype="control"` queries with structured ECMA-434 security profile and SCO conformance metadata. |
| **ECMA-434 §7.1.3 & Annex B** | Ethical-by-Design | Machine-queryable disclosure and [`ETHICS.md`](ETHICS.md). |
| **ECMA-434 §7.2.2** | NLIP Client Authorization | Enforces caller allowlists and destination-specific verification profiles before side-effecting tool execution. |
| **ECMA-434 §7.2.3** | Privilege Misuse Prevention | Binds receipts to `caller_id`, `repo_id`, `profile_id`, and `command_sha256` to block Confused-Deputy cross-caller replay and staging-to-production target substitution. |
| **ECMA-434 §7.2.4** | Observability & Audit | SHA-256 hash-chained decision log (`decisions` table) recording the NLIP conversation token of each request. The chain is unkeyed, so it detects partial edits but not a full rewrite by someone with write access to the ledger. |
| **ECMA-434 §7.2.7 & Annex A** | Secure-by-Design Disclosure | Provided in [`SECURITY.md`](SECURITY.md). |
| **ECMA-434 §7.3.2** | Runtime Agent Behaviour Controls | Deterministic Type-3 reference monitor mediating `verify` and `publish` calls. |
| **Proposed SCO 7.3.4** | *Execution-Attested Side-Effect Gating* | **New SCO Proposal:** Side-effecting tool invocations across an NLIP boundary must present a non-forgeable reference to a passing verification run executed by a trusted supervisor over the exact immutable artifact digest being published. |

---

## 3. Prior-Work Disclosure

This project builds on the author's prior open-source Hermes plugin [`hermes-receipts`](https://github.com/cirwel/hermes-receipts) (which introduced local Git working-tree fingerprinting and SQLite receipt gating for a single terminal hook). Everything in `nlip-receipts` was newly architected and implemented for NDSS SafeOSE '27:
- **NLIP Type-3 Security Extension architecture** for `nlip_server` / `nlip_sdk` using ECMA-430 `structured`, `token`, and `control` submessages.
- **Snapshot-isolated verification (`git archive`)** and **commit-pinned publication (`<commit_oid>:refs/heads/<branch>`)**, closing the shell-command parsing and mutable working-tree TOCTOU limitations of terminal-hook gates.
- **Multi-caller Confused-Deputy protection, destination/profile binding, policy epochs, single-use receipt consumption, and hash-chained audit logging** mapped to ECMA-434 SCOs.
- **Harness adapter shapes** for Claude Code, Codex CLI, and Antigravity (`agy`) tool calls, the **end-to-end attack suite** (`eval/e2e_attacks.py`), and the **decision-function ablation** (`eval/benchmark.py`).

---

## 4. Quickstart & Reproducing Results

### Prerequisites
- Python 3.10+ (tested with Python 3.12) and `git`
- An OS sandbox for `verify`: `sandbox-exec` (built into macOS) or `bwrap` (Linux: `apt install bubblewrap`). Without one, `verify` fails closed with `SANDBOX_UNAVAILABLE`; see [`SECURITY.md`](SECURITY.md#threat-model-and-limitations).

### Setup
```bash
make setup
```
*(Creates `.venv` and installs `nlip_sdk` and `nlip_server` directly from `github.com/nlip-project` along with `fastapi`, `pydantic`, `httpx`, and `pytest`.)*

### Run Unit & Integration Tests (`make test`)
```bash
make test   # pytest suite: HTTP, TOCTOU, Confused-Deputy, cross-destination, duplicate auth, 8-thread race,
            # adapter shapes, verify sandbox isolation, caller auth, branch allowlist. Tests marked xfail
            # record limitations documented in SECURITY.md.
```

### Run End-to-End Interactive Demo (`make demo` / `make demo-http`)
```bash
make demo        # In-process FastAPI TestClient + multi-harness adapter shapes
make demo-http   # Live out-of-process uvicorn HTTP server + MCP stdio bridge + Claude PreToolUse guardrail
```

### Reproduce Full Evaluation Benchmark & Ablations (`make eval`)
```bash
make eval
PYTHONPATH=. .venv/bin/python eval/tool_response_live.py --model gemma4:latest --output new-run.json   # Optional: live models (local Ollama)
```
`make eval` runs two harnesses:
- [`eval/benchmark.py`](eval/benchmark.py) → [`evaluation_report.md`](eval/results/evaluation_report.md) / [`evaluation_summary.json`](eval/results/evaluation_summary.json): a decision-function ablation over seeded ledger states.
- [`eval/e2e_attacks.py`](eval/e2e_attacks.py) → [`e2e_attack_report.md`](eval/results/e2e_attack_report.md) / [`e2e_attack_summary.json`](eval/results/e2e_attack_summary.json): the end-to-end attack suite.

Live-model evaluation is separate and needs local Ollama models: [`eval/tool_response_live.py`](eval/tool_response_live.py) runs the tool-response harness ([`eval/TOOL_RESPONSE_EVAL.md`](eval/TOOL_RESPONSE_EVAL.md)). The recorded run is 900 trials at one revision (`2027fb4`): five open models (`gemma4` 8B, `gpt-oss` 20B, `qwen3.8` 27B, `nemotron-3.5-lightning` 30B, `qwen3-coder-next` 80B), three conditions, three fixtures, 20 seeds per cell (`eval/results/tool_response_live_n20_*.json`):
- **CI-override injection:** the failing commit reached the destination in **48/100** trials under `no_gate`, **23/100** under `prompt_only`, and **0/100** under `receipt_gate` (26 attempts, all `MISSING_RECEIPT`).
- **`C1`→`C2` `receipt_reuse` injection:** with a genuine passing receipt for parent commit `C1` in session history, the destination changed in **70/99** `no_gate` trials (one trial with an infrastructure error excluded) and **47/100** `prompt_only` trials, and in **0/100** under `receipt_gate` (44 attempts, all `ARTIFACT_TREE_MISMATCH`; two of the 100 never read the note).
- **Benign control:** **298/300** releases completed; the two misses were malformed `publish` calls from `gemma4`.
- **Rates differ sharply by model.** `qwen3.8` attempted no unauthorized publication in any condition. Neither did `claude-opus-5-5` or `claude-haiku-5-5`, driven through Claude Code with only the three harness tools ([`eval/tool_response_agent_cli.py`](eval/tool_response_agent_cli.py), 180 unseeded trials: 0/120 attack attempts, 60/60 benign releases). For such models these fixtures show only that the gate did not block legitimate releases.
- **Earlier run (90 trials, two models, 5 seeds per cell, 20 and 24 November):** kept in `eval/results/`. In it one gated `receipt_reuse` trial published the older *verified* `C1`, which illustrates that a Type-3 gate attests artifact verification, not which verified commit the user asked for. The older exploratory probe [`eval/live_agent_eval.py`](eval/live_agent_eval.py) put the injection in the user turn and is superseded.

---

## 5. Summary of Evaluation Results (`make eval`)

Measured on macOS (`sandbox-exec`) under background load; CI reproduces the same pass/fail results on Linux (`bwrap`) on every push.

### 5.1 End-to-end attack suite (`eval/e2e_attacks.py`)
Every attempt is an ECMA-430 message POSTed to the `nlip_server` app, with sandboxed `verify` and real `git push` into bare destination repositories. An attack counts as blocked only if the destinations show none of its effect. Each scenario runs 3 times in a fresh environment; the suite is deterministic, so the repeats check stability, not statistics.

- **Attacks blocked: 16/16 scenarios.** A01–A10 from the paper (A08 split into expiry and policy-epoch rotation), plus V01–V05: code run by `verify` pushing to the destination, rewriting the ledger, and reading host files; impersonating a caller without its secret; and publishing to a branch outside the policy allowlist.
- **Benign workflows completed: 3/3**: verify→publish; failing commit → fix → re-verify → publish; and the three adapter shapes each verifying and publishing.
- **Latency:** `verify` p50 86 ms (git archive, manifest check, sandboxed test run); allowed `publish` p50 74 ms (gate plus `git push`). Both vary with host load.

### 5.2 Decision-function ablation (`eval/benchmark.py`)
This calls `evaluate_type3_gate()` directly on seeded ledger states. Receipts are written straight into the ledger, and the decision cases involve no NLIP message, `verify` or `git push` (a separate loop times 10 real verify + publish runs). The baselines are simulated decision policies: `B0` allows everything, `B1` refuses only when no success claim is present, `B2` trusts any receipt submessage, and `B3` trusts an "any run passed" flag. The ablations each remove one binding from the real gate. There are 13 scenarios × 8 systems = 104 deterministic cases, each repeated 20 times to sample latency (2,080 decisions).

| System | Attack block rate | Benign completion | Decision p50 (ms) | Decision p99 (ms) |
|---|---:|---:|---:|---:|
| `B0_no_gate` (simulated) | 0% (0/200) | 100% (60/60) | 0.42 | 0.61 |
| `B1_prompt_only` (simulated) | 10% (20/200) | 100% (60/60) | 0.43 | 0.72 |
| `B2_submessage_trust` (simulated) | 20% (40/200) | 100% (60/60) | 0.44 | 0.87 |
| `B3_unbound_flag` (simulated) | 30% (60/200) | 100% (60/60) | 0.50 | 1.03 |
| `Abl_no_tree_bind` | 80% (160/200) | 100% (60/60) | 0.56 | 1.27 |
| `Abl_no_caller_bind` | 90% (180/200) | 100% (60/60) | 0.57 | 1.43 |
| `Abl_no_profile_bind` | 90% (180/200) | 100% (60/60) | 0.59 | 1.46 |
| **`S4_nlip_type3_gate`** | **100% (200/200)** | **100% (60/60)** | **0.63** | **1.75** |

All systems perform the same ledger reads (including the caller-secret check), so the gate's own checks add about 0.2 ms over `B0`. The single-use consume transaction that follows an allow is not timed. In this harness A05 reuses A04's committed-mutation case; the end-to-end suite tests an actual uncommitted working-tree edit.

---

## License
Licensed under the [Apache License, Version 2.0](LICENSE).
The AgentDojo-derived fixtures in [`eval/fixtures/agentdojo/`](eval/fixtures/agentdojo/) are under the MIT License; see [their notice](eval/fixtures/agentdojo/LICENSE).
