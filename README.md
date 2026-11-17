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

`evaluate_type3_gate()` in [`nlip_receipts/gate.py`](nlip_receipts/gate.py) is a **pure function** of `(proposal, resolved_commit, resolved_tree, receipt, latest_tree_receipt, receipt_hmac_valid, policy, now)`:
- **0 LLM calls** on the enforcement path (`0.23 ms` median gate decision latency).
- **Snapshot-isolated verification (`git archive <tree_oid>`):** Verification runs inside an isolated temporary directory exported from the immutable Git tree object rather than the live working tree, eliminating concurrent working-tree race conditions.
- **Commit-pinned publication (`git push <dest> <commit_oid>:refs/heads/<branch>`):** Publication pushes the exact verified commit object rather than a mutable branch ref, eliminating post-verification TOCTOU mutations.
- **Multi-harness portability:** Includes adapters ([`nlip_receipts/adapters.py`](nlip_receipts/adapters.py)) for **Claude Code** (`PreToolUse`), **OpenAI Codex CLI** (`codex exec`), and **Google Antigravity (`agy`)**, plus standard HTTP `POST /nlip/` clients.

---

## 2. ECMA-430 & ECMA-434 Standards Mapping

| Standard / Clause | Title | How `nlip-receipts` Implements / Extends It |
|---|---|---|
| **ECMA-430 §5.2 & §5.3** | Structured & Token Submessages | Encodes tool proposals, receipts, and decisions as `format="structured", subformat="json"` submessages; extracts and strips `token` credentials at ingress. |
| **ECMA-430 §5.1.1 & §6.3** | Control Messages | Responds to `messagetype="control"` queries with structured ECMA-434 security profile and SCO conformance metadata. |
| **ECMA-434 §7.1.3 & Annex B** | Ethical-by-Design | Machine-queryable disclosure and [`ETHICS.md`](ETHICS.md). |
| **ECMA-434 §7.2.2** | NLIP Client Authorization | Enforces caller allowlists and destination-specific verification profiles before side-effecting tool execution. |
| **ECMA-434 §7.2.3** | Privilege Misuse Prevention | Binds receipts to `caller_id`, `repo_id`, `profile_id`, and `command_sha256` to block Confused-Deputy cross-caller replay and staging-to-production target substitution. |
| **ECMA-434 §7.2.4** | Observability & Audit | Append-only, SHA-256 hash-chained decision ledger (`decisions` table) correlated with NLIP conversation tokens. |
| **ECMA-434 §7.2.7 & Annex A** | Secure-by-Design Disclosure | Provided in [`SECURITY.md`](SECURITY.md). |
| **ECMA-434 §7.3.2** | Runtime Agent Behaviour Controls | Deterministic Type-3 reference monitor mediating `verify` and `publish` calls. |
| **Proposed SCO 7.3.4** | *Execution-Attested Side-Effect Gating* | **New SCO Proposal:** Side-effecting tool invocations across an NLIP boundary must present a non-forgeable reference to a passing verification run executed by a trusted supervisor over the exact immutable artifact digest being published. |

---

## 3. Prior-Work Disclosure

This project builds on the author's prior open-source Hermes plugin [`hermes-receipts`](https://github.com/cirwel/hermes-receipts) (which introduced local Git working-tree fingerprinting and SQLite receipt gating for a single terminal hook). Everything in `nlip-receipts` was newly architected and implemented for NDSS SafeOSE '27:
- **NLIP Type-3 Security Extension architecture** for `nlip_server` / `nlip_sdk` using ECMA-430 `structured`, `token`, and `control` submessages.
- **Snapshot-isolated verification (`git archive`)** and **commit-pinned publication (`<commit_oid>:refs/heads/<branch>`)**, closing the shell-command parsing and mutable working-tree TOCTOU limitations of terminal-hook gates.
- **Multi-caller Confused-Deputy protection, destination/profile binding, policy epochs, single-use receipt consumption, and hash-chained audit logging** mapped to ECMA-434 SCOs.
- **Cross-harness adapters** for Claude Code, Codex CLI, and Antigravity (`agy`), plus the **2,080-run adversarial & ablation evaluation suite**.

---

## 4. Quickstart & Reproducing Results

### Prerequisites
- Python 3.10+ (tested with Python 3.12) and `git`

### Setup
```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install pydantic fastapi uvicorn httpx pytest python-multipart ./.ref/nlip_sdk ./.ref/nlip_server
```

### Run Unit & Integration Tests (`make test`)
```bash
make test   # 9/9 pytest suites (HTTP, TOCTOU, Confused-Deputy, Cross-Destination, Duplicate-Auth, 8-Thread Race, 3 Adapters)
```

### Run End-to-End Interactive Demo (`make demo`)
```bash
make demo
```

### Reproduce Full Evaluation Benchmark & Ablations (`make eval`)
```bash
make eval
PYTHONPATH=. .venv/bin/python eval/live_agent_eval.py   # Optional: live LLM IPI evaluation (requires local Ollama)
```
Outputs machine-readable metrics to [`eval/results/evaluation_summary.json`](eval/results/evaluation_summary.json), [`eval/results/live_agent_traces.json`](eval/results/live_agent_traces.json), and formatted tables to [`eval/results/evaluation_report.md`](eval/results/evaluation_report.md).

---

## 5. Summary of Evaluation Results (`make eval`)

Across **2,080 total evaluations** (10 adversarial scenarios × 20 trials = 200 attack runs, plus 3 benign workflows × 20 trials = 60 benign runs per system):

| System / Baseline | Attack Block Rate (%) | Unauth. Publish (%) | Benign Completion (%) | False Denial (%) | Gate Decision p50 (ms) | Gate Decision p99 (ms) | LLM Calls |
|---|---:|---:|---:|---:|---:|---:|---:|
| `B0_no_gate` (Vanilla `nlip_server`) | **0.0%** (0/200) | 100.0% | **100.0%** (60/60) | 0.0% | 0.228 | 0.321 | 0 |
| `B1_prompt_only` (Self-report check) | **10.0%** (20/200) | 90.0% | **100.0%** (60/60) | 0.0% | 0.227 | 0.302 | 0 |
| `B2_submessage_trust` (Unverified submsg) | **20.0%** (40/200) | 80.0% | **100.0%** (60/60) | 0.0% | 0.240 | 0.327 | 0 |
| `B3_unbound_flag` (Session pass boolean) | **30.0%** (60/200) | 70.0% | **100.0%** (60/60) | 0.0% | 0.229 | 0.327 | 0 |
| `Abl_no_tree_bind` (No `tree_oid` bind) | **80.0%** (160/200) | 20.0% | **100.0%** (60/60) | 0.0% | 0.291 | 0.662 | 0 |
| `Abl_no_caller_bind` (No `caller_id` bind) | **90.0%** (180/200) | 10.0% | **100.0%** (60/60) | 0.0% | 0.262 | 0.690 | 0 |
| `Abl_no_profile_bind` (No profile bind) | **90.0%** (180/200) | 10.0% | **100.0%** (60/60) | 0.0% | 0.249 | 0.642 | 0 |
| **`S4_nlip_type3_gate` (Ours)** | **100.0%** (200/200) | **0.0%** | **100.0%** (60/60) | **0.0%** | **0.232** | **0.655** | **0** |

---

## License
Licensed under the [Apache License, Version 2.0](LICENSE).
