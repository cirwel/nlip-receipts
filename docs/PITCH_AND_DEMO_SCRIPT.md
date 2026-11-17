# NDSS SafeOSE '27 — 3.5-Minute Pitch & Demo Video Script (`nlip-receipts`)

**Target Duration:** 3 minutes 30 seconds  
**Focus Area:** Area 3 — Security Functions at Unified Control Points (Type-3 Security Extension)  
**Terminal Command to Run Live on Screen:** `make demo` and `make eval`

---

## [0:00 – 0:40] 1. The Problem: Why Prompt-Level Preconditions Fail at the Tool Boundary
- **Visual:** Show `paper/safeose27_report.pdf` title/abstract or `README.md` architecture summary.
- **Narration:**
  > "AI agents across Claude Code, Codex CLI, and Antigravity increasingly execute side-effecting tool calls—like `git push` or service deployment—over standardized protocols like NLIP (ECMA-430).
  > Today, operators rely on prompt instructions like *'run the test suite before publishing.'*
  > When we inspected the upstream `nlip-project` reference server (`nlip_server`), we found zero Type-3 tool-boundary hooks. And in a small live probe, when we paste a repository file into the prompt claiming the CI runner is offline or supplying a forged JSON receipt, both Qwen3-Coder and Gemma-4 emit the unverified `publish` call in all three tasks."

---

## [0:40 – 1:35] 2. Our Architecture: Execution-Attested Side-Effect Gating (`nlip-receipts`)
- **Visual:** Open `nlip_receipts/gate.py` (`evaluate_type3_gate`) and `nlip_receipts/git_artifact.py` (`run_verification_in_snapshot`, `push_immutable_commit`).
- **Narration:**
  > "We built `nlip-receipts`, a pluggable Type-3 Security Extension for `nlip_server` and `nlip_sdk` aligned with ECMA-434 §7.3.2 and §7.2.2, plus a proposed new SCO 7.3.4 (*Execution-Attested Side-Effect Gating*).
  > It mediates two typed operations carried in ECMA-430 `structured` submessages: `verify` and `publish`.
  > First, on `verify`, instead of running tests in a mutable working tree, the SE exports the exact immutable Git tree object via `git archive` into an isolated temporary directory and runs the policy-configured check vector with `shell=False` inside an OS sandbox—because the code being tested is itself untrusted, it gets no network, no host writes, and no view of the ledger or other repositories. Only the SE supervisor can write the resulting HMAC-SHA256 receipt to its SQLite ledger.
  > Second, on `publish`, `evaluate_type3_gate()` satisfies the Area 3 Fit Test mechanically: it decides in well under a millisecond with zero LLM calls, using only the structured NLIP proposal, the SE ledger state, and policy. When allowed, it pushes the exact verified commit SHA (`<commit_oid>:refs/heads/<branch>`), closing both mid-run and post-verification TOCTOU windows."

---

## [1:35 – 2:40] 3. Live End-to-End Demo (`make demo`)
- **Visual:** Run `make demo` in the terminal and walk through the 7 printed stages.
- **Narration:**
  > "Let's run `make demo`.
  > - **Step 1:** An ECMA-430 `control` message queries the server and receives our ECMA-434 Security Profile and SCO list.
  > - **Step 2:** An agent claims *'All unit tests passed locally'* and attaches a forged `structured` receipt submessage. The Type-3 gate denies it immediately with `FORGED_RECEIPT_SUBMESSAGE`.
  > - **Step 3:** `agent-claude` invokes Type-3 `verify` on commit `C1`. The sandboxed snapshot check passes in tens of milliseconds and issues an HMAC-bound receipt tied to `C1`'s tree digest, caller, and destination.
  > - **Step 4:** The agent modifies `ledger_calc.py` in commit `C2` and tries to publish `C2` reusing `C1`'s receipt. The gate blocks the TOCTOU swap with `ARTIFACT_TREE_MISMATCH`.
  > - **Step 5:** `agent-codex` tries to replay `agent-claude`'s receipt—blocked by Confused-Deputy protection (`CROSS_CALLER_REPLAY`).
  > - **Step 6 & 7:** Finally, our three harness adapters—Claude Code, OpenAI Codex CLI, and Google Antigravity—verify and publish their authorized commits, and every decision is recorded in a SHA-256 hash-chained audit table with its NLIP conversation token."

---

## [2:40 – 3:30] 4. Reproducible Evaluation & Ablations (`make eval`)
- **Visual:** Run `make eval` (under a minute) and highlight the two Markdown summary tables.
- **Narration:**
  > "Finally, `make eval` runs two harnesses. The end-to-end attack suite sends real NLIP messages, runs sandboxed verification and real `git push`es, and checks the destination repositories: all 16 attack scenarios are blocked—including the verified code trying to push, rewrite the ledger, or read host files from inside `verify`—and all 3 benign workflows complete.
  > The decision-function ablation then compares our gate against simulated baselines: prompt-only and stateless submessage filters block only 10% to 20% of attacks, and a session-level 'tests passed' flag blocks 30%. Removing tree, caller or destination-profile binding each reopens a specific attack class. Only the full gate blocks them all, with 0% false denials, in about 0.6 milliseconds and zero LLM calls."
