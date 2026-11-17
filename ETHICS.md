# Ethical Compliance Statement (ECMA-434 Annex B)

This statement conforms to **ECMA-434 §7.1.3 (Agent Lifecycle: Ethical-by-Design)** and **Annex B.2 (Agent Security Profile 2)**, based on the *Ethics Guidelines for Trustworthy AI* (European Commission High-Level Expert Group on AI).

## 1. Transparency & Disclosure
- Users and peer agents are explicitly informed via NLIP `control` and `structured` submessages when interacting with an `nlip-receipts`-governed endpoint.
- **What the extension does:** Mediates side-effecting publication calls (`publish`) at the NLIP Type-3 tool boundary by requiring a trusted, content-bound verification receipt (`verify`) over the exact immutable Git tree digest.
- **What it does not do (Limitations):** A verification receipt proves that the configured verification suite executed and exited `0` on an isolated snapshot of the exact tree being published; it does *not* prove that the verification suite itself is complete, nor does it protect against a compromised host kernel or stolen server HMAC key.

## 2. User Control
- **Override / Off-switch:** Operators control the policy database (`ReceiptLedger`) outside the agent's write scope and can revoke policies (`ledger.revoke_policy`), rotate the policy epoch (`ledger.set_policy`), or disable a publication destination (`ledger.disable_destination`) at any time. Revocation is permanent for existing receipts: re-creating a revoked policy starts a new epoch.
- **Fail-closed default:** When verification evidence is missing, expired, mismatched, or superseded by a failed run, the Type-3 gate fails closed (`action="deny"`) and returns a structured remediation hint.

## 3. Privacy & Data Handling
- The Type-3 Security Extension stores only cryptographic content digests (`tree_oid`, `commit_oid`, `output_sha256`), exit codes, timestamps, caller identifiers, and NLIP conversation tokens in its local SQLite ledger.
- No personal data (PII) or model hidden reasoning traces are collected or transmitted. Receipts for a repository can be purged, and its policies revoked, at any time via `ledger.clear_repo(repo_id)`. The hash-chained decision log is retained for audit; it includes the NLIP conversation token of each request, which is client-supplied, so deployments should not place personal or session-identifying data in conversation tokens.

## 4. Fairness & Accessibility
- All Type-3 boundary decisions are deterministic functions of `(structured_call, ledger_state, policy)`, ensuring identical treatment across all agent frameworks, models (Claude, Codex, Antigravity, local models), and human clients.
- All denial reasons and audit records are emitted in both machine-readable JSON (`structured` submessage) and plain English (`text` submessage).

## 5. Safety & Robustness
- Verification runs execute inside isolated temporary snapshots exported from the immutable Git object store (`git archive`), preventing concurrent working-tree mutations (TOCTOU) from corrupting verification or publication.
- All Git subprocess invocations disable external hooks (`core.hooksPath=/dev/null`) and terminal prompts (`GIT_TERMINAL_PROMPT=0`).

## 6. Accountability
- Every verification execution and publication gate decision is logged with a unique `decision_id`, timestamp, caller identity, artifact digest, and ECMA-434 SCO reference.
