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
