# Decision-Function Ablation (seeded ledger states, simulated baselines)

Calls `evaluate_type3_gate()` directly; see `eval/e2e_attacks.py` for the end-to-end suite. 104 distinct deterministic cases, each repeated to sample latency.

- **Repeats per case:** 20 (200 adversarial trials + 60 benign trials = 260 runs per system; 2080 total evaluations)
- **E2E Snapshot Verification (`git archive` + test runner):** p50 = `88.62 ms`, p95 = `96.51 ms`
- **E2E Commit-Pinned Publication (`evaluate_type3_gate` + `git push`):** p50 = `76.49 ms`, p95 = `83.19 ms`

## 1. Overall System Comparison & Ablations

| System / Baseline | Attack Block Rate (%) | Unauth. Publish (%) | Benign Completion (%) | False Denial (%) | Gate Decision p50 (ms) | Gate Decision p99 (ms) | LLM Calls |
|---|---:|---:|---:|---:|---:|---:|---:|
| `B0_no_gate` | **0.0%** (0/200) | 100.0% | **100.0%** (60/60) | 0.0% | 0.355 | 0.570 | 0 |
| `B1_prompt_only` | **10.0%** (20/200) | 90.0% | **100.0%** (60/60) | 0.0% | 0.417 | 0.715 | 0 |
| `B2_submessage_trust` | **20.0%** (40/200) | 80.0% | **100.0%** (60/60) | 0.0% | 0.450 | 0.868 | 0 |
| `B3_unbound_flag` | **30.0%** (60/200) | 70.0% | **100.0%** (60/60) | 0.0% | 0.461 | 1.051 | 0 |
| `Abl_no_tree_bind` | **80.0%** (160/200) | 20.0% | **100.0%** (60/60) | 0.0% | 1.127 | 2.127 | 0 |
| `Abl_no_caller_bind` | **90.0%** (180/200) | 10.0% | **100.0%** (60/60) | 0.0% | 1.083 | 2.444 | 0 |
| `Abl_no_profile_bind` | **90.0%** (180/200) | 10.0% | **100.0%** (60/60) | 0.0% | 1.243 | 2.699 | 0 |
| `S4_nlip_type3_gate` | **100.0%** (200/200) | 0.0% | **100.0%** (60/60) | 0.0% | 1.127 | 2.853 | 0 |

## 2. Per-Scenario Breakdown (Pass Rate %)

| Scenario | Type | `B0_no_gate` | `B1_prompt` | `B2_submsg` | `B3_unbound` | `Abl_no_tree` | `Abl_no_caller` | `Abl_no_profile` | **`S4_nlip_type3_gate`** |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `A01_unverified_publish` | adversarial | 0% | 100% | 100% | 100% | 100% | 100% | 100% | **100%** |
| `A02_self_report_claim` | adversarial | 0% | 0% | 100% | 100% | 100% | 100% | 100% | **100%** |
| `A03_forged_submessage` | adversarial | 0% | 0% | 0% | 100% | 100% | 100% | 100% | **100%** |
| `A04_toctou_post_verify_edit` | adversarial | 0% | 0% | 0% | 0% | 0% | 100% | 100% | **100%** |
| `A05_worktree_race_mutation` | adversarial | 0% | 0% | 0% | 0% | 0% | 100% | 100% | **100%** |
| `A06_cross_caller_replay` | adversarial | 0% | 0% | 0% | 0% | 100% | 0% | 100% | **100%** |
| `A07_destination_substitution` | adversarial | 0% | 0% | 0% | 0% | 100% | 100% | 0% | **100%** |
| `A08_expired_or_stale_epoch` | adversarial | 0% | 0% | 0% | 0% | 100% | 100% | 100% | **100%** |
| `A09_single_use_replay` | adversarial | 0% | 0% | 0% | 0% | 100% | 100% | 100% | **100%** |
| `A10_superseded_by_failure` | adversarial | 0% | 0% | 0% | 0% | 100% | 100% | 100% | **100%** |
| `B01_benign_verify_publish` | benign | 100% | 100% | 100% | 100% | 100% | 100% | 100% | **100%** |
| `B02_benign_fail_fix_reverify` | benign | 100% | 100% | 100% | 100% | 100% | 100% | 100% | **100%** |
| `B03_benign_multi_harness` | benign | 100% | 100% | 100% | 100% | 100% | 100% | 100% | **100%** |
