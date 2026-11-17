# Decision-Function Ablation (seeded ledger states, simulated baselines)

Calls `evaluate_type3_gate()` directly; see `eval/e2e_attacks.py` for the end-to-end suite. 104 distinct deterministic cases, each repeated to sample latency.

- **Repeats per case:** 20 (200 adversarial trials + 60 benign trials = 260 runs per system; 2080 total evaluations)
- **E2E Snapshot Verification (`git archive` + test runner):** p50 = `81.11 ms`, p95 = `90.94 ms`
- **E2E Commit-Pinned Publication (`evaluate_type3_gate` + `git push`):** p50 = `69.68 ms`, p95 = `74.55 ms`

## 1. Overall System Comparison & Ablations

| System / Baseline | Attack Block Rate (%) | Unauth. Publish (%) | Benign Completion (%) | False Denial (%) | Gate Decision p50 (ms) | Gate Decision p99 (ms) | LLM Calls |
|---|---:|---:|---:|---:|---:|---:|---:|
| `B0_no_gate` | **0.0%** (0/200) | 100.0% | **100.0%** (60/60) | 0.0% | 0.415 | 0.607 | 0 |
| `B1_prompt_only` | **10.0%** (20/200) | 90.0% | **100.0%** (60/60) | 0.0% | 0.433 | 0.718 | 0 |
| `B2_submessage_trust` | **20.0%** (40/200) | 80.0% | **100.0%** (60/60) | 0.0% | 0.442 | 0.874 | 0 |
| `B3_unbound_flag` | **30.0%** (60/200) | 70.0% | **100.0%** (60/60) | 0.0% | 0.496 | 1.027 | 0 |
| `Abl_no_tree_bind` | **80.0%** (160/200) | 20.0% | **100.0%** (60/60) | 0.0% | 0.555 | 1.270 | 0 |
| `Abl_no_caller_bind` | **90.0%** (180/200) | 10.0% | **100.0%** (60/60) | 0.0% | 0.572 | 1.430 | 0 |
| `Abl_no_profile_bind` | **90.0%** (180/200) | 10.0% | **100.0%** (60/60) | 0.0% | 0.585 | 1.459 | 0 |
| `S4_nlip_type3_gate` | **100.0%** (200/200) | 0.0% | **100.0%** (60/60) | 0.0% | 0.626 | 1.745 | 0 |

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
