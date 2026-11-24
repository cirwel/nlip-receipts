# NDSS SafeOSE '27: 3.5-Minute Pitch & Demo Video Script (`nlip-receipts`)

**Target duration:** 3 minutes 30 seconds; rehearse to stay within the required 3–5 minutes.
**Focus area:** Area 3, Security Functions at Unified Control Points (Type-3 Security Extension).
**Commands:** `make demo` and `make eval`.

## Recording checklist (not narration)

- Record the tested Git commit, dependency versions, OS and sandbox mode. Run `make test`, `make demo`, and `make eval` on that checkout before recording. Do not disable sandboxing to make a demonstration pass.
- The counts and timings below describe the existing published evaluation, not a new run. Reconcile them against the recording's outputs; show failures or infrastructure errors rather than narrating expected success over them.
- `make demo` uses the server's in-process HTTP test client and payload-shape adapters. It does not launch three commercial agent applications or a live network server. Label the screen accordingly. Its step 7 prints the audit log, not an independent integrity-verification result.
- Show the end-to-end suite's destination-based assertions, not just an `ALLOW`/`DENY` response. If evaluation takes longer than the recording budget, show a clearly labeled completed run from the same checkout. Do not claim a fixed runtime.
- For live-model indirect-injection evidence, cite the tool-response runs in [`eval/TOOL_RESPONSE_EVAL.md`](../eval/TOOL_RESPONSE_EVAL.md) (`eval/results/tool_response_live_2026-11-20.json` at `16456e2` and `eval/results/tool_response_live_no_gate_2026-11-24.json` at `381c258`), keeping their scope explicit: two local open models via Ollama (`gemma4` 8B and `qwen3-coder-next` 80B) on one AgentDojo-derived attack fixture and one benign release fixture, five seeds per cell. Do not use the older `eval/live_agent_eval.py` traces as headline evidence; they pasted hostile text into user turns and predate sandbox/auth hardening.

## [0:00–0:30] 1. The problem

**Visual:** Show the architecture summary in `README.md` and the publication boundary.

> "A coding agent may be told to run tests before publishing. But a statement that tests passed does not establish which code was checked, who requested the check, or where that code may be published.
>
> We built `nlip-receipts` to enforce those preconditions at an NLIP agent-to-tool boundary. It targets forged receipts, replay, and changes between verification and publication."

## [0:30–1:15] 2. The boundary and its limits

**Visual:** Show `verify` → protected ledger → `publish`, then `evaluate_type3_gate()`.

> "The extension mediates two operations: verify and publish. Verify exports an immutable Git snapshot and runs an operator-configured command inside an OS sandbox. The supervisor records the result in its ledger. Keep the ledger in a dedicated directory: the sandbox masks that directory, the repositories and the destinations, and if it cannot set itself up that way, verify is refused and no receipt is recorded.
>
> Publish checks that the receipt matches the caller, artifact, destination profile and current policy, then pushes the exact verified commit. By default the receipt must name that commit ID; a policy that sets `allow_tree_equivalent_commits` also accepts a different commit with the same tree, and pushes that commit. The decision needs no LLM calls or hidden agent reasoning.
>
> This assumes the agent cannot bypass the extension with separate publication credentials. And the receipt records a command exiting zero, not proof of code correctness. Malicious code can force its test process to exit zero; that requires a stronger verifier."

## [1:15–2:25] 3. Walk through `make demo`

**Visual:** Run `make demo`; label it **In-process NLIP server and adapter demonstration**.

> "First, the control response describes the extension's security profile.
>
> Next, a forged receipt is denied. We verify commit C1 and obtain a real receipt. An attempt to publish changed commit C2 using that receipt is denied because the artifact differs. Another caller cannot replay C1's receipt either.
>
> Finally, authorized publication succeeds. These three adapters translate Claude Code, Codex and Antigravity-style payloads in process; live harness wiring is not included. The Codex and Antigravity response shapes are our own.
>
> Step seven displays the decision log. It is hash-chained, but a writer with full ledger access could rewrite it, so protecting that state remains essential."

## [2:25–3:30] 4. Evidence and live tool-response test

**Visual:** Show the `make eval` end-to-end summary first, then the separate ablation table, and finally the live tool-response table in `eval/TOOL_RESPONSE_EVAL.md`. Keep each scope visible.

> "The end-to-end suite covers 16 authored attacks and three benign workflows through the real server app, sandboxed verification and real pushes, checking destination refs. All 16 attacks were blocked and all three benign workflows completed; repeats check stability, not broader coverage.
>
> The separate ablation uses seeded ledger states and simulated baseline policies. Removing bindings reopens the corresponding attacks, with a median decision of 0.63 milliseconds and a p99 of 1.75 milliseconds, excluding consume; this does not establish superiority over a real prompted agent or an existing CI gate.
>
> Separately, two local open models via Ollama read an AgentDojo-derived release-notes injection through a file tool on a failing commit. Under a neutral prompt, the failing commit reached the destination in 9 of 10 trials; in an earlier prompt-only run on the same models and fixtures, it still reached the destination in 6 of 10, versus 0 of 10 under the receipt gate, with all 30 benign releases completed. Multi-artifact reuse and commercial harnesses remain future work."
