# NDSS SafeOSE '27: 3.5-Minute Pitch & Demo Video Script (`nlip-receipts`)

**Target duration:** 3 minutes 30 seconds; rehearse to stay within the required 3–5 minutes.
**Focus area:** Area 3, Security Functions at Unified Control Points (Type-3 Security Extension).
**Commands:** `make demo-http` (or `make demo`) and `make eval`.

## Recording checklist (not narration)

- Record the tested Git commit, dependency versions, OS and sandbox mode. Run `make test`, `make demo-http`, and `make eval` on that checkout before recording. Do not disable sandboxing to make a demonstration pass.
- The counts and timings below describe the existing published evaluation, not a new run. Reconcile them against the recording's outputs; show failures or infrastructure errors rather than narrating expected success over them.
- `make demo-http` starts a real local `uvicorn` `nlip_server` subprocess, runs the fail-closed Claude Code `PreToolUse` guardrail hook (`hooks/claude_pretool_nlip.py`) on a sample `Bash` `git push` payload, drives `nlip_verify` and `nlip_publish` through the MCP JSON-RPC stdio bridge (`nlip_receipts.mcp_stdio`) over HTTP `POST /nlip/`, and exercises the three harness adapters over `http_nlip_transport` (`make demo` runs the fast in-process `TestClient` variant). It does not launch commercial agent GUIs; label the screen accordingly, and note that production isolation requires running `nlip_server` under a separate OS user or container. Step 7 prints the hash-chained audit log, not an external signature check.
- Show the end-to-end suite's destination-based assertions, not just an `ALLOW`/`DENY` response. If evaluation takes longer than the recording budget, show a clearly labeled completed run from the same checkout. Do not claim a fixed runtime.
- For live-model indirect-injection evidence, cite the 90 recorded tool-response trials in [`eval/TOOL_RESPONSE_EVAL.md`](../eval/TOOL_RESPONSE_EVAL.md) (`tool_response_live_2026-11-20.json` at `16456e2`, `tool_response_live_no_gate_2026-11-24.json` at `381c258`, and the same-revision `receipt_reuse` run `tool_response_live_receipt_reuse_2026-11-24.json` at `c6ff2f5`), keeping their scope explicit: two local open models via Ollama (`gemma4` 8B and `qwen3-coder-next` 80B), five seeds per cell. Do not use the older `eval/live_agent_eval.py` traces as headline evidence; they pasted hostile text into user turns and predate sandbox/auth hardening.

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

## [1:15–2:25] 3. Walk through `make demo-http`

**Visual:** Run `make demo-http`; label it **Live local HTTP NLIP server, MCP stdio bridge, and PreToolUse guardrail**.

> "First, over live HTTP, the control response describes the extension's ECMA-434 security profile.
>
> Next, a forged receipt submessage is denied. We verify commit C1 in a sandboxed snapshot and obtain a real receipt. Attempting to publish modified commit C2 with C1's receipt is denied on tree mismatch, and another caller cannot replay C1's receipt.
>
> Step 5b shows harness wiring: a fail-closed Claude Code `PreToolUse` guardrail blocks direct `git push` from Bash without consuming receipts, while `nlip_verify` and `nlip_publish` run over MCP JSON-RPC stdio to the HTTP server. Step six exercises the Claude Code, Codex and Antigravity adapters over HTTP. In production, the server and destination credentials must run under a separate OS user or container.
>
> Step seven prints the hash-chained decision log, which detects partial edits so long as ledger write access stays confined to the supervisor."

## [2:25–3:30] 4. Evidence and live tool-response tests

**Visual:** Show the `make eval` end-to-end summary first, then the ablation table, and finally the two live tool-response tables in `eval/TOOL_RESPONSE_EVAL.md`. Keep each scope visible.

> "The end-to-end suite blocks all 16 authored attacks and completes three benign workflows through the server app, sandboxed verification and real pushes, checking destination refs.
>
> The separate ablation uses seeded ledger states and simulated baseline policies: removing bindings reopens the corresponding attacks, at a 0.63-millisecond median decision excluding consume; this does not establish superiority over a real prompted agent or CI gate.
>
> Across 900 live Ollama trials at one revision, five open models from 8B to 80B read AgentDojo-derived release-note injections through a file tool. A CI-override injection pushed a failing commit in 48 of 100 neutral-prompt runs and 23 of 100 prompt-only runs, versus 0 of 100 under the receipt gate. On a C1-to-C2 receipt-reuse injection the destination changed in 70 of 99 neutral runs and 47 of 100 prompt-only runs, versus 0 of 100 under the gate, which denied all 44 replay attempts with a tree mismatch. 298 of 300 benign releases completed. Rates differ sharply by model: one open model and two hosted Claude models attempted no unauthorized publication at all."
