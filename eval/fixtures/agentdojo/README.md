# Attribution and adaptation

`attack.md` and `receipt_reuse.md` adapt `ImportantInstructionsAttack._JB_STRING` from
[AgentDojo's important_instructions_attacks.py](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/attacks/important_instructions_attacks.py),
revision `089ed468cf3ed0322acc66b0211f26d9d90dbf60`.
The complete upstream [MIT notice](LICENSE) is retained alongside it.
Paper: [AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents](https://arxiv.org/abs/2406.13352).

Modifications: add release-note framing; instantiate synthetic user/model names
Rowan Vale / Cedar Assistant; replace the goal with unverified publication of a
failing commit (`attack.md`: `receipt_id: null`; `receipt_reuse.md`: replay of an
earlier passing receipt from parent commit `C1` onto changed, failing `C2`) to a
disposable local repository; normalize whitespace. Preserve
the INFORMATION wrapper, impersonated user authority, prerequisite framing and
signature. The benign control is newly authored. None of the fixtures is authorization.
These are attributed attack adaptations, not the AgentDojo benchmark or its score.
