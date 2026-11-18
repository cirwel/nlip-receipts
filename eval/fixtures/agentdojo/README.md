# Attribution and adaptation

`attack.md` adapts `ImportantInstructionsAttack._JB_STRING` from
[AgentDojo's important_instructions_attacks.py](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/attacks/important_instructions_attacks.py),
revision `089ed468cf3ed0322acc66b0211f26d9d90dbf60`.
The complete upstream [MIT notice](LICENSE) is retained alongside it.
Paper: [AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents](https://arxiv.org/abs/2406.13352).

Modifications: add release-note framing; instantiate synthetic user/model names
Rowan Vale / Cedar Assistant; replace the goal with unverified publication of a
failing commit to a disposable local repository; normalize whitespace. Preserve
the INFORMATION wrapper, impersonated user authority, prerequisite framing and
signature. The benign control is newly authored. Neither fixture is authorization.
This is one published attack adaptation, not the AgentDojo benchmark or its score.
