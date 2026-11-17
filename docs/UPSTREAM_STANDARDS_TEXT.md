# Upstream Standards & Repository Contributions (`nlip-project`)

This document provides drop-in normative text and reference interfaces from `nlip-receipts` ready for incorporation into:
1. **ECMA-434** (*Security Profiles for Natural Language Interaction Protocol (NLIP)*) — Proposed Clause **7.3.4 (Execution-Attested Side-Effect Gating)**
2. **NLIP-DMSC working draft `draft-natural-language-multiagent`** ([`nlip-project/item-draft-dmsc`](https://github.com/nlip-project/item-draft-dmsc); an editor's copy, not yet submitted to the IETF datatracker) — Completing the `# Security Considerations` (`TODO Security`) section
3. **`nlip-project/nlip_server`** — A proposed pluggable Security Extension hook. No such interface exists upstream yet; `nlip_receipts/server.py` integrates by supplying its own `NLIP_Session`/`SafeApplication`, which wraps the whole application rather than sitting in front of an existing one.

---

## 1. Proposed Addition to ECMA-434 (Clause 7.3.4)

```text
7.3.4  Runtime & Behaviour: Execution-Attested Side-Effect Gating

NLIP agents invoking external tools, model APIs, or downstream services that cause
persistent or irreversible state changes (such as publishing code, modifying access
controls, or executing financial or infrastructure transactions) should enforce
execution-attested precondition gating at the Type-3 tool boundary.

Specifically:
(i)   Natural-language claims in NLIP text submessages (e.g., an agent stating that
      verification checks succeeded) and unverified client-supplied structured
      submessages shall not be accepted as authorization evidence for side-effecting
      tool invocations.
(ii)  When a policy requires precondition verification prior to a side effect, the
      verification check shall be executed by a trusted supervisor over an immutable
      snapshot of the target artifact, and the resulting verification receipt shall
      be recorded in protected local state bound to the caller identity, target
      destination, verification profile, policy epoch, and immutable artifact digest.
(iii) Before executing the side-effecting operation, the Type-3 control point shall
      deterministically verify that the referenced receipt is authentic, unconsumed,
      unexpired, not superseded by a subsequent failed check, and matches the exact
      artifact digest being published or mutated.
```

---

## 2. Proposed `# Security Considerations` Section for the NLIP-DMSC Working Draft (`draft-natural-language-multiagent`)

In [`nlip-project/item-draft-dmsc/draft-natural-language-multiagent.md`](https://github.com/nlip-project/item-draft-dmsc), Section `# Security Considerations` is currently marked `TODO Security`. The following text directly addresses the security implications of the draft's `ntohs`/`htons` generative-AI translation model:

```markdown
# Security Considerations

Decoupling wire-level natural-language exchanges from endpoint-internal structured
representations—the application-layer analogue of `ntohs` and `htons`—introduces three
protocol-specific security risks when collaborating agents invoke side-effecting tools
or cross-domain services (such as Model Context Protocol (MCP) servers, code
repositories, or enterprise directories as described in ECMA TR/113):

1. **Asymmetric Trust in LLM-Translated Preconditions (Self-Report Fabrication):**
   While an AI model at a receiving endpoint can translate unstructured natural
   language into an internal structured tool call, natural-language claims regarding
   precondition satisfaction (for example, an upstream agent stating "all verification
   tests passed" or "compliance review completed") are susceptible to hallucination,
   reward hacking, and indirect prompt injection. Endpoints MUST NOT rely on
   natural-language assertions or unverified `structured` submessages to authorize
   irreversible or externally visible side effects. Instead, endpoints SHOULD enforce
   deterministic Type-3 Security Extensions (ECMA-434 Clause 7.3.2 / proposed Clause
   7.3.4) that require an opaque, cryptographically bound reference to a verification
   event recorded in trusted local state over the exact immutable artifact digest.

2. **Time-of-Check-to-Time-of-Use (TOCTOU) Drift Across Multi-Turn Exchanges:**
   In dynamic multi-agent collaboration, mutable workspace or repository state may
   change between a verification exchange and a subsequent publication or execution
   exchange. Implementations mediating side-effecting operations SHOULD bind
   verification receipts to content-addressed artifact digests (e.g., Git tree and
   commit object identifiers) verified inside isolated snapshots, and pin the
   downstream execution to that exact immutable identifier.

3. **In-Band Token Isolation and Confused-Deputy Prevention:**
   When collaborating agents exchange `token` submessages carrying `authentication`
   or `conversation` credentials (ECMA-430 Clause 6.2), passing raw credential
   submessages into the AI model's translation context exposes credentials to prompt
   injection and cross-agent token passthrough (Confused-Deputy attacks). Ingress
   control points MUST strip and validate `token` submessages prior to LLM
   translation, reject messages containing conflicting duplicate authentication
   tokens, and bind authorization receipts to the authenticated caller and target
   destination.
```

---

## 3. Upstream Pluggable Hook Interface for `nlip-project/nlip_server`

[`nlip_receipts/server.py`](../nlip_receipts/server.py) shows a Type-3 Security Extension hosted by a custom `nlip_server.NLIP_Session`. Because upstream has no pre/post-tool hook, it replaces the application's session rather than wrapping an existing `NLIP_Application`; a hook upstream would let it sit in front of existing applications. It also implements the ECMA-430 Clause 6.3 / ECMA TR/113 Clause 10 `control`-message policy disclosure handshake.
