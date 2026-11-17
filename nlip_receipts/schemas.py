"""ECMA-430 / ECMA-434 schemas and NLIP message helpers for Type-3 receipt gating."""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal, Optional

from nlip_sdk.nlip import AllowedFormats, NLIP_Message, NLIP_SubMessage
from pydantic import BaseModel, Field

TOOL_CALL_LABEL = "nlip.se.type3.tool_call"
RECEIPT_LABEL = "nlip.se.type3.receipt"
DECISION_LABEL = "nlip.se.type3.decision"


class PolicyConfig(BaseModel):
    """Per-repository / per-destination verification policy stored in SE local state."""

    repo_id: str
    destination: str
    profile_id: str = "default"
    command: list[str]
    allowed_callers: list[str] = Field(default_factory=list)
    ttl_seconds: float = 900.0
    single_use: bool = True
    policy_epoch: int = 1


class ToolCallProposal(BaseModel):
    """Structured tool invocation crossing the NLIP Type-3 Security Extension boundary."""

    operation: Literal["verify", "publish", "status"]
    repo_id: str
    artifact_ref: str = "HEAD"
    destination: str = "origin"
    branch: str = "main"
    profile_id: str = "default"
    receipt_id: Optional[str] = None
    caller_id: str = "anonymous"
    agent_claimed_status: Optional[str] = None
    untrusted_receipt_submessage: Optional[dict[str, Any]] = None


class VerificationReceipt(BaseModel):
    """Trusted verification record stored in SE-protected local state."""

    receipt_id: str
    issuer_id: str
    caller_id: str
    repo_id: str
    destination: str = "origin"
    commit_oid: str
    tree_oid: str
    profile_id: str
    command_sha256: str
    env_fingerprint: str
    status: Literal["passed", "failed", "error"]
    exit_code: int
    duration_ms: float
    output_sha256: str
    policy_epoch: int
    issued_at: float
    expires_at: float
    consumed: bool = False
    hmac_tag: str = ""


class Type3Decision(BaseModel):
    """Structured enforcement decision produced by the Type-3 Security Extension."""

    decision_id: str = Field(default_factory=lambda: f"dec-{uuid.uuid4().hex[:12]}")
    action: Literal["allow", "deny"]
    reason_code: str
    message: str
    sco_refs: list[str]
    operation: str
    repo_id: str
    caller_id: str
    destination: str = ""
    commit_oid: str = ""
    tree_oid: str = ""
    receipt_id: Optional[str] = None
    policy_epoch: int = 0
    latency_ms: float = 0.0
    published_ref: Optional[str] = None


def extract_caller_identity(msg: NLIP_Message) -> tuple[str, NLIP_Message]:
    """Extract caller identity from ECMA-430 authentication/authorization token submessages
    and return a sanitized copy of the NLIP_Message with credential submessages stripped
    (ECMA-434 §7.2.1 / §7.2.3 / security_guidelines §3.3 & §3.5).

    Raises ValueError if multiple conflicting authentication/authorization token submessages
    are present (preventing token-pollution / parameter-spoofing attacks).
    """
    seen_callers: list[str] = []
    kept_submessages: list[NLIP_SubMessage] = []

    for sub in msg.submessages or []:
        fmt = str(getattr(sub.format, "value", sub.format)).lower()
        subfmt = (sub.subformat or "").lower()
        if fmt == "token" and (
            subfmt.startswith("authentication") or subfmt.startswith("authorization")
        ):
            parsed = "anonymous"
            if isinstance(sub.content, str) and sub.content.strip():
                raw = sub.content.strip()
                parsed = raw.split(":", 1)[0].strip() if ":" in raw else raw
            elif "_" in subfmt:
                parsed = subfmt.split("_", 1)[1].strip() or "anonymous"
            seen_callers.append(parsed)
            # Strip credential submessage so it is not forwarded to downstream tools/LLMs
            continue
        kept_submessages.append(sub)

    if len(set(seen_callers)) > 1:
        raise ValueError(
            f"Conflicting authentication token submessages in NLIP_Message: {seen_callers}"
        )
    caller_id = seen_callers[0] if seen_callers else "anonymous"

    sanitized = NLIP_Message(
        messagetype=msg.messagetype,
        format=msg.format,
        subformat=msg.subformat,
        content=msg.content,
        label=msg.label,
        submessages=kept_submessages or None,
    )
    return caller_id, sanitized


def pack_tool_call_message(
    proposal: ToolCallProposal,
    *,
    auth_token: Optional[str] = None,
    conversation_id: Optional[str] = None,
    text_summary: Optional[str] = None,
    forged_receipt: Optional[dict[str, Any]] = None,
) -> NLIP_Message:
    """Create a standards-conformant ECMA-430 NLIP_Message carrying a Type-3 tool call."""
    summary = text_summary or (
        f"NLIP Type-3 tool request: {proposal.operation} on {proposal.repo_id}@{proposal.artifact_ref}"
    )
    payload = proposal.model_dump(exclude={"caller_id", "untrusted_receipt_submessage"})
    msg = NLIP_Message(
        format=AllowedFormats.text,
        subformat="english",
        content=summary,
        submessages=[
            NLIP_SubMessage(
                format=AllowedFormats.structured,
                subformat="json",
                label=TOOL_CALL_LABEL,
                content=payload,
            )
        ],
    )
    if forged_receipt is not None:
        msg.add_submessage(
            NLIP_SubMessage(
                format=AllowedFormats.structured,
                subformat="json",
                label=RECEIPT_LABEL,
                content=forged_receipt,
            )
        )
    if auth_token:
        # Support ECMA-430 §6.2.2 authentication token subformat
        msg.add_submessage(
            NLIP_SubMessage(
                format=AllowedFormats.token,
                subformat="authorization",
                label="caller_auth",
                content=auth_token,
            )
        )
    if conversation_id:
        msg.add_conversation_token(conversation_id)
    return msg


def unpack_tool_call_message(msg: NLIP_Message) -> tuple[ToolCallProposal, NLIP_Message]:
    """Extract a ToolCallProposal and caller identity from an incoming NLIP_Message."""
    caller_id, sanitized = extract_caller_identity(msg)

    raw_call: Optional[dict[str, Any]] = None
    untrusted_receipt: Optional[dict[str, Any]] = None

    top_fmt = str(getattr(sanitized.format, "value", sanitized.format)).lower()
    if top_fmt == "structured" and (sanitized.label or "").lower() == TOOL_CALL_LABEL:
        raw_call = (
            json.loads(sanitized.content)
            if isinstance(sanitized.content, str)
            else dict(sanitized.content)
        )

    for sub in sanitized.submessages or []:
        sub_fmt = str(getattr(sub.format, "value", sub.format)).lower()
        if sub_fmt == "structured":
            lbl = (sub.label or "").lower()
            content_dict = (
                json.loads(sub.content) if isinstance(sub.content, str) else dict(sub.content)
            )
            if lbl == TOOL_CALL_LABEL and raw_call is None:
                raw_call = content_dict
            elif lbl == RECEIPT_LABEL:
                untrusted_receipt = content_dict

    if raw_call is None:
        raise ValueError(f"NLIP message missing structured submessage with label '{TOOL_CALL_LABEL}'")

    text_claim = sanitized.extract_text("english")
    raw_call["caller_id"] = caller_id
    if text_claim:
        raw_call.setdefault("agent_claimed_status", text_claim)
    if untrusted_receipt is not None:
        raw_call["untrusted_receipt_submessage"] = untrusted_receipt
        if not raw_call.get("receipt_id") and isinstance(untrusted_receipt.get("receipt_id"), str):
            raw_call["receipt_id"] = untrusted_receipt["receipt_id"]

    return ToolCallProposal(**raw_call), sanitized


def pack_decision_message(
    decision: Type3Decision,
    *,
    receipt: Optional[VerificationReceipt] = None,
    conversation_id: Optional[str] = None,
) -> NLIP_Message:
    """Pack a Type3Decision (and optional VerificationReceipt reference) into an NLIP_Message."""
    submessages = [
        NLIP_SubMessage(
            format=AllowedFormats.structured,
            subformat="json",
            label=DECISION_LABEL,
            content=decision.model_dump(),
        )
    ]
    if receipt is not None:
        # Expose non-sensitive receipt metadata; never expose internal HMAC secret
        submessages.append(
            NLIP_SubMessage(
                format=AllowedFormats.structured,
                subformat="json",
                label=RECEIPT_LABEL,
                content=receipt.model_dump(exclude={"hmac_tag"}),
            )
        )
    msg = NLIP_Message(
        format=AllowedFormats.text,
        subformat="english",
        content=decision.message,
        submessages=submessages,
    )
    if conversation_id:
        msg.add_conversation_token(conversation_id)
    return msg
