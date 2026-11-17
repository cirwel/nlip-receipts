"""Multi-harness adapters for Claude Code, Codex CLI, and Antigravity (AGY) over NLIP.

Demonstrates that the Type-3 Security Extension is completely framework- and harness-agnostic:
each adapter translates a harness-native tool invocation into a standard ECMA-430 `NLIP_Message`,
sends it through the NLIP Type-3 boundary (in-process by default, or any `transport` such as `POST /nlip/`),
and converts the structured `NLIP_Message` response back to the harness's native hook format.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from nlip_sdk.nlip import NLIP_Message

from .gate import Type3ReceiptExtension
from .schemas import (
    DECISION_LABEL,
    RECEIPT_LABEL,
    ToolCallProposal,
    Type3Decision,
    VerificationReceipt,
    pack_tool_call_message,
)


def extract_decision_from_response(
    rsp: NLIP_Message,
) -> tuple[Type3Decision, Optional[VerificationReceipt]]:
    """Extract `(Type3Decision, VerificationReceipt | None)` from an NLIP response message."""
    dec_dict: Optional[dict[str, Any]] = None
    rec_dict: Optional[dict[str, Any]] = None

    for sub in rsp.submessages or []:
        sub_fmt = str(getattr(sub.format, "value", sub.format)).lower()
        if sub_fmt == "structured":
            lbl = (sub.label or "").lower()
            body = json.loads(sub.content) if isinstance(sub.content, str) else dict(sub.content)
            if lbl == DECISION_LABEL:
                dec_dict = body
            elif lbl == RECEIPT_LABEL:
                rec_dict = body

    if dec_dict is None:
        raise ValueError("NLIP response did not contain a structured Type-3 decision submessage")

    return (
        Type3Decision(**dec_dict),
        VerificationReceipt(**rec_dict) if rec_dict is not None else None,
    )


class BaseHarnessAdapter:
    """Base adapter routing harness tool proposals through an NLIP Type-3 endpoint."""

    harness_name: str = "generic"

    def __init__(
        self,
        extension: Type3ReceiptExtension,
        auth_token: str,
        *,
        transport: Optional[Callable[[NLIP_Message], NLIP_Message]] = None,
    ):
        """`transport` sends an NLIP request and returns the response (e.g. an HTTP POST to
        `/nlip/`); by default the adapter calls the extension in-process."""
        self.extension = extension
        self.auth_token = auth_token
        self.transport = transport or extension.handle_nlip_message

    def send_nlip(
        self,
        proposal: ToolCallProposal,
        *,
        conversation_id: Optional[str] = None,
        text_summary: Optional[str] = None,
        forged_receipt: Optional[dict[str, Any]] = None,
    ) -> tuple[Type3Decision, Optional[VerificationReceipt], NLIP_Message]:
        req_msg = pack_tool_call_message(
            proposal,
            auth_token=self.auth_token,
            conversation_id=conversation_id,
            text_summary=text_summary,
            forged_receipt=forged_receipt,
        )
        rsp_msg = self.transport(req_msg)
        decision, receipt = extract_decision_from_response(rsp_msg)
        return decision, receipt, rsp_msg


class ClaudeCodePreToolAdapter(BaseHarnessAdapter):
    """Adapter for Claude Code's `PreToolUse` hook contract (`permissionDecision: allow|deny`)."""

    harness_name = "claude-code"

    def evaluate_pre_tool_use(self, hook_event: dict[str, Any]) -> dict[str, Any]:
        tool_input = hook_event.get("tool_input") or {}
        session_id = hook_event.get("session_id") or "claude-session"
        proposal = ToolCallProposal(
            operation=tool_input.get("operation", "publish"),
            repo_id=tool_input.get("repo_id", "default"),
            artifact_ref=tool_input.get("artifact_ref", "HEAD"),
            destination=tool_input.get("destination", "origin"),
            branch=tool_input.get("branch", "main"),
            profile_id=tool_input.get("profile_id", "default"),
            receipt_id=tool_input.get("receipt_id"),
        )
        decision, receipt, _rsp = self.send_nlip(
            proposal,
            conversation_id=session_id,
            text_summary=hook_event.get("assistant_message"),
            forged_receipt=tool_input.get("forged_receipt"),
        )
        return {
            "harness": self.harness_name,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow" if decision.action == "allow" else "deny",
                "permissionDecisionReason": decision.message,
            },
            "nlip_decision": decision.model_dump(),
            "nlip_receipt": receipt.model_dump(exclude={"hmac_tag"}) if receipt else None,
        }


class CodexExecToolAdapter(BaseHarnessAdapter):
    """Adapter for OpenAI Codex CLI (`codex exec --json`) tool-boundary mediation."""

    harness_name = "codex-cli"

    def evaluate_codex_tool_call(self, item_event: dict[str, Any]) -> dict[str, Any]:
        args = item_event.get("arguments") or {}
        thread_id = item_event.get("thread_id") or "codex-thread"
        proposal = ToolCallProposal(
            operation=args.get("operation", "publish"),
            repo_id=args.get("repo_id", "default"),
            artifact_ref=args.get("artifact_ref", "HEAD"),
            destination=args.get("destination", "origin"),
            branch=args.get("branch", "main"),
            profile_id=args.get("profile_id", "default"),
            receipt_id=args.get("receipt_id"),
        )
        decision, receipt, _rsp = self.send_nlip(
            proposal,
            conversation_id=thread_id,
            text_summary=item_event.get("agent_reasoning_summary"),
            forged_receipt=args.get("forged_receipt"),
        )
        return {
            "harness": self.harness_name,
            "type": "tool.execution.result",
            "allowed": decision.action == "allow",
            "reason_code": decision.reason_code,
            "message": decision.message,
            "receipt_id": receipt.receipt_id if receipt else decision.receipt_id,
            "published_ref": decision.published_ref,
        }


class AntigravityToolAdapter(BaseHarnessAdapter):
    """Adapter for Google Antigravity (`agy`) tool-boundary mediation."""

    harness_name = "antigravity"

    def evaluate_agy_tool_call(self, call_payload: dict[str, Any]) -> dict[str, Any]:
        params = call_payload.get("parameters") or {}
        conv_id = call_payload.get("conversation_id") or "agy-conv"
        proposal = ToolCallProposal(
            operation=params.get("operation", "publish"),
            repo_id=params.get("repo_id", "default"),
            artifact_ref=params.get("artifact_ref", "HEAD"),
            destination=params.get("destination", "origin"),
            branch=params.get("branch", "main"),
            profile_id=params.get("profile_id", "default"),
            receipt_id=params.get("receipt_id"),
        )
        decision, receipt, _rsp = self.send_nlip(
            proposal,
            conversation_id=conv_id,
            text_summary=call_payload.get("toolSummary"),
            forged_receipt=params.get("forged_receipt"),
        )
        return {
            "harness": self.harness_name,
            "status": "EXECUTED" if decision.action == "allow" else "BLOCKED_BY_NLIP_SE",
            "reason_code": decision.reason_code,
            "output": decision.message,
            "receipt_id": receipt.receipt_id if receipt else decision.receipt_id,
            "published_ref": decision.published_ref,
        }
