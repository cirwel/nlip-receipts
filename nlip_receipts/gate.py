"""NLIP Type-3 Security Extension: Pure Decision Engine & Enforcing Executor.

Satisfies the NDSS SafeOSE '27 Focus Area 3 Fit Test:
- The security decision (`evaluate_type3_gate`) is a pure, deterministic function of:
  (1) structured tool-call data visible at the NLIP Type-3 boundary (`ToolCallProposal`),
  (2) trusted verification state previously recorded by the SE (`VerificationReceipt`), and
  (3) explicit operator policy (`PolicyConfig`).
- Zero LLM calls, zero dependence on hidden reasoning, and zero trust in agent self-reports.
"""

from __future__ import annotations

import os
import time
from typing import Optional

from nlip_sdk.nlip import NLIP_Message

from .git_artifact import (
    ArtifactError,
    compute_env_fingerprint,
    push_immutable_commit,
    resolve_commit_and_tree,
    run_verification_in_snapshot,
)
from .ledger import ReceiptLedger
from .schemas import (
    PolicyConfig,
    ToolCallProposal,
    Type3Decision,
    VerificationReceipt,
    pack_decision_message,
    unpack_tool_call_message,
)


def evaluate_type3_gate(
    *,
    proposal: ToolCallProposal,
    resolved_commit: str,
    resolved_tree: str,
    receipt: Optional[VerificationReceipt],
    latest_tree_receipt: Optional[VerificationReceipt],
    receipt_hmac_valid: bool,
    policy: Optional[PolicyConfig],
    now: float,
) -> Type3Decision:
    """Pure boundary decision function for `publish` invocations at the Type-3 control point."""
    base_kwargs = {
        "operation": proposal.operation,
        "repo_id": proposal.repo_id,
        "caller_id": proposal.caller_id,
        "destination": proposal.destination,
        "commit_oid": resolved_commit,
        "tree_oid": resolved_tree,
        "receipt_id": proposal.receipt_id,
        "policy_epoch": policy.policy_epoch if policy else 0,
    }

    # 1. Fail closed if no policy governs this (repo, destination, profile)
    if policy is None:
        return Type3Decision(
            action="deny",
            reason_code="POLICY_NOT_FOUND",
            message=(
                f"[NLIP-SE Type-3] Denied publish: no verification policy configured for "
                f"repo='{proposal.repo_id}', destination='{proposal.destination}', profile='{proposal.profile_id}'."
            ),
            sco_refs=["ECMA-434:7.2.2", "ECMA-434:7.3.2"],
            **base_kwargs,
        )

    # 2. Enforce caller authorization (ECMA-434 §7.2.2)
    if policy.allowed_callers and proposal.caller_id not in policy.allowed_callers:
        return Type3Decision(
            action="deny",
            reason_code="CALLER_UNAUTHORIZED",
            message=(
                f"[NLIP-SE Type-3] Denied publish: caller '{proposal.caller_id}' is not authorized "
                f"for destination '{proposal.destination}'."
            ),
            sco_refs=["ECMA-434:7.2.1", "ECMA-434:7.2.2", "ECMA-434:7.2.3"],
            **base_kwargs,
        )

    # 3. Reject missing or unverified receipts (including forged submessages or self-reports)
    if not proposal.receipt_id or receipt is None:
        if proposal.untrusted_receipt_submessage is not None:
            return Type3Decision(
                action="deny",
                reason_code="FORGED_RECEIPT_SUBMESSAGE",
                message=(
                    "[NLIP-SE Type-3] Denied publish: incoming NLIP submessage contained an "
                    "untrusted/forged receipt not present in the SE ledger."
                ),
                sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
                **base_kwargs,
            )
        return Type3Decision(
            action="deny",
            reason_code="MISSING_RECEIPT",
            message=(
                "[NLIP-SE Type-3] Denied publish: no verification receipt provided. "
                "Agent self-reports cannot authorize publication; invoke Type-3 'verify' first."
            ),
            sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
            **base_kwargs,
        )

    # 4. Verify SE-held HMAC tag on stored receipt
    if not receipt_hmac_valid:
        return Type3Decision(
            action="deny",
            reason_code="RECEIPT_INTEGRITY_FAILED",
            message="[NLIP-SE Type-3] Denied publish: receipt HMAC integrity check failed.",
            sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
            **base_kwargs,
        )

    # 5. Prevent Confused-Deputy / cross-caller receipt theft (ECMA-434 §7.2.3)
    if receipt.caller_id != proposal.caller_id:
        return Type3Decision(
            action="deny",
            reason_code="CROSS_CALLER_REPLAY",
            message=(
                f"[NLIP-SE Type-3] Denied publish: receipt '{receipt.receipt_id}' was issued to "
                f"'{receipt.caller_id}', not '{proposal.caller_id}' (Confused-Deputy prevention)."
            ),
            sco_refs=["ECMA-434:7.2.3", "ECMA-434:7.3.2"],
            **base_kwargs,
        )

    # 6. Verify repository, profile, and command digest binding (blocks destination substitution)
    expected_cmd_sha, _ = compute_env_fingerprint(policy.command)
    if (
        receipt.repo_id != proposal.repo_id
        or receipt.profile_id != policy.profile_id
        or receipt.command_sha256 != expected_cmd_sha
    ):
        return Type3Decision(
            action="deny",
            reason_code="PROFILE_OR_REPO_MISMATCH",
            message=(
                f"[NLIP-SE Type-3] Denied publish: receipt '{receipt.receipt_id}' does not match "
                f"required verification profile '{policy.profile_id}' for destination '{proposal.destination}'."
            ),
            sco_refs=["ECMA-434:7.2.2", "ECMA-434:7.3.2", "ECMA-434:7.3.4"],
            **base_kwargs,
        )

    # 7. Verify policy epoch, TTL expiration, and single-use consumption
    if receipt.policy_epoch != policy.policy_epoch:
        return Type3Decision(
            action="deny",
            reason_code="POLICY_EPOCH_STALE",
            message=(
                f"[NLIP-SE Type-3] Denied publish: receipt epoch ({receipt.policy_epoch}) "
                f"predates current policy epoch ({policy.policy_epoch}). Re-run verification."
            ),
            sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
            **base_kwargs,
        )

    if now > receipt.expires_at:
        return Type3Decision(
            action="deny",
            reason_code="RECEIPT_EXPIRED",
            message=f"[NLIP-SE Type-3] Denied publish: receipt '{receipt.receipt_id}' has expired.",
            sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
            **base_kwargs,
        )

    if policy.single_use and receipt.consumed:
        return Type3Decision(
            action="deny",
            reason_code="RECEIPT_ALREADY_CONSUMED",
            message=f"[NLIP-SE Type-3] Denied publish: single-use receipt '{receipt.receipt_id}' was already consumed.",
            sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
            **base_kwargs,
        )

    # 8. Check verification outcome status
    if receipt.status != "passed" or receipt.exit_code != 0:
        return Type3Decision(
            action="deny",
            reason_code="VERIFICATION_FAILED",
            message=(
                f"[NLIP-SE Type-3] Denied publish: receipt '{receipt.receipt_id}' recorded "
                f"status='{receipt.status}' (exit_code={receipt.exit_code})."
            ),
            sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
            **base_kwargs,
        )

    # 9. Verify exact immutable Git tree digest match (blocks post-verification TOCTOU mutations)
    if receipt.tree_oid != resolved_tree:
        return Type3Decision(
            action="deny",
            reason_code="ARTIFACT_TREE_MISMATCH",
            message=(
                f"[NLIP-SE Type-3] Denied publish (TOCTOU blocked): candidate tree '{resolved_tree[:12]}' "
                f"differs from verified receipt tree '{receipt.tree_oid[:12]}'."
            ),
            sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
            **base_kwargs,
        )

    # 10. Enforce superseding-failure invariant: a newer failed run on the same tree invalidates older passes
    if (
        latest_tree_receipt is not None
        and latest_tree_receipt.receipt_id != receipt.receipt_id
        and latest_tree_receipt.issued_at >= receipt.issued_at
        and latest_tree_receipt.status != "passed"
    ):
        return Type3Decision(
            action="deny",
            reason_code="SUPERSEDED_BY_FAILURE",
            message=(
                f"[NLIP-SE Type-3] Denied publish: passing receipt '{receipt.receipt_id}' was superseded "
                f"by a subsequent failed run ('{latest_tree_receipt.receipt_id}') on the same tree."
            ),
            sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
            **base_kwargs,
        )

    return Type3Decision(
        action="allow",
        reason_code="VERIFIED_RECEIPT_VALID",
        message=(
            f"[NLIP-SE Type-3] Allowed publish of commit {resolved_commit[:12]} "
            f"(tree {resolved_tree[:12]}) to '{proposal.destination}' under receipt '{receipt.receipt_id}'."
        ),
        sco_refs=["ECMA-434:7.2.2", "ECMA-434:7.2.3", "ECMA-434:7.2.4", "ECMA-434:7.3.2", "ECMA-434:7.3.4"],
        **base_kwargs,
    )


class Type3ReceiptExtension:
    """Pluggable NLIP Type-3 Security Extension mediating `verify` and `publish` calls."""

    def __init__(
        self,
        ledger: ReceiptLedger,
        repos: dict[str, str],
        destinations: dict[str, str],
    ):
        """
        Args:
            ledger: SE-protected ReceiptLedger instance.
            repos: Mapping of logical `repo_id` -> local repository path.
            destinations: Mapping of logical `destination` -> server-controlled bare Git repo path.
        """
        self.ledger = ledger
        self.repos = {k: os.path.realpath(v) for k, v in repos.items()}
        self.destinations = {k: os.path.realpath(v) for k, v in destinations.items()}

    def handle_proposal(
        self, proposal: ToolCallProposal, *, now: Optional[float] = None
    ) -> tuple[Type3Decision, Optional[VerificationReceipt]]:
        t0 = time.perf_counter()
        current_time = now if now is not None else time.time()

        repo_path = self.repos.get(proposal.repo_id)
        if not repo_path:
            decision = Type3Decision(
                action="deny",
                reason_code="UNKNOWN_REPOSITORY",
                message=f"[NLIP-SE Type-3] Denied: unknown repository id '{proposal.repo_id}'.",
                sco_refs=["ECMA-434:7.2.2"],
                operation=proposal.operation,
                repo_id=proposal.repo_id,
                caller_id=proposal.caller_id,
                destination=proposal.destination,
                latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )
            self.ledger.record_decision(decision)
            return decision, None

        try:
            artifact = resolve_commit_and_tree(repo_path, proposal.artifact_ref)
        except ArtifactError as exc:
            decision = Type3Decision(
                action="deny",
                reason_code="INVALID_ARTIFACT_REF",
                message=f"[NLIP-SE Type-3] Denied: could not resolve artifact '{proposal.artifact_ref}': {exc}",
                sco_refs=["ECMA-434:7.3.2"],
                operation=proposal.operation,
                repo_id=proposal.repo_id,
                caller_id=proposal.caller_id,
                destination=proposal.destination,
                latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )
            self.ledger.record_decision(decision)
            return decision, None

        policy = self.ledger.get_policy(proposal.repo_id, proposal.destination, proposal.profile_id)

        if proposal.operation == "verify":
            if policy is None:
                decision = Type3Decision(
                    action="deny",
                    reason_code="POLICY_NOT_FOUND",
                    message=(
                        f"[NLIP-SE Type-3] Denied verify: no policy configured for "
                        f"repo='{proposal.repo_id}', destination='{proposal.destination}', profile='{proposal.profile_id}'."
                    ),
                    sco_refs=["ECMA-434:7.2.2"],
                    operation="verify",
                    repo_id=proposal.repo_id,
                    caller_id=proposal.caller_id,
                    destination=proposal.destination,
                    commit_oid=artifact.commit_oid,
                    tree_oid=artifact.tree_oid,
                    latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                )
                self.ledger.record_decision(decision)
                return decision, None

            if policy.allowed_callers and proposal.caller_id not in policy.allowed_callers:
                decision = Type3Decision(
                    action="deny",
                    reason_code="CALLER_UNAUTHORIZED",
                    message=f"[NLIP-SE Type-3] Denied verify: caller '{proposal.caller_id}' is not authorized.",
                    sco_refs=["ECMA-434:7.2.1", "ECMA-434:7.2.2"],
                    operation="verify",
                    repo_id=proposal.repo_id,
                    caller_id=proposal.caller_id,
                    destination=proposal.destination,
                    commit_oid=artifact.commit_oid,
                    tree_oid=artifact.tree_oid,
                    policy_epoch=policy.policy_epoch,
                    latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                )
                self.ledger.record_decision(decision)
                return decision, None

            exit_code, run_ms, out_sha, cmd_sha, env_fp = run_verification_in_snapshot(
                repo_path, artifact.tree_oid, policy.command
            )
            status = "passed" if exit_code == 0 else "failed"
            receipt = self.ledger.issue_receipt(
                caller_id=proposal.caller_id,
                repo_id=proposal.repo_id,
                commit_oid=artifact.commit_oid,
                tree_oid=artifact.tree_oid,
                profile_id=policy.profile_id,
                command_sha256=cmd_sha,
                env_fingerprint=env_fp,
                status=status,
                exit_code=exit_code,
                duration_ms=run_ms,
                output_sha256=out_sha,
                policy_epoch=policy.policy_epoch,
                ttl_seconds=policy.ttl_seconds,
                issued_at=current_time,
            )
            action = "allow" if status == "passed" else "deny"
            reason = "VERIFICATION_PASSED" if status == "passed" else "VERIFICATION_CHECK_FAILED"
            decision = Type3Decision(
                action=action,
                reason_code=reason,
                message=(
                    f"[NLIP-SE Type-3] Verification {status} (exit={exit_code}) on isolated snapshot "
                    f"of tree {artifact.tree_oid[:12]}; receipt='{receipt.receipt_id}'."
                ),
                sco_refs=["ECMA-434:7.2.4", "ECMA-434:7.3.2", "ECMA-434:7.3.4"],
                operation="verify",
                repo_id=proposal.repo_id,
                caller_id=proposal.caller_id,
                destination=proposal.destination,
                commit_oid=artifact.commit_oid,
                tree_oid=artifact.tree_oid,
                receipt_id=receipt.receipt_id,
                policy_epoch=policy.policy_epoch,
                latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )
            self.ledger.record_decision(decision)
            return decision, receipt

        # Operation == "publish"
        stored_receipt = self.ledger.get_receipt(proposal.receipt_id) if proposal.receipt_id else None
        hmac_valid = self.ledger.verify_receipt_hmac(stored_receipt) if stored_receipt else False
        latest_tree_rec = self.ledger.latest_receipt_for_tree(
            proposal.repo_id, artifact.tree_oid, proposal.profile_id
        )

        decision = evaluate_type3_gate(
            proposal=proposal,
            resolved_commit=artifact.commit_oid,
            resolved_tree=artifact.tree_oid,
            receipt=stored_receipt,
            latest_tree_receipt=latest_tree_rec,
            receipt_hmac_valid=hmac_valid,
            policy=policy,
            now=current_time,
        )

        if decision.action == "allow" and stored_receipt is not None and policy is not None:
            dest_path = self.destinations.get(proposal.destination)
            if not dest_path:
                decision = Type3Decision(
                    action="deny",
                    reason_code="UNKNOWN_DESTINATION",
                    message=f"[NLIP-SE Type-3] Denied publish: unknown destination '{proposal.destination}'.",
                    sco_refs=["ECMA-434:7.2.2"],
                    operation="publish",
                    repo_id=proposal.repo_id,
                    caller_id=proposal.caller_id,
                    destination=proposal.destination,
                    commit_oid=artifact.commit_oid,
                    tree_oid=artifact.tree_oid,
                    receipt_id=stored_receipt.receipt_id,
                    policy_epoch=policy.policy_epoch,
                )
            else:
                if policy.single_use and not self.ledger.mark_consumed(stored_receipt.receipt_id):
                    decision = Type3Decision(
                        action="deny",
                        reason_code="RECEIPT_ALREADY_CONSUMED",
                        message=f"[NLIP-SE Type-3] Denied publish: receipt '{stored_receipt.receipt_id}' already consumed.",
                        sco_refs=["ECMA-434:7.3.2", "ECMA-434:7.3.4"],
                        operation="publish",
                        repo_id=proposal.repo_id,
                        caller_id=proposal.caller_id,
                        destination=proposal.destination,
                        commit_oid=artifact.commit_oid,
                        tree_oid=artifact.tree_oid,
                        receipt_id=stored_receipt.receipt_id,
                        policy_epoch=policy.policy_epoch,
                    )
                else:
                    published_ref = push_immutable_commit(
                        repo_path,
                        artifact.commit_oid,
                        dest_path,
                        branch=proposal.branch,
                    )
                    decision.published_ref = published_ref

        decision.latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        self.ledger.record_decision(decision)
        return decision, stored_receipt

    def handle_nlip_message(self, msg: NLIP_Message, *, now: Optional[float] = None) -> NLIP_Message:
        """Process an ECMA-430 NLIP_Message at the Type-3 control point and return an NLIP_Message."""
        conv_token = msg.extract_conversation_token()
        proposal, _sanitized = unpack_tool_call_message(msg)
        decision, receipt = self.handle_proposal(proposal, now=now)
        return pack_decision_message(decision, receipt=receipt, conversation_id=conv_token)
