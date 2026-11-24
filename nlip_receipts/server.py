"""FastAPI NLIP Server integration (`nlip_server`) with Type-3 Security Extension support."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI
from nlip_sdk.nlip import AllowedFormats, NLIP_Message, NLIP_SubMessage, ReservedTokens
from nlip_server import server as nlip_srv

from .gate import Type3ReceiptExtension
from .ledger import ReceiptLedger
from .schemas import PolicyConfig, Type3Decision, pack_decision_message


class ReceiptNLIPSession(nlip_srv.NLIP_Session):
    """NLIP_Session that routes tool-boundary requests through `Type3ReceiptExtension`
    and answers ECMA-430 §5.1.1/§6.3 `control` messages with ECMA-434 profile metadata.
    """

    def __init__(self, extension: Type3ReceiptExtension):
        self.extension = extension
        self.set_correlator()

    async def execute(self, msg: NLIP_Message) -> NLIP_Message:
        # ECMA-430 §5.1.1 & §6.3: Control messages query endpoint policy and ECMA-434 profile
        if msg.is_control_msg():
            return NLIP_Message(
                messagetype=ReservedTokens.control,
                format=AllowedFormats.text,
                subformat="english",
                content=(
                    "NLIP Type-3 Security Extension active. Conforms to ECMA-430 and ECMA-434 "
                    "(SCOs 7.1.3, 7.2.2, 7.2.3, 7.2.4, 7.3.2, and proposed SCO 7.3.4)."
                ),
                submessages=[
                    NLIP_SubMessage(
                        format=AllowedFormats.structured,
                        subformat="json",
                        label="ecma434.profile",
                        content={
                            "standard": "ECMA-434:2025",
                            "extension_type": "Type-3 (Tool/Execution Boundary)",
                            "implemented_scos": [
                                "7.1.3",
                                "7.2.2",
                                "7.2.3",
                                "7.2.4",
                                "7.2.7",
                                "7.3.2",
                                "7.3.4-proposed",
                            ],
                            "issuer_id": self.extension.ledger.issuer_id(),
                            "ethical_disclosure": "ETHICS.md",
                            "security_disclosure": "SECURITY.md",
                        },
                    )
                ],
            )

        try:
            return self.extension.handle_nlip_message(msg)
        except ValueError as exc:
            decision = Type3Decision(
                action="deny",
                reason_code="MALFORMED_NLIP_TOOL_CALL",
                message=f"[NLIP-SE Type-3] Denied: {exc}",
                sco_refs=["ECMA-434:7.3.2"],
                operation="unknown",
                repo_id="unknown",
                caller_id="anonymous",
            )
            return pack_decision_message(decision)


class ReceiptNLIPApplication(nlip_srv. SafeApplication):
    """`nlip_server.SafeApplication` hosting the Type-3 Security Extension."""

    def __init__(self, extension: Type3ReceiptExtension):
        self.extension = extension

    def create_session(self) -> nlip_srv.NLIP_Session:
        return ReceiptNLIPSession(self.extension)


def create_nlip_receipt_server(extension: Type3ReceiptExtension) -> FastAPI:
    """Create a FastAPI app using `nlip_server.setup_server`."""
    client_app = ReceiptNLIPApplication(extension)
    client_app.session_list = []
    app = nlip_srv.setup_server(client_app)
    app.state.client_app = client_app
    return app


def load_or_create_hmac_key(key_path: Path | str) -> bytes:
    """Load or create an owner-only (`0600`) >=32-byte HMAC key so receipts survive restarts."""
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        key = secrets.token_bytes(32)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key

    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            if mode & 0o022:
                raise PermissionError(
                    f"HMAC key {path} is group/world-writable and could not be restricted"
                ) from exc
    key = path.read_bytes()
    if len(key) < 32:
        raise ValueError(f"HMAC key {path} must be at least 32 bytes (got {len(key)})")
    return key


def _policy_matches_desired(existing: PolicyConfig, desired: PolicyConfig) -> bool:
    return existing.model_dump(exclude={"policy_epoch"}) == desired.model_dump(
        exclude={"policy_epoch"}
    )


def build_extension_from_config(config_path: Path | str) -> Type3ReceiptExtension:
    """Construct a `Type3ReceiptExtension` from a JSON server configuration file.

    Unchanged policies preserve their active `policy_epoch` across restarts so previously issued
    receipts remain valid until TTL expiry; modified or newly created policies advance `policy_epoch`.
    """
    cfg_file = Path(config_path)
    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
    if not isinstance(cfg, dict):
        raise ValueError("server config must be a JSON object")

    inline_callers = cfg.get("callers") or {}
    if inline_callers:
        mode = cfg_file.stat().st_mode & 0o777
        if mode & 0o022:
            raise PermissionError(
                f"server config {cfg_file} contains inline caller secrets and must not be group/world-writable"
            )

    ledger_path = Path(cfg["ledger_path"])
    hmac_key_path = Path(cfg.get("hmac_key_path") or f"{ledger_path}.hmac")
    hmac_key = load_or_create_hmac_key(hmac_key_path)
    ledger = ReceiptLedger(
        ledger_path,
        hmac_key=hmac_key,
        strict_caller_auth=bool(cfg.get("strict_caller_auth", True)),
    )

    for caller_id, secret in inline_callers.items():
        if not secret:
            raise ValueError(f"empty secret for caller {caller_id!r}")
        ledger.register_caller_secret(str(caller_id), str(secret))

    for caller_id, env_name in (cfg.get("caller_secrets_env") or {}).items():
        secret = os.environ.get(str(env_name), "")
        if not secret:
            raise ValueError(
                f"environment variable {env_name!r} for caller {caller_id!r} is unset or empty"
            )
        ledger.register_caller_secret(str(caller_id), secret)

    for pol in cfg.get("policies") or []:
        desired = PolicyConfig(
            repo_id=pol["repo_id"],
            destination=pol["destination"],
            profile_id=pol.get("profile_id", "default"),
            command=list(pol["command"]),
            allowed_callers=list(pol.get("allowed_callers") or []),
            pinned_file_sha256=dict(pol.get("pinned_file_sha256") or {}),
            ttl_seconds=float(pol.get("ttl_seconds", 900.0)),
            single_use=bool(pol.get("single_use", True)),
            allow_tree_equivalent_commits=bool(pol.get("allow_tree_equivalent_commits", False)),
            allowed_branches=list(pol.get("allowed_branches") or ["main"]),
        )
        existing = ledger.get_policy(desired.repo_id, desired.destination, desired.profile_id)
        if existing is None or not _policy_matches_desired(existing, desired):
            ledger.set_policy(
                repo_id=desired.repo_id,
                destination=desired.destination,
                profile_id=desired.profile_id,
                command=desired.command,
                allowed_callers=desired.allowed_callers,
                pinned_file_sha256=desired.pinned_file_sha256,
                ttl_seconds=desired.ttl_seconds,
                single_use=desired.single_use,
                allow_tree_equivalent_commits=desired.allow_tree_equivalent_commits,
                allowed_branches=desired.allowed_branches,
            )

    return Type3ReceiptExtension(
        ledger=ledger,
        repos=dict(cfg.get("repos") or {}),
        destinations=dict(cfg.get("destinations") or {}),
        verify_sandbox=str(cfg.get("verify_sandbox", "required")),
    )


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the NLIP Type-3 Security Extension HTTP server (uvicorn)."
    )
    parser.add_argument("--config", type=Path, required=True, help="Path to server JSON config.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8765, help="Bind TCP port (default: 8765).")
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Explicitly allow binding plain HTTP to a non-loopback address (use behind TLS proxy only).",
    )
    parser.add_argument("--log-level", default="warning", help="Uvicorn log level.")
    args = parser.parse_args(argv)

    if not _is_loopback_host(args.host) and not args.allow_non_loopback:
        sys.stderr.write(
            f"Refusing to bind plain HTTP NLIP server to non-loopback host {args.host!r} without "
            "--allow-non-loopback (token submessages carry caller secrets).\n"
        )
        return 2

    import uvicorn

    ext = build_extension_from_config(args.config)
    app = create_nlip_receipt_server(ext)
    # Single worker: ReceiptLedger coordinates in-process threads + SQLite BEGIN IMMEDIATE.
    uvicorn.run(app, host=args.host, port=args.port, workers=1, log_level=args.log_level)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
