"""Minimal MCP JSON-RPC 2.0 stdio server bridging harness tool calls to an HTTP `nlip_server`.

Execution of `verify` and `publish` belongs here (at the tool invocation itself) rather than in a
`PreToolUse` hook, so single-use receipts and commit-pinned pushes never run before the harness
finishes permission resolution. Pair with `hooks/claude_pretool_nlip.py` as a fail-closed,
deny-only `PreToolUse` guardrail against direct `git push` or hook-configuration edits.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, BinaryIO, Optional

from nlip_sdk.nlip import AllowedFormats, NLIP_Message, ReservedTokens

from .adapters import NLIPTransportError, extract_decision_from_response, http_nlip_transport
from .schemas import ToolCallProposal, pack_tool_call_message

MCP_PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_MCP_VERSIONS = ("2024-11-05", "2025-03-26")

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "nlip_verify",
        "description": (
            "Run the operator-configured verification check in an isolated snapshot via the NLIP "
            "Type-3 Security Extension and return an HMAC-authenticated receipt ID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_id": {"type": "string", "description": "Configured repository identifier."},
                "artifact_ref": {
                    "type": "string",
                    "description": "Commit OID or ref to verify in an exported git snapshot.",
                },
                "destination": {
                    "type": "string",
                    "description": "Configured destination name (e.g. 'staging').",
                },
                "branch": {
                    "type": "string",
                    "description": "Target destination branch (default: 'main').",
                },
                "profile_id": {
                    "type": "string",
                    "description": "Verification profile identifier (default: 'default').",
                },
            },
            "required": ["repo_id", "artifact_ref", "destination"],
            "additionalProperties": False,
        },
    },
    {
        "name": "nlip_publish",
        "description": (
            "Publish an exact verified commit to a configured destination via the NLIP Type-3 "
            "Security Extension, presenting a passing single-use verification receipt."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_id": {"type": "string", "description": "Configured repository identifier."},
                "artifact_ref": {
                    "type": "string",
                    "description": "Exact commit OID to publish.",
                },
                "destination": {
                    "type": "string",
                    "description": "Configured destination name (e.g. 'staging').",
                },
                "branch": {
                    "type": "string",
                    "description": "Destination branch (default: 'main').",
                },
                "profile_id": {
                    "type": "string",
                    "description": "Verification profile identifier (default: 'default').",
                },
                "receipt_id": {
                    "type": ["string", "null"],
                    "description": "Verification receipt ID previously returned by nlip_verify.",
                },
            },
            "required": ["repo_id", "artifact_ref", "destination"],
            "additionalProperties": False,
        },
    },
    {
        "name": "nlip_control",
        "description": "Query the NLIP Type-3 endpoint's ECMA-434 security profile and active SCOs.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]


def _tool_result(payload: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
        "isError": is_error,
    }


def dispatch_tool_call(
    name: str,
    arguments: dict[str, Any],
    *,
    transport: Any,
    auth_token: str,
) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        return _tool_result({"error": "arguments must be a JSON object"}, is_error=True)

    try:
        if name == "nlip_control":
            ctrl = NLIP_Message(
                messagetype=ReservedTokens.control,
                format=AllowedFormats.text,
                subformat="english",
                content="Query endpoint ECMA-434 security profile",
            )
            rsp = transport(ctrl)
            structured = []
            for sub in rsp.submessages or []:
                content = (
                    json.loads(sub.content) if isinstance(sub.content, str) else dict(sub.content)
                )
                structured.append({"label": sub.label, "content": content})
            return _tool_result({"content": rsp.content, "submessages": structured}, is_error=False)

        if name not in ("nlip_verify", "nlip_publish"):
            return _tool_result({"error": f"unknown tool {name!r}"}, is_error=True)

        missing = [k for k in ("repo_id", "artifact_ref", "destination") if not arguments.get(k)]
        if missing:
            return _tool_result(
                {"error": f"missing required arguments: {', '.join(missing)}"}, is_error=True
            )

        operation = "verify" if name == "nlip_verify" else "publish"
        proposal = ToolCallProposal(
            operation=operation,
            repo_id=str(arguments["repo_id"]),
            artifact_ref=str(arguments["artifact_ref"]),
            destination=str(arguments["destination"]),
            branch=str(arguments.get("branch") or "main"),
            profile_id=str(arguments.get("profile_id") or "default"),
            receipt_id=arguments.get("receipt_id"),
        )
        req = pack_tool_call_message(proposal, auth_token=auth_token)
        rsp = transport(req)
        decision, receipt = extract_decision_from_response(rsp)
        body: dict[str, Any] = {
            "decision": decision.model_dump(),
            "receipt": receipt.model_dump(exclude={"hmac_tag"}) if receipt else None,
        }
        return _tool_result(body, is_error=(decision.action != "allow"))
    except NLIPTransportError as exc:
        return _tool_result({"transport_error": str(exc)}, is_error=True)
    except Exception as exc:
        return _tool_result({"error": f"{type(exc).__name__}: {exc}"}, is_error=True)


def handle_jsonrpc_message(
    req: dict[str, Any],
    *,
    transport: Any,
    auth_token: str,
) -> Optional[dict[str, Any]]:
    method = req.get("method")
    req_id = req.get("id")

    # Notifications carry no id and expect no JSON-RPC response.
    if req_id is None and isinstance(method, str) and method.startswith("notifications/"):
        return None

    if not isinstance(method, str):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid JSON-RPC request"},
        }

    params = req.get("params") or {}
    if method == "initialize":
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        negotiated = requested if requested in SUPPORTED_MCP_VERSIONS else MCP_PROTOCOL_VERSION
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "nlip-receipts-mcp", "version": "0.1.0"},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}
    if method == "tools/call":
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "tools/call requires string name"},
            }
        result = dispatch_tool_call(
            params["name"],
            params.get("arguments") or {},
            transport=transport,
            auth_token=auth_token,
        )
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def _iter_stdio_messages(stream: BinaryIO):
    """Yield `(message_dict_or_error, framed_bool)` supporting both line-delimited JSON-RPC (MCP
    stdio standard) and `Content-Length:` framed JSON-RPC."""
    while True:
        line = stream.readline()
        if not line:
            return
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(b"content-length:"):
            try:
                length = int(stripped.split(b":", 1)[1].strip())
            except ValueError:
                yield None, True
                continue
            while True:
                hdr = stream.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            raw = stream.read(length)
            if not raw:
                return
            try:
                yield json.loads(raw.decode("utf-8")), True
            except ValueError:
                yield None, True
        else:
            try:
                yield json.loads(stripped.decode("utf-8")), False
            except ValueError:
                yield None, False


def _write_stdio_message(stream: BinaryIO, payload: dict[str, Any], *, framed: bool) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if framed:
        stream.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded)
    else:
        stream.write(encoded + b"\n")
    stream.flush()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--server-url",
        default=os.environ.get("NLIP_SERVER_URL", "http://127.0.0.1:8765"),
        help="Base URL of the NLIP Type-3 server (default: $NLIP_SERVER_URL or http://127.0.0.1:8765)",
    )
    parser.add_argument(
        "--token-env",
        default="NLIP_CALLER_TOKEN",
        help="Environment variable holding '<caller_id>:<secret>' (default: NLIP_CALLER_TOKEN)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP timeout in seconds (default: 30.0)",
    )
    args = parser.parse_args(argv)
    auth_token = os.environ.get(args.token_env, "")
    if not auth_token:
        sys.stderr.write(
            f"nlip-receipts-mcp: environment variable {args.token_env} must be set\n"
        )
        return 2

    transport = http_nlip_transport(args.server_url, timeout=args.timeout)
    for msg, framed in _iter_stdio_messages(sys.stdin.buffer):
        if not isinstance(msg, dict):
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            _write_stdio_message(sys.stdout.buffer, err, framed=framed)
            continue
        rsp = handle_jsonrpc_message(msg, transport=transport, auth_token=auth_token)
        if rsp is not None:
            _write_stdio_message(sys.stdout.buffer, rsp, framed=framed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
