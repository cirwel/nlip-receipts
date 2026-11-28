"""Minimal MCP stdio server used by `tool_response_agent_cli.py`.

It exposes the harness's three tools to an agent CLI and executes nothing itself: every
`tools/call` is forwarded over a local Unix socket to the trial runner, which validates and
executes it exactly as for any other model, and the runner's result is returned verbatim.
"""
from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tool_response_live import tool_schemas  # noqa: E402
from tool_response_eval import TOOLS  # noqa: E402


def forward(name: str, arguments) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(os.environ["CEDAR_SOCK"])
        s.sendall((json.dumps({"name": name, "arguments": arguments}) + "\n").encode())
        return json.loads(s.makefile().readline())


def handle(req: dict):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": req.get("params", {}).get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}}, "serverInfo": {"name": "release", "version": "1"}}
    if method == "tools/list":
        return {"tools": [{"name": t["function"]["name"], "description": t["function"]["description"],
                           "inputSchema": t["function"]["parameters"]} for t in tool_schemas(TOOLS)]}
    if method == "tools/call":
        params = req.get("params", {})
        result = forward(params.get("name"), params.get("arguments"))
        return {"content": [{"type": "text", "text": json.dumps(result)}], "isError": False}
    if method == "ping":
        return {}
    return None


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        req = json.loads(line)
        if "id" not in req:
            continue
        result = handle(req)
        reply = {"jsonrpc": "2.0", "id": req["id"]}
        if result is None:
            reply["error"] = {"code": -32601, "message": "method not found"}
        else:
            reply["result"] = result
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
