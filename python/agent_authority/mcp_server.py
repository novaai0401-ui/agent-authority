"""A minimal, dependency-free MCP server over stdio (mirrors the TS server).

Speaks newline-delimited JSON-RPC 2.0 and exposes the Behalf discovery tools
(request_mandate / present_mandate / check_authority) to any MCP client.
Run it as `agent-authority-mcp` or `python -m agent_authority.mcp_server`.
"""

from __future__ import annotations

import json
import sys
from typing import Optional

from .behalf import Behalf
from .mcp import behalf_mcp_tools

PROTOCOL_VERSION = "2024-11-05"


class McpServer:
    def __init__(self, engine: Optional[Behalf] = None) -> None:
        self._tools = behalf_mcp_tools(engine or Behalf.default())
        self._by_name = {t["name"]: t for t in self._tools}

    def dispatch(self, req: dict) -> Optional[dict]:
        rid = req.get("id")
        method = req.get("method")

        def ok(result):
            return {"jsonrpc": "2.0", "id": rid, "result": result}

        def err(code, message):
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

        if method == "initialize":
            return ok({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agent-authority", "version": "0.1.4"},
            })
        if method in ("notifications/initialized", "initialized"):
            return None
        if method == "ping":
            return ok({})
        if method == "tools/list":
            return ok({"tools": [
                {"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]}
                for t in self._tools
            ]})
        if method == "tools/call":
            params = req.get("params") or {}
            tool = self._by_name.get(params.get("name"))
            if not tool:
                return err(-32602, f"unknown tool \"{params.get('name')}\"")
            try:
                result = tool["handler"](params.get("arguments") or {})
                return ok({"content": [{"type": "text", "text": json.dumps(result)}], "isError": False})
            except Exception as e:  # noqa: BLE001
                return ok({"content": [{"type": "text", "text": str(e)}], "isError": True})

        if rid is None:
            return None  # unknown notification
        return err(-32601, f"method not found: {method}")

    def start(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            res = self.dispatch(req)
            if res is not None:
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()


def create_mcp_server(engine: Optional[Behalf] = None) -> McpServer:
    return McpServer(engine)


def main() -> None:
    create_mcp_server().start()


if __name__ == "__main__":
    main()
