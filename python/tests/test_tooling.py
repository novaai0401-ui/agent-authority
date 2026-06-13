"""Tests for the Python tooling parity: quickstart, MCP server, CLI."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_authority.mcp_server import create_mcp_server  # noqa: E402
from agent_authority.quickstart import find_surface, generate_quickstart, list_surfaces  # noqa: E402

PKG_DIR = os.path.join(os.path.dirname(__file__), "..")


class QuickstartTests(unittest.TestCase):
    def test_main_surfaces_present(self):
        ids = [s["id"] for s in list_surfaces()]
        for sid in ["claude-code", "cursor", "copilot", "gemini", "gpt"]:
            self.assertIn(sid, ids)

    def test_mcp_surface_renders_config(self):
        qs = generate_quickstart(find_surface("claude-code"), command="node", args=["dist/mcp-server.js"])
        cfg = json.loads(qs["snippet"])
        self.assertEqual(cfg["mcpServers"]["agent-authority"], {"command": "node", "args": ["dist/mcp-server.js"]})
        self.assertIn("claude mcp add agent-authority -- node dist/mcp-server.js", qs["cli"])

    def test_copilot_uses_servers_key_and_stdio(self):
        cfg = json.loads(generate_quickstart(find_surface("copilot"))["snippet"])
        self.assertEqual(cfg["servers"]["agent-authority"]["type"], "stdio")

    def test_gpt_function_tools(self):
        cfg = json.loads(generate_quickstart(find_surface("gpt"))["snippet"])
        names = [t["function"]["name"] for t in cfg["tools"]]
        self.assertIn("check_authority", names)

    def test_custom_surface(self):
        custom = {"id": "my-agent", "name": "Mine", "kind": "mcp", "configKey": "mcpServers"}
        self.assertTrue(any(s["id"] == "my-agent" for s in list_surfaces([custom])))


class McpServerTests(unittest.TestCase):
    def test_initialize_and_tools(self):
        s = create_mcp_server()
        init = s.dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(init["result"]["serverInfo"]["name"], "agent-authority")
        self.assertIsNone(s.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        tools = s.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        self.assertEqual(
            sorted(t["name"] for t in tools),
            ["check_authority", "present_mandate", "request_mandate"],
        )

    def test_tools_call_roundtrip(self):
        s = create_mcp_server()
        issued = s.dispatch({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "request_mandate",
                       "arguments": {"principal": "u", "agent": "a", "can": ["read:calendar"], "expiresIn": "1h"}},
        })
        mandate = json.loads(issued["result"]["content"][0]["text"])["mandate"]
        checked = s.dispatch({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "check_authority", "arguments": {"mandate": mandate, "action": "read:calendar"}},
        })
        self.assertTrue(json.loads(checked["result"]["content"][0]["text"])["allowed"])

    def test_unknown_method_errors(self):
        s = create_mcp_server()
        res = s.dispatch({"jsonrpc": "2.0", "id": 5, "method": "bogus"})
        self.assertEqual(res["error"]["code"], -32601)


class CliTests(unittest.TestCase):
    def _run(self, *args, home):
        env = {**os.environ, "BEHALF_HOME": home, "PYTHONPATH": PKG_DIR}
        return subprocess.run(
            [sys.executable, "-m", "agent_authority.cli", *args],
            cwd=PKG_DIR, env=env, capture_output=True, text=True,
        )

    def test_grant_authorize_revoke_lifecycle(self):
        with tempfile.TemporaryDirectory() as home:
            grant = self._run(
                "grant", "--principal", "alice", "--agent", "research",
                "--can", "read:calendar", "--can", "spend:usd<=50", "--expires", "1h", home=home,
            )
            self.assertEqual(grant.returncode, 0, grant.stderr)
            mandate = grant.stdout.strip()

            allow = self._run("authorize", mandate, "spend:usd=20", home=home)
            self.assertEqual(allow.returncode, 0)
            self.assertIn("ALLOW", allow.stdout)

            deny = self._run("authorize", mandate, "spend:usd=99", home=home)
            self.assertEqual(deny.returncode, 1)
            self.assertIn("DENY", deny.stdout)

            inspect = json.loads(self._run("inspect", mandate, home=home).stdout)
            self.assertTrue(inspect["valid"])
            mid = inspect["id"]

            self.assertEqual(self._run("revoke", mid, home=home).returncode, 0)
            after = self._run("authorize", mandate, "spend:usd=20", home=home)
            self.assertEqual(after.returncode, 1)
            self.assertIn("revoked", after.stdout)

    def test_quickstart_and_lint(self):
        with tempfile.TemporaryDirectory() as home:
            qs = self._run("quickstart", "claude-code", home=home)
            self.assertEqual(qs.returncode, 0)
            self.assertIn("mcpServers", qs.stdout)

            lint = self._run("lint", "spend:usd", "*", home=home)
            self.assertEqual(lint.returncode, 1)  # warnings present
            self.assertIn("WARN", lint.stdout)


if __name__ == "__main__":
    unittest.main()
