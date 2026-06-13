"""Dynamic per-surface quickstart generator (mirrors the TS implementation).

Renders ready-to-paste wiring for any AI surface from a data-driven registry:
MCP server entries (Claude Code/Desktop, Cursor, Copilot, Windsurf, Gemini CLI,
OpenAI Agents) and function-calling tool schemas (OpenAI / Gemini). Any other AI
is configurable via a custom surface or the generic MCP template.
"""

from __future__ import annotations

import json
from typing import Optional

from .mcp import behalf_mcp_tools

DEFAULT_SURFACES: list[dict] = [
    {"id": "claude-code", "name": "Claude Code", "kind": "mcp",
     "configFile": ".mcp.json (project) or ~/.claude.json", "configKey": "mcpServers",
     "cli": "claude mcp add {name} -- {command} {args}"},
    {"id": "claude-desktop", "name": "Claude Desktop", "kind": "mcp",
     "configFile": "~/Library/Application Support/Claude/claude_desktop_config.json (macOS) / %APPDATA%\\Claude\\claude_desktop_config.json (Windows)",
     "configKey": "mcpServers"},
    {"id": "cursor", "name": "Cursor", "kind": "mcp",
     "configFile": ".cursor/mcp.json (project) or ~/.cursor/mcp.json (global)", "configKey": "mcpServers"},
    {"id": "copilot", "name": "GitHub Copilot (VS Code)", "kind": "mcp",
     "configFile": ".vscode/mcp.json", "configKey": "servers", "stdioType": True,
     "notes": "Enable agent mode; VS Code uses the `servers` key and a `type` field."},
    {"id": "windsurf", "name": "Windsurf", "kind": "mcp",
     "configFile": "~/.codeium/windsurf/mcp_config.json", "configKey": "mcpServers"},
    {"id": "gemini-cli", "name": "Gemini CLI", "kind": "mcp",
     "configFile": "~/.gemini/settings.json", "configKey": "mcpServers"},
    {"id": "openai-agents", "name": "OpenAI Agents SDK", "kind": "mcp",
     "configFile": "your agent setup (MCP stdio server)", "configKey": "mcpServers",
     "notes": "The Agents SDK launches MCP servers over stdio; use this command/args."},
    {"id": "gpt", "name": "GPT / OpenAI API (function calling)", "kind": "tool-api", "api": "openai",
     "notes": "Pass these as `tools`. Have the model call `check_authority` before any sensitive action."},
    {"id": "gemini", "name": "Gemini API (function calling)", "kind": "tool-api", "api": "gemini",
     "notes": "Pass these as `functionDeclarations` in a `tools` entry."},
    {"id": "generic-mcp", "name": "Any MCP client (generic)", "kind": "mcp",
     "configFile": "your MCP client's config", "configKey": "mcpServers",
     "notes": "Most MCP clients accept a `mcpServers` map of stdio servers."},
]

_DEFAULTS = {"name": "agent-authority", "command": "npx", "args": ["-y", "agent-authority-mcp"]}


def find_surface(id: str, extra: Optional[list[dict]] = None) -> Optional[dict]:
    for s in DEFAULT_SURFACES + (extra or []):
        if s["id"] == id:
            return s
    return None


def list_surfaces(extra: Optional[list[dict]] = None) -> list[dict]:
    return [{"id": s["id"], "name": s["name"]} for s in DEFAULT_SURFACES + (extra or [])]


def generate_quickstart(
    surface: dict,
    *,
    name: Optional[str] = None,
    command: Optional[str] = None,
    args: Optional[list[str]] = None,
    env: Optional[dict] = None,
) -> dict:
    name = name or _DEFAULTS["name"]
    command = command or _DEFAULTS["command"]
    args = args if args is not None else list(_DEFAULTS["args"])

    if surface.get("kind") == "tool-api":
        return _render_tool_api(surface)
    return _render_mcp(surface, name, command, args, env)


def _render_mcp(surface, name, command, args, env) -> dict:
    entry = {"command": command, "args": args}
    if surface.get("stdioType"):
        entry["type"] = "stdio"
    if env:
        entry["env"] = env
    config = {surface.get("configKey", "mcpServers"): {name: entry}}
    snippet = json.dumps(config, indent=2)
    cli = None
    if surface.get("cli"):
        cli = (
            surface["cli"]
            .replace("{name}", name)
            .replace("{command}", command)
            .replace("{args}", " ".join(args))
        )
    instructions = f"Add to {surface.get('configFile', 'your MCP client config')}:"
    parts = [f"# {surface['name']} — Behalf quickstart", "", instructions, "", "```json", snippet, "```"]
    if cli:
        parts += ["", "Or from the CLI:", "", "```bash", cli, "```"]
    if surface.get("notes"):
        parts += ["", f"Note: {surface['notes']}"]
    return {"surface": surface["id"], "name": surface["name"], "kind": "mcp",
            "instructions": instructions, "snippet": snippet, "cli": cli,
            "notes": surface.get("notes"), "text": "\n".join(parts)}


def _render_tool_api(surface) -> dict:
    tools = behalf_mcp_tools()
    if surface.get("api") == "gemini":
        decls = [{"name": t["name"], "description": t["description"], "parameters": t["inputSchema"]} for t in tools]
        snippet = json.dumps({"tools": [{"functionDeclarations": decls}]}, indent=2)
        instructions = "Register these function declarations with the Gemini API:"
    else:
        fns = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["inputSchema"]}} for t in tools]
        snippet = json.dumps({"tools": fns}, indent=2)
        instructions = "Pass these tools to the OpenAI API (Chat Completions / Responses):"
    parts = [f"# {surface['name']} — Behalf quickstart", "", instructions, "", "```json", snippet, "```"]
    if surface.get("notes"):
        parts += ["", f"Note: {surface['notes']}"]
    return {"surface": surface["id"], "name": surface["name"], "kind": "tool-api",
            "instructions": instructions, "snippet": snippet, "notes": surface.get("notes"),
            "text": "\n".join(parts)}
