# Behalf quickstarts — wire it into any AI

Behalf wires into an AI surface in one of two shapes:

- **MCP server** — Claude Code, Claude Desktop, Cursor, GitHub Copilot (VS Code),
  Windsurf, Gemini CLI, OpenAI Agents SDK, and most agent runtimes.
- **Function-calling tools** — the OpenAI and Gemini APIs (and anything that
  accepts JSON-schema tool definitions).

Rather than maintain a doc per tool, the snippets are **generated** from a
surface registry, so the three mains (Claude Code, Cursor, Copilot), Gemini and
GPT are built in — and **any other AI is configurable** via a custom surface or
the generic MCP template.

```bash
agent-authority quickstart --list              # every built-in surface
agent-authority quickstart claude-code         # print the config to paste
agent-authority quickstart copilot
agent-authority quickstart gpt                 # OpenAI function tools
agent-authority quickstart gemini              # Gemini functionDeclarations

# customise the launch command / name / env
agent-authority quickstart cursor --local                      # node dist/mcp-server.js
agent-authority quickstart cursor --command npx --arg -y --arg agent-authority-mcp
agent-authority quickstart claude-code --name auth --env BEHALF_HOME=/data/behalf
agent-authority quickstart <surface> --format json             # machine-readable
```

## The three mains

### Claude Code

```bash
claude mcp add agent-authority -- npx -y agent-authority-mcp
```

or `.mcp.json` / `~/.claude.json`:

```json
{ "mcpServers": { "agent-authority": { "command": "npx", "args": ["-y", "agent-authority-mcp"] } } }
```

### Cursor — `.cursor/mcp.json`

```json
{ "mcpServers": { "agent-authority": { "command": "npx", "args": ["-y", "agent-authority-mcp"] } } }
```

### GitHub Copilot (VS Code) — `.vscode/mcp.json`

```json
{ "servers": { "agent-authority": { "command": "npx", "args": ["-y", "agent-authority-mcp"], "type": "stdio" } } }
```

## GPT and Gemini (and any function-calling model)

`agent-authority quickstart gpt` / `agent-authority quickstart gemini` emit the three discovery
tools — `request_mandate`, `present_mandate`, `check_authority` — as OpenAI
`tools` or Gemini `functionDeclarations`. Have the model call `check_authority`
before any sensitive action, then enforce with `mandate.authorize(...)` server-side.

## Any AI — bring your own surface

Every surface is just data. Describe a new one in JSON and pass it with
`--surfaces`:

```json
[
  {
    "id": "my-agent",
    "name": "My In-House Agent",
    "kind": "mcp",
    "configFile": "my-agent/config.json",
    "configKey": "mcpServers"
  }
]
```

```bash
agent-authority quickstart my-agent --surfaces ./surfaces.json
```

For an MCP client whose config you don't know yet, `agent-authority quickstart
generic-mcp` prints the near-universal `mcpServers` stdio form. Programmatic use
mirrors the CLI:

```ts
import { generateQuickstart, findSurface } from "agent-authority";
const qs = generateQuickstart(findSurface("cursor")!, { command: "npx", args: ["-y", "agent-authority-mcp"] });
console.log(qs.snippet); // the JSON to paste
```
