import { behalfMcpTools } from "./mcp.js";

/**
 * Dynamic, per-surface quickstart generator.
 *
 * Wiring Behalf into an AI surface is one of two shapes: an MCP server entry
 * (Claude Code/Desktop, Cursor, Copilot/VS Code, Windsurf, Gemini CLI, OpenAI
 * Agents, ...) or a function-calling tool schema (OpenAI / Gemini APIs). Rather
 * than hand-write a doc per tool, surfaces are described as DATA and rendered on
 * demand — so the three mains (Claude Code, Cursor, Copilot), Gemini and GPT are
 * built in, and ANY other AI is configurable via a custom surface or the generic
 * MCP template.
 */

export interface Surface {
  id: string;
  name: string;
  kind: "mcp" | "tool-api";
  /** mcp: where the config lives. */
  configFile?: string;
  /** mcp: top-level key — usually "mcpServers", VS Code uses "servers". */
  configKey?: string;
  /** mcp: include `"type": "stdio"` in the entry (VS Code, some clients). */
  stdioType?: boolean;
  /** mcp: optional one-liner CLI to register, with {name}/{command}/{args}. */
  cli?: string;
  /** tool-api: which function-calling dialect to emit. */
  api?: "openai" | "gemini";
  /** Freeform guidance shown with the snippet. */
  notes?: string;
}

export interface QuickstartOptions {
  /** Server name shown in the client config. Default "agent-authority". */
  name?: string;
  /** Command to launch the MCP server. Default "npx". */
  command?: string;
  /** Args for the command. Default ["-y", "agent-authority-mcp"]. */
  args?: string[];
  /** Extra environment variables for the server entry. */
  env?: Record<string, string>;
}

export interface Quickstart {
  surface: string;
  name: string;
  kind: Surface["kind"];
  instructions: string;
  /** The config/snippet to paste (JSON or code). */
  snippet: string;
  /** Optional one-line CLI alternative (MCP surfaces). */
  cli?: string;
  notes?: string;
  /** A ready-to-print text rendering of everything above. */
  text: string;
}

/** Built-in surfaces. Extend at runtime by passing your own {@link Surface}. */
export const DEFAULT_SURFACES: Surface[] = [
  {
    id: "claude-code",
    name: "Claude Code",
    kind: "mcp",
    configFile: ".mcp.json (project) or ~/.claude.json",
    configKey: "mcpServers",
    cli: "claude mcp add {name} -- {command} {args}",
  },
  {
    id: "claude-desktop",
    name: "Claude Desktop",
    kind: "mcp",
    configFile:
      "~/Library/Application Support/Claude/claude_desktop_config.json (macOS) / %APPDATA%\\Claude\\claude_desktop_config.json (Windows)",
    configKey: "mcpServers",
  },
  {
    id: "cursor",
    name: "Cursor",
    kind: "mcp",
    configFile: ".cursor/mcp.json (project) or ~/.cursor/mcp.json (global)",
    configKey: "mcpServers",
  },
  {
    id: "copilot",
    name: "GitHub Copilot (VS Code)",
    kind: "mcp",
    configFile: ".vscode/mcp.json",
    configKey: "servers",
    stdioType: true,
    notes: "Enable agent mode; VS Code uses the `servers` key and a `type` field.",
  },
  {
    id: "windsurf",
    name: "Windsurf",
    kind: "mcp",
    configFile: "~/.codeium/windsurf/mcp_config.json",
    configKey: "mcpServers",
  },
  {
    id: "gemini-cli",
    name: "Gemini CLI",
    kind: "mcp",
    configFile: "~/.gemini/settings.json",
    configKey: "mcpServers",
  },
  {
    id: "openai-agents",
    name: "OpenAI Agents SDK",
    kind: "mcp",
    configFile: "your agent setup (MCP stdio server)",
    configKey: "mcpServers",
    notes: "The Agents SDK launches MCP servers over stdio; use this command/args.",
  },
  {
    id: "gpt",
    name: "GPT / OpenAI API (function calling)",
    kind: "tool-api",
    api: "openai",
    notes:
      "Pass these as `tools`. Have the model call `check_authority` before any sensitive action.",
  },
  {
    id: "gemini",
    name: "Gemini API (function calling)",
    kind: "tool-api",
    api: "gemini",
    notes: "Pass these as `functionDeclarations` in a `tools` entry.",
  },
  {
    id: "generic-mcp",
    name: "Any MCP client (generic)",
    kind: "mcp",
    configFile: "your MCP client's config",
    configKey: "mcpServers",
    notes: "Most MCP clients accept a `mcpServers` map of stdio servers.",
  },
];

const DEFAULTS: Required<Omit<QuickstartOptions, "env">> = {
  name: "agent-authority",
  command: "npx",
  args: ["-y", "agent-authority-mcp"],
};

/** Look up a built-in (or supplied) surface by id. */
export function findSurface(id: string, extra: Surface[] = []): Surface | undefined {
  return [...DEFAULT_SURFACES, ...extra].find((s) => s.id === id);
}

/** List all surface ids/names (built-in plus any supplied). */
export function listSurfaces(extra: Surface[] = []): { id: string; name: string }[] {
  return [...DEFAULT_SURFACES, ...extra].map((s) => ({ id: s.id, name: s.name }));
}

/** Render a ready-to-paste quickstart for a surface. */
export function generateQuickstart(surface: Surface, opts: QuickstartOptions = {}): Quickstart {
  const o = {
    name: opts.name ?? DEFAULTS.name,
    command: opts.command ?? DEFAULTS.command,
    args: opts.args ?? DEFAULTS.args,
    env: opts.env,
  };

  if (surface.kind === "tool-api") {
    return renderToolApi(surface, o);
  }
  return renderMcp(surface, o);
}

function renderMcp(surface: Surface, o: Required<Omit<QuickstartOptions, "env">> & { env?: Record<string, string> }): Quickstart {
  const entry: Record<string, unknown> = { command: o.command, args: o.args };
  if (surface.stdioType) entry.type = "stdio";
  if (o.env) entry.env = o.env;

  const config = { [surface.configKey ?? "mcpServers"]: { [o.name]: entry } };
  const snippet = JSON.stringify(config, null, 2);
  const cli = surface.cli
    ? surface.cli
        .replace("{name}", o.name)
        .replace("{command}", o.command)
        .replace("{args}", o.args.join(" "))
    : undefined;

  const instructions = `Add to ${surface.configFile ?? "your MCP client config"}:`;
  const text = [
    `# ${surface.name} — Behalf quickstart`,
    "",
    instructions,
    "",
    "```json",
    snippet,
    "```",
    cli ? `\nOr from the CLI:\n\n\`\`\`bash\n${cli}\n\`\`\`` : "",
    surface.notes ? `\nNote: ${surface.notes}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  return { surface: surface.id, name: surface.name, kind: "mcp", instructions, snippet, cli, notes: surface.notes, text };
}

function renderToolApi(surface: Surface, o: { name: string }): Quickstart {
  const tools = behalfMcpTools();
  let snippet: string;
  let instructions: string;

  if (surface.api === "gemini") {
    const decls = tools.map((t) => ({
      name: t.name,
      description: t.description,
      parameters: t.inputSchema,
    }));
    snippet = JSON.stringify({ tools: [{ functionDeclarations: decls }] }, null, 2);
    instructions = "Register these function declarations with the Gemini API:";
  } else {
    const fns = tools.map((t) => ({
      type: "function",
      function: { name: t.name, description: t.description, parameters: t.inputSchema },
    }));
    snippet = JSON.stringify({ tools: fns }, null, 2);
    instructions = "Pass these tools to the OpenAI API (Chat Completions / Responses):";
  }

  const text = [
    `# ${surface.name} — Behalf quickstart`,
    "",
    instructions,
    "",
    "```json",
    snippet,
    "```",
    surface.notes ? `\nNote: ${surface.notes}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  return { surface: surface.id, name: surface.name, kind: "tool-api", instructions, snippet, notes: surface.notes, text };
}
