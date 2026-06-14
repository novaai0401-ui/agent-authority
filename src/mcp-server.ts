#!/usr/bin/env node
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import { Behalf } from "./behalf.js";
import { behalfMcpTools, type ToolDefinition } from "./mcp.js";

/**
 * A minimal, dependency-free MCP server over stdio (newline-delimited JSON-RPC
 * 2.0). It exposes the Behalf discovery tools — `request_mandate`,
 * `present_mandate`, `check_authority` — so any MCP client (Claude Desktop,
 * Cursor, ...) can obtain and use authority natively. Staying SDK-free keeps the
 * "thin, near-zero-deps" principle: the wire protocol is small enough to own.
 */

const PROTOCOL_VERSION = "2024-11-05";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string };
}

export interface McpServer {
  /** Handle one JSON-RPC request; returns a response, or null for notifications. */
  dispatch(req: JsonRpcRequest): Promise<JsonRpcResponse | null>;
  /** Wire the server to stdin/stdout and run until the stream closes. */
  start(): void;
}

export function createMcpServer(engine: Behalf = Behalf.default): McpServer {
  const tools: ToolDefinition[] = behalfMcpTools(engine);
  const byName = new Map(tools.map((t) => [t.name, t]));

  async function dispatch(req: JsonRpcRequest): Promise<JsonRpcResponse | null> {
    const id = req.id ?? null;
    const ok = (result: unknown): JsonRpcResponse => ({ jsonrpc: "2.0", id, result });
    const err = (code: number, message: string): JsonRpcResponse => ({
      jsonrpc: "2.0",
      id,
      error: { code, message },
    });

    switch (req.method) {
      case "initialize":
        return ok({
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: "agent-authority", version: "0.1.3" },
        });

      case "notifications/initialized":
      case "initialized":
        return null; // notification, no reply

      case "ping":
        return ok({});

      case "tools/list":
        return ok({
          tools: tools.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        });

      case "tools/call": {
        const name = req.params?.name as string;
        const args = (req.params?.arguments as Record<string, unknown>) ?? {};
        const tool = byName.get(name);
        if (!tool) return err(-32602, `unknown tool "${name}"`);
        try {
          const result = await tool.handler(args);
          return ok({
            content: [{ type: "text", text: JSON.stringify(result) }],
            isError: false,
          });
        } catch (e) {
          return ok({
            content: [{ type: "text", text: (e as Error).message }],
            isError: true,
          });
        }
      }

      default:
        // Ignore other notifications; error on unknown requests.
        if (req.id === undefined) return null;
        return err(-32601, `method not found: ${req.method}`);
    }
  }

  function start(): void {
    const rl = createInterface({ input: process.stdin });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      let req: JsonRpcRequest;
      try {
        req = JSON.parse(trimmed);
      } catch {
        return; // ignore malformed input
      }
      dispatch(req).then((res) => {
        if (res) process.stdout.write(JSON.stringify(res) + "\n");
      });
    });
  }

  return { dispatch, start };
}

// Allow `node dist/mcp-server.js` (and the `agent-authority-mcp` bin) to run the server,
// while never auto-starting when imported (e.g. by tests). Compares real paths
// so an npm bin symlink still resolves to this module.
function runningAsMain(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}
if (runningAsMain()) {
  createMcpServer().start();
}
