import { Behalf } from "./behalf.js";
import { Mandate } from "./mandate.js";
import { AuthorizationError } from "./errors.js";

/**
 * MCP middleware — the adoption killer. Wrap any MCP-style tool server once and
 * every tool call is automatically checked against the caller's mandate: scope,
 * limits, expiry, revocation, and audit, with no per-tool code.
 */

/** Minimal structural view of an MCP-ish tool server. */
export interface ToolServerLike {
  callTool(name: string, args: Record<string, unknown>, ctx?: CallContext): Promise<unknown>;
}

/** Per-call context; the caller's mandate rides here. */
export interface CallContext {
  mandate?: Mandate;
  [k: string]: unknown;
}

/** A capability requirement: a fixed string or one derived from call args. */
export type CapabilityRule = string | ((args: Record<string, unknown>) => string);

export interface WithBehalfOptions {
  /** Map each tool name to the capability it requires. */
  policy: Record<string, CapabilityRule>;
  /** What to do on a denied call. */
  onDenied?: "throw" | "prompt";
  /**
   * Just-in-time consent callback (used when onDenied === "prompt"). Return true
   * to allow the call through despite the missing authority.
   */
  onPrompt?: (info: { tool: string; capability: string; mandate?: Mandate }) => Promise<boolean>;
  /** Engine to use (defaults to the shared Behalf default). */
  engine?: Behalf;
}

/**
 * Wrap a tool server so every call is authorized first.
 *
 *   const server = withBehalf(myMcpServer, {
 *     policy: {
 *       send_email: "write:email",
 *       read_calendar: "read:calendar",
 *       transfer_funds: (args) => `spend:usd<=${args.amount}`,
 *     },
 *     onDenied: "throw",
 *   });
 */
export function withBehalf(server: ToolServerLike, opts: WithBehalfOptions): ToolServerLike {
  return {
    async callTool(name, args, ctx) {
      const rule = opts.policy[name];
      // Tools without a policy entry pass through unguarded (explicit opt-in).
      if (rule === undefined) return server.callTool(name, args, ctx);

      const capability = typeof rule === "function" ? rule(args) : rule;
      const mandate = ctx?.mandate;

      let denied: string | undefined;
      if (!mandate) {
        denied = "no mandate presented";
      } else {
        try {
          await mandate.authorize(capability);
        } catch (e) {
          denied = e instanceof AuthorizationError ? e.reason : String(e);
        }
      }

      if (denied) {
        if (opts.onDenied === "prompt" && opts.onPrompt) {
          const allow = await opts.onPrompt({ tool: name, capability, mandate });
          if (!allow) throw new AuthorizationError(capability, `${denied} (consent declined)`);
        } else {
          throw new AuthorizationError(capability, denied);
        }
      }

      return server.callTool(name, args, ctx);
    },
  };
}

/** Symmetric binding for agent-to-agent (A2A) calls — same enforcement shape. */
export function withBehalfA2A(server: ToolServerLike, opts: WithBehalfOptions): ToolServerLike {
  return withBehalf(server, opts);
}

/** A tool definition for the agent-legibility layer. */
export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>, ctx?: CallContext) => Promise<unknown>;
}

/**
 * The three discovery tools that let any agent obtain and use authority
 * natively: `request_mandate`, `present_mandate`, and `check_authority`.
 */
export function behalfMcpTools(engine: Behalf = Behalf.default): ToolDefinition[] {
  return [
    {
      name: "request_mandate",
      description:
        "Request a scoped, time-bound mandate authorizing an agent to act on a principal's behalf.",
      inputSchema: {
        type: "object",
        required: ["principal", "agent", "can", "expiresIn"],
        properties: {
          principal: { type: "string" },
          agent: { type: "string" },
          can: { type: "array", items: { type: "string" } },
          expiresIn: { type: "string", description: 'e.g. "1h", "10m"' },
        },
      },
      handler: async (args) => {
        const m = engine.grant({
          principal: String(args.principal),
          agent: String(args.agent),
          can: args.can as string[],
          expiresIn: String(args.expiresIn),
        });
        return { mandate: m.serialize(), id: m.id };
      },
    },
    {
      name: "present_mandate",
      description: "Validate a serialized mandate and return its decoded scope, principal, and expiry.",
      inputSchema: {
        type: "object",
        required: ["mandate"],
        properties: { mandate: { type: "string" } },
      },
      handler: async (args) => {
        const m = engine.import(String(args.mandate));
        engine.verifySignature(m.token);
        return {
          valid: true,
          id: m.id,
          principal: m.principal,
          agent: m.agent,
          expiresAt: m.expiresAt,
          chain: m.chain,
        };
      },
    },
    {
      name: "check_authority",
      description:
        "Advisory check of whether a mandate's scope would allow an action (does not perform it and does not prove possession).",
      inputSchema: {
        type: "object",
        required: ["mandate", "action"],
        properties: { mandate: { type: "string" }, action: { type: "string" } },
      },
      handler: async (args) => {
        const m = engine.import(String(args.mandate));
        return engine.inspect(m.token, String(args.action));
      },
    },
  ];
}
