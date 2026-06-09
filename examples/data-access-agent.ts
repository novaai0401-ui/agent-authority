/**
 * Reference integration #1 — a data-access agent.
 *
 * A user grants a read-only research agent access to their calendar and docs.
 * The agent reads what it's allowed to and is blocked the moment it strays.
 *
 *   npm run build && node dist-test/examples/data-access-agent.js
 */
import { createBehalf } from "../src/behalf.js";
import { withBehalf, type ToolServerLike } from "../src/mcp.js";

// A toy "data" tool server. In real life this is your MCP server.
const dataServer: ToolServerLike = {
  async callTool(name, args) {
    switch (name) {
      case "read_calendar":
        return { events: ["Standup 9:00", "1:1 14:00"] };
      case "read_docs":
        return { doc: `contents of ${args.path}` };
      case "delete_doc":
        return { deleted: args.path };
      default:
        return { error: "unknown tool" };
    }
  },
};

async function main() {
  const behalf = createBehalf();

  // 1. GRANT — read-only access to calendar and the /reports doc tree.
  const mandate = behalf.grant({
    principal: "alice",
    agent: "research-agent",
    can: ["read:calendar", "read:docs/reports"],
    expiresIn: "1h",
  });

  // Wrap the server once: each tool maps to the capability it needs.
  const guarded = withBehalf(dataServer, {
    policy: {
      read_calendar: "read:calendar",
      read_docs: (args) => `read:docs/${args.path}`,
      delete_doc: (args) => `delete:docs/${args.path}`,
    },
    onDenied: "throw",
  });

  console.log("calendar:", await guarded.callTool("read_calendar", {}, { mandate }));
  console.log(
    "report:",
    await guarded.callTool("read_docs", { path: "reports/q2" }, { mandate }),
  );

  // Out of scope: reading outside /reports.
  await tryCall(guarded, "read_docs", { path: "salaries/all" }, mandate);
  // Out of scope: a destructive verb the agent was never granted.
  await tryCall(guarded, "delete_doc", { path: "reports/q2" }, mandate);

  const trail = await mandate.audit();
  console.log(`\naudit (${trail.length} records):`);
  for (const e of trail) console.log(`  ${e.decision.padEnd(5)} ${e.action}`);
}

async function tryCall(
  server: ToolServerLike,
  tool: string,
  args: Record<string, unknown>,
  mandate: unknown,
) {
  try {
    await server.callTool(tool, args, { mandate } as never);
    console.log(`${tool}: allowed`);
  } catch (e) {
    console.log(`${tool}: DENIED -> ${(e as Error).message}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
