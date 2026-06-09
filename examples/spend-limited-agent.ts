/**
 * Reference integration #2 — a spend-limited agent.
 *
 * A user grants a shopping agent a hard budget cap and an email rate limit.
 * The agent can spend up to the cap and is denied the moment it exceeds it.
 *
 *   npm run build && node dist-test/examples/spend-limited-agent.js
 */
import { createBehalf } from "../src/behalf.js";
import { withBehalf, type ToolServerLike } from "../src/mcp.js";

const commerceServer: ToolServerLike = {
  async callTool(name, args) {
    switch (name) {
      case "purchase":
        return { ok: true, charged: args.amount };
      case "notify":
        return { sent: true };
      default:
        return { error: "unknown tool" };
    }
  },
};

async function main() {
  const behalf = createBehalf();

  // 1. GRANT — up to $50 total per charge, at most 3 notification emails/hour.
  const mandate = behalf.grant({
    principal: "bob",
    agent: "shopping-agent",
    can: ["spend:usd<=50", "send:email rate<=3/h"],
    expiresIn: "1h",
  });

  const guarded = withBehalf(commerceServer, {
    policy: {
      purchase: (args) => `spend:usd=${args.amount}`,
      notify: "send:email",
    },
    onDenied: "throw",
  });

  await tryCall(guarded, "purchase", { amount: 20 }, mandate); // ok
  await tryCall(guarded, "purchase", { amount: 25 }, mandate); // ok
  await tryCall(guarded, "purchase", { amount: 80 }, mandate); // DENIED — over cap

  for (let i = 1; i <= 4; i++) {
    await tryCall(guarded, "notify", {}, mandate); // 4th is DENIED — rate limit
  }

  const trail = await mandate.audit();
  const denied = trail.filter((e) => e.decision === "deny").length;
  console.log(`\naudit: ${trail.length} records, ${denied} denied`);
}

async function tryCall(
  server: ToolServerLike,
  tool: string,
  args: Record<string, unknown>,
  mandate: unknown,
) {
  try {
    const r = await server.callTool(tool, args, { mandate } as never);
    console.log(`${tool}(${JSON.stringify(args)}): allowed ->`, r);
  } catch (e) {
    console.log(`${tool}(${JSON.stringify(args)}): DENIED -> ${(e as Error).message}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
