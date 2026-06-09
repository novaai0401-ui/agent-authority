import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { withBehalf, behalfMcpTools, type ToolServerLike } from "../src/mcp.js";
import { AuthorizationError } from "../src/errors.js";

function fakeServer(): ToolServerLike & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async callTool(name) {
      calls.push(name);
      return { ok: true };
    },
  };
}

test("withBehalf allows calls the mandate permits", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const base = fakeServer();
  const guarded = withBehalf(base, { policy: { read_calendar: "read:calendar" } });

  await guarded.callTool("read_calendar", {}, { mandate: m });
  assert.deepEqual(base.calls, ["read_calendar"]);
});

test("withBehalf denies calls outside scope and does not invoke the tool", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const base = fakeServer();
  const guarded = withBehalf(base, { policy: { send_email: "write:email" } });

  await assert.rejects(
    () => guarded.callTool("send_email", {}, { mandate: m }),
    AuthorizationError,
  );
  assert.deepEqual(base.calls, []);
});

test("withBehalf derives the capability from args", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["spend:usd<=50"], expiresIn: "1h" });
  const base = fakeServer();
  const guarded = withBehalf(base, {
    policy: { transfer_funds: (args) => `spend:usd=${args.amount}` },
  });

  await guarded.callTool("transfer_funds", { amount: 20 }, { mandate: m });
  await assert.rejects(
    () => guarded.callTool("transfer_funds", { amount: 51 }, { mandate: m }),
    AuthorizationError,
  );
  assert.deepEqual(base.calls, ["transfer_funds"]);
});

test("withBehalf denies when no mandate is presented", async () => {
  const base = fakeServer();
  const guarded = withBehalf(base, { policy: { read_calendar: "read:calendar" } });
  await assert.rejects(() => guarded.callTool("read_calendar", {}), AuthorizationError);
});

test('onDenied "prompt" can grant just-in-time consent', async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const base = fakeServer();
  const guarded = withBehalf(base, {
    policy: { send_email: "write:email" },
    onDenied: "prompt",
    onPrompt: async () => true,
  });

  await guarded.callTool("send_email", {}, { mandate: m });
  assert.deepEqual(base.calls, ["send_email"]);
});

test("unpoliced tools pass through", async () => {
  const base = fakeServer();
  const guarded = withBehalf(base, { policy: {} });
  await guarded.callTool("public_tool", {});
  assert.deepEqual(base.calls, ["public_tool"]);
});

test("discovery tools issue and check mandates", async () => {
  const b = createBehalf();
  const [requestTool, presentTool, checkTool] = behalfMcpTools(b);

  const issued = (await requestTool.handler({
    principal: "u",
    agent: "a",
    can: ["read:calendar"],
    expiresIn: "1h",
  })) as { mandate: string; id: string };
  assert.ok(issued.mandate);

  const presented = (await presentTool.handler({ mandate: issued.mandate })) as {
    valid: boolean;
    principal: string;
  };
  assert.equal(presented.valid, true);
  assert.equal(presented.principal, "u");

  const allowed = (await checkTool.handler({
    mandate: issued.mandate,
    action: "read:calendar",
  })) as { allowed: boolean };
  assert.equal(allowed.allowed, true);

  const denied = (await checkTool.handler({
    mandate: issued.mandate,
    action: "write:email",
  })) as { allowed: boolean };
  assert.equal(denied.allowed, false);
});
