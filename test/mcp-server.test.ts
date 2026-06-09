import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { createMcpServer } from "../src/mcp-server.js";

test("initialize advertises tools capability", async () => {
  const server = createMcpServer(createBehalf());
  const res = await server.dispatch({ jsonrpc: "2.0", id: 1, method: "initialize" });
  assert.ok(res);
  const result = res!.result as { capabilities: { tools: object }; serverInfo: { name: string } };
  assert.deepEqual(result.capabilities.tools, {});
  assert.equal(result.serverInfo.name, "behalf");
});

test("notifications get no reply", async () => {
  const server = createMcpServer(createBehalf());
  const res = await server.dispatch({ jsonrpc: "2.0", method: "notifications/initialized" });
  assert.equal(res, null);
});

test("tools/list returns the three discovery tools", async () => {
  const server = createMcpServer(createBehalf());
  const res = await server.dispatch({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  const { tools } = res!.result as { tools: { name: string }[] };
  assert.deepEqual(
    tools.map((t) => t.name).sort(),
    ["check_authority", "present_mandate", "request_mandate"],
  );
});

test("tools/call issues then checks a mandate end-to-end", async () => {
  const server = createMcpServer(createBehalf());

  const granted = await server.dispatch({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: {
      name: "request_mandate",
      arguments: { principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" },
    },
  });
  const issued = JSON.parse(
    (granted!.result as { content: { text: string }[] }).content[0].text,
  ) as { mandate: string };
  assert.ok(issued.mandate);

  const checked = await server.dispatch({
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "check_authority", arguments: { mandate: issued.mandate, action: "read:calendar" } },
  });
  const decision = JSON.parse(
    (checked!.result as { content: { text: string }[] }).content[0].text,
  ) as { allowed: boolean };
  assert.equal(decision.allowed, true);
});

test("unknown method yields a JSON-RPC error", async () => {
  const server = createMcpServer(createBehalf());
  const res = await server.dispatch({ jsonrpc: "2.0", id: 5, method: "bogus/method" });
  assert.equal(res!.error?.code, -32601);
});

test("unknown tool yields an invalid-params error", async () => {
  const server = createMcpServer(createBehalf());
  const res = await server.dispatch({
    jsonrpc: "2.0",
    id: 6,
    method: "tools/call",
    params: { name: "nope", arguments: {} },
  });
  assert.equal(res!.error?.code, -32602);
});
