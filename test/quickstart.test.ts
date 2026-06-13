import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateQuickstart,
  findSurface,
  listSurfaces,
  type Surface,
} from "../src/quickstart.js";

test("the three main surfaces plus Gemini and GPT are built in", () => {
  const ids = listSurfaces().map((s) => s.id);
  for (const id of ["claude-code", "cursor", "copilot", "gemini", "gpt"]) {
    assert.ok(ids.includes(id), `missing surface ${id}`);
  }
});

test("an MCP surface renders an mcpServers entry", () => {
  const qs = generateQuickstart(findSurface("claude-code")!, {
    command: "node",
    args: ["dist/mcp-server.js"],
  });
  const config = JSON.parse(qs.snippet);
  assert.deepEqual(config.mcpServers["agent-authority"], { command: "node", args: ["dist/mcp-server.js"] });
  assert.match(qs.cli ?? "", /claude mcp add agent-authority -- node dist\/mcp-server\.js/);
});

test("VS Code / Copilot uses the `servers` key and a stdio type", () => {
  const qs = generateQuickstart(findSurface("copilot")!);
  const config = JSON.parse(qs.snippet);
  assert.ok(config.servers["agent-authority"]);
  assert.equal(config.servers["agent-authority"].type, "stdio");
});

test("GPT renders OpenAI function tools", () => {
  const qs = generateQuickstart(findSurface("gpt")!);
  const parsed = JSON.parse(qs.snippet);
  assert.ok(Array.isArray(parsed.tools));
  assert.equal(parsed.tools[0].type, "function");
  const names = parsed.tools.map((t: { function: { name: string } }) => t.function.name);
  assert.ok(names.includes("check_authority"));
});

test("Gemini renders functionDeclarations", () => {
  const qs = generateQuickstart(findSurface("gemini")!);
  const parsed = JSON.parse(qs.snippet);
  assert.ok(Array.isArray(parsed.tools[0].functionDeclarations));
  assert.ok(parsed.tools[0].functionDeclarations.some((d: { name: string }) => d.name === "request_mandate"));
});

test("any AI is configurable via a custom surface", () => {
  const custom: Surface = {
    id: "my-agent",
    name: "My Custom Agent",
    kind: "mcp",
    configFile: "my-agent.json",
    configKey: "mcpServers",
  };
  assert.ok(listSurfaces([custom]).some((s) => s.id === "my-agent"));
  const qs = generateQuickstart(custom, { name: "auth", command: "npx", args: ["-y", "agent-authority-mcp"] });
  assert.equal(JSON.parse(qs.snippet).mcpServers.auth.command, "npx");
});

test("env vars are included in the server entry", () => {
  const qs = generateQuickstart(findSurface("cursor")!, { env: { BEHALF_HOME: "/tmp/b" } });
  assert.deepEqual(JSON.parse(qs.snippet).mcpServers["agent-authority"].env, { BEHALF_HOME: "/tmp/b" });
});
