import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBehalf } from "../src/behalf.js";
import { FileRateStore } from "../src/persist.js";
import { behalfMcpTools } from "../src/mcp.js";

// Regression tests for the post-PoP issuance/delegation wiring (A3–A5): a
// mandate must be transferable to another process WITH its delegation key, or
// it can never authorize anything.

test("serializeWithKey transfers a usable holder credential across engines", async () => {
  const issuer = createBehalf();
  const root = issuer.grant({
    principal: "u",
    agent: "orchestrator",
    can: ["read:calendar", "spend:usd<=50"],
    expiresIn: "1h",
  });
  const child = root.attenuate({ can: ["spend:usd<=20"], agent: "worker" });

  // "Another process": a fresh engine that trusts the issuer's public key.
  const worker = createBehalf({ trust: [issuer.publicKey] });
  const received = worker.import(child.serializeWithKey());

  assert.equal(received.canDelegate, true);
  await assert.doesNotReject(received.authorize("spend:usd=15")); // full holder powers
  await assert.rejects(() => received.authorize("spend:usd=30")); // still attenuated
  // It can even delegate further (and only narrow).
  const grandchild = received.attenuate({ can: ["spend:usd<=5"], agent: "sub" });
  await assert.doesNotReject(grandchild.authorize("spend:usd=5"));
});

test("the public serialize() form remains inspect-only", async () => {
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const pub = issuer.import(m.serialize());
  assert.equal(pub.canDelegate, false);
  await assert.rejects(() => pub.authorize("read:calendar"));
  assert.throws(() => pub.serializeWithKey());
  assert.equal((await issuer.inspect(pub.token, "read:calendar")).allowed, true);
});

test("a mandate issued via MCP request_mandate is actually usable (A3)", async () => {
  const engine = createBehalf();
  const [requestTool] = behalfMcpTools(engine);
  const issued = (await requestTool.handler({
    principal: "u",
    agent: "a",
    can: ["read:calendar"],
    expiresIn: "1h",
  })) as { mandate: string; publicToken: string };

  // The requester imports the holder credential and can authorize with it.
  const holder = engine.import(issued.mandate);
  await assert.doesNotReject(holder.authorize("read:calendar"));
  // The public token is included separately and is inspect-only.
  assert.equal(engine.import(issued.publicToken).canDelegate, false);
});

test("FileRateStore persists rate windows across restarts (B2)", () => {
  const dir = mkdtempSync(join(tmpdir(), "behalf-rate-"));
  try {
    const path = join(dir, "rate.json");
    const a = new FileRateStore(path);
    assert.equal(a.hit("k", 3_600_000, 2, 1000), true);
    assert.equal(a.hit("k", 3_600_000, 2, 2000), true);

    // "Restart": a new store over the same file remembers both hits.
    const b = new FileRateStore(path);
    assert.equal(b.hit("k", 3_600_000, 2, 3000), false);
    // Outside the window, it admits again.
    assert.equal(b.hit("k", 3_600_000, 2, 3_700_000), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
