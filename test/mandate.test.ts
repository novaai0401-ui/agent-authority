import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { AuthorizationError, IntegrityError } from "../src/errors.js";

test("grant produces a verifiable, scoped mandate", async () => {
  const b = createBehalf();
  const m = b.grant({
    principal: "user-1",
    agent: "research-agent",
    can: ["read:calendar", "spend:usd<=50"],
    expiresIn: "1h",
  });

  assert.equal(m.principal, "user-1");
  assert.equal(m.agent, "research-agent");
  assert.ok(m.expiresAt! > Date.now());
  await assert.doesNotReject(m.authorize("read:calendar"));
  await assert.doesNotReject(m.authorize("spend:usd=20"));
});

test("authorize throws when out of scope", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  await assert.rejects(() => m.authorize("write:email"), AuthorizationError);
});

test("authorize throws when over a quantitative limit", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["spend:usd<=50"], expiresIn: "1h" });
  await assert.rejects(() => m.authorize("spend:usd=51"), AuthorizationError);
});

test("expired mandates are denied", async () => {
  let now = 1_000_000;
  const b = createBehalf({ now: () => now });
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  now += 3_600_001;
  await assert.rejects(() => m.authorize("read:calendar"), AuthorizationError);
});

test("a tampered token fails signature verification", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });

  // Forge a wider scope by editing the cap caveat in place.
  const forged = structuredClone(m.token);
  for (const block of forged.blocks)
    for (const c of block.caveats) if (c.t === "cap") c.can = ["*"];
  assert.throws(() => b.verifySignature(forged), IntegrityError);

  // And an advisory check denies it rather than honoring the forgery.
  assert.equal((await b.inspect(forged, "spend:usd=999")).allowed, false);
});

test("serialize / import round-trips", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const restored = b.import(m.serialize());
  assert.equal(restored.id, m.id);
  // The restored (public) token still authorizes when the holder presents a proof.
  await assert.doesNotReject(b.authorize(restored.token, "read:calendar", m.prove()));
});

test("rate limits are enforced across calls", async () => {
  let now = 0;
  const b = createBehalf({ now: () => now });
  const m = b.grant({ principal: "u", agent: "a", can: ["send:email rate<=2/h"], expiresIn: "1d" });

  await assert.doesNotReject(m.authorize("send:email"));
  await assert.doesNotReject(m.authorize("send:email"));
  await assert.rejects(() => m.authorize("send:email"), AuthorizationError);

  // After the window slides, calls are allowed again.
  now += 3_600_001;
  await assert.doesNotReject(m.authorize("send:email"));
});
