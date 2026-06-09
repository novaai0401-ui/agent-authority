import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { AuthorizationError, WideningError } from "../src/errors.js";

test("attenuation narrows scope for a sub-agent", async () => {
  const b = createBehalf();
  const parent = b.grant({
    principal: "u",
    agent: "orchestrator",
    can: ["read:calendar", "spend:usd<=50"],
    expiresIn: "1h",
  });

  const child = parent.attenuate({ can: ["read:calendar"], expiresIn: "10m", agent: "sub" });
  assert.equal(child.agent, "sub");
  assert.notEqual(child.id, parent.id);
  assert.equal(child.chain[0], parent.id); // shares the root

  await assert.doesNotReject(child.authorize("read:calendar"));
  // The narrowing dropped spend authority entirely.
  await assert.rejects(() => child.authorize("spend:usd=10"), AuthorizationError);
});

test("attenuation can tighten a quantitative limit", async () => {
  const b = createBehalf();
  const parent = b.grant({ principal: "u", agent: "a", can: ["spend:usd<=50"], expiresIn: "1h" });
  const child = parent.attenuate({ can: ["spend:usd<=20"] });

  await assert.doesNotReject(child.authorize("spend:usd=20"));
  await assert.rejects(() => child.authorize("spend:usd=21"), AuthorizationError);
});

test("attenuation cannot widen (eager check)", () => {
  const b = createBehalf();
  const parent = b.grant({ principal: "u", agent: "a", can: ["spend:usd<=50"], expiresIn: "1h" });
  assert.throws(() => parent.attenuate({ can: ["spend:usd<=80"] }), WideningError);
  assert.throws(() => parent.attenuate({ can: ["write:email"] }), WideningError);
});

test("two-hop delegation keeps the intersection (no splicing)", async () => {
  const b = createBehalf();
  const root = b.grant({
    principal: "u",
    agent: "a1",
    can: ["read:calendar", "spend:usd<=50"],
    expiresIn: "1h",
  });
  const mid = root.attenuate({ can: ["spend:usd<=30"], agent: "a2" });
  const leaf = mid.attenuate({ can: ["spend:usd<=10"], agent: "a3" });

  await assert.doesNotReject(leaf.authorize("spend:usd=10"));
  await assert.rejects(() => leaf.authorize("spend:usd=11"), AuthorizationError);
  await assert.rejects(() => leaf.authorize("read:calendar"), AuthorizationError);
});

test("a compromised middle agent cannot forge a wider child", async () => {
  const b = createBehalf();
  const root = b.grant({ principal: "u", agent: "a1", can: ["spend:usd<=10"], expiresIn: "1h" });
  const mid = root.attenuate({ can: ["spend:usd<=10"], agent: "a2" });

  // Attacker hand-edits the leaf token to inject a wider cap caveat, bypassing
  // the eager check. The signature chain no longer verifies, so it is denied.
  const forged = structuredClone(mid.token);
  forged.blocks[forged.blocks.length - 1].caveats.push({ t: "cap", can: ["spend:usd<=10000"] });
  const tampered = b.import(Buffer.from(JSON.stringify(forged)).toString("base64url"));
  await assert.rejects(() => tampered.authorize("spend:usd=9999"), AuthorizationError);

  // Appending a brand-new block without a valid signature is also rejected.
  const spliced = structuredClone(mid.token);
  spliced.blocks.push({ caveats: [{ t: "cap", can: ["spend:usd<=10000"] }], nextPub: spliced.rootPub });
  spliced.sigs.push("AAAA");
  const splicedM = b.import(Buffer.from(JSON.stringify(spliced)).toString("base64url"));
  await assert.rejects(() => splicedM.authorize("spend:usd=9999"), AuthorizationError);
});
