import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { verify } from "../src/audit.js";

test("every authorize writes an audit record", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });

  await m.authorize("read:calendar");
  try {
    await m.authorize("write:email");
  } catch {
    /* expected deny */
  }

  const trail = await m.audit();
  assert.equal(trail.length, 2);
  assert.equal(trail[0].decision, "allow");
  assert.equal(trail[1].decision, "deny");
  assert.equal(trail[1].action, "write:email");
});

test("the audit log is tamper-evident", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  await m.authorize("read:calendar");
  await m.authorize("read:calendar");

  const integrity = await b.verifyAuditLog();
  assert.ok(integrity.ok);

  // Mutating an entry breaks the hash chain.
  const entries = await m.audit();
  entries[0].decision = "deny";
  const broken = verify(entries);
  assert.ok(!broken.ok);
  assert.equal(broken.brokenAt, 0);
});

test("audit trail follows the delegation chain", async () => {
  const b = createBehalf();
  const root = b.grant({ principal: "u", agent: "a1", can: ["read:calendar"], expiresIn: "1h" });
  const child = root.attenuate({ can: ["read:calendar"], agent: "a2" });
  await child.authorize("read:calendar");

  // The child's action is visible from the root's vantage (shared chain).
  const rootView = await root.audit();
  assert.ok(rootView.some((e) => e.action === "read:calendar"));
});
