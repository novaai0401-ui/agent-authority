import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { AuthorizationError } from "../src/errors.js";

test("revoking a mandate denies further use", async () => {
  const b = createBehalf();
  const m = b.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  await assert.doesNotReject(m.authorize("read:calendar"));

  await m.revoke();
  await assert.rejects(() => m.authorize("read:calendar"), AuthorizationError);
});

test("revoking the root kills the entire downstream chain", async () => {
  const b = createBehalf();
  const root = b.grant({ principal: "u", agent: "a1", can: ["read:calendar"], expiresIn: "1h" });
  const child = root.attenuate({ can: ["read:calendar"], agent: "a2" });
  const grandchild = child.attenuate({ can: ["read:calendar"], agent: "a3" });

  await b.revoke(root.id);

  await assert.rejects(() => root.authorize("read:calendar"), AuthorizationError);
  await assert.rejects(() => child.authorize("read:calendar"), AuthorizationError);
  await assert.rejects(() => grandchild.authorize("read:calendar"), AuthorizationError);
});

test("revoking a child leaves the parent and siblings intact", async () => {
  const b = createBehalf();
  const root = b.grant({ principal: "u", agent: "a1", can: ["read:calendar"], expiresIn: "1h" });
  const childA = root.attenuate({ can: ["read:calendar"], agent: "a2" });
  const childB = root.attenuate({ can: ["read:calendar"], agent: "a3" });

  await childA.revoke();

  await assert.rejects(() => childA.authorize("read:calendar"), AuthorizationError);
  await assert.doesNotReject(() => childB.authorize("read:calendar"));
  await assert.doesNotReject(() => root.authorize("read:calendar"));
});
