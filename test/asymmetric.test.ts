import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { AuthorizationError, IntegrityError } from "../src/errors.js";

test("a separate verifier checks a mandate with only the issuer public key", async () => {
  const issuer = createBehalf();
  const mandate = issuer.grant({
    principal: "u",
    agent: "a",
    can: ["read:calendar", "spend:usd<=50"],
    expiresIn: "1h",
  });

  // The verifier holds NO secret — just the issuer's public key.
  const verifier = createBehalf({ trust: [issuer.publicKey] });
  const received = verifier.import(mandate.serialize());

  await assert.doesNotReject(received.authorize("spend:usd=20"));
  await assert.rejects(() => received.authorize("spend:usd=60"), AuthorizationError);
});

test("a verifier rejects a mandate from an untrusted issuer", async () => {
  const issuer = createBehalf();
  const mandate = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });

  const stranger = createBehalf(); // trusts only its own key
  const received = stranger.import(mandate.serialize());
  await assert.rejects(() => received.authorize("read:calendar"), AuthorizationError);
  assert.throws(() => stranger.verifySignature(received.token), IntegrityError);
});

test("an attenuated chain verifies under the same issuer key", async () => {
  const issuer = createBehalf();
  const root = issuer.grant({ principal: "u", agent: "a1", can: ["spend:usd<=50"], expiresIn: "1h" });
  const child = root.attenuate({ can: ["spend:usd<=10"], agent: "a2" });

  const verifier = createBehalf({ trust: [issuer.publicKey] });
  const received = verifier.import(child.serialize());
  await assert.doesNotReject(received.authorize("spend:usd=10"));
  await assert.rejects(() => received.authorize("spend:usd=11"), AuthorizationError);
});

test("an imported mandate cannot be delegated (no delegation key)", () => {
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  assert.equal(m.canDelegate, true);

  const imported = issuer.import(m.serialize());
  assert.equal(imported.canDelegate, false);
  assert.throws(() => imported.attenuate({ can: ["read:calendar"] }));
});

test("serialize never leaks a private key", () => {
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const wire = Buffer.from(m.serialize(), "base64url").toString("utf8");
  // PKCS8 private keys are large; the public token should not contain one.
  assert.ok(!/PRIVATE/i.test(wire));
  const parsed = JSON.parse(wire);
  assert.equal(parsed.v, 2);
  assert.ok(Array.isArray(parsed.blocks));
  assert.ok(Array.isArray(parsed.sigs));
});
