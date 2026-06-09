import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { AuthorizationError, IntegrityError } from "../src/errors.js";

test("a separate verifier checks a presented mandate with only the issuer public key", async () => {
  const issuer = createBehalf();
  const mandate = issuer.grant({
    principal: "u",
    agent: "a",
    can: ["read:calendar", "spend:usd<=50"],
    expiresIn: "1h",
  });

  // The verifier holds NO secret — just the issuer's public key. The holder
  // presents the token plus a proof of possession of its terminal key.
  const verifier = createBehalf({ trust: [issuer.publicKey] });
  await assert.doesNotReject(verifier.authorize(mandate.token, "spend:usd=20", mandate.prove()));
  await assert.rejects(
    () => verifier.authorize(mandate.token, "spend:usd=60", mandate.prove()),
    AuthorizationError,
  );
});

test("a verifier rejects a mandate from an untrusted issuer", async () => {
  const issuer = createBehalf();
  const mandate = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });

  const stranger = createBehalf(); // trusts only its own key
  await assert.rejects(
    () => stranger.authorize(mandate.token, "read:calendar", mandate.prove()),
    AuthorizationError,
  );
  assert.throws(() => stranger.verifySignature(mandate.token), IntegrityError);
});

test("an attenuated chain verifies under the same issuer key", async () => {
  const issuer = createBehalf();
  const root = issuer.grant({ principal: "u", agent: "a1", can: ["spend:usd<=50"], expiresIn: "1h" });
  const child = root.attenuate({ can: ["spend:usd<=10"], agent: "a2" });

  const verifier = createBehalf({ trust: [issuer.publicKey] });
  await assert.doesNotReject(verifier.authorize(child.token, "spend:usd=10", child.prove()));
  await assert.rejects(
    () => verifier.authorize(child.token, "spend:usd=11", child.prove()),
    AuthorizationError,
  );
});

test("truncating the chain to recover a parent's scope is denied (C-1)", async () => {
  const issuer = createBehalf();
  const root = issuer.grant({
    principal: "u",
    agent: "a1",
    can: ["read:calendar", "spend:usd<=50"],
    expiresIn: "1h",
  });
  // Sub-agent narrowed to read-only; it holds the full chain + its own key.
  const child = root.attenuate({ can: ["read:calendar"], agent: "a2" });

  const verifier = createBehalf({ trust: [issuer.publicKey] });

  // Honest use works.
  await assert.doesNotReject(verifier.authorize(child.token, "read:calendar", child.prove()));
  // The child must not be able to spend (its block dropped that).
  await assert.rejects(
    () => verifier.authorize(child.token, "spend:usd=50", child.prove()),
    AuthorizationError,
  );

  // Attack: drop the trailing narrowing block to expose the root's wider scope.
  const truncated = {
    v: 2 as const,
    id: child.token.id,
    blocks: [child.token.blocks[0]],
    sigs: [child.token.sigs[0]],
    rootPub: child.token.rootPub,
  };
  // The truncated prefix verifies as a chain, but the child cannot produce a
  // possession proof for it (it lacks the root block's terminal key), so any
  // proof it can make is for the full chain and won't match the prefix.
  await assert.rejects(
    () => verifier.authorize(truncated, "spend:usd=50", child.prove()),
    AuthorizationError,
  );
  // Even reusing nothing: an empty/no proof is refused outright.
  await assert.rejects(() => verifier.authorize(truncated, "spend:usd=50"), AuthorizationError);
});

test("an imported mandate cannot be delegated (no delegation key)", async () => {
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  assert.equal(m.canDelegate, true);

  const imported = issuer.import(m.serialize());
  assert.equal(imported.canDelegate, false);
  assert.throws(() => imported.attenuate({ can: ["read:calendar"] }));
  // ...nor authorized as a holder (no key to prove possession).
  await assert.rejects(() => imported.authorize("read:calendar"));
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
