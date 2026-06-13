import { test } from "node:test";
import assert from "node:assert/strict";
import { newSealKeyPair, seal, unseal } from "../src/seal.js";
import { createBehalf } from "../src/behalf.js";

// ---- #8: sealed holder credentials (encrypt serializeWithKey to a recipient) ----

test("seal/unseal round-trips for the intended recipient", () => {
  const kp = newSealKeyPair();
  const msg = "holder-credential-" + "x".repeat(80);
  assert.equal(unseal(seal(msg, kp.publicKey), kp), msg);
});

test("a different recipient cannot open the seal", () => {
  const kp = newSealKeyPair();
  const other = newSealKeyPair();
  const sealed = seal("secret", kp.publicKey);
  assert.throws(() => unseal(sealed, other));
});

test("tampering the ciphertext is rejected (AEAD)", () => {
  const kp = newSealKeyPair();
  const sealed = seal("secret", kp.publicKey);
  const wire = JSON.parse(Buffer.from(sealed, "base64url").toString("utf8"));
  const ct = Buffer.from(wire.ct, "base64url");
  ct[0] ^= 0xff; // flip a bit
  wire.ct = ct.toString("base64url");
  const tampered = Buffer.from(JSON.stringify(wire), "utf8").toString("base64url");
  assert.throws(() => unseal(tampered, kp));
});

test("malformed / wrong-version input is rejected", () => {
  const kp = newSealKeyPair();
  assert.throws(() => unseal("not-base64-json!!", kp), /malformed/);
  const badVer = Buffer.from(JSON.stringify({ v: "seal-9" }), "utf8").toString("base64url");
  assert.throws(() => unseal(badVer, kp), /unsupported or malformed/);
});

test("each seal of the same plaintext differs (ephemeral key + nonce)", () => {
  const kp = newSealKeyPair();
  assert.notEqual(seal("same", kp.publicKey), seal("same", kp.publicKey));
});

test("end-to-end: sealForRecipient -> importSealed -> authorize", async () => {
  const recipient = newSealKeyPair();
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });

  // Sender seals the holder credential to the recipient's public key.
  const sealed = m.sealForRecipient(recipient.publicKey);

  // Recipient (a verifier trusting the issuer) opens and uses it.
  const verifier = createBehalf({ trust: [issuer.publicKey] });
  const opened = verifier.importSealed(sealed, recipient);
  assert.equal(opened.canDelegate, true);
  assert.equal(opened.id, m.id);
  await assert.doesNotReject(opened.authorize("read:calendar"));

  // The wrong recipient cannot open it, so cannot use it.
  const wrong = newSealKeyPair();
  assert.throws(() => verifier.importSealed(sealed, wrong));
});
