import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBehalf } from "../src/behalf.js";
import { FileAuditStore } from "../src/persist.js";
import { AuthorizationError, BehalfError } from "../src/errors.js";

// ---- B5: issuer key rotation with overlap ----

test("rotation keeps old mandates valid through the overlap, then retires them", async () => {
  const v1 = createBehalf();
  const oldMandate = v1.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });

  // Rotate: fresh key, same stores, old key still trusted.
  const v2 = v1.rotate();
  assert.notEqual(v2.publicKey, v1.publicKey);
  assert.ok(v2.trustedKeys.includes(v1.publicKey));

  // During the overlap the rotated engine accepts old AND new mandates.
  await assert.doesNotReject(
    v2.authorize(oldMandate.token, "read:calendar", oldMandate.prove("read:calendar")),
  );
  const newMandate = v2.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  assert.equal(newMandate.token.rootPub, v2.publicKey); // new grants use the new key
  await assert.doesNotReject(newMandate.authorize("read:calendar"));

  // End the overlap: old-key mandates are no longer accepted; new ones still are.
  assert.equal(v2.untrustKey(v1.publicKey), true);
  await assert.rejects(
    () => v2.authorize(oldMandate.token, "read:calendar", oldMandate.prove("read:calendar")),
    AuthorizationError,
  );
  await assert.doesNotReject(newMandate.authorize("read:calendar"));
});

test("an engine refuses to untrust its own key", () => {
  const e = createBehalf();
  assert.throws(() => e.untrustKey(e.publicKey), BehalfError);
});

test("verifiers follow a rotation by trusting both keys, then dropping the old", async () => {
  const v1 = createBehalf();
  const v2 = v1.rotate();
  const verifier = createBehalf({ trust: [v1.publicKey, v2.publicKey] });

  const oldM = v1.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const newM = v2.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  await assert.doesNotReject(verifier.authorize(oldM.token, "read:calendar", oldM.prove("read:calendar")));
  await assert.doesNotReject(verifier.authorize(newM.token, "read:calendar", newM.prove("read:calendar")));

  verifier.untrustKey(v1.publicKey);
  await assert.rejects(
    () => verifier.authorize(oldM.token, "read:calendar", oldM.prove("read:calendar")),
    AuthorizationError,
  );
});

// ---- C4: signed audit checkpoints ----

test("a signed checkpoint detects audit tail-deletion", async () => {
  const dir = mkdtempSync(join(tmpdir(), "behalf-cp-"));
  try {
    const path = join(dir, "audit.jsonl");
    const keyPair = (await import("../src/crypto.js")).newKeyPair();
    const a = createBehalf({ rootKeyPair: keyPair, audit: new FileAuditStore(path) });
    const m = a.grant({ principal: "u", agent: "x", can: ["read:calendar"], expiresIn: "1h" });
    await m.authorize("read:calendar");
    await m.authorize("read:calendar");
    await m.authorize("read:calendar");

    const checkpoint = await a.checkpointAudit();
    assert.equal((await a.verifyAuditCheckpoint(checkpoint)).ok, true);

    // Adversary with write access deletes the newest entry: the bare hash
    // chain still verifies, but the checkpoint exposes the deletion.
    const lines = readFileSync(path, "utf8").trim().split("\n");
    writeFileSync(path, lines.slice(0, -1).join("\n") + "\n", "utf8");
    const b = createBehalf({ rootKeyPair: keyPair, audit: new FileAuditStore(path) });
    assert.equal((await b.verifyAuditLog()).ok, true, "unkeyed chain cannot see tail deletion");
    const result = await b.verifyAuditCheckpoint(checkpoint);
    assert.equal(result.ok, false);
    assert.match(result.reason ?? "", /missing or rewritten/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a checkpoint from an untrusted signer is rejected", async () => {
  const a = createBehalf();
  const stranger = createBehalf();
  const checkpoint = await stranger.checkpointAudit();
  const result = await a.verifyAuditCheckpoint(checkpoint);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /not trusted/);
});
