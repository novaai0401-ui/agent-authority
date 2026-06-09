import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBehalf } from "../src/behalf.js";
import { FileRevocationStore, FileAuditStore } from "../src/persist.js";
import { AuthorizationError } from "../src/errors.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "behalf-"));
}

test("revocation persists across engine instances", async () => {
  const dir = tmp();
  try {
    const keyPair = (await import("../src/crypto.js")).newKeyPair();
    const revPath = join(dir, "revocations.json");

    const a = createBehalf({ rootKeyPair: keyPair, revocations: new FileRevocationStore(revPath) });
    const m = a.grant({ principal: "u", agent: "ag", can: ["read:calendar"], expiresIn: "1h" });
    const wire = m.serialize();
    await a.revoke(m.id);

    // A brand-new engine reading the same file sees the revocation.
    const b = createBehalf({ rootKeyPair: keyPair, revocations: new FileRevocationStore(revPath) });
    await assert.rejects(() => b.import(wire).authorize("read:calendar"), AuthorizationError);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("audit entries persist and remain tamper-evident on disk", async () => {
  const dir = tmp();
  try {
    const auditPath = join(dir, "audit.jsonl");
    const a = createBehalf({ audit: new FileAuditStore(auditPath) });
    const m = a.grant({ principal: "u", agent: "ag", can: ["read:calendar"], expiresIn: "1h" });
    await m.authorize("read:calendar");
    await m.authorize("read:calendar");

    // Reload from disk in a fresh store and verify the hash chain.
    const reloaded = new FileAuditStore(auditPath);
    const entries = reloaded.all();
    assert.equal(entries.length, 2);
    const { verify } = await import("../src/audit.js");
    assert.ok(verify(entries).ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
