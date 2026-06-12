import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { createControlPlane } from "../src/control-plane.js";
import {
  HttpRevocationStore,
  HttpRateStore,
  HttpAuditStore,
  ControlPlaneClient,
} from "../src/remote.js";
import { newKeyPair, exportPublicKey } from "../src/crypto.js";
import { AuthorizationError } from "../src/errors.js";

async function withControlPlane(
  fn: (base: string) => Promise<void>,
  opts = {},
): Promise<void> {
  const cp = createControlPlane(opts);
  const port = await cp.listen(0);
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await cp.close();
  }
}

// ---- C2: verifier-issued single-use nonce ----

test("a nonce-bound proof is single-use (replay is denied)", async () => {
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const verifier = createBehalf({ trust: [issuer.publicKey] });

  const nonce = verifier.challenge();
  const proof = m.prove("read:calendar", { nonce });
  await assert.doesNotReject(verifier.authorize(m.token, "read:calendar", proof));
  // Exact replay of the captured proof: the nonce was consumed.
  await assert.rejects(
    () => verifier.authorize(m.token, "read:calendar", proof),
    /already-used nonce/,
  );
  // A made-up nonce is also rejected.
  const fake = m.prove("read:calendar", { nonce: "not-issued" });
  await assert.rejects(() => verifier.authorize(m.token, "read:calendar", fake), AuthorizationError);
});

test("requireNonce engines refuse plain (nonce-less) proofs", async () => {
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const verifier = createBehalf({ trust: [issuer.publicKey], requireNonce: true });

  await assert.rejects(
    () => verifier.authorize(m.token, "read:calendar", m.prove("read:calendar")),
    /nonce required/,
  );
  const nonce = verifier.challenge();
  await assert.doesNotReject(
    verifier.authorize(m.token, "read:calendar", m.prove("read:calendar", { nonce })),
  );
});

test("the in-process holder path works under requireNonce (self-challenge)", async () => {
  const engine = createBehalf({ requireNonce: true });
  const m = engine.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  await assert.doesNotReject(m.authorize("read:calendar"));
});

// ---- B1: tenant isolation of revocation / rate / consent ----

test("tenant revocations are namespaced; admin revocations are global", async () => {
  const kpA = newKeyPair();
  const kpB = newKeyPair();
  const issuerA = exportPublicKey(kpA.publicKey);
  const issuerB = exportPublicKey(kpB.publicKey);
  await withControlPlane(
    async (base) => {
      const revA = new HttpRevocationStore(base, { token: "tokA" });
      const revB = new HttpRevocationStore(base, { token: "tokB" });
      const revAdmin = new HttpRevocationStore(base, { token: "admintok" });

      // Tenant A revokes an id: A sees it, B does NOT (no cross-tenant DoS).
      await revA.revoke("shared-id");
      assert.equal(await revA.isRevoked("shared-id"), true);
      assert.equal(await revB.isRevoked("shared-id"), false);

      // Admin revocations are global: every tenant sees them.
      await revAdmin.revoke("global-id");
      assert.equal(await revA.isRevoked("global-id"), true);
      assert.equal(await revB.isRevoked("global-id"), true);
    },
    { tenants: { tokA: issuerA, tokB: issuerB }, token: "admintok" },
  );
});

test("tenant rate caps are isolated per issuer", async () => {
  const kpA = newKeyPair();
  const kpB = newKeyPair();
  await withControlPlane(
    async (base) => {
      const a = createBehalf({ rootKeyPair: kpA, rate: new HttpRateStore(base, { token: "tokA" }) });
      const b = createBehalf({ rootKeyPair: kpB, rate: new HttpRateStore(base, { token: "tokB" }) });
      const mA = a.grant({ principal: "u", agent: "x", can: ["send:email rate<=1/h"], expiresIn: "1h" });
      const mB = b.grant({ principal: "u", agent: "y", can: ["send:email rate<=1/h"], expiresIn: "1h" });

      await assert.doesNotReject(mA.authorize("send:email"));
      // B has its own budget even though the raw rate key would collide.
      await assert.doesNotReject(mB.authorize("send:email"));
      await assert.rejects(() => mA.authorize("send:email"), AuthorizationError);
    },
    { tenants: { tokA: exportPublicKey(kpA.publicKey), tokB: exportPublicKey(kpB.publicKey) } },
  );
});

test("tenant consent records are invisible and undecidable across tenants", async () => {
  await withControlPlane(
    async (base) => {
      const a = new ControlPlaneClient(base, { token: "tokA" });
      const b = new ControlPlaneClient(base, { token: "tokB" });
      const rec = await a.requestConsent("agent-a", "write:email");

      await assert.rejects(() => b.getConsent(rec.id)); // 404 for the other tenant
      await assert.rejects(() => b.decideConsent(rec.id, true));
      assert.equal((await a.getConsent(rec.id)).status, "pending"); // untouched
    },
    { tenants: { tokA: "issuerA", tokB: "issuerB" } },
  );
});

// ---- B3: consent TTL ----

test("pending consent expires after the TTL and the provider denies it", async () => {
  await withControlPlane(
    async (base) => {
      const client = new ControlPlaneClient(base);
      const rec = await client.requestConsent("agent", "write:email");
      await new Promise((r) => setTimeout(r, 30));
      const after = await client.getConsent(rec.id);
      assert.equal(after.status, "expired");
      // Deciding an expired request does not resurrect it.
      const decided = await client.decideConsent(rec.id, true);
      assert.equal(decided.status, "expired");
    },
    { consentTtlMs: 10 },
  );
});

// ---- B4: audit pagination ----

test("audit queries paginate with limit/offset and report total", async () => {
  await withControlPlane(async (base) => {
    const engine = createBehalf({ audit: new HttpAuditStore(base) });
    const m = engine.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
    for (let i = 0; i < 5; i++) await m.authorize("read:calendar");

    const page = (await (
      await fetch(`${base}/v1/audit?offset=1&limit=2`)
    ).json()) as { entries: { seq: number }[]; total: number };
    assert.equal(page.total, 5);
    assert.deepEqual(
      page.entries.map((e) => e.seq),
      [1, 2],
    );
  });
});
