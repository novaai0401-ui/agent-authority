import { test } from "node:test";
import assert from "node:assert/strict";
import { CachingRateStore, MemoryRateStore, type RateStore } from "../src/store.js";
import { startAuditCheckpointing } from "../src/checkpoint.js";
import { createBehalf } from "../src/behalf.js";
import { createControlPlane } from "../src/control-plane.js";
import type { AuditCheckpoint } from "../src/types.js";

// ---- CachingRateStore: caches denials only (never over-permits) ----

test("CachingRateStore caches a denial and stops calling the inner store", async () => {
  let calls = 0;
  const inner: RateStore = {
    hit() {
      calls++;
      return false; // always "over limit"
    },
  };
  const rate = new CachingRateStore(inner, { ttlMs: 1000 });
  assert.equal(await rate.hit("k", 1000, 1, 0), false);
  assert.equal(calls, 1);
  // Within ttl: served from cache, inner not consulted again.
  assert.equal(await rate.hit("k", 1000, 1, 500), false);
  assert.equal(calls, 1);
  // After ttl: re-consults inner.
  assert.equal(await rate.hit("k", 1000, 1, 1001), false);
  assert.equal(calls, 2);
});

test("CachingRateStore never caches an allow (cap stays authoritative)", async () => {
  let calls = 0;
  const inner: RateStore = {
    hit() {
      calls++;
      return true;
    },
  };
  const rate = new CachingRateStore(inner, { ttlMs: 1000 });
  await rate.hit("k", 1000, 5, 0);
  await rate.hit("k", 1000, 5, 1);
  await rate.hit("k", 1000, 5, 2);
  assert.equal(calls, 3); // every allow consulted the inner store
});

test("CachingRateStore enforces a real cap end-to-end via an engine", async () => {
  let t = 0;
  const rate = new CachingRateStore(new MemoryRateStore(), { ttlMs: 10_000 });
  const issuer = createBehalf({ rate, now: () => t });
  const m = issuer.grant({ principal: "u", agent: "a", can: ["send:email rate<=1/h"], expiresIn: "1h" });
  await assert.doesNotReject(m.authorize("send:email"));
  await assert.rejects(() => m.authorize("send:email"), /rate limit exceeded/);
});

// ---- requireTenant: strict isolation on the control plane ----

async function withPlane(opts: object, fn: (base: string) => Promise<void>): Promise<void> {
  const cp = createControlPlane(opts);
  const port = await cp.listen(0);
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await cp.close();
  }
}

test("requireTenant refuses admin and anonymous, allows tenant tokens", async () => {
  await withPlane(
    { token: "admin-secret", tenants: { "tenant-a": "issuerApub" }, requireTenant: true },
    async (base) => {
      // Anonymous → 401 (no auth at all).
      assert.equal((await fetch(`${base}/v1/revoked`)).status, 401);
      // Admin token → 403 (admin is not a tenant under requireTenant).
      const admin = await fetch(`${base}/v1/revoked`, { headers: { authorization: "Bearer admin-secret" } });
      assert.equal(admin.status, 403);
      // Tenant token → OK.
      const tenant = await fetch(`${base}/v1/revoked`, { headers: { authorization: "Bearer tenant-a" } });
      assert.equal(tenant.status, 200);
    },
  );
});

// ---- startAuditCheckpointing: periodic anchoring ----

test("startAuditCheckpointing emits verifiable checkpoints to the sink", async () => {
  const engine = createBehalf();
  const m = engine.grant({ principal: "u", agent: "a", can: ["read:x"], expiresIn: "1h" });
  await m.authorize("read:x"); // write an audit record

  const got: AuditCheckpoint[] = [];
  const stop = startAuditCheckpointing(engine, {
    intervalMs: 5,
    sink: (cp) => {
      got.push(cp);
    },
  });
  await new Promise((r) => setTimeout(r, 30));
  stop();
  assert.ok(got.length >= 1, "expected at least one checkpoint");
  // The emitted checkpoint verifies against the engine's own log.
  const { ok } = await engine.verifyAuditCheckpoint(got[got.length - 1]);
  assert.equal(ok, true);
});
