import { test } from "node:test";
import assert from "node:assert/strict";
import { CachingRevocationStore, type RevocationStore } from "../src/store.js";

/** A counting inner store so we can assert how often it's consulted. */
function countingInner(revoked = new Set<string>()) {
  const calls = { isRevoked: 0, revoke: 0 };
  const inner: RevocationStore = {
    revoke(id) {
      calls.revoke++;
      revoked.add(id);
    },
    isRevoked(id) {
      calls.isRevoked++;
      return revoked.has(id);
    },
  };
  return { inner, calls, revoked };
}

test("a not-revoked answer is cached within the TTL", async () => {
  let now = 0;
  const { inner, calls } = countingInner();
  const cache = new CachingRevocationStore(inner, { ttlMs: 1000, now: () => now });

  assert.equal(await cache.isRevoked("m"), false);
  assert.equal(await cache.isRevoked("m"), false);
  assert.equal(calls.isRevoked, 1, "second check served from cache");

  now = 1001; // TTL expired
  assert.equal(await cache.isRevoked("m"), false);
  assert.equal(calls.isRevoked, 2, "re-checked after the staleness window");
});

test("a revoked answer is cached permanently (no further checks)", async () => {
  let now = 0;
  const { inner, calls, revoked } = countingInner();
  revoked.add("bad");
  const cache = new CachingRevocationStore(inner, { ttlMs: 1000, now: () => now });

  assert.equal(await cache.isRevoked("bad"), true);
  now = 999_999;
  assert.equal(await cache.isRevoked("bad"), true);
  assert.equal(calls.isRevoked, 1, "revocation is monotonic — never re-checked");
});

test("revoke writes through and is reflected immediately", async () => {
  const { inner, calls } = countingInner();
  const cache = new CachingRevocationStore(inner, { ttlMs: 60_000 });

  await cache.revoke("x");
  assert.equal(calls.revoke, 1);
  assert.equal(await cache.isRevoked("x"), true);
  assert.equal(calls.isRevoked, 0, "served from the write-through cache, no inner check");
});

test("revoke invalidates a prior not-revoked cache entry", async () => {
  const { inner } = countingInner();
  const cache = new CachingRevocationStore(inner, { ttlMs: 60_000 });

  assert.equal(await cache.isRevoked("y"), false); // negatively cached
  await cache.revoke("y");
  assert.equal(await cache.isRevoked("y"), true); // positive cache now wins
});
