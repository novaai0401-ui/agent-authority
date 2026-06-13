import { test } from "node:test";
import assert from "node:assert/strict";
import { TokenBucketRateStore, MemoryRateStore } from "../src/store.js";
import { createBehalf } from "../src/behalf.js";

// ---- #5: token-bucket rate limiting (burst-shaping alternative) ----

test("allows an initial burst up to the limit, then denies until refill", () => {
  const rate = new TokenBucketRateStore();
  const now = 1_000_000;
  // capacity 3 over 3000ms => 1 token/sec refill.
  assert.equal(rate.hit("k", 3000, 3, now), true);
  assert.equal(rate.hit("k", 3000, 3, now), true);
  assert.equal(rate.hit("k", 3000, 3, now), true);
  assert.equal(rate.hit("k", 3000, 3, now), false); // bucket empty
});

test("refills continuously over time", () => {
  const rate = new TokenBucketRateStore();
  let now = 0;
  for (let i = 0; i < 5; i++) assert.equal(rate.hit("k", 5000, 5, now), true);
  assert.equal(rate.hit("k", 5000, 5, now), false);
  now += 1000; // 5 per 5000ms => 1 token/sec
  assert.equal(rate.hit("k", 5000, 5, now), true);
  assert.equal(rate.hit("k", 5000, 5, now), false); // only one refilled
});

test("never exceeds capacity even after a long idle", () => {
  const rate = new TokenBucketRateStore();
  assert.equal(rate.hit("k", 1000, 2, 0), true);
  // Idle far longer than the window; bucket caps at `limit`, not unbounded.
  let n = 0;
  for (let i = 0; i < 10; i++) if (rate.hit("k", 1000, 2, 1_000_000)) n++;
  assert.equal(n, 2);
});

test("limit<=0 or window<=0 always denies", () => {
  const rate = new TokenBucketRateStore();
  assert.equal(rate.hit("k", 1000, 0, 0), false);
  assert.equal(rate.hit("k", 0, 5, 0), false);
});

test("keys are independent", () => {
  const rate = new TokenBucketRateStore();
  assert.equal(rate.hit("a", 1000, 1, 0), true);
  assert.equal(rate.hit("a", 1000, 1, 0), false);
  assert.equal(rate.hit("b", 1000, 1, 0), true); // separate bucket
});

test("drops into an engine as the rate store and enforces a cap", async () => {
  let t = 0;
  const issuer = createBehalf({ rate: new TokenBucketRateStore(), now: () => t });
  const m = issuer.grant({
    principal: "u",
    agent: "a",
    can: ["send:email rate<=2/h"],
    expiresIn: "1h",
  });
  await assert.doesNotReject(m.authorize("send:email"));
  await assert.doesNotReject(m.authorize("send:email"));
  await assert.rejects(() => m.authorize("send:email"), /rate limit exceeded/);
});

test("is interchangeable with the sliding store at the interface level", () => {
  const stores = [new MemoryRateStore(), new TokenBucketRateStore()];
  for (const s of stores) {
    assert.equal(s.hit("k", 1000, 1, 0), true);
    assert.equal(s.hit("k", 1000, 1, 0), false);
  }
});
