import { test } from "node:test";
import assert from "node:assert/strict";
import { parse, permits, satisfies, isNarrowing } from "../src/capability.js";

test("parses a simple capability", () => {
  const c = parse("read:calendar");
  assert.equal(c.verb, "read");
  assert.equal(c.resource, "calendar");
  assert.equal(c.amount, undefined);
});

test("parses a quantitative limit", () => {
  const c = parse("spend:usd<=50");
  assert.equal(c.verb, "spend");
  assert.equal(c.resource, "usd");
  assert.deepEqual(c.amount, { op: "<=", value: 50 });
});

test("parses a rate limit with unit", () => {
  const c = parse("send:email rate<=10/h");
  assert.equal(c.verb, "send");
  assert.equal(c.resource, "email");
  assert.deepEqual(c.rate, { op: "<=", value: 10, per: "h" });
});

test("parses resource paths", () => {
  const c = parse("write:repo/acme-app");
  assert.equal(c.resource, "repo/acme-app");
});

test("rejects malformed capabilities", () => {
  assert.throws(() => parse(""));
  assert.throws(() => parse("nocolon"));
});

test("amount satisfaction respects the cap", () => {
  assert.ok(permits("spend:usd<=50", "spend:usd=20"));
  assert.ok(permits("spend:usd<=50", "spend:usd=50"));
  assert.ok(!permits("spend:usd<=50", "spend:usd=51"));
});

test("an unbounded request never satisfies a bounded grant", () => {
  assert.ok(!permits("spend:usd<=50", "spend:usd"));
});

test("resource path is segment-prefix covered", () => {
  assert.ok(permits("write:repo", "write:repo/acme-app"));
  assert.ok(!permits("write:repo/acme-app", "write:repo/other"));
});

test("wildcard grant permits anything", () => {
  assert.ok(permits("*", "spend:usd=999"));
  assert.ok(satisfies(parse("*"), parse("anything:goes")));
});

test("isNarrowing accepts a tighter scope and rejects a wider one", () => {
  assert.ok(isNarrowing(["spend:usd<=50", "read:calendar"], ["read:calendar"]).ok);
  assert.ok(isNarrowing(["spend:usd<=50"], ["spend:usd<=20"]).ok);

  const wider = isNarrowing(["spend:usd<=50"], ["spend:usd<=80"]);
  assert.ok(!wider.ok);
  assert.equal(wider.offending, "spend:usd<=80");

  const newScope = isNarrowing(["read:calendar"], ["write:email"]);
  assert.ok(!newScope.ok);
});
