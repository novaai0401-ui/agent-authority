import { test } from "node:test";
import assert from "node:assert/strict";
import { lint, isClean } from "../src/lint.js";

test("a tight scope is clean", () => {
  assert.deepEqual(lint(["read:calendar", "spend:usd<=50", "send:email rate<=10/h"]), []);
  assert.ok(isClean(["read:calendar", "spend:usd<=50"]));
});

test("wildcard warns", () => {
  const [f] = lint(["*"]);
  assert.equal(f.level, "warn");
  assert.equal(f.rule, "wildcard");
  assert.ok(!isClean(["*"]));
});

test("an unbounded spend warns", () => {
  const f = lint(["spend:usd"]).find((x) => x.rule === "unbounded-amount");
  assert.ok(f);
  assert.equal(f!.level, "warn");
  assert.match(f!.message, /usd<=50/);
});

test("a rate-less send is an info hint, not a failure", () => {
  const findings = lint(["send:email"]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].level, "info");
  assert.ok(isClean(["send:email"])); // info doesn't fail
});

test("unparseable capabilities are errors", () => {
  const [f] = lint(["nocolon"]);
  assert.equal(f.level, "error");
  assert.equal(f.rule, "unparseable");
});

test("duplicates warn", () => {
  const f = lint(["read:calendar", "read:calendar"]).find((x) => x.rule === "duplicate");
  assert.ok(f);
});
