import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createBehalf } from "../src/behalf.js";
import type { MandateToken, Proof } from "../src/types.js";

// Shared cross-language fixture: a mandate + action + possession proof generated
// once and committed. Both the TS and Python suites load THIS file and must
// agree on canonicalization, the signature chain, and the proof — structurally
// guaranteeing the two ports stay wire-compatible (L-1).
interface Vector {
  action: string;
  pubkey: string;
  token: MandateToken;
  proof: Proof;
}

// Compiled to dist-test/test/, so the repo-root vectors/ dir is two levels up.
const vectorPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "vectors",
  "mandate-vector.json",
);
const vector = JSON.parse(readFileSync(vectorPath, "utf8")) as Vector;

test("the committed cross-language vector authorizes", async () => {
  // Pin the clock to the proof's timestamp so freshness/expiry are deterministic.
  const verifier = createBehalf({ trust: [vector.pubkey], now: () => vector.proof.ts });
  await assert.doesNotReject(verifier.authorize(vector.token, vector.action, vector.proof));
});

test("tampering the committed vector is rejected", async () => {
  const verifier = createBehalf({ trust: [vector.pubkey], now: () => vector.proof.ts });

  // Widen a cap in place → signature chain no longer verifies.
  const forged = structuredClone(vector.token);
  for (const block of forged.blocks)
    for (const c of block.caveats) if (c.t === "cap") c.can = ["*"];
  assert.equal((await verifier.inspect(forged, vector.action)).allowed, false);

  // A different action than the proof was bound to → possession proof fails.
  await assert.rejects(
    () => verifier.authorize(vector.token, "spend:usd=20", vector.proof),
    /possession proof/,
  );
});
