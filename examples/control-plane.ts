/**
 * Reference integration #5 — the control plane (revocation propagation).
 *
 * Two independent agents point at one control plane. When the first revokes a
 * mandate, the second sees it immediately — the "revoke once, propagates
 * everywhere" model. The same plane retains a single hash-chained audit log.
 *
 *   npm run build && node dist-test/examples/control-plane.js
 */
import { createControlPlane } from "../src/control-plane.js";
import { HttpRevocationStore, HttpAuditStore } from "../src/remote.js";
import { createBehalf } from "../src/behalf.js";
import { newKeyPair } from "../src/crypto.js";

async function main() {
  const plane = createControlPlane();
  const port = await plane.listen(0);
  const base = `http://127.0.0.1:${port}`;
  console.log(`control plane on ${base}\n`);

  // Shared issuer key; two agents in different "processes", same control plane.
  const keyPair = newKeyPair();
  const issuer = createBehalf({
    rootKeyPair: keyPair,
    revocations: new HttpRevocationStore(base),
    audit: new HttpAuditStore(base),
  });
  const worker = createBehalf({
    rootKeyPair: keyPair,
    revocations: new HttpRevocationStore(base),
    audit: new HttpAuditStore(base),
  });

  const mandate = issuer.grant({
    principal: "alice",
    agent: "issuer",
    can: ["read:calendar"],
    expiresIn: "1h",
  });
  // Hand the worker a HOLDER credential (token + delegation key) so it can
  // actually authorize in its own process. Secret — deliver over a secure channel.
  const wire = mandate.serializeWithKey();

  await show(worker, wire, "before revoke");
  console.log("\nissuer revokes via the control plane...\n");
  await issuer.revoke(mandate.id);
  await show(worker, wire, "after revoke");

  // The audit log is centralized — the worker's check is visible to everyone.
  const central = new HttpAuditStore(base);
  const trail = await central.forMandate(mandate.id);
  console.log(`\ncentral audit: ${trail.length} record(s)`);
  for (const e of trail) console.log(`  ${e.decision.padEnd(5)} ${e.action}`);

  await plane.close();
}

async function show(engine: ReturnType<typeof createBehalf>, wire: string, label: string) {
  try {
    await engine.import(wire).authorize("read:calendar");
    console.log(`worker (${label}): ALLOWED`);
  } catch (e) {
    console.log(`worker (${label}): DENIED -> ${(e as Error).message}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
