/**
 * Reference integration #3 — two-agent delegation.
 *
 * An orchestrator agent holds a broad mandate and delegates a strictly narrower
 * one to a worker sub-agent. The worker can do its slice of the job and nothing
 * more — and revoking the orchestrator instantly kills the worker too.
 *
 *   npm run build && node dist-test/examples/two-agent-delegation.js
 */
import { createBehalf } from "../src/behalf.js";

async function main() {
  const behalf = createBehalf();

  // 1. GRANT — the orchestrator may read the calendar and spend up to $50.
  const orchestrator = behalf.grant({
    principal: "carol",
    agent: "orchestrator",
    can: ["read:calendar", "spend:usd<=50"],
    expiresIn: "1h",
  });
  console.log("orchestrator can: read:calendar, spend:usd<=50");

  // 3. DELEGATE — hand the booking worker a narrowed, short-lived mandate.
  const worker = orchestrator.attenuate({
    agent: "booking-worker",
    can: ["spend:usd<=20"],
    expiresIn: "10m",
  });
  console.log("worker can: spend:usd<=20 (calendar access dropped)\n");

  await show(worker, "spend:usd=15"); // allowed
  await show(worker, "spend:usd=30"); // DENIED — above the worker's tighter cap
  await show(worker, "read:calendar"); // DENIED — never delegated

  // The worker cannot widen its own authority back up.
  try {
    worker.attenuate({ can: ["spend:usd<=50"] });
  } catch (e) {
    console.log(`\nworker attempt to widen: BLOCKED -> ${(e as Error).message}`);
  }

  // 4. REVOKE — killing the orchestrator cascades to the worker.
  await behalf.revoke(orchestrator.id);
  console.log("\nrevoked orchestrator:");
  await show(orchestrator, "read:calendar");
  await show(worker, "spend:usd=5");
}

async function show(mandate: { authorize(a: string): Promise<void> }, action: string) {
  try {
    await mandate.authorize(action);
    console.log(`  ${action}: allowed`);
  } catch (e) {
    console.log(`  ${action}: DENIED -> ${(e as Error).message}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
