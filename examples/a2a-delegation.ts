/**
 * Reference integration #4 — agent-to-agent (A2A) delegation over HTTP.
 *
 * A "planner" agent holds a broad mandate from a user. It calls a remote
 * "payments" agent, attenuating its mandate on the way out so the callee gets
 * strictly less authority. The payments agent trusts only the issuer's PUBLIC
 * key and verifies the whole delegation chain offline before acting.
 *
 *   npm run build && node dist-test/examples/a2a-delegation.js
 */
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createBehalf } from "../src/behalf.js";
import { behalfFetch, guard, type GuardedRequest } from "../src/a2a.js";

async function main() {
  // The user's issuer. Its public key is all the payments agent needs to trust.
  const issuer = createBehalf();

  // ---- The remote payments agent (a separate trust domain) ----
  const payments = createBehalf({ trust: [issuer.publicKey] });
  const gate = guard({
    engine: payments,
    // This endpoint requires authority to spend exactly $40.
    capability: () => "spend:usd=40",
  });
  const server = createServer(async (req: GuardedRequest, res) => {
    if (!(await gate(req, res))) return; // 403 already written
    res.statusCode = 200;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ charged: 40, by: req.mandate?.agent }));
  });
  await new Promise<void>((r) => server.listen(0, r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/charge`;

  // ---- The planner agent ----
  const planner = issuer.grant({
    principal: "alice",
    agent: "planner",
    can: ["read:calendar", "spend:usd<=50"],
    expiresIn: "1h",
  });

  // 1) Forward the planner's mandate as-is: $40 is within its $50 cap → allowed.
  const ok = await behalfFetch(url, planner, { method: "POST" }, { action: "spend:usd=40" });
  console.log("as-is  ->", ok.status, await ok.json());

  // 2) Attenuate to <=$20 before forwarding: the $40 charge now exceeds the
  //    delegated authority → denied, even though the planner itself could.
  const denied = await behalfFetch(
    url,
    planner,
    { method: "POST" },
    { action: "spend:usd=40", attenuate: { can: ["spend:usd<=20"], agent: "scoped-planner" } },
  );
  console.log("scoped ->", denied.status, await denied.json());

  server.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
