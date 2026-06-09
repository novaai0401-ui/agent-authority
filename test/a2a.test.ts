import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createBehalf, type Behalf } from "../src/behalf.js";
import { behalfFetch, guard, type GuardedRequest } from "../src/a2a.js";

/** Start an A2A-guarded HTTP server; returns its base URL and a close fn. */
async function startServer(
  engine: Behalf,
  capabilityFor: (method: string) => string | undefined,
): Promise<{ url: string; close: () => Promise<void>; server: Server }> {
  const gate = guard({ engine, capability: (req) => capabilityFor(req.method ?? "") });
  const server = createServer(async (req: GuardedRequest, res) => {
    const ok = await gate(req, res);
    if (!ok) return; // guard already wrote 403
    res.statusCode = 200;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ok: true, agent: req.mandate?.agent }));
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/`,
    server,
    close: () => new Promise((r) => server.close(() => r())),
  };
}

test("a verified mandate authorizes a cross-agent call", async () => {
  // The callee trusts the caller's issuer public key — nothing else shared.
  const issuer = createBehalf();
  const callee = createBehalf({ trust: [issuer.publicKey] });
  const srv = await startServer(callee, () => "spend:usd<=50");
  try {
    const mandate = issuer.grant({
      principal: "u",
      agent: "caller",
      can: ["spend:usd<=50"],
      expiresIn: "1h",
    });
    const res = await behalfFetch(srv.url, mandate, { method: "POST" });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, agent: "caller" });
  } finally {
    await srv.close();
  }
});

test("a missing mandate is rejected with 403", async () => {
  const callee = createBehalf();
  const srv = await startServer(callee, () => "spend:usd<=50");
  try {
    const res = await fetch(srv.url, { method: "POST" });
    assert.equal(res.status, 403);
    const body = (await res.json()) as { error?: string };
    assert.equal(body.error, "forbidden");
  } finally {
    await srv.close();
  }
});

test("an untrusted issuer's mandate is rejected", async () => {
  const issuer = createBehalf();
  const callee = createBehalf(); // does NOT trust issuer
  const srv = await startServer(callee, () => "read:calendar");
  try {
    const mandate = issuer.grant({ principal: "u", agent: "x", can: ["read:calendar"], expiresIn: "1h" });
    const res = await behalfFetch(srv.url, mandate, { method: "GET" });
    assert.equal(res.status, 403);
  } finally {
    await srv.close();
  }
});

test("the caller can attenuate before forwarding (downstream gets less)", async () => {
  const issuer = createBehalf();
  const callee = createBehalf({ trust: [issuer.publicKey] });
  const srv = await startServer(callee, () => "spend:usd=40");
  try {
    const mandate = issuer.grant({ principal: "u", agent: "caller", can: ["spend:usd<=50"], expiresIn: "1h" });

    // Narrow to <=20 before sending — the callee's required spend:usd=40 now fails.
    const res = await behalfFetch(
      srv.url,
      mandate,
      { method: "POST" },
      { attenuate: { can: ["spend:usd<=20"], agent: "sub" } },
    );
    assert.equal(res.status, 403);
  } finally {
    await srv.close();
  }
});
