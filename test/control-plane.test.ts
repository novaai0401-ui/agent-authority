import { test } from "node:test";
import assert from "node:assert/strict";
import { createControlPlane } from "../src/control-plane.js";
import { HttpRevocationStore, HttpAuditStore, HttpRateStore, ControlPlaneClient } from "../src/remote.js";
import { createBehalf } from "../src/behalf.js";
import { newKeyPair } from "../src/crypto.js";
import { AuthorizationError } from "../src/errors.js";

async function withControlPlane(
  fn: (base: string) => Promise<void>,
  opts = {},
): Promise<void> {
  const cp = createControlPlane(opts);
  const port = await cp.listen(0);
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await cp.close();
  }
}

test("revocation propagates across engines via the control plane", async () => {
  await withControlPlane(async (base) => {
    const keyPair = newKeyPair();

    // Two independent engines, same issuer key, both pointed at the control plane.
    const agentA = createBehalf({ rootKeyPair: keyPair, revocations: new HttpRevocationStore(base) });
    const agentB = createBehalf({ rootKeyPair: keyPair, revocations: new HttpRevocationStore(base) });

    const mandate = agentA.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
    const wire = mandate.serialize();

    // B can use it...
    await assert.doesNotReject(agentB.import(wire).authorize("read:calendar"));

    // ...A revokes through the control plane...
    await agentA.revoke(mandate.id);

    // ...and B sees the revocation immediately.
    await assert.rejects(() => agentB.import(wire).authorize("read:calendar"), AuthorizationError);
  });
});

test("audit is retained centrally and stays tamper-evident", async () => {
  await withControlPlane(async (base) => {
    const engine = createBehalf({ audit: new HttpAuditStore(base) });
    const m = engine.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
    await m.authorize("read:calendar");
    try {
      await m.authorize("write:email");
    } catch {
      /* expected */
    }

    // Query the central log directly.
    const remote = new HttpAuditStore(base);
    const trail = await remote.forMandate(m.id);
    assert.equal(trail.length, 2);
    assert.equal(trail[0].decision, "allow");
    assert.equal(trail[1].decision, "deny");

    const { verify } = await import("../src/audit.js");
    assert.ok(verify(await remote.all()).ok);
  });
});

test("concurrent writers keep the central audit chain race-free and intact", async () => {
  await withControlPlane(async (base) => {
    const keyPair = newKeyPair();
    // Several agents authorize in parallel against one shared control plane.
    const agents = Array.from({ length: 5 }, () =>
      createBehalf({ rootKeyPair: keyPair, audit: new HttpAuditStore(base) }),
    );
    const mandates = agents.map((a, i) =>
      a.grant({ principal: "u", agent: `a${i}`, can: ["read:calendar"], expiresIn: "1h" }),
    );

    // 5 agents x 6 authorizations, all interleaved.
    await Promise.all(
      mandates.flatMap((m) => Array.from({ length: 6 }, () => m.authorize("read:calendar"))),
    );

    const remote = new HttpAuditStore(base);
    const all = await remote.all();
    assert.equal(all.length, 30, "every record landed exactly once");
    // Sequence numbers are a contiguous 0..29 with no gaps or dupes.
    assert.deepEqual(
      all.map((e) => e.seq).sort((x, y) => x - y),
      Array.from({ length: 30 }, (_, i) => i),
    );
    const { verify } = await import("../src/audit.js");
    assert.ok(verify(all).ok, "hash chain stays valid under concurrency");
  });
});

test("rate limit is shared across agents via the control plane", async () => {
  await withControlPlane(async (base) => {
    const keyPair = newKeyPair();
    // Two separate agent processes share the same mandate scope + control plane.
    const agentA = createBehalf({ rootKeyPair: keyPair, rate: new HttpRateStore(base) });
    const agentB = createBehalf({ rootKeyPair: keyPair, rate: new HttpRateStore(base) });

    const mA = agentA.grant({ principal: "u", agent: "a", can: ["send:email rate<=3/h"], expiresIn: "1h" });
    // B holds the SAME mandate (same id) — re-issued under the same key/scope.
    const mB = agentB.import(mA.serialize());

    // Combined budget is 3/h. A spends 2, B spends 1 → all allowed; the 4th denies.
    await assert.doesNotReject(mA.authorize("send:email"));
    await assert.doesNotReject(mA.authorize("send:email"));
    await assert.doesNotReject(mB.authorize("send:email"));
    await assert.rejects(() => mB.authorize("send:email"), AuthorizationError);
    // ...and A is also blocked — the cap is genuinely shared, not per-process.
    await assert.rejects(() => mA.authorize("send:email"), AuthorizationError);
  });
});

test("consent flow: request stays pending until decided", async () => {
  await withControlPlane(async (base) => {
    const client = new ControlPlaneClient(base);
    const { id, status } = await client.requestConsent("agent-1", "write:email", { to: "x@y.z" });
    assert.equal(status, "pending");

    const decided = await client.decideConsent(id, true);
    assert.equal(decided.status, "approved");

    const fetched = await client.getConsent(id);
    assert.equal(fetched.status, "approved");
  });
});

test("policy can be stored and retrieved", async () => {
  await withControlPlane(async (base) => {
    const client = new ControlPlaneClient(base);
    const policy = { send_email: "write:email", read_calendar: "read:calendar" };
    await client.putPolicy("research-agent", policy);
    const got = await client.getPolicy<typeof policy>("research-agent");
    assert.deepEqual(got.policy, policy);
  });
});

test("the control plane enforces its bearer token", async () => {
  await withControlPlane(
    async (base) => {
      // No token → 401.
      const res = await fetch(`${base}/v1/revoked`);
      assert.equal(res.status, 401);

      // With token → ok.
      const ok = await fetch(`${base}/v1/revoked`, { headers: { authorization: "Bearer s3cret" } });
      assert.equal(ok.status, 200);
    },
    { token: "s3cret" },
  );
});

test("the dashboard renders HTML", async () => {
  await withControlPlane(async (base) => {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    assert.match(await res.text(), /Behalf Control Plane/);
  });
});
