import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane } from "../src/control-plane.js";
import {
  HttpRevocationStore,
  HttpAuditStore,
  HttpRateStore,
  ControlPlaneClient,
  controlPlaneConsent,
} from "../src/remote.js";
import { createBehalf } from "../src/behalf.js";
import { newKeyPair, exportPublicKey } from "../src/crypto.js";
import { withBehalf, type ToolServerLike } from "../src/mcp.js";
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

test("audit is scoped per issuer (multi-tenant isolation)", async () => {
  await withControlPlane(async (base) => {
    // Two independent issuers (different keys) share one control plane.
    const tenantA = createBehalf({ audit: new HttpAuditStore(base) });
    const tenantB = createBehalf({ audit: new HttpAuditStore(base) });

    await tenantA.grant({ principal: "a", agent: "x", can: ["read:calendar"], expiresIn: "1h" }).authorize("read:calendar");
    await tenantB.grant({ principal: "b", agent: "y", can: ["read:calendar"], expiresIn: "1h" }).authorize("read:calendar");
    await tenantB.grant({ principal: "b", agent: "z", can: ["read:calendar"], expiresIn: "1h" }).authorize("read:calendar");

    const reader = new HttpAuditStore(base);
    const aEntries = await reader.forIssuer(tenantA.publicKey);
    const bEntries = await reader.forIssuer(tenantB.publicKey);

    assert.equal(aEntries.length, 1);
    assert.equal(bEntries.length, 2);
    assert.ok(aEntries.every((e) => e.issuer === tenantA.publicKey));
    assert.ok(bEntries.every((e) => e.issuer === tenantB.publicKey));
  });
});

test("per-tenant tokens isolate audit by authenticated identity", async () => {
  const kpA = newKeyPair();
  const kpB = newKeyPair();
  const issuerA = exportPublicKey(kpA.publicKey);
  const issuerB = exportPublicKey(kpB.publicKey);

  await withControlPlane(
    async (base) => {
      const a = createBehalf({ rootKeyPair: kpA, audit: new HttpAuditStore(base, { token: "tokA" }) });
      const b = createBehalf({ rootKeyPair: kpB, audit: new HttpAuditStore(base, { token: "tokB" }) });
      await a.grant({ principal: "a", agent: "x", can: ["read:calendar"], expiresIn: "1h" }).authorize("read:calendar");
      await b.grant({ principal: "b", agent: "y", can: ["read:calendar"], expiresIn: "1h" }).authorize("read:calendar");

      // Tenant A sees only its own audit, regardless of the request shape.
      const aEntries = await new HttpAuditStore(base, { token: "tokA" }).all();
      assert.equal(aEntries.length, 1);
      assert.ok(aEntries.every((e) => e.issuer === issuerA));

      // Even an explicit ?issuer=B is ignored for a tenant token.
      const aProbingB = await new HttpAuditStore(base, { token: "tokA" }).forIssuer(issuerB);
      assert.ok(aProbingB.every((e) => e.issuer === issuerA));

      // No credential → 401.
      assert.equal((await fetch(`${base}/v1/audit`)).status, 401);

      // A tenant cannot write audit attributed to another issuer: A holds a
      // B-issued mandate but audits with its own token → the record is refused.
      const stray = b.grant({ principal: "b", agent: "z", can: ["read:calendar"], expiresIn: "1h" });
      const aVerifier = createBehalf({
        rootKeyPair: kpA,
        trust: [issuerB],
        audit: new HttpAuditStore(base, { token: "tokA" }),
      });
      await assert.rejects(() => aVerifier.import(stray.serialize()).authorize("read:calendar"));

      // The admin token sees everything.
      const adminAll = await new HttpAuditStore(base, { token: "admintok" }).all();
      assert.ok(adminAll.length >= 2);
    },
    { tenants: { tokA: issuerA, tokB: issuerB }, token: "admintok" },
  );
});

test("the dashboard does not leak another tenant's audit", async () => {
  const kpA = newKeyPair();
  const kpB = newKeyPair();
  const issuerA = exportPublicKey(kpA.publicKey);
  const issuerB = exportPublicKey(kpB.publicKey);

  await withControlPlane(
    async (base) => {
      const a = createBehalf({ rootKeyPair: kpA, audit: new HttpAuditStore(base, { token: "tokA" }) });
      const b = createBehalf({ rootKeyPair: kpB, audit: new HttpAuditStore(base, { token: "tokB" }) });
      await a.grant({ principal: "a", agent: "x", can: ["read:calendar"], expiresIn: "1h" }).authorize("read:calendar");
      await b.grant({ principal: "b", agent: "y", can: ["read:repo/secret-b"], expiresIn: "1h" }).authorize("read:repo/secret-b");

      // Tenant A loads the dashboard: it must show A's action, never B's.
      const aHtml = await (await fetch(`${base}/`, { headers: { authorization: "Bearer tokA" } })).text();
      assert.match(aHtml, /read:calendar/);
      assert.doesNotMatch(aHtml, /read:repo\/secret-b/);
      assert.doesNotMatch(aHtml, new RegExp(issuerB.slice(0, 16)));

      // The admin still sees everything.
      const adminHtml = await (await fetch(`${base}/`, { headers: { authorization: "Bearer admintok" } })).text();
      assert.match(adminHtml, /read:repo\/secret-b/);
    },
    { tenants: { tokA: issuerA, tokB: issuerB }, token: "admintok" },
  );
});

test("tenant-scoped mode refuses the unscoped audit list", async () => {
  await withControlPlane(
    async (base) => {
      const tenant = createBehalf({ audit: new HttpAuditStore(base) });
      await tenant.grant({ principal: "u", agent: "x", can: ["read:calendar"], expiresIn: "1h" }).authorize("read:calendar");

      // Unscoped list is refused...
      const res = await fetch(`${base}/v1/audit`);
      assert.equal(res.status, 403);

      // ...but a scoped query works.
      const scoped = await new HttpAuditStore(base).forIssuer(tenant.publicKey);
      assert.equal(scoped.length, 1);
    },
    { tenantScoped: true },
  );
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

test("control-plane consent wires just-in-time approval into the middleware", async () => {
  await withControlPlane(async (base) => {
    const engine = createBehalf();
    // A mandate WITHOUT write:email — the send_email tool requires it.
    const mandate = engine.grant({ principal: "u", agent: "mailer", can: ["read:calendar"], expiresIn: "1h" });

    const calls: string[] = [];
    const server: ToolServerLike = {
      async callTool(name) {
        calls.push(name);
        return { ok: true };
      },
    };

    const approver = new ControlPlaneClient(base);
    const guarded = withBehalf(server, {
      policy: { send_email: "write:email" },
      onDenied: "prompt",
      // Approve as soon as the pending request appears (a human/dashboard would).
      onPrompt: controlPlaneConsent(approver, {
        pollMs: 5,
        onPending: (rec) => void approver.decideConsent(rec.id, true),
      }),
    });

    // Denied by scope, but consent is granted out-of-band → the call proceeds.
    await guarded.callTool("send_email", {}, { mandate });
    assert.deepEqual(calls, ["send_email"]);

    // And when consent is declined, the call is rejected.
    const denying = withBehalf(server, {
      policy: { send_email: "write:email" },
      onDenied: "prompt",
      onPrompt: controlPlaneConsent(approver, {
        pollMs: 5,
        onPending: (rec) => void approver.decideConsent(rec.id, false),
      }),
    });
    await assert.rejects(() => denying.callTool("send_email", {}, { mandate }), AuthorizationError);
    assert.deepEqual(calls, ["send_email"]); // not called again
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

test("consent and policy survive a control-plane restart (file-backed)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "behalf-cp-"));
  try {
    const { FileConsentStore, FilePolicyStore } = await import("../src/persist.js");
    const consentsPath = join(dir, "consents.json");
    const policiesPath = join(dir, "policies.json");

    // First control plane: create a consent + a policy, then shut down.
    const cp1 = createControlPlane({
      consents: new FileConsentStore(consentsPath),
      policies: new FilePolicyStore(policiesPath),
    });
    const port1 = await cp1.listen(0);
    const base1 = `http://127.0.0.1:${port1}`;
    const client1 = new ControlPlaneClient(base1);
    const { id } = await client1.requestConsent("agent-1", "write:email");
    await client1.decideConsent(id, true);
    await client1.putPolicy("research-agent", { send_email: "write:email" });
    await cp1.close();

    // Second control plane over the SAME files: state is still there.
    const cp2 = createControlPlane({
      consents: new FileConsentStore(consentsPath),
      policies: new FilePolicyStore(policiesPath),
    });
    const port2 = await cp2.listen(0);
    const base2 = `http://127.0.0.1:${port2}`;
    const client2 = new ControlPlaneClient(base2);
    try {
      assert.equal((await client2.getConsent(id)).status, "approved");
      assert.deepEqual((await client2.getPolicy("research-agent")).policy, {
        send_email: "write:email",
      });
    } finally {
      await cp2.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the dashboard renders HTML", async () => {
  await withControlPlane(async (base) => {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    assert.match(await res.text(), /Behalf Control Plane/);
  });
});
