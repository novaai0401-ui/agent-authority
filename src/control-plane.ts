#!/usr/bin/env node
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import {
  MemoryRevocationStore,
  MemoryAuditStore,
  MemoryRateStore,
  MemoryConsentStore,
  MemoryPolicyStore,
  type AuditStore,
  type RevocationStore,
  type RateStore,
  type ConsentStore,
  type PolicyStore,
} from "./store.js";
import type { AuditEntry, AuditFields, ConsentRecord } from "./types.js";

export type { ConsentRecord } from "./types.js";

/**
 * The Behalf control plane (Phase 2 / open-core hosted surface).
 *
 * It centralizes the three things that benefit from being shared across agents
 * and processes: revocation propagation (revoke once, everyone sees it), audit
 * retention (one tamper-evident log of every decision), and a consent/policy
 * surface (just-in-time human approval + named tool→capability policies). It's a
 * thin HTTP service over the same pluggable stores the library already uses, so
 * it can be backed by the in-memory defaults or the file stores for durability.
 *
 * Agents talk to it through `HttpRevocationStore` / `HttpAuditStore` (see
 * `behalf/remote`), so the five-verb API and enforcement are unchanged — only
 * where revocation/audit live moves.
 */

export interface ControlPlaneOptions {
  revocations?: RevocationStore;
  audit?: AuditStore;
  rate?: RateStore;
  /** Consent record storage. Defaults to in-memory; use a file store to persist. */
  consents?: ConsentStore;
  /** Named-policy storage. Defaults to in-memory; use a file store to persist. */
  policies?: PolicyStore;
  /**
   * Multi-tenant mode: require audit queries to name an `?issuer=`, and refuse
   * the unscoped "all entries" list (and omit it from the dashboard). Keeps one
   * tenant from reading another's audit through a shared control plane.
   */
  tenantScoped?: boolean;
  /**
   * Per-tenant bearer tokens: a map of `token -> issuer public key`. A tenant
   * token may only read/write audit for its own issuer (any `?issuer=` is
   * ignored, cross-issuer writes are refused) and gets a private policy
   * namespace. Combine with `token` (an admin credential with full, unscoped
   * access). When either is set, every request must authenticate.
   */
  tenants?: Record<string, string>;
  /** Admin credential — full, unscoped access. */
  token?: string;
}

export interface ControlPlane {
  /** Raw request listener — handy for tests without binding a socket. */
  handler: (req: IncomingMessage, res: ServerResponse) => void;
  /** Bind to a port; resolves with the chosen port (0 picks a free one). */
  listen(port?: number): Promise<number>;
  close(): Promise<void>;
}

export function createControlPlane(options: ControlPlaneOptions = {}): ControlPlane {
  const revocations = options.revocations ?? new MemoryRevocationStore();
  const audit = options.audit ?? new MemoryAuditStore();
  const rate = options.rate ?? new MemoryRateStore();
  const consents = options.consents ?? new MemoryConsentStore();
  const policies = options.policies ?? new MemoryPolicyStore();
  let server: Server | undefined;

  const handler = (req: IncomingMessage, res: ServerResponse): void => {
    void route(req, res).catch((e) => send(res, 500, { error: String(e) }));
  };

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Resolve the caller. `token` is an admin credential (full, unscoped);
    // `tenants` maps a bearer token to the issuer it is allowed to act for.
    let isAdmin = false;
    let callerIssuer: string | undefined;
    if (options.token || options.tenants) {
      const auth = req.headers["authorization"];
      const bearer = typeof auth === "string" && auth.startsWith("Bearer ") ? auth.slice(7) : "";
      if (options.token && bearer === options.token) {
        isAdmin = true;
      } else if (options.tenants && Object.prototype.hasOwnProperty.call(options.tenants, bearer) && bearer) {
        callerIssuer = options.tenants[bearer];
      } else {
        return send(res, 401, { error: "unauthorized" });
      }
    }

    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    // ---- Dashboard ----
    if (method === "GET" && path === "/") {
      // A tenant only ever sees its own audit; the shared revocation/consent
      // views are withheld so the dashboard can't leak across tenants.
      if (callerIssuer) {
        const recent = (await audit.forIssuer(callerIssuer)).slice(-20).reverse();
        return sendHtml(res, dashboard([], recent, []));
      }
      // Admin / single-trust-domain: full view (withheld under tenantScoped).
      const recent = options.tenantScoped ? [] : (await audit.all()).slice(-20).reverse();
      return sendHtml(res, dashboard(listRevoked(revocations), recent, await consents.list()));
    }

    // ---- Revocation ----
    if (method === "POST" && path === "/v1/revoke") {
      const body = await readJson(req);
      if (!body?.id) return send(res, 400, { error: "id required" });
      await revocations.revoke(String(body.id));
      return send(res, 200, { ok: true });
    }
    if (method === "GET" && path === "/v1/revoked") {
      return send(res, 200, { ids: listRevoked(revocations) });
    }
    const revMatch = method === "GET" && /^\/v1\/revoked\/(.+)$/.exec(path);
    if (revMatch) {
      const id = decodeURIComponent(revMatch[1]);
      return send(res, 200, { revoked: Boolean(await revocations.isRevoked(id)) });
    }

    // ---- Audit retention ----
    if (method === "POST" && path === "/v1/audit") {
      const body = await readJson(req);
      // Preferred path: the client sends raw fields and the control plane (the
      // single writer) seals them onto the chain — race-free, O(1) per record.
      if (body?.fields) {
        const fields = body.fields as AuditFields;
        if (callerIssuer && fields.issuer !== callerIssuer) {
          return send(res, 403, { error: "issuer does not match tenant token" });
        }
        const entry = await audit.record(fields);
        return send(res, 200, { entry });
      }
      // Replication path: store an already-sealed entry verbatim.
      if (body?.entry) {
        if (callerIssuer && (body.entry as AuditEntry).issuer !== callerIssuer) {
          return send(res, 403, { error: "issuer does not match tenant token" });
        }
        await audit.append(body.entry as AuditEntry);
        return send(res, 200, { entry: body.entry });
      }
      return send(res, 400, { error: "fields or entry required" });
    }
    if (method === "GET" && path === "/v1/audit") {
      // A tenant token is locked to its own issuer, ignoring any ?issuer.
      if (callerIssuer) return send(res, 200, { entries: await audit.forIssuer(callerIssuer) });
      const issuer = url.searchParams.get("issuer");
      if (issuer) return send(res, 200, { entries: await audit.forIssuer(issuer) });
      if (options.tenantScoped) {
        return send(res, 403, { error: "issuer query required (tenant-scoped)" });
      }
      return send(res, 200, { entries: await audit.all() });
    }
    const auditMatch = method === "GET" && /^\/v1\/audit\/(.+)$/.exec(path);
    if (auditMatch) {
      const id = decodeURIComponent(auditMatch[1]);
      let entries = await audit.forMandate(id);
      if (callerIssuer) entries = entries.filter((e) => e.issuer === callerIssuer);
      return send(res, 200, { entries });
    }

    // ---- Shared rate limiting ----
    if (method === "POST" && path === "/v1/rate") {
      const body = await readJson(req);
      if (!body?.key) return send(res, 400, { error: "key required" });
      const windowMs = Number(body.windowMs);
      const limit = Number(body.limit);
      if (!Number.isFinite(windowMs) || windowMs <= 0 || !Number.isFinite(limit) || limit < 0) {
        return send(res, 400, { error: "windowMs must be > 0 and limit must be >= 0" });
      }
      // The control plane is the time authority — the client's clock is ignored
      // so it can't slide the window to evade the shared cap.
      const allowed = await rate.hit(String(body.key), windowMs, limit, Date.now());
      return send(res, 200, { allowed });
    }

    // ---- Consent ----
    if (method === "POST" && path === "/v1/consent") {
      const body = await readJson(req);
      if (!body?.agent || !body?.capability) {
        return send(res, 400, { error: "agent and capability required" });
      }
      const id = randomId();
      const record: ConsentRecord = {
        id,
        agent: String(body.agent),
        capability: String(body.capability),
        context: body.context as Record<string, unknown> | undefined,
        status: "pending",
        createdAt: Date.now(),
      };
      await consents.put(record);
      return send(res, 201, record);
    }
    if (method === "GET" && path === "/v1/consent") {
      return send(res, 200, { consents: await consents.list() });
    }
    const consentDecide = method === "POST" && /^\/v1\/consent\/([^/]+)\/decision$/.exec(path);
    if (consentDecide) {
      const record = await consents.get(consentDecide[1]);
      if (!record) return send(res, 404, { error: "not found" });
      const body = await readJson(req);
      record.status = body?.approve ? "approved" : "denied";
      record.decidedAt = Date.now();
      await consents.put(record);
      return send(res, 200, record);
    }
    const consentGet = method === "GET" && /^\/v1\/consent\/([^/]+)$/.exec(path);
    if (consentGet) {
      const record = await consents.get(consentGet[1]);
      return record ? send(res, 200, record) : send(res, 404, { error: "not found" });
    }

    // ---- Policy ----
    const policyMatch = /^\/v1\/policy\/([^/]+)$/.exec(path);
    if (policyMatch) {
      const name = policyMatch[1];
      // Tenants get a private namespace so policy names can't clash or leak.
      const key = callerIssuer ? `${callerIssuer} ${name}` : name;
      if (method === "GET") {
        return (await policies.has(key))
          ? send(res, 200, { name, policy: await policies.get(key) })
          : send(res, 404, { error: "not found" });
      }
      if (method === "PUT") {
        const body = await readJson(req);
        await policies.set(key, body?.policy ?? body);
        return send(res, 200, { name, policy: await policies.get(key) });
      }
    }

    return send(res, 404, { error: `no route for ${method} ${path}` });
  }

  return {
    handler,
    listen(port = 0) {
      server = createServer(handler);
      return new Promise((resolve) => {
        server!.listen(port, () => {
          const addr = server!.address();
          resolve(typeof addr === "object" && addr ? addr.port : port);
        });
      });
    },
    close() {
      return new Promise((resolve) => (server ? server.close(() => resolve()) : resolve()));
    },
  };
}

// ---- helpers ----

function readJson(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      if (!data) return resolve(null);
      try {
        resolve(JSON.parse(data));
      } catch {
        resolve(null);
      }
    });
    req.on("error", () => resolve(null));
  });
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, html: string): void {
  res.statusCode = 200;
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.end(html);
}

function randomId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function listRevoked(store: RevocationStore): string[] {
  // MemoryRevocationStore keeps a private Set; expose what we can generically.
  return (store as unknown as { revoked?: Set<string> }).revoked
    ? [...(store as unknown as { revoked: Set<string> }).revoked]
    : [];
}

function esc(s: unknown): string {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
}

function dashboard(
  revoked: string[],
  recent: AuditEntry[],
  consents: ConsentRecord[],
): string {
  const pending = consents.filter((c) => c.status === "pending");

  return `<!doctype html><html><head><meta charset="utf-8"><title>Behalf Control Plane</title>
<style>body{font:14px system-ui,sans-serif;margin:2rem;max-width:60rem}h1{font-size:1.4rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0 2rem}td,th{border:1px solid #ddd;padding:.3rem .5rem;text-align:left}
.deny{color:#b00}.allow{color:#070}code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}</style></head><body>
<h1>Behalf Control Plane</h1>
<h2>Revoked mandates (${revoked.length})</h2>
<table><tr><th>id</th></tr>${revoked.map((id) => `<tr><td><code>${esc(id)}</code></td></tr>`).join("") || "<tr><td>none</td></tr>"}</table>
<h2>Pending consent (${pending.length})</h2>
<table><tr><th>id</th><th>agent</th><th>capability</th></tr>${
    pending.map((c) => `<tr><td><code>${esc(c.id)}</code></td><td>${esc(c.agent)}</td><td><code>${esc(c.capability)}</code></td></tr>`).join("") ||
    "<tr><td colspan=3>none</td></tr>"
  }</table>
<h2>Recent audit (${recent.length})</h2>
<table><tr><th>time</th><th>decision</th><th>action</th><th>reason</th></tr>${
    recent
      .map(
        (e) =>
          `<tr><td>${new Date(e.ts).toISOString()}</td><td class="${e.decision}">${esc(e.decision)}</td><td><code>${esc(e.action)}</code></td><td>${esc(e.reason ?? "")}</td></tr>`,
      )
      .join("") || "<tr><td colspan=4>none</td></tr>"
  }</table>
</body></html>`;
}

// Allow `node dist/control-plane.js` (and the `behalf-control-plane` bin) to run
// a durable, file-backed control plane. PORT and BEHALF_HOME are read from env.
function runningAsMain(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}
if (runningAsMain()) {
  void (async () => {
    const { join } = await import("node:path");
    const { homedir } = await import("node:os");
    const { FileRevocationStore, FileAuditStore, FileConsentStore, FilePolicyStore, FileRateStore } =
      await import("./persist.js");
    const home = process.env.BEHALF_HOME ?? join(homedir(), ".behalf");
    const port = Number(process.env.PORT ?? 8787);
    const cp = createControlPlane({
      revocations: new FileRevocationStore(join(home, "revocations.json")),
      audit: new FileAuditStore(join(home, "audit.jsonl")),
      consents: new FileConsentStore(join(home, "consents.json")),
      policies: new FilePolicyStore(join(home, "policies.json")),
      rate: new FileRateStore(join(home, "rate.json")),
      token: process.env.BEHALF_TOKEN,
    });
    const bound = await cp.listen(port);
    console.error(`behalf control plane listening on http://127.0.0.1:${bound}  (dashboard at /)`);
  })();
}
