import type { AuditEntry, AuditFields } from "./types.js";
import type { AuditStore, RevocationStore, RateStore } from "./store.js";

/**
 * Client stores that back an engine with a remote {@link createControlPlane}.
 * Drop them into `createBehalf({ revocations, audit })` and revocation
 * propagates across every agent pointed at the same control plane, while audit
 * is retained centrally — with the five-verb API and enforcement unchanged.
 */

export interface RemoteOptions {
  /** Bearer token, if the control plane requires one. */
  token?: string;
  /** Injectable fetch (defaults to global fetch) — handy for tests. */
  fetch?: typeof fetch;
}

class RemoteBase {
  protected readonly base: string;
  protected readonly fetch: typeof fetch;
  private readonly token?: string;

  constructor(baseUrl: string, opts: RemoteOptions = {}) {
    this.base = baseUrl.replace(/\/$/, "");
    this.fetch = opts.fetch ?? fetch;
    this.token = opts.token;
  }

  protected headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.token) h["authorization"] = `Bearer ${this.token}`;
    return h;
  }

  protected async get<T>(path: string): Promise<T> {
    const res = await this.fetch(this.base + path, { headers: this.headers() });
    if (!res.ok) throw new Error(`control plane ${res.status} for GET ${path}`);
    return (await res.json()) as T;
  }

  protected async post<T>(path: string, body: unknown): Promise<T> {
    const res = await this.fetch(this.base + path, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`control plane ${res.status} for POST ${path}`);
    return (await res.json()) as T;
  }
}

/** Revocation backed by the control plane — revoke once, propagates to all. */
export class HttpRevocationStore extends RemoteBase implements RevocationStore {
  async revoke(id: string): Promise<void> {
    await this.post("/v1/revoke", { id });
  }
  async isRevoked(id: string): Promise<boolean> {
    const { revoked } = await this.get<{ revoked: boolean }>(
      `/v1/revoked/${encodeURIComponent(id)}`,
    );
    return revoked;
  }
}

/** Tamper-evident audit retained centrally by the control plane. */
export class HttpAuditStore extends RemoteBase implements AuditStore {
  /** One round-trip per record; the control plane (single writer) seals it. */
  async record(fields: AuditFields): Promise<AuditEntry> {
    return (await this.post<{ entry: AuditEntry }>("/v1/audit", { fields })).entry;
  }
  async append(entry: AuditEntry): Promise<void> {
    await this.post("/v1/audit", { entry });
  }
  async all(): Promise<AuditEntry[]> {
    return (await this.get<{ entries: AuditEntry[] }>("/v1/audit")).entries;
  }
  async forMandate(mandateId: string): Promise<AuditEntry[]> {
    return (
      await this.get<{ entries: AuditEntry[] }>(`/v1/audit/${encodeURIComponent(mandateId)}`)
    ).entries;
  }
}

/** Rate limiting enforced centrally — one cap shared across all agents. */
export class HttpRateStore extends RemoteBase implements RateStore {
  async hit(key: string, windowMs: number, limit: number, now: number): Promise<boolean> {
    return (
      await this.post<{ allowed: boolean }>("/v1/rate", { key, windowMs, limit, now })
    ).allowed;
  }
}

/** Lightweight typed client for the consent + policy endpoints. */
export class ControlPlaneClient extends RemoteBase {
  requestConsent(agent: string, capability: string, context?: Record<string, unknown>) {
    return this.post<{ id: string; status: string }>("/v1/consent", { agent, capability, context });
  }
  getConsent(id: string) {
    return this.get<{ id: string; status: string }>(`/v1/consent/${encodeURIComponent(id)}`);
  }
  decideConsent(id: string, approve: boolean) {
    return this.post<{ id: string; status: string }>(
      `/v1/consent/${encodeURIComponent(id)}/decision`,
      { approve },
    );
  }
  getPolicy<T = unknown>(name: string) {
    return this.get<{ name: string; policy: T }>(`/v1/policy/${encodeURIComponent(name)}`);
  }
  async putPolicy<T = unknown>(name: string, policy: T) {
    const res = await this.fetch(`${this.base}/v1/policy/${encodeURIComponent(name)}`, {
      method: "PUT",
      headers: this.headers(),
      body: JSON.stringify({ policy }),
    });
    if (!res.ok) throw new Error(`control plane ${res.status} for PUT policy`);
    return (await res.json()) as { name: string; policy: T };
  }
}
