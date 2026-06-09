import { seal } from "./audit.js";
import type { AuditEntry, AuditFields, ConsentRecord } from "./types.js";

/**
 * Pluggable persistence. Defaults are in-memory and local-first, so the library
 * works with zero setup; swap in a networked store for distributed revocation.
 */

export interface RevocationStore {
  revoke(id: string): Promise<void> | void;
  isRevoked(id: string): Promise<boolean> | boolean;
}

export interface RateStore {
  /**
   * Atomically record a hit against `key` and report whether it falls within
   * `limit` over the sliding `windowMs`. A rejected hit is NOT counted. Back it
   * with a shared store (the control plane) to enforce one limit across every
   * agent that holds the mandate — otherwise each process gets its own cap.
   */
  hit(key: string, windowMs: number, limit: number, now: number): Promise<boolean> | boolean;
}

export interface AuditStore {
  /**
   * Seal `fields` onto the chain and persist — the primary write path used by
   * the engine. The store owns sequencing/hashing so writes stay O(1) and, for
   * a shared store, race-free under a single writer.
   */
  record(fields: AuditFields): Promise<AuditEntry> | AuditEntry;
  /** Append an already-sealed entry verbatim (replication / import). */
  append(entry: AuditEntry): Promise<void> | void;
  /** Entries whose chain includes `mandateId`, in order. */
  forMandate(mandateId: string): Promise<AuditEntry[]> | AuditEntry[];
  all(): Promise<AuditEntry[]> | AuditEntry[];
}

/** Storage for just-in-time consent records (control plane). */
export interface ConsentStore {
  put(record: ConsentRecord): Promise<void> | void;
  get(id: string): Promise<ConsentRecord | undefined> | ConsentRecord | undefined;
  list(): Promise<ConsentRecord[]> | ConsentRecord[];
}

/** Storage for named tool→capability policies (control plane). */
export interface PolicyStore {
  set(name: string, policy: unknown): Promise<void> | void;
  get(name: string): Promise<unknown> | unknown;
  has(name: string): Promise<boolean> | boolean;
}

export class MemoryConsentStore implements ConsentStore {
  private readonly records = new Map<string, ConsentRecord>();
  put(record: ConsentRecord): void {
    this.records.set(record.id, record);
  }
  get(id: string): ConsentRecord | undefined {
    return this.records.get(id);
  }
  list(): ConsentRecord[] {
    return [...this.records.values()];
  }
}

export class MemoryPolicyStore implements PolicyStore {
  private readonly policies = new Map<string, unknown>();
  set(name: string, policy: unknown): void {
    this.policies.set(name, policy);
  }
  get(name: string): unknown {
    return this.policies.get(name);
  }
  has(name: string): boolean {
    return this.policies.has(name);
  }
}

export class MemoryRevocationStore implements RevocationStore {
  private revoked = new Set<string>();
  revoke(id: string): void {
    this.revoked.add(id);
  }
  isRevoked(id: string): boolean {
    return this.revoked.has(id);
  }
}

export interface CacheOptions {
  /** How long a "not revoked" answer may be reused before re-checking. */
  ttlMs: number;
  /** Override the clock — handy for tests. */
  now?: () => number;
}

/**
 * Wraps another {@link RevocationStore} (typically the networked
 * `HttpRevocationStore`) with a bounded cache, so a hot mandate isn't
 * re-checked over the network on every `authorize()`.
 *
 * Safe by construction: revocation is monotonic, so a *revoked* answer is cached
 * forever, while a *not-revoked* answer is cached only for `ttlMs`. The cost is
 * a bounded staleness window — a mandate revoked elsewhere may still pass for up
 * to `ttlMs`. This is exactly the "short TTL + revocation check" trade-off; keep
 * the TTL small (seconds) for tight revocation, larger to cut traffic.
 */
export class CachingRevocationStore implements RevocationStore {
  private readonly revoked = new Set<string>();
  private readonly freshUntil = new Map<string, number>();
  private readonly now: () => number;

  constructor(
    private readonly inner: RevocationStore,
    private readonly opts: CacheOptions,
  ) {
    this.now = opts.now ?? (() => Date.now());
  }

  async revoke(id: string): Promise<void> {
    await this.inner.revoke(id);
    this.revoked.add(id);
    this.freshUntil.delete(id);
  }

  async isRevoked(id: string): Promise<boolean> {
    if (this.revoked.has(id)) return true;
    const until = this.freshUntil.get(id);
    if (until !== undefined && this.now() < until) return false;

    const revoked = await this.inner.isRevoked(id);
    if (revoked) this.revoked.add(id);
    else this.freshUntil.set(id, this.now() + this.opts.ttlMs);
    return revoked;
  }
}

export class MemoryRateStore implements RateStore {
  private readonly hits = new Map<string, number[]>();
  hit(key: string, windowMs: number, limit: number, now: number): boolean {
    const recent = (this.hits.get(key) ?? []).filter((t) => now - t < windowMs);
    if (recent.length + 1 > limit) {
      this.hits.set(key, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(key, recent);
    return true;
  }
}

export class MemoryAuditStore implements AuditStore {
  private entries: AuditEntry[] = [];
  record(fields: AuditFields): AuditEntry {
    const entry = seal(this.entries[this.entries.length - 1] ?? null, fields);
    this.entries.push(entry);
    return entry;
  }
  append(entry: AuditEntry): void {
    this.entries.push(entry);
  }
  forMandate(mandateId: string): AuditEntry[] {
    return this.entries.filter((e) => e.chain.includes(mandateId));
  }
  all(): AuditEntry[] {
    return [...this.entries];
  }
}
