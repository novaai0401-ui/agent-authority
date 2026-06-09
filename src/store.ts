import { seal } from "./audit.js";
import type { AuditEntry, AuditFields } from "./types.js";

/**
 * Pluggable persistence. Defaults are in-memory and local-first, so the library
 * works with zero setup; swap in a networked store for distributed revocation.
 */

export interface RevocationStore {
  revoke(id: string): Promise<void> | void;
  isRevoked(id: string): Promise<boolean> | boolean;
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

export class MemoryRevocationStore implements RevocationStore {
  private revoked = new Set<string>();
  revoke(id: string): void {
    this.revoked.add(id);
  }
  isRevoked(id: string): boolean {
    return this.revoked.has(id);
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
