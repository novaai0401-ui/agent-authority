import type { AuditEntry } from "./types.js";

/**
 * Pluggable persistence. Defaults are in-memory and local-first, so the library
 * works with zero setup; swap in a networked store for distributed revocation.
 */

export interface RevocationStore {
  revoke(id: string): Promise<void> | void;
  isRevoked(id: string): Promise<boolean> | boolean;
}

export interface AuditStore {
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
