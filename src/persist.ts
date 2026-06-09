import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { AuditEntry } from "./types.js";
import type { AuditStore, RevocationStore } from "./store.js";

/**
 * Local-first, file-backed stores. These keep revocation and audit state across
 * process restarts with zero infrastructure — the "offline-verifiable, only
 * revocation needs a check" model, persisted to disk. Swap in a networked store
 * for distributed revocation propagation (the Phase-2 control plane).
 */

function ensureDir(file: string): void {
  const dir = dirname(file);
  if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true });
}

/** Revocation list persisted as a JSON array of ids. */
export class FileRevocationStore implements RevocationStore {
  private readonly revoked: Set<string>;

  constructor(private readonly path: string) {
    ensureDir(path);
    this.revoked = existsSync(path)
      ? new Set<string>(JSON.parse(readFileSync(path, "utf8")))
      : new Set<string>();
  }

  revoke(id: string): void {
    this.revoked.add(id);
    writeFileSync(this.path, JSON.stringify([...this.revoked]), "utf8");
  }

  isRevoked(id: string): boolean {
    return this.revoked.has(id);
  }
}

/** Append-only audit log persisted as JSON Lines (one entry per line). */
export class FileAuditStore implements AuditStore {
  constructor(private readonly path: string) {
    ensureDir(path);
    if (!existsSync(path)) writeFileSync(path, "", "utf8");
  }

  append(entry: AuditEntry): void {
    appendFileSync(this.path, JSON.stringify(entry) + "\n", "utf8");
  }

  all(): AuditEntry[] {
    const raw = readFileSync(this.path, "utf8");
    return raw
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l) as AuditEntry);
  }

  forMandate(mandateId: string): AuditEntry[] {
    return this.all().filter((e) => e.chain.includes(mandateId));
  }
}
