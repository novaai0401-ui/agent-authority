import { sha256Hex } from "./crypto.js";
import type { AuditEntry, AuditFields, AuditIntegrity } from "./types.js";

export const GENESIS = "0".repeat(64);

/** Canonical body (everything that is hashed, excluding the hash itself). */
function body(e: Omit<AuditEntry, "hash">): string {
  return JSON.stringify({
    seq: e.seq,
    ts: e.ts,
    mandateId: e.mandateId,
    chain: e.chain,
    action: e.action,
    decision: e.decision,
    reason: e.reason ?? "",
    prevHash: e.prevHash,
  });
}

/**
 * Seal a new entry onto the chain after `prev` (or `null` for the first entry).
 * Pure and O(1): the caller supplies the previous entry, so there is no need to
 * re-read the whole log per record. The store that owns the log is the single
 * writer, which keeps the hash chain race-free.
 */
export function seal(prev: AuditEntry | null, fields: AuditFields): AuditEntry {
  const seq = prev ? prev.seq + 1 : 0;
  const prevHash = prev ? prev.hash : GENESIS;
  const partial: Omit<AuditEntry, "hash"> = {
    seq,
    ts: Date.now(),
    mandateId: fields.mandateId,
    chain: fields.chain,
    action: fields.action,
    decision: fields.decision,
    reason: fields.reason,
    prevHash,
  };
  return { ...partial, hash: sha256Hex(prevHash + body(partial)) };
}

/** Replay the hash chain to confirm nothing was tampered with. */
export function verify(entries: AuditEntry[]): AuditIntegrity {
  let prevHash = GENESIS;
  for (const e of entries) {
    if (e.prevHash !== prevHash) return { ok: false, brokenAt: e.seq };
    const expected = sha256Hex(prevHash + body(e));
    if (expected !== e.hash) return { ok: false, brokenAt: e.seq };
    prevHash = e.hash;
  }
  return { ok: true };
}
