import { sha256Hex } from "./crypto.js";
import type { AuditEntry, AuditIntegrity } from "./types.js";
import type { AuditStore } from "./store.js";

const GENESIS = "0".repeat(64);

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
 * Append a tamper-evident record. Each entry's hash chains to the previous one,
 * so any edit, deletion, or reordering breaks every hash downstream — the log
 * is verifiable without trusting the storage layer.
 */
export async function record(
  store: AuditStore,
  fields: Pick<AuditEntry, "mandateId" | "chain" | "action" | "decision" | "reason">,
): Promise<AuditEntry> {
  const existing = await store.all();
  const prev = existing[existing.length - 1];
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
  const entry: AuditEntry = { ...partial, hash: sha256Hex(prevHash + body(partial)) };
  await store.append(entry);
  return entry;
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
