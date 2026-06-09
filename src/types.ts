/**
 * Core type definitions for Behalf.
 *
 * A Mandate is a signed, scoped, time-bound capability token that proves who
 * authorized what, within which limits, and through which chain of agents.
 *
 * The token model is macaroon-style: an `identifier` (the root mandate id) plus
 * an ordered list of `caveats` (restrictions), bound together by an HMAC chain.
 * Holders can attenuate (append narrowing caveats) without any key, and the
 * intersection rule is enforced structurally — every caveat must be satisfied,
 * so a downstream agent can only ever shrink authority, never widen it.
 */

/** Restriction attached to a mandate. */
export type Caveat =
  | { t: "principal"; principal: string }
  | { t: "agent"; agent: string }
  | { t: "cap"; can: string[] }
  | { t: "expires"; at: number }
  | { t: "id"; id: string };

/** Wire form of a mandate — exactly what gets serialized/transmitted. */
export interface MandateToken {
  /** Format version. */
  v: 1;
  /** Root identifier (stable across the whole delegation chain). */
  id: string;
  /** Ordered restrictions, root grant first, narrowings appended after. */
  caveats: Caveat[];
  /** HMAC chain signature over (id, caveats...). Hex. */
  sig: string;
}

/** Options for {@link Behalf.grant}. */
export interface GrantOptions {
  /** The human/org authorizing the agent. */
  principal: string;
  /** The agent being authorized. */
  agent: string;
  /** Capabilities granted (capability grammar strings). */
  can: string[];
  /** Lifetime, e.g. "1h", "10m", "30s", or milliseconds as a number. */
  expiresIn: string | number;
}

/** Options for {@link Mandate.attenuate}. */
export interface AttenuateOptions {
  /** Narrowed capability set — must be a subset/narrowing of the parent's. */
  can?: string[];
  /** New (shorter) lifetime relative to now. Never extends past the parent. */
  expiresIn?: string | number;
  /** Optionally re-bind to a specific sub-agent. */
  agent?: string;
}

/** A single tamper-evident audit record. */
export interface AuditEntry {
  seq: number;
  ts: number;
  mandateId: string;
  /** Full chain of ids this token belongs to (root → leaf). */
  chain: string[];
  action: string;
  decision: "allow" | "deny";
  reason?: string;
  /** Hash of the previous entry (hash chain). */
  prevHash: string;
  /** sha256 over (prevHash + canonical entry body). */
  hash: string;
}

/** Result of verifying audit-log integrity. */
export interface AuditIntegrity {
  ok: boolean;
  /** seq of the first broken entry, if any. */
  brokenAt?: number;
}
