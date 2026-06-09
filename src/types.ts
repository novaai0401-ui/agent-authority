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

/**
 * One link in the delegation chain: a set of restrictions plus the public key
 * (`nextPub`) that authorizes whoever signs the *next* block.
 */
export interface Block {
  caveats: Caveat[];
  /** base64url SPKI Ed25519 public key for the next block's signature. */
  nextPub: string;
}

/** Wire form of a mandate — exactly what gets serialized/transmitted. */
export interface MandateToken {
  /** Format version. */
  v: 2;
  /** Root identifier (stable across the whole delegation chain). */
  id: string;
  /** Ordered blocks: root grant first, narrowings appended after. */
  blocks: Block[];
  /** Per-block Ed25519 signatures (base64url). sigs[i] signs blocks[i]. */
  sigs: string[];
  /** Issuer (root) public key, base64url SPKI — pin this to establish trust. */
  rootPub: string;
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

/** The decision fields of an audit record, before it is sealed into the chain. */
export type AuditFields = Pick<
  AuditEntry,
  "mandateId" | "chain" | "action" | "decision" | "reason"
>;

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

/** A just-in-time consent request tracked by the control plane. */
export interface ConsentRecord {
  id: string;
  agent: string;
  capability: string;
  context?: Record<string, unknown>;
  status: "pending" | "approved" | "denied";
  createdAt: number;
  decidedAt?: number;
}
