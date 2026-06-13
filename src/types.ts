/**
 * Core type definitions for Behalf.
 *
 * A Mandate is a signed, scoped, time-bound capability token that proves who
 * authorized what, within which limits, and through which chain of agents.
 *
 * The token is a biscuit-style Ed25519 signature chain of blocks. Each block
 * carries restrictions (caveats) and publishes a fresh public key; the next
 * block is signed by the matching private key, which the holder must possess to
 * attenuate (append a narrowing block) or to authorize (prove possession of the
 * terminal key). The intersection rule is enforced structurally — every cap
 * caveat must be satisfied — so a downstream agent can only ever shrink
 * authority, never widen it, and a holder cannot present a truncated prefix of
 * its chain because it lacks that prefix's terminal key.
 */

/** Restriction attached to a mandate. */
export type Caveat =
  | { t: "principal"; principal: string }
  | { t: "agent"; agent: string }
  | { t: "cap"; can: string[] }
  | { t: "expires"; at: number }
  | { t: "id"; id: string }
  /**
   * Cryptographic agent identity binding (SVID-style): the holder must, at
   * authorize, also prove possession of the private key for this public key.
   * Conjunctive — every `agentKey` caveat must be satisfied — so a thief who
   * holds the credential cannot append their own binding to bypass it.
   */
  | { t: "agentKey"; key: string };

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

/**
 * Proof of possession of a mandate's terminal key, presented at authorize time
 * to prove the bearer is the legitimate tail of the chain (not a truncated
 * prefix). `ts` is when it was minted (checked for freshness); `sig` is the
 * Ed25519 signature over the proof message.
 */
export interface Proof {
  ts: number;
  sig: string;
  /**
   * Optional verifier-issued single-use nonce (from `engine.challenge()`).
   * When present it is bound into the signature and consumed on use, giving
   * true anti-replay; without it, replay is bounded only by `proofSkewMs`.
   */
  nonce?: string;
  /**
   * Agent-identity signatures over the same proof message, one per agent key the
   * holder controls. At authorize, every `agentKey` caveat in the chain must be
   * satisfied by one of these (conjunctive), proving the presenter is the bound
   * agent — not merely a possessor of the credential.
   */
  agentSigs?: string[];
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
  /**
   * Cryptographically bind this grant to an agent identity (the agent's public
   * key, base64url). The holder must then prove possession of the matching
   * private key at authorize — see the `agentKey` caveat.
   */
  bindAgent?: string;
}

/** Options for {@link Mandate.attenuate}. */
export interface AttenuateOptions {
  /** Narrowed capability set — must be a subset/narrowing of the parent's. */
  can?: string[];
  /** New (shorter) lifetime relative to now. Never extends past the parent. */
  expiresIn?: string | number;
  /** Optionally re-bind to a specific sub-agent. */
  agent?: string;
  /**
   * Add a cryptographic agent-identity binding (the agent's public key,
   * base64url). Conjunctive with any inherited `agentKey` caveats, so it can
   * only ever add a requirement, never remove one.
   */
  bindAgent?: string;
}

/** The decision fields of an audit record, before it is sealed into the chain. */
export type AuditFields = Pick<
  AuditEntry,
  "mandateId" | "chain" | "action" | "decision" | "reason" | "issuer"
>;

/** A single hash-chained audit record (integrity-chained; see README Limitations). */
export interface AuditEntry {
  seq: number;
  ts: number;
  mandateId: string;
  /** Issuer (root) public key of the mandate, for per-tenant scoping. */
  issuer?: string;
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

/**
 * A signed anchor over the audit log's head. Because the head hash commits to
 * every prior entry, a stored checkpoint makes later tail-deletion or rewrites
 * detectable — something the unkeyed hash chain alone cannot do.
 */
export interface AuditCheckpoint {
  /** seq of the head entry at checkpoint time (-1 for an empty log). */
  seq: number;
  /** Head entry's hash (the genesis hash for an empty log). */
  hash: string;
  ts: number;
  /** Public key (base64url) of the engine that signed this checkpoint. */
  signer: string;
  /** Ed25519 signature over the canonical {seq, hash, ts} message. */
  sig: string;
}

/** A just-in-time consent request tracked by the control plane. */
export interface ConsentRecord {
  id: string;
  agent: string;
  capability: string;
  context?: Record<string, unknown>;
  /** Tenant issuer this request belongs to (set when created with a tenant token). */
  issuer?: string;
  status: "pending" | "approved" | "denied" | "expired";
  createdAt: number;
  decidedAt?: number;
}
