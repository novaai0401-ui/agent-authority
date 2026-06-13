import type { AttenuateOptions, AuditEntry, Caveat, MandateToken, Proof } from "./types.js";
import { exportPrivateKey, type KeyPair } from "./crypto.js";
import { seal } from "./seal.js";
import type { KeyObject } from "node:crypto";

/**
 * The engine that actually verifies and enforces — implemented by {@link Behalf}.
 * Kept as an interface here to avoid a circular import with the Mandate wrapper.
 */
export interface Engine {
  authorizeAsHolder(
    token: MandateToken,
    action: string,
    delegationKey: KeyObject | undefined,
  ): Promise<void>;
  attenuate(token: MandateToken, delegationKey: KeyObject | undefined, opts: AttenuateOptions): Mandate;
  provePossession(
    token: MandateToken,
    delegationKey: KeyObject,
    action: string,
    nonce?: string,
    agentKeys?: KeyObject[],
  ): Proof;
  revoke(id: string): Promise<void>;
  audit(id: string): Promise<AuditEntry[]>;
}

/**
 * A handle to a capability token. Construction is internal — obtain one via
 * `Behalf.grant(...)`, `mandate.attenuate(...)`, or `Behalf.import(token)`.
 *
 * A mandate obtained from `grant`/`attenuate` also carries an in-memory
 * `delegationKey` (the Ed25519 private key that authorizes the next block), so
 * it can be further attenuated. A mandate restored via `import` has only the
 * public token: it can be verified, authorized, and audited, but not delegated.
 */
export class Mandate {
  constructor(
    /** The serializable wire token. */
    readonly token: MandateToken,
    private readonly engine: Engine,
    /** Private key for the next attenuation block; undefined if imported. */
    private readonly delegationKey?: KeyObject,
  ) {}

  /** Every caveat across every block, in chain order. */
  private get caveats(): Caveat[] {
    return this.token.blocks.flatMap((b) => b.caveats);
  }

  /** This mandate's own id (the deepest id in the chain). */
  get id(): string {
    const ids = this.chain;
    return ids[ids.length - 1];
  }

  /** Full chain of ids, root → this mandate. Revoking any kills this one. */
  get chain(): string[] {
    const ids = [this.token.id];
    for (const c of this.caveats) if (c.t === "id") ids.push(c.id);
    return ids;
  }

  /** The principal that authorized the root grant, if present. */
  get principal(): string | undefined {
    for (const c of this.caveats) if (c.t === "principal") return c.principal;
    return undefined;
  }

  /** The agent this mandate is currently bound to (latest binding wins). */
  get agent(): string | undefined {
    let agent: string | undefined;
    for (const c of this.caveats) if (c.t === "agent") agent = c.agent;
    return agent;
  }

  /** Effective expiry (earliest expires caveat). */
  get expiresAt(): number | undefined {
    let earliest: number | undefined;
    for (const c of this.caveats) {
      if (c.t === "expires") earliest = earliest === undefined ? c.at : Math.min(earliest, c.at);
    }
    return earliest;
  }

  /** True if this mandate carries the secret needed to delegate further. */
  get canDelegate(): boolean {
    return this.delegationKey !== undefined;
  }

  /**
   * Prove authority for a concrete action. Resolves if permitted; throws
   * {@link AuthorizationError} otherwise. Always writes an audit record.
   *
   * Requires this mandate to hold its delegation key (i.e. it came from
   * `grant`/`attenuate`, not `import`): authorization includes a proof of
   * possession of the chain's terminal key, which closes truncation and makes a
   * serialized token unusable as a bare bearer credential. To authorize a
   * mandate you received from elsewhere, the holder must present a proof — see
   * `behalf/a2a`, or use `engine.inspect()` for an advisory (no-possession)
   * check.
   */
  authorize(action: string): Promise<void> {
    return this.engine.authorizeAsHolder(this.token, action, this.delegationKey);
  }

  /** Hand a narrowed mandate to a sub-agent. Can only shrink scope. */
  attenuate(opts: AttenuateOptions): Mandate {
    return this.engine.attenuate(this.token, this.delegationKey, opts);
  }

  /**
   * Mint a fresh proof of possession for performing `action`, to present this
   * mandate across a trust boundary (e.g. an A2A call). Bound to the action and
   * the exact chain. Requires the delegation key, so only the legitimate holder
   * can produce it.
   */
  prove(action: string, opts: { nonce?: string; agentKeys?: KeyPair[] } = {}): Proof {
    if (!this.delegationKey) {
      throw new Error("cannot prove possession: this mandate was imported without its key");
    }
    const agentKeys = opts.agentKeys?.map((k) => k.privateKey);
    return this.engine.provePossession(this.token, this.delegationKey, action, opts.nonce, agentKeys);
  }

  /** Revoke this mandate and its entire downstream chain. */
  revoke(): Promise<void> {
    return this.engine.revoke(this.id);
  }

  /** This mandate's hash-chained audit trail. */
  audit(): Promise<AuditEntry[]> {
    return this.engine.audit(this.id);
  }

  /** Compact, transmittable string form (base64url JSON of the public token). */
  serialize(): string {
    return Buffer.from(JSON.stringify(this.token), "utf8").toString("base64url");
  }

  /**
   * Transferable holder credential: the token PLUS its delegation key, so the
   * recipient can authorize, prove, and attenuate after `engine.import(...)`.
   * This is how a delegated mandate is handed to a sub-agent in another process.
   *
   * TREAT AS A SECRET: anyone holding this string can exercise the mandate's
   * full authority until expiry/revocation. Deliver only over a secure channel.
   * Use `serialize()` for the public, presentation-only form.
   */
  serializeWithKey(): string {
    if (!this.delegationKey) {
      throw new Error("cannot export with key: this mandate was imported without its key");
    }
    const payload = { token: this.token, key: exportPrivateKey(this.delegationKey) };
    return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  }

  /**
   * Holder credential, encrypted to a recipient's X25519 sealing key — so the
   * credential is unreadable in transit/at rest to anyone but the intended
   * agent. Open it with `engine.importSealed(sealed, recipientKeyPair)`. This is
   * `serializeWithKey()` wrapped in `seal()`; use it when the delivery channel
   * isn't fully trusted. (Defense-in-depth on top of `bindAgent`.)
   */
  sealForRecipient(recipientPublicKey: string): string {
    return seal(this.serializeWithKey(), recipientPublicKey);
  }
}
