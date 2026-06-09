import type { AttenuateOptions, AuditEntry, Caveat, MandateToken } from "./types.js";
import type { KeyObject } from "node:crypto";

/**
 * The engine that actually verifies and enforces — implemented by {@link Behalf}.
 * Kept as an interface here to avoid a circular import with the Mandate wrapper.
 */
export interface Engine {
  authorize(token: MandateToken, action: string): Promise<void>;
  attenuate(token: MandateToken, delegationKey: KeyObject | undefined, opts: AttenuateOptions): Mandate;
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
   */
  authorize(action: string): Promise<void> {
    return this.engine.authorize(this.token, action);
  }

  /** Hand a narrowed mandate to a sub-agent. Can only shrink scope. */
  attenuate(opts: AttenuateOptions): Mandate {
    return this.engine.attenuate(this.token, this.delegationKey, opts);
  }

  /** Revoke this mandate and its entire downstream chain. */
  revoke(): Promise<void> {
    return this.engine.revoke(this.id);
  }

  /** This mandate's tamper-evident audit trail. */
  audit(): Promise<AuditEntry[]> {
    return this.engine.audit(this.id);
  }

  /** Compact, transmittable string form (base64url JSON of the public token). */
  serialize(): string {
    return Buffer.from(JSON.stringify(this.token), "utf8").toString("base64url");
  }
}
