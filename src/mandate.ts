import type { AttenuateOptions, AuditEntry, Caveat, MandateToken } from "./types.js";

/**
 * The engine that actually verifies and enforces — implemented by {@link Behalf}.
 * Kept as an interface here to avoid a circular import with the Mandate wrapper.
 */
export interface Engine {
  authorize(token: MandateToken, action: string): Promise<void>;
  attenuate(token: MandateToken, opts: AttenuateOptions): Mandate;
  revoke(id: string): Promise<void>;
  audit(id: string): Promise<AuditEntry[]>;
}

/**
 * A handle to a capability token. Construction is internal — obtain one via
 * `Behalf.grant(...)`, `mandate.attenuate(...)`, or `Behalf.import(token)`.
 */
export class Mandate {
  constructor(
    /** The serializable wire token. */
    readonly token: MandateToken,
    private readonly engine: Engine,
  ) {}

  /** This mandate's own id (the deepest id in the chain). */
  get id(): string {
    const ids = this.chain;
    return ids[ids.length - 1];
  }

  /** Full chain of ids, root → this mandate. Revoking any kills this one. */
  get chain(): string[] {
    const ids = [this.token.id];
    for (const c of this.token.caveats) {
      if (c.t === "id") ids.push(c.id);
    }
    return ids;
  }

  /** The principal that authorized the root grant, if present. */
  get principal(): string | undefined {
    return find(this.token.caveats, "principal")?.principal;
  }

  /** The agent this mandate is currently bound to (latest binding wins). */
  get agent(): string | undefined {
    let agent: string | undefined;
    for (const c of this.token.caveats) if (c.t === "agent") agent = c.agent;
    return agent;
  }

  /** Effective expiry (earliest expires caveat). */
  get expiresAt(): number | undefined {
    let earliest: number | undefined;
    for (const c of this.token.caveats) {
      if (c.t === "expires") earliest = earliest === undefined ? c.at : Math.min(earliest, c.at);
    }
    return earliest;
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
    return this.engine.attenuate(this.token, opts);
  }

  /** Revoke this mandate and its entire downstream chain. */
  revoke(): Promise<void> {
    return this.engine.revoke(this.id);
  }

  /** This mandate's tamper-evident audit trail. */
  audit(): Promise<AuditEntry[]> {
    return this.engine.audit(this.id);
  }

  /** Compact, transmittable string form (base64url of the JSON token). */
  serialize(): string {
    return Buffer.from(JSON.stringify(this.token), "utf8").toString("base64url");
  }
}

function find<T extends Caveat["t"]>(
  caveats: Caveat[],
  t: T,
): Extract<Caveat, { t: T }> | undefined {
  return caveats.find((c) => c.t === t) as Extract<Caveat, { t: T }> | undefined;
}
