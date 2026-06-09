import {
  chainSignature,
  extendSignature,
  newId,
  newRootKey,
} from "./crypto.js";
import {
  parse,
  satisfies,
  isNarrowing,
  windowMs,
  type Capability,
} from "./capability.js";
import { record, verify as verifyAudit } from "./audit.js";
import {
  MemoryAuditStore,
  MemoryRevocationStore,
  type AuditStore,
  type RevocationStore,
} from "./store.js";
import { Mandate, type Engine } from "./mandate.js";
import {
  AuthorizationError,
  IntegrityError,
  WideningError,
} from "./errors.js";
import type {
  AttenuateOptions,
  AuditEntry,
  AuditIntegrity,
  Caveat,
  GrantOptions,
  MandateToken,
} from "./types.js";

export interface BehalfConfig {
  /** Root signing key. Auto-generated (in-memory) if omitted. */
  rootKey?: Buffer;
  revocations?: RevocationStore;
  audit?: AuditStore;
  /** Override the clock — handy for tests. */
  now?: () => number;
}

const DURATION_RE = /^(\d+(?:\.\d+)?)(ms|s|m|h|d)$/;

function toMs(d: string | number): number {
  if (typeof d === "number") return d;
  const m = DURATION_RE.exec(d.trim());
  if (!m) throw new Error(`invalid duration "${d}" (use e.g. "1h", "10m", "30s")`);
  const n = Number(m[1]);
  switch (m[2]) {
    case "ms":
      return n;
    case "s":
      return n * 1000;
    case "m":
      return n * 60_000;
    case "h":
      return n * 3_600_000;
    case "d":
      return n * 86_400_000;
    default:
      return n;
  }
}

/**
 * The Behalf engine: holds the signing key and the revocation / audit stores,
 * and implements the five verbs. Use the default singleton via the static
 * facade (`Behalf.grant`, ...) or construct an isolated instance with
 * `createBehalf()`.
 */
export class Behalf implements Engine {
  private readonly rootKey: Buffer;
  private readonly revocations: RevocationStore;
  private readonly auditStore: AuditStore;
  private readonly now: () => number;
  /** Sliding-window rate tracking: key -> sorted allow timestamps. */
  private readonly rateHits = new Map<string, number[]>();

  constructor(config: BehalfConfig = {}) {
    this.rootKey = config.rootKey ?? newRootKey();
    this.revocations = config.revocations ?? new MemoryRevocationStore();
    this.auditStore = config.audit ?? new MemoryAuditStore();
    this.now = config.now ?? (() => Date.now());
  }

  /** GRANT — a principal authorizes an agent: scoped, capped, short-lived. */
  grant(opts: GrantOptions): Mandate {
    const id = newId();
    const caveats: Caveat[] = [
      { t: "principal", principal: opts.principal },
      { t: "agent", agent: opts.agent },
      { t: "cap", can: opts.can },
      { t: "expires", at: this.now() + toMs(opts.expiresIn) },
    ];
    const sig = chainSignature(this.rootKey, id, caveats);
    return new Mandate({ v: 1, id, caveats, sig }, this);
  }

  /** ATTENUATE — narrow a mandate for a sub-agent. Never widens. */
  attenuate(token: MandateToken, opts: AttenuateOptions): Mandate {
    this.verifySignature(token);

    const parentCans = capsFromToken(token);
    const added: Caveat[] = [];

    if (opts.can) {
      const check = isNarrowing(parentCans, opts.can);
      if (!check.ok) throw new WideningError(check.offending!);
      added.push({ t: "cap", can: opts.can });
    }
    if (opts.expiresIn !== undefined) {
      added.push({ t: "expires", at: this.now() + toMs(opts.expiresIn) });
    }
    if (opts.agent) {
      added.push({ t: "agent", agent: opts.agent });
    }
    // A fresh id makes this link individually revocable; it stays downstream of
    // the parent, so revoking the parent still kills it.
    added.push({ t: "id", id: newId() });

    let sig = token.sig;
    for (const c of added) sig = extendSignature(sig, c);

    return new Mandate(
      { v: 1, id: token.id, caveats: [...token.caveats, ...added], sig },
      this,
    );
  }

  /** AUTHORIZE — verify a token then check a concrete action against it. */
  async authorize(token: MandateToken, action: string): Promise<void> {
    const chain = chainIds(token);
    const deny = async (reason: string): Promise<never> => {
      await record(this.auditStore, {
        mandateId: chain[chain.length - 1],
        chain,
        action,
        decision: "deny",
        reason,
      });
      throw new AuthorizationError(action, reason);
    };

    // 1. Signature integrity (offline, no network).
    try {
      this.verifySignature(token);
    } catch {
      return deny("invalid signature");
    }

    // 2. Revocation: this mandate or any ancestor.
    for (const id of chain) {
      if (await this.revocations.isRevoked(id)) {
        return deny(`revoked (${id})`);
      }
    }

    // 3. Expiry: earliest expires caveat wins.
    const now = this.now();
    for (const c of token.caveats) {
      if (c.t === "expires" && now > c.at) {
        return deny("expired");
      }
    }

    // 4. Scope: the action must satisfy EVERY cap caveat (the intersection).
    let request: Capability;
    try {
      request = parse(action);
    } catch (e) {
      return deny((e as Error).message);
    }
    let matched: Capability | undefined;
    for (const c of token.caveats) {
      if (c.t !== "cap") continue;
      const grant = c.can.map(parse).find((g) => satisfies(g, request));
      if (!grant) return deny(`"${action}" not within granted scope`);
      // Remember the tightest grant that carries a rate limit, for step 5.
      if (grant.rate) matched = grant;
    }

    // 5. Rate limits (stateful, sliding window).
    if (matched?.rate) {
      const key = `${chain[0]}|${request.verb}:${request.resource}`;
      const win = windowMs(matched.rate.per);
      const hits = (this.rateHits.get(key) ?? []).filter((t) => now - t < win);
      if (hits.length + 1 > matched.rate.value) {
        return deny(`rate limit exceeded (${matched.rate.value}/${matched.rate.per})`);
      }
      hits.push(now);
      this.rateHits.set(key, hits);
    }

    // Allowed — write the tamper-evident record.
    await record(this.auditStore, {
      mandateId: chain[chain.length - 1],
      chain,
      action,
      decision: "allow",
    });
  }

  /** REVOKE — kill a mandate (and, transitively, everything downstream). */
  async revoke(id: string): Promise<void> {
    await this.revocations.revoke(id);
  }

  /** AUDIT — fetch the tamper-evident trail for a mandate's chain. */
  async audit(id: string): Promise<AuditEntry[]> {
    return this.auditStore.forMandate(id);
  }

  /** Verify the integrity of the entire audit log. */
  async verifyAuditLog(): Promise<AuditIntegrity> {
    return verifyAudit(await this.auditStore.all());
  }

  /** Re-hydrate a Mandate from a serialized string (does not verify yet). */
  import(serialized: string): Mandate {
    const token = JSON.parse(
      Buffer.from(serialized, "base64url").toString("utf8"),
    ) as MandateToken;
    return new Mandate(token, this);
  }

  /** Throws {@link IntegrityError} if the HMAC chain does not replay. */
  verifySignature(token: MandateToken): void {
    const expected = chainSignature(this.rootKey, token.id, token.caveats);
    if (expected !== token.sig) throw new IntegrityError();
  }

  // ---- Static facade over a lazily-created default instance ----

  private static _default: Behalf | undefined;
  static get default(): Behalf {
    return (Behalf._default ??= new Behalf());
  }
  /** Replace the default instance (e.g. to inject a persistent store). */
  static configure(config: BehalfConfig): Behalf {
    return (Behalf._default = new Behalf(config));
  }

  static grant(opts: GrantOptions): Mandate {
    return Behalf.default.grant(opts);
  }
  static revoke(id: string): Promise<void> {
    return Behalf.default.revoke(id);
  }
  static audit(id: string): Promise<AuditEntry[]> {
    return Behalf.default.audit(id);
  }
  static import(serialized: string): Mandate {
    return Behalf.default.import(serialized);
  }
}

/** Construct an isolated engine (own key + stores). */
export function createBehalf(config: BehalfConfig = {}): Behalf {
  return new Behalf(config);
}

function chainIds(token: MandateToken): string[] {
  const ids = [token.id];
  for (const c of token.caveats) if (c.t === "id") ids.push(c.id);
  return ids;
}

function capsFromToken(token: MandateToken): string[] {
  // Effective grant for narrowing = the most recent cap caveat (already the
  // intersection of all prior ones by construction of attenuation).
  let latest: string[] = [];
  for (const c of token.caveats) if (c.t === "cap") latest = c.can;
  return latest;
}
