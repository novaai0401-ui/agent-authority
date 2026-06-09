import {
  newKeyPair,
  newId,
  signBlock,
  verifyBlock,
  exportPublicKey,
  importPublicKey,
  type KeyPair,
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
import { AuthorizationError, BehalfError, IntegrityError, WideningError } from "./errors.js";
import type {
  AttenuateOptions,
  AuditEntry,
  AuditIntegrity,
  Block,
  Caveat,
  GrantOptions,
  MandateToken,
} from "./types.js";
import type { KeyObject } from "node:crypto";

export interface BehalfConfig {
  /** Issuer keypair. Auto-generated if omitted (so the engine can grant). */
  rootKeyPair?: KeyPair;
  /** Additional trusted issuer public keys (base64url SPKI) for foreign mandates. */
  trust?: string[];
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
  const unit: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
  return n * unit[m[2]];
}

/**
 * The Behalf engine: holds the issuer keypair and the revocation / audit stores,
 * and implements the five verbs. Use the default singleton via the static
 * facade (`Behalf.grant`, ...) or construct an isolated instance with
 * `createBehalf()`. A verify-only engine (no grant) is made with
 * `createBehalf({ trust: [issuerPublicKey] })` and a generated throwaway key.
 */
export class Behalf implements Engine {
  private readonly rootKeyPair: KeyPair;
  private readonly trusted: Set<string>;
  private readonly revocations: RevocationStore;
  private readonly auditStore: AuditStore;
  private readonly now: () => number;
  /** Sliding-window rate tracking: key -> sorted allow timestamps. */
  private readonly rateHits = new Map<string, number[]>();

  constructor(config: BehalfConfig = {}) {
    this.rootKeyPair = config.rootKeyPair ?? newKeyPair();
    this.trusted = new Set(config.trust ?? []);
    this.trusted.add(exportPublicKey(this.rootKeyPair.publicKey));
    this.revocations = config.revocations ?? new MemoryRevocationStore();
    this.auditStore = config.audit ?? new MemoryAuditStore();
    this.now = config.now ?? (() => Date.now());
  }

  /** This engine's issuer public key (base64url SPKI). Share it with verifiers. */
  get publicKey(): string {
    return exportPublicKey(this.rootKeyPair.publicKey);
  }

  /** GRANT — a principal authorizes an agent: scoped, capped, short-lived. */
  grant(opts: GrantOptions): Mandate {
    const id = newId();
    const next = newKeyPair();
    const block: Block = {
      caveats: [
        { t: "principal", principal: opts.principal },
        { t: "agent", agent: opts.agent },
        { t: "cap", can: opts.can },
        { t: "expires", at: this.now() + toMs(opts.expiresIn) },
      ],
      nextPub: exportPublicKey(next.publicKey),
    };
    const sig = signBlock(this.rootKeyPair.privateKey, block);
    const token: MandateToken = {
      v: 2,
      id,
      blocks: [block],
      sigs: [sig],
      rootPub: this.publicKey,
    };
    return new Mandate(token, this, next.privateKey);
  }

  /** ATTENUATE — narrow a mandate for a sub-agent. Never widens. */
  attenuate(
    token: MandateToken,
    delegationKey: KeyObject | undefined,
    opts: AttenuateOptions,
  ): Mandate {
    if (!delegationKey) {
      throw new BehalfDelegationError();
    }
    this.verifySignature(token);

    const parentCans = capsFromToken(token);
    const caveats: Caveat[] = [];
    if (opts.can) {
      const check = isNarrowing(parentCans, opts.can);
      if (!check.ok) throw new WideningError(check.offending!);
      caveats.push({ t: "cap", can: opts.can });
    }
    if (opts.expiresIn !== undefined) {
      caveats.push({ t: "expires", at: this.now() + toMs(opts.expiresIn) });
    }
    if (opts.agent) {
      caveats.push({ t: "agent", agent: opts.agent });
    }
    // A fresh id makes this link individually revocable; it stays downstream of
    // the parent, so revoking the parent still kills it.
    caveats.push({ t: "id", id: newId() });

    const next = newKeyPair();
    const block: Block = { caveats, nextPub: exportPublicKey(next.publicKey) };
    const sig = signBlock(delegationKey, block);

    const newToken: MandateToken = {
      v: 2,
      id: token.id,
      blocks: [...token.blocks, block],
      sigs: [...token.sigs, sig],
      rootPub: token.rootPub,
    };
    return new Mandate(newToken, this, next.privateKey);
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

    // 1. Signature chain integrity (offline, public-key only).
    try {
      this.verifySignature(token);
    } catch (e) {
      return deny(e instanceof IntegrityError ? e.message : "invalid signature");
    }

    // 2. Revocation: this mandate or any ancestor.
    for (const id of chain) {
      if (await this.revocations.isRevoked(id)) return deny(`revoked (${id})`);
    }

    const caveats = allCaveats(token);

    // 3. Expiry: earliest expires caveat wins.
    const now = this.now();
    for (const c of caveats) {
      if (c.t === "expires" && now > c.at) return deny("expired");
    }

    // 4. Scope: the action must satisfy EVERY cap caveat (the intersection).
    let request: Capability;
    try {
      request = parse(action);
    } catch (e) {
      return deny((e as Error).message);
    }
    let matched: Capability | undefined;
    for (const c of caveats) {
      if (c.t !== "cap") continue;
      const grant = c.can.map(parse).find((g) => satisfies(g, request));
      if (!grant) return deny(`"${action}" not within granted scope`);
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

  /** Re-hydrate a Mandate from a serialized string (verify/authorize only). */
  import(serialized: string): Mandate {
    const token = JSON.parse(
      Buffer.from(serialized, "base64url").toString("utf8"),
    ) as MandateToken;
    return new Mandate(token, this);
  }

  /**
   * Throws {@link IntegrityError} if the issuer is untrusted or the Ed25519
   * signature chain does not verify. Pure public-key checks — no secrets.
   */
  verifySignature(token: MandateToken): void {
    if (token.v !== 2) throw new IntegrityError(`unsupported token version ${token.v}`);
    if (!this.trusted.has(token.rootPub)) throw new IntegrityError("untrusted issuer");
    if (token.blocks.length !== token.sigs.length) throw new IntegrityError("malformed token");

    let signerPub = importPublicKey(token.rootPub);
    for (let i = 0; i < token.blocks.length; i++) {
      const block = token.blocks[i];
      if (!verifyBlock(signerPub, block, token.sigs[i])) {
        throw new IntegrityError(`signature failed at block ${i}`);
      }
      signerPub = importPublicKey(block.nextPub);
    }
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

/** Thrown when attenuating a mandate that has no in-memory delegation key. */
export class BehalfDelegationError extends BehalfError {
  constructor() {
    super("this mandate cannot be delegated (it was imported without its delegation key)");
  }
}

/** Construct an isolated engine (own key + stores). */
export function createBehalf(config: BehalfConfig = {}): Behalf {
  return new Behalf(config);
}

function chainIds(token: MandateToken): string[] {
  const ids = [token.id];
  for (const c of allCaveats(token)) if (c.t === "id") ids.push(c.id);
  return ids;
}

function allCaveats(token: MandateToken): Caveat[] {
  return token.blocks.flatMap((b) => b.caveats);
}

function capsFromToken(token: MandateToken): string[] {
  let latest: string[] = [];
  for (const c of allCaveats(token)) if (c.t === "cap") latest = c.can;
  return latest;
}
