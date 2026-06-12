import {
  newKeyPair,
  newId,
  signBlock,
  verifyBlock,
  exportPublicKey,
  importPublicKey,
  importPrivateKey,
  signProof,
  verifyProof,
  type KeyPair,
} from "./crypto.js";
import {
  parse,
  satisfies,
  isNarrowing,
  windowMs,
  type Capability,
} from "./capability.js";
import { verify as verifyAudit } from "./audit.js";
import {
  MemoryAuditStore,
  MemoryRevocationStore,
  MemoryRateStore,
  type AuditStore,
  type RevocationStore,
  type RateStore,
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
  Proof,
} from "./types.js";
import type { KeyObject } from "node:crypto";

export interface BehalfConfig {
  /** Issuer keypair. Auto-generated if omitted (so the engine can grant). */
  rootKeyPair?: KeyPair;
  /** Additional trusted issuer public keys (base64url SPKI) for foreign mandates. */
  trust?: string[];
  revocations?: RevocationStore;
  audit?: AuditStore;
  /** Rate-limit accounting. Use a shared store to enforce one cap across agents. */
  rate?: RateStore;
  /** Max age (ms) of a possession proof accepted at authorize. Default 5 min. */
  proofSkewMs?: number;
  /**
   * Require a verifier-issued single-use nonce (see `challenge()`) on every
   * possession proof — eliminates replay within the freshness window at the
   * cost of a challenge round-trip. Default false.
   */
  requireNonce?: boolean;
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
  private readonly rateStore: RateStore;
  private readonly proofSkewMs: number;
  private readonly requireNonce: boolean;
  /** Outstanding single-use challenges: nonce → expiry (ms). */
  private readonly nonces = new Map<string, number>();
  private readonly now: () => number;

  constructor(config: BehalfConfig = {}) {
    this.rootKeyPair = config.rootKeyPair ?? newKeyPair();
    this.trusted = new Set(config.trust ?? []);
    this.trusted.add(exportPublicKey(this.rootKeyPair.publicKey));
    this.revocations = config.revocations ?? new MemoryRevocationStore();
    this.auditStore = config.audit ?? new MemoryAuditStore();
    this.rateStore = config.rate ?? new MemoryRateStore();
    this.proofSkewMs = config.proofSkewMs ?? 300_000;
    this.requireNonce = config.requireNonce ?? false;
    this.now = config.now ?? (() => Date.now());
  }

  /**
   * Issue a single-use challenge nonce. The holder binds it into its possession
   * proof (`prove(action, { nonce })`); `authorize` consumes it, so that proof
   * can never be replayed — even within the freshness window.
   */
  challenge(): string {
    const nonce = newId();
    this.nonces.set(nonce, this.now() + this.proofSkewMs);
    return nonce;
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

  /**
   * Mint a possession proof for `token` using `delegationKey` (the holder's
   * terminal key). Throws if the key is absent — you cannot act on a mandate you
   * only hold the public token for.
   */
  provePossession(
    token: MandateToken,
    delegationKey: KeyObject,
    action: string,
    nonce?: string,
  ): Proof {
    const ts = this.now();
    return {
      ts,
      sig: signProof(delegationKey, token.id, token.sigs, ts, action, nonce ?? ""),
      ...(nonce !== undefined ? { nonce } : {}),
    };
  }

  /** Holder path: `mandate.authorize()` routes here, minting a PoP from its key. */
  async authorizeAsHolder(
    token: MandateToken,
    action: string,
    delegationKey: KeyObject | undefined,
  ): Promise<void> {
    if (!delegationKey) throw new BehalfDelegationError();
    // In-process the engine is its own verifier, so it can self-issue a nonce.
    const nonce = this.requireNonce ? this.challenge() : undefined;
    return this.authorize(token, action, this.provePossession(token, delegationKey, action, nonce));
  }

  /**
   * AUTHORIZE — verify a token, prove the presenter possesses the chain's
   * terminal key, then check a concrete action. The `proof` is required: it
   * binds the presenter to the exact (untruncated) chain and a fresh timestamp,
   * which is what closes trailing-block truncation and stops a serialized token
   * from being a reusable bearer credential. Produce one with `provePossession`
   * (or, across the wire, `behalf/a2a`'s `present`).
   */
  async authorize(token: MandateToken, action: string, proof?: Proof): Promise<void> {
    const chain = chainIds(token);
    const deny = async (reason: string): Promise<never> => {
      await this.auditStore.record({
        mandateId: chain[chain.length - 1],
        issuer: token.rootPub,
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

    // 2. Proof of possession of the chain's terminal key (anti-truncation).
    if (!proof) return deny("possession proof required");
    if (Math.abs(this.now() - proof.ts) > this.proofSkewMs) return deny("stale possession proof");
    // 2b. Single-use nonce: consumed on first use, so a captured proof can
    // never be replayed. Mandatory when the engine is configured requireNonce.
    if (proof.nonce !== undefined) {
      const expiry = this.nonces.get(proof.nonce);
      if (expiry === undefined || this.now() > expiry) {
        return deny("unknown or already-used nonce");
      }
      this.nonces.delete(proof.nonce);
    } else if (this.requireNonce) {
      return deny("nonce required (request one via challenge())");
    }
    const terminal = importPublicKey(token.blocks[token.blocks.length - 1].nextPub);
    if (!verifyProof(terminal, token.id, token.sigs, proof.ts, action, proof.sig, proof.nonce ?? "")) {
      return deny("invalid possession proof");
    }

    // 3. Revocation + expiry + scope (shared with inspect()).
    const ev = await this.evaluate(token, action);
    if (!ev.ok) return deny(ev.reason);

    // 4. Rate limits (sliding window; shareable via the rate store).
    if (ev.matched?.rate) {
      const key = `${chain[0]}|${ev.request.verb}:${ev.request.resource}`;
      const allowed = await this.rateStore.hit(
        key,
        windowMs(ev.matched.rate.per),
        ev.matched.rate.value,
        this.now(),
      );
      if (!allowed) {
        return deny(`rate limit exceeded (${ev.matched.rate.value}/${ev.matched.rate.per})`);
      }
    }

    await this.auditStore.record({
      mandateId: chain[chain.length - 1],
      issuer: token.rootPub,
      chain,
      action,
      decision: "allow",
    });
  }

  /**
   * INSPECT — advisory check of signature, revocation, expiry, and scope WITHOUT
   * a possession proof. Use for "would this token allow X?" tooling (CLI,
   * dashboards, `check_authority`). It does NOT prove the caller holds the
   * mandate, does not consume rate budget, and writes no audit record — never
   * gate a real action on it; use `authorize` for that.
   */
  async inspect(token: MandateToken, action: string): Promise<{ allowed: boolean; reason?: string }> {
    const ev = await this.evaluate(token, action);
    return ev.ok ? { allowed: true } : { allowed: false, reason: ev.reason };
  }

  /** Shared signature + revocation + expiry + scope check (no PoP, no side effects). */
  private async evaluate(
    token: MandateToken,
    action: string,
  ): Promise<
    | { ok: true; matched?: Capability; request: Capability }
    | { ok: false; reason: string }
  > {
    try {
      this.verifySignature(token);
    } catch (e) {
      return { ok: false, reason: e instanceof IntegrityError ? e.message : "invalid signature" };
    }
    for (const id of chainIds(token)) {
      if (await this.revocations.isRevoked(id)) return { ok: false, reason: `revoked (${id})` };
    }
    const caveats = allCaveats(token);
    const now = this.now();
    for (const c of caveats) {
      if (c.t === "expires" && now > c.at) return { ok: false, reason: "expired" };
    }
    let request: Capability;
    try {
      request = parse(action);
    } catch (e) {
      return { ok: false, reason: (e as Error).message };
    }
    let matched: Capability | undefined;
    for (const c of caveats) {
      if (c.t !== "cap") continue;
      const grant = c.can.map(parse).find((g) => satisfies(g, request));
      if (!grant) return { ok: false, reason: `"${action}" not within granted scope` };
      if (grant.rate) matched = grant;
    }
    return { ok: true, matched, request };
  }

  /** REVOKE — kill a mandate (and, transitively, everything downstream). */
  async revoke(id: string): Promise<void> {
    await this.revocations.revoke(id);
  }

  /** AUDIT — fetch the hash-chained audit trail for a mandate's chain. */
  async audit(id: string): Promise<AuditEntry[]> {
    return this.auditStore.forMandate(id);
  }

  /** Verify the integrity of the entire audit log. */
  async verifyAuditLog(): Promise<AuditIntegrity> {
    return verifyAudit(await this.auditStore.all());
  }

  /**
   * Re-hydrate a Mandate from a serialized string. Accepts both forms:
   * - `serialize()` (public token) → inspect/verify only; cannot authorize,
   *   prove, or attenuate (no delegation key).
   * - `serializeWithKey()` (token + delegation key) → a full holder credential
   *   that can authorize, prove, and attenuate.
   */
  import(serialized: string): Mandate {
    const parsed = JSON.parse(Buffer.from(serialized, "base64url").toString("utf8")) as
      | MandateToken
      | { token: MandateToken; key: string };
    if ("token" in parsed && "key" in parsed) {
      const token = parsed.token;
      // The delegation key's public half is the chain's terminal nextPub.
      const pub = token.blocks[token.blocks.length - 1].nextPub;
      return new Mandate(token, this, importPrivateKey(parsed.key, pub));
    }
    return new Mandate(parsed as MandateToken, this);
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
