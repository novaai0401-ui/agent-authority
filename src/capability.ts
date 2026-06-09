import { CapabilityParseError } from "./errors.js";

/**
 * Capability grammar.
 *
 *   read:calendar              simple capability
 *   write:repo/acme-app        resource-scoped (path segments)
 *   spend:usd<=50              quantitative limit
 *   send:email rate<=10/h      rate limit
 *   *                          wildcard (discouraged; lint warns)
 *
 * A capability is `<verb>:<resource>[<op><amount>] [<key><op><value>[/<unit>]]`.
 */

export type Op = "<=" | ">=" | "<" | ">" | "=";

export interface Amount {
  op: Op;
  value: number;
}

export interface Rate {
  op: Op;
  value: number;
  /** Window unit: seconds, minutes, hours, days. Defaults to hours. */
  per: "s" | "m" | "h" | "d";
}

export interface Capability {
  raw: string;
  wildcard: boolean;
  verb: string;
  resource: string;
  /** Quantitative constraint on the resource, e.g. usd<=50. */
  amount?: Amount;
  /** Rate constraint, e.g. rate<=10/h. */
  rate?: Rate;
}

const OP_RE = "<=|>=|<|>|=";
const MAIN_RE = new RegExp(`^([^:\\s]+):([^<>=\\s]+)(?:(${OP_RE})([0-9]*\\.?[0-9]+))?$`);
const RATE_RE = new RegExp(`^rate(${OP_RE})([0-9]*\\.?[0-9]+)(?:\\/([smhd]))?$`);

/** Parse a capability string into structured form. Throws on malformed input. */
export function parse(raw: string): Capability {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new CapabilityParseError(raw, "empty");
  }
  if (trimmed === "*") {
    return { raw: trimmed, wildcard: true, verb: "*", resource: "*" };
  }

  const parts = trimmed.split(/\s+/);
  const main = parts[0];
  const m = MAIN_RE.exec(main);
  if (!m) {
    throw new CapabilityParseError(
      raw,
      'expected "<verb>:<resource>" optionally with a constraint',
    );
  }

  const cap: Capability = {
    raw: trimmed,
    wildcard: false,
    verb: m[1],
    resource: m[2],
  };
  if (m[3]) {
    cap.amount = { op: m[3] as Op, value: Number(m[4]) };
  }

  for (const extra of parts.slice(1)) {
    const r = RATE_RE.exec(extra);
    if (!r) {
      throw new CapabilityParseError(raw, `unrecognized constraint "${extra}"`);
    }
    cap.rate = { op: r[1] as Op, value: Number(r[2]), per: (r[3] as Rate["per"]) ?? "h" };
  }

  return cap;
}

/** Window length in milliseconds for a rate unit. */
export function windowMs(per: Rate["per"]): number {
  switch (per) {
    case "s":
      return 1000;
    case "m":
      return 60_000;
    case "h":
      return 3_600_000;
    case "d":
      return 86_400_000;
  }
}

function applyOp(value: number, op: Op, limit: number): boolean {
  switch (op) {
    case "<=":
      return value <= limit;
    case ">=":
      return value >= limit;
    case "<":
      return value < limit;
    case ">":
      return value > limit;
    case "=":
      return value === limit;
  }
}

/** Does grant's resource path cover the request's? Segment-prefix + wildcard. */
function resourceCovers(grant: string, request: string): boolean {
  if (grant === "*" || grant === request) return true;
  if (grant.endsWith("/*")) {
    const base = grant.slice(0, -2);
    return request === base || request.startsWith(base + "/");
  }
  // Bare prefix segment: "repo" covers "repo/acme-app".
  return request.startsWith(grant + "/");
}

/**
 * Does the `grant` capability permit the `request` action?
 *
 * The request is the concrete action being attempted (e.g. `spend:usd=20`); the
 * grant is the authority held (e.g. `spend:usd<=50`). Rate limits are *not*
 * evaluated here — they require call history and are enforced by the engine.
 */
export function satisfies(grant: Capability, request: Capability): boolean {
  if (grant.wildcard) return true;
  if (request.wildcard) return false; // can't request unbounded against a bounded grant

  if (grant.verb !== request.verb) return false;
  if (!resourceCovers(grant.resource, request.resource)) return false;

  if (grant.amount) {
    // The grant imposes a quantitative cap; the request must name an amount
    // that falls within it.
    if (!request.amount) return false;
    if (!applyOp(request.amount.value, grant.amount.op, grant.amount.value)) {
      return false;
    }
  }

  return true;
}

/** Convenience: parse both sides then check satisfaction. */
export function permits(grant: string, request: string): boolean {
  return satisfies(parse(grant), parse(request));
}

/**
 * Is every capability in `child` covered by some capability in `parent`?
 * Used to reject widening at attenuation time (the chain enforces it too, but
 * this gives a clear, early error).
 */
export function isNarrowing(parent: string[], child: string[]): { ok: boolean; offending?: string } {
  const parents = parent.map(parse);
  for (const c of child) {
    const childCap = parse(c);
    const covered = parents.some((p) => coversCapability(p, childCap));
    if (!covered) return { ok: false, offending: c };
  }
  return { ok: true };
}

/**
 * Is `child`'s quantitative bound a genuine tightening of `grant`'s, in the same
 * direction? An upper bound (`<=`/`<`) may only be narrowed by another upper
 * bound or an exact value within it; a lower bound (`>=`/`>`) likewise; `=` must
 * match. This rejects direction flips like narrowing `usd<=50` to `usd>=10`.
 */
function amountNarrows(grant: Amount, child: Amount): boolean {
  const isUpper = (op: Op) => op === "<=" || op === "<";
  const isLower = (op: Op) => op === ">=" || op === ">";
  if (grant.op === "=") return child.op === "=" && child.value === grant.value;
  if (isUpper(grant.op)) {
    if (!isUpper(child.op) && child.op !== "=") return false;
    return applyOp(child.value, grant.op, grant.value);
  }
  if (isLower(grant.op)) {
    if (!isLower(child.op) && child.op !== "=") return false;
    return applyOp(child.value, grant.op, grant.value);
  }
  return false;
}

/**
 * Does grant cover a *narrower capability* (not a concrete action)? This is the
 * attenuation check: e.g. `spend:usd<=50` covers `spend:usd<=20` but not
 * `spend:usd<=80`, and `read:calendar` covers `read:calendar`.
 */
function coversCapability(grant: Capability, child: Capability): boolean {
  if (grant.wildcard) return true;
  if (child.wildcard) return false;
  if (grant.verb !== child.verb) return false;
  if (!resourceCovers(grant.resource, child.resource)) return false;

  if (grant.amount) {
    if (!child.amount) return false; // child must also be bounded
    // The child must narrow in the SAME direction as the grant — a `<=` cap may
    // only be tightened by another upper bound (or `=`), never flipped to `>=`.
    if (!amountNarrows(grant.amount, child.amount)) return false;
  }
  if (grant.rate) {
    if (!child.rate) return false;
    if (child.rate.value / windowMs(child.rate.per) > grant.rate.value / windowMs(grant.rate.per)) {
      return false;
    }
  }
  return true;
}
