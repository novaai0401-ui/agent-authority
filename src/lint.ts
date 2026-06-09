import { parse, type Capability } from "./capability.js";
import { CapabilityParseError } from "./errors.js";

/**
 * Capability linting. The grammar permits broad or unbounded scopes (`*`, an
 * unconstrained `spend:`, ...); the spec says these are "discouraged; lint
 * warns". This surfaces them so humans and agents write tight scopes by default.
 */

export type LintLevel = "error" | "warn" | "info";

export interface LintFinding {
  capability: string;
  level: LintLevel;
  rule: string;
  message: string;
}

/** Verbs that move a quantity and should carry an amount limit. */
const QUANTITATIVE_VERBS = new Set(["spend", "pay", "transfer", "charge", "withdraw", "refund"]);
/** Verbs that fan out and should usually carry a rate limit. */
const RATE_VERBS = new Set(["send", "email", "sms", "notify", "post", "publish", "call"]);

/** Lint a set of capability strings; returns findings ordered by input. */
export function lint(capabilities: string[]): LintFinding[] {
  const findings: LintFinding[] = [];
  const seen = new Set<string>();

  for (const raw of capabilities) {
    if (seen.has(raw)) {
      findings.push({
        capability: raw,
        level: "warn",
        rule: "duplicate",
        message: "duplicate capability; remove the repeat",
      });
      continue;
    }
    seen.add(raw);

    let cap: Capability;
    try {
      cap = parse(raw);
    } catch (e) {
      findings.push({
        capability: raw,
        level: "error",
        rule: "unparseable",
        message: e instanceof CapabilityParseError ? e.message : String(e),
      });
      continue;
    }

    if (cap.wildcard) {
      findings.push({
        capability: raw,
        level: "warn",
        rule: "wildcard",
        message: "`*` grants unlimited authority; grant specific capabilities instead",
      });
      continue;
    }

    if (cap.verb === "*" || cap.resource === "*") {
      findings.push({
        capability: raw,
        level: "warn",
        rule: "wildcard-part",
        message: "a `*` verb or resource is overly broad; name it explicitly",
      });
    }

    if (QUANTITATIVE_VERBS.has(cap.verb) && !cap.amount) {
      findings.push({
        capability: raw,
        level: "warn",
        rule: "unbounded-amount",
        message: `"${cap.verb}" has no limit; add a cap like "${cap.verb}:${cap.resource}<=50"`,
      });
    }

    if (RATE_VERBS.has(cap.verb) && !cap.rate) {
      findings.push({
        capability: raw,
        level: "info",
        rule: "no-rate-limit",
        message: `"${cap.verb}" has no rate limit; consider "${raw} rate<=10/h"`,
      });
    }
  }

  return findings;
}

/** True if linting found nothing at `warn` or `error` level. */
export function isClean(capabilities: string[]): boolean {
  return !lint(capabilities).some((f) => f.level !== "info");
}
