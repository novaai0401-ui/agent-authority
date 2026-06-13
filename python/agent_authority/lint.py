"""Capability linting (mirrors the TypeScript implementation).

The grammar permits broad or unbounded scopes; the spec says these are
"discouraged; lint warns". This surfaces them so tight scopes are the default.
"""

from __future__ import annotations

from dataclasses import dataclass

from .capability import parse
from .errors import CapabilityParseError

_QUANTITATIVE_VERBS = {"spend", "pay", "transfer", "charge", "withdraw", "refund"}
_RATE_VERBS = {"send", "email", "sms", "notify", "post", "publish", "call"}


@dataclass
class LintFinding:
    capability: str
    level: str  # "error" | "warn" | "info"
    rule: str
    message: str


def lint(capabilities: list[str]) -> list[LintFinding]:
    findings: list[LintFinding] = []
    seen: set[str] = set()

    for raw in capabilities:
        if raw in seen:
            findings.append(
                LintFinding(raw, "warn", "duplicate", "duplicate capability; remove the repeat")
            )
            continue
        seen.add(raw)

        try:
            cap = parse(raw)
        except CapabilityParseError as e:
            findings.append(LintFinding(raw, "error", "unparseable", str(e)))
            continue

        if cap.wildcard:
            findings.append(
                LintFinding(
                    raw,
                    "warn",
                    "wildcard",
                    "`*` grants unlimited authority; grant specific capabilities instead",
                )
            )
            continue

        if cap.verb == "*" or cap.resource == "*":
            findings.append(
                LintFinding(
                    raw, "warn", "wildcard-part", "a `*` verb or resource is overly broad; name it explicitly"
                )
            )

        if cap.verb in _QUANTITATIVE_VERBS and cap.amount is None:
            findings.append(
                LintFinding(
                    raw,
                    "warn",
                    "unbounded-amount",
                    f'"{cap.verb}" has no limit; add a cap like "{cap.verb}:{cap.resource}<=50"',
                )
            )

        if cap.verb in _RATE_VERBS and cap.rate is None:
            findings.append(
                LintFinding(
                    raw, "info", "no-rate-limit", f'"{cap.verb}" has no rate limit; consider "{raw} rate<=10/h"'
                )
            )

    return findings


def is_clean(capabilities: list[str]) -> bool:
    return not any(f.level != "info" for f in lint(capabilities))
