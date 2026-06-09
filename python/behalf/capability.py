"""Capability grammar — parsing, satisfaction, and narrowing checks.

    read:calendar              simple capability
    write:repo/acme-app        resource-scoped (path segments)
    spend:usd<=50              quantitative limit
    send:email rate<=10/h      rate limit
    *                          wildcard (discouraged; lint warns)

A capability is ``<verb>:<resource>[<op><amount>] [<key><op><value>[/<unit>]]``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .errors import CapabilityParseError

_OP = r"<=|>=|<|>|="
_MAIN_RE = re.compile(rf"^([^:\s]+):([^<>=\s]+)(?:({_OP})([0-9]*\.?[0-9]+))?$")
_RATE_RE = re.compile(rf"^rate({_OP})([0-9]*\.?[0-9]+)(?:/([smhd]))?$")

_WINDOW_MS = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


@dataclass
class Amount:
    op: str
    value: float


@dataclass
class Rate:
    op: str
    value: float
    per: str = "h"


@dataclass
class Capability:
    raw: str
    wildcard: bool
    verb: str
    resource: str
    amount: Optional[Amount] = None
    rate: Optional[Rate] = None


def parse(raw: str) -> Capability:
    """Parse a capability string into structured form. Raises on malformed input."""
    trimmed = raw.strip()
    if not trimmed:
        raise CapabilityParseError(raw, "empty")
    if trimmed == "*":
        return Capability(raw=trimmed, wildcard=True, verb="*", resource="*")

    parts = re.split(r"\s+", trimmed)
    m = _MAIN_RE.match(parts[0])
    if not m:
        raise CapabilityParseError(
            raw, 'expected "<verb>:<resource>" optionally with a constraint'
        )

    cap = Capability(raw=trimmed, wildcard=False, verb=m.group(1), resource=m.group(2))
    if m.group(3):
        cap.amount = Amount(op=m.group(3), value=float(m.group(4)))

    for extra in parts[1:]:
        r = _RATE_RE.match(extra)
        if not r:
            raise CapabilityParseError(raw, f'unrecognized constraint "{extra}"')
        cap.rate = Rate(op=r.group(1), value=float(r.group(2)), per=r.group(3) or "h")

    return cap


def window_ms(per: str) -> int:
    return _WINDOW_MS[per]


def _apply_op(value: float, op: str, limit: float) -> bool:
    return {
        "<=": value <= limit,
        ">=": value >= limit,
        "<": value < limit,
        ">": value > limit,
        "=": value == limit,
    }[op]


def _resource_covers(grant: str, request: str) -> bool:
    if grant == "*" or grant == request:
        return True
    if grant.endswith("/*"):
        base = grant[:-2]
        return request == base or request.startswith(base + "/")
    return request.startswith(grant + "/")


def satisfies(grant: Capability, request: Capability) -> bool:
    """Does ``grant`` permit the concrete ``request`` action? (rate handled by engine)."""
    if grant.wildcard:
        return True
    if request.wildcard:
        return False
    if grant.verb != request.verb:
        return False
    if not _resource_covers(grant.resource, request.resource):
        return False
    if grant.amount is not None:
        if request.amount is None:
            return False
        if not _apply_op(request.amount.value, grant.amount.op, grant.amount.value):
            return False
    return True


def permits(grant: str, request: str) -> bool:
    return satisfies(parse(grant), parse(request))


def is_narrowing(parent: list[str], child: list[str]) -> tuple[bool, Optional[str]]:
    """Is every capability in ``child`` covered by some capability in ``parent``?"""
    parents = [parse(p) for p in parent]
    for c in child:
        child_cap = parse(c)
        if not any(_covers_capability(p, child_cap) for p in parents):
            return (False, c)
    return (True, None)


def _covers_capability(grant: Capability, child: Capability) -> bool:
    """Does grant cover a narrower *capability* (not a concrete action)?"""
    if grant.wildcard:
        return True
    if child.wildcard:
        return False
    if grant.verb != child.verb:
        return False
    if not _resource_covers(grant.resource, child.resource):
        return False
    if grant.amount is not None:
        if child.amount is None:
            return False
        if not _apply_op(child.amount.value, grant.amount.op, grant.amount.value):
            return False
    if grant.rate is not None:
        if child.rate is None:
            return False
        if child.rate.value / window_ms(child.rate.per) > grant.rate.value / window_ms(
            grant.rate.per
        ):
            return False
    return True
