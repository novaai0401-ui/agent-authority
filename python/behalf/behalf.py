"""The Behalf engine: holds the signing key and stores, implements the five verbs."""

from __future__ import annotations

import base64
import json
import re
import time
from typing import Callable, Optional

from . import audit as audit_mod
from . import capability as cap
from .crypto import chain_signature, extend_signature, new_id, new_root_key
from .errors import AuthorizationError, IntegrityError, WideningError
from .mandate import Mandate
from .store import (
    AuditStore,
    MemoryAuditStore,
    MemoryRevocationStore,
    RevocationStore,
)

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)(ms|s|m|h|d)$")
_DURATION_MS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


def _to_ms(d: str | int | float) -> int:
    if isinstance(d, (int, float)):
        return int(d)
    m = _DURATION_RE.match(d.strip())
    if not m:
        raise ValueError(f'invalid duration "{d}" (use e.g. "1h", "10m", "30s")')
    return int(float(m.group(1)) * _DURATION_MS[m.group(2)])


class Behalf:
    """The five-verb engine. Use ``create_behalf()`` or the classmethod facade."""

    _default: Optional["Behalf"] = None

    def __init__(
        self,
        *,
        root_key: Optional[bytes] = None,
        revocations: Optional[RevocationStore] = None,
        audit: Optional[AuditStore] = None,
        now: Optional[Callable[[], int]] = None,
    ) -> None:
        self._root_key = root_key or new_root_key()
        self._revocations = revocations or MemoryRevocationStore()
        self._audit = audit or MemoryAuditStore()
        self._now = now or (lambda: int(time.time() * 1000))
        self._rate_hits: dict[str, list[int]] = {}

    # ---- the five verbs ----

    def grant(self, *, principal: str, agent: str, can: list[str], expires_in: str | int) -> Mandate:
        """GRANT — a principal authorizes an agent: scoped, capped, short-lived."""
        ident = new_id()
        caveats = [
            {"t": "principal", "principal": principal},
            {"t": "agent", "agent": agent},
            {"t": "cap", "can": list(can)},
            {"t": "expires", "at": self._now() + _to_ms(expires_in)},
        ]
        sig = chain_signature(self._root_key, ident, caveats)
        return Mandate({"v": 1, "id": ident, "caveats": caveats, "sig": sig}, self)

    def attenuate(
        self,
        token: dict,
        *,
        can: Optional[list[str]] = None,
        expires_in: Optional[str | int] = None,
        agent: Optional[str] = None,
    ) -> Mandate:
        """ATTENUATE — narrow a mandate for a sub-agent. Never widens."""
        self.verify_signature(token)
        parent_cans = _caps_from_token(token)
        added: list[dict] = []

        if can is not None:
            ok, offending = cap.is_narrowing(parent_cans, can)
            if not ok:
                raise WideningError(offending)
            added.append({"t": "cap", "can": list(can)})
        if expires_in is not None:
            added.append({"t": "expires", "at": self._now() + _to_ms(expires_in)})
        if agent is not None:
            added.append({"t": "agent", "agent": agent})
        added.append({"t": "id", "id": new_id()})

        sig = token["sig"]
        for c in added:
            sig = extend_signature(sig, c)

        new_token = {
            "v": 1,
            "id": token["id"],
            "caveats": [*token["caveats"], *added],
            "sig": sig,
        }
        return Mandate(new_token, self)

    def authorize(self, token: dict, action: str) -> None:
        """AUTHORIZE — verify a token then check a concrete action against it."""
        chain = _chain_ids(token)

        def deny(reason: str) -> None:
            audit_mod.record(
                self._audit,
                mandate_id=chain[-1],
                chain=chain,
                action=action,
                decision="deny",
                reason=reason,
            )
            raise AuthorizationError(action, reason)

        # 1. Signature integrity (offline).
        try:
            self.verify_signature(token)
        except IntegrityError:
            return deny("invalid signature")

        # 2. Revocation.
        for cid in chain:
            if self._revocations.is_revoked(cid):
                return deny(f"revoked ({cid})")

        # 3. Expiry.
        now = self._now()
        for c in token["caveats"]:
            if c["t"] == "expires" and now > c["at"]:
                return deny("expired")

        # 4. Scope: action must satisfy EVERY cap caveat (the intersection).
        try:
            request = cap.parse(action)
        except Exception as e:  # noqa: BLE001 - surface parse detail
            return deny(str(e))
        matched = None
        for c in token["caveats"]:
            if c["t"] != "cap":
                continue
            grant = next(
                (g for g in (cap.parse(x) for x in c["can"]) if cap.satisfies(g, request)),
                None,
            )
            if grant is None:
                return deny(f'"{action}" not within granted scope')
            if grant.rate is not None:
                matched = grant

        # 5. Rate limits (sliding window).
        if matched is not None and matched.rate is not None:
            key = f"{chain[0]}|{request.verb}:{request.resource}"
            win = cap.window_ms(matched.rate.per)
            hits = [t for t in self._rate_hits.get(key, []) if now - t < win]
            if len(hits) + 1 > matched.rate.value:
                return deny(f"rate limit exceeded ({matched.rate.value:g}/{matched.rate.per})")
            hits.append(now)
            self._rate_hits[key] = hits

        audit_mod.record(
            self._audit,
            mandate_id=chain[-1],
            chain=chain,
            action=action,
            decision="allow",
        )

    def revoke(self, id: str) -> None:
        """REVOKE — kill a mandate (and everything downstream)."""
        self._revocations.revoke(id)

    def audit(self, id: str) -> list[dict]:
        """AUDIT — fetch the tamper-evident trail for a mandate's chain."""
        return self._audit.for_mandate(id)

    # ---- helpers ----

    def verify_audit_log(self) -> dict:
        return audit_mod.verify(self._audit.all())

    def import_(self, serialized: str) -> Mandate:
        pad = "=" * (-len(serialized) % 4)
        raw = base64.urlsafe_b64decode(serialized + pad)
        return Mandate(json.loads(raw), self)

    def verify_signature(self, token: dict) -> None:
        expected = chain_signature(self._root_key, token["id"], token["caveats"])
        if expected != token["sig"]:
            raise IntegrityError()

    # ---- static facade over a lazily-created default instance ----

    @classmethod
    def default(cls) -> "Behalf":
        if cls._default is None:
            cls._default = cls()
        return cls._default

    @classmethod
    def configure(cls, **config) -> "Behalf":
        cls._default = cls(**config)
        return cls._default


def create_behalf(**config) -> Behalf:
    """Construct an isolated engine (own key + stores)."""
    return Behalf(**config)


def _chain_ids(token: dict) -> list[str]:
    ids = [token["id"]]
    for c in token["caveats"]:
        if c["t"] == "id":
            ids.append(c["id"])
    return ids


def _caps_from_token(token: dict) -> list[str]:
    latest: list[str] = []
    for c in token["caveats"]:
        if c["t"] == "cap":
            latest = c["can"]
    return latest
