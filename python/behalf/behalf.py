"""The Behalf engine: holds the issuer keypair and stores, implements five verbs."""

from __future__ import annotations

import base64
import json
import re
import time
from typing import Callable, Optional

from . import audit as audit_mod
from . import capability as cap
from .crypto import (
    KeyPair,
    new_id,
    new_key_pair,
    public_of,
    sign_block,
    verify_block,
)
from .errors import AuthorizationError, BehalfError, IntegrityError, WideningError
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


class DelegationError(BehalfError):
    """Raised when attenuating a mandate that has no in-memory delegation key."""

    def __init__(self) -> None:
        super().__init__(
            "this mandate cannot be delegated (it was imported without its delegation key)"
        )


class Behalf:
    """The five-verb engine. Use ``create_behalf()`` or the classmethod facade."""

    _default: Optional["Behalf"] = None

    def __init__(
        self,
        *,
        root_key_pair: Optional[KeyPair] = None,
        trust: Optional[list[str]] = None,
        revocations: Optional[RevocationStore] = None,
        audit: Optional[AuditStore] = None,
        now: Optional[Callable[[], int]] = None,
    ) -> None:
        self._keys = root_key_pair or new_key_pair()
        self._trusted: set[str] = set(trust or [])
        self._trusted.add(self._keys.public)
        self._revocations = revocations or MemoryRevocationStore()
        self._audit = audit or MemoryAuditStore()
        self._now = now or (lambda: int(time.time() * 1000))
        self._rate_hits: dict[str, list[int]] = {}

    @property
    def public_key(self) -> str:
        """This engine's issuer public key (base64url). Share it with verifiers."""
        return self._keys.public

    # ---- the five verbs ----

    def grant(self, *, principal: str, agent: str, can: list[str], expires_in: str | int) -> Mandate:
        ident = new_id()
        nxt = new_key_pair()
        block = {
            "caveats": [
                {"t": "principal", "principal": principal},
                {"t": "agent", "agent": agent},
                {"t": "cap", "can": list(can)},
                {"t": "expires", "at": self._now() + _to_ms(expires_in)},
            ],
            "nextPub": nxt.public,
        }
        sig = sign_block(self._keys.private, block)
        token = {"v": 2, "id": ident, "blocks": [block], "sigs": [sig], "rootPub": self._keys.public}
        return Mandate(token, self, nxt.private)

    def attenuate(
        self,
        token: dict,
        delegation_key: Optional[str],
        *,
        can: Optional[list[str]] = None,
        expires_in: Optional[str | int] = None,
        agent: Optional[str] = None,
    ) -> Mandate:
        if delegation_key is None:
            raise DelegationError()
        self.verify_signature(token)

        parent_cans = _caps_from_token(token)
        caveats: list[dict] = []
        if can is not None:
            ok, offending = cap.is_narrowing(parent_cans, can)
            if not ok:
                raise WideningError(offending)
            caveats.append({"t": "cap", "can": list(can)})
        if expires_in is not None:
            caveats.append({"t": "expires", "at": self._now() + _to_ms(expires_in)})
        if agent is not None:
            caveats.append({"t": "agent", "agent": agent})
        caveats.append({"t": "id", "id": new_id()})

        nxt = new_key_pair()
        block = {"caveats": caveats, "nextPub": nxt.public}
        sig = sign_block(delegation_key, block)

        new_token = {
            "v": 2,
            "id": token["id"],
            "blocks": [*token["blocks"], block],
            "sigs": [*token["sigs"], sig],
            "rootPub": token["rootPub"],
        }
        return Mandate(new_token, self, nxt.private)

    def authorize(self, token: dict, action: str) -> None:
        chain = _chain_ids(token)

        def deny(reason: str) -> None:
            self._audit.record(
                mandate_id=chain[-1],
                chain=chain,
                action=action,
                decision="deny",
                reason=reason,
            )
            raise AuthorizationError(action, reason)

        # 1. Signature chain integrity (offline, public-key only).
        try:
            self.verify_signature(token)
        except IntegrityError as e:
            return deny(str(e))

        # 2. Revocation.
        for cid in chain:
            if self._revocations.is_revoked(cid):
                return deny(f"revoked ({cid})")

        caveats = _all_caveats(token)

        # 3. Expiry.
        now = self._now()
        for c in caveats:
            if c["t"] == "expires" and now > c["at"]:
                return deny("expired")

        # 4. Scope: action must satisfy EVERY cap caveat (the intersection).
        try:
            request = cap.parse(action)
        except Exception as e:  # noqa: BLE001
            return deny(str(e))
        matched = None
        for c in caveats:
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

        # 5. Rate limits.
        if matched is not None and matched.rate is not None:
            key = f"{chain[0]}|{request.verb}:{request.resource}"
            win = cap.window_ms(matched.rate.per)
            hits = [t for t in self._rate_hits.get(key, []) if now - t < win]
            if len(hits) + 1 > matched.rate.value:
                return deny(f"rate limit exceeded ({matched.rate.value:g}/{matched.rate.per})")
            hits.append(now)
            self._rate_hits[key] = hits

        self._audit.record(mandate_id=chain[-1], chain=chain, action=action, decision="allow")

    def revoke(self, id: str) -> None:
        self._revocations.revoke(id)

    def audit(self, id: str) -> list[dict]:
        return self._audit.for_mandate(id)

    # ---- helpers ----

    def verify_audit_log(self) -> dict:
        return audit_mod.verify(self._audit.all())

    def import_(self, serialized: str) -> Mandate:
        pad = "=" * (-len(serialized) % 4)
        raw = base64.urlsafe_b64decode(serialized + pad)
        return Mandate(json.loads(raw), self)

    def verify_signature(self, token: dict) -> None:
        if token.get("v") != 2:
            raise IntegrityError(f"unsupported token version {token.get('v')}")
        if token["rootPub"] not in self._trusted:
            raise IntegrityError("untrusted issuer")
        if len(token["blocks"]) != len(token["sigs"]):
            raise IntegrityError("malformed token")
        signer = token["rootPub"]
        for i, block in enumerate(token["blocks"]):
            if not verify_block(signer, block, token["sigs"][i]):
                raise IntegrityError(f"signature failed at block {i}")
            signer = block["nextPub"]

    # ---- static facade ----

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
    return Behalf(**config)


def _chain_ids(token: dict) -> list[str]:
    ids = [token["id"]]
    for c in _all_caveats(token):
        if c["t"] == "id":
            ids.append(c["id"])
    return ids


def _all_caveats(token: dict) -> list[dict]:
    out: list[dict] = []
    for block in token["blocks"]:
        out.extend(block["caveats"])
    return out


def _caps_from_token(token: dict) -> list[str]:
    latest: list[str] = []
    for c in _all_caveats(token):
        if c["t"] == "cap":
            latest = c["can"]
    return latest
