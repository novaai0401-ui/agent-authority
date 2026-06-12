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
    sign_proof,
    verify_block,
    verify_proof,
)
from .errors import AuthorizationError, BehalfError, IntegrityError, WideningError
from .mandate import Mandate
from .store import (
    AuditStore,
    MemoryAuditStore,
    MemoryRateStore,
    MemoryRevocationStore,
    RateStore,
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
        rate: Optional[RateStore] = None,
        proof_skew_ms: int = 300_000,
        require_nonce: bool = False,
        now: Optional[Callable[[], int]] = None,
    ) -> None:
        self._keys = root_key_pair or new_key_pair()
        self._trusted: set[str] = set(trust or [])
        self._trusted.add(self._keys.public)
        self._revocations = revocations or MemoryRevocationStore()
        self._audit = audit or MemoryAuditStore()
        self._rate = rate or MemoryRateStore()
        self._proof_skew_ms = proof_skew_ms
        self._require_nonce = require_nonce
        self._nonces: dict[str, int] = {}
        self._now = now or (lambda: int(time.time() * 1000))

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

    def challenge(self) -> str:
        """Issue a single-use nonce; bind it into a proof for true anti-replay."""
        nonce = new_id()
        self._nonces[nonce] = self._now() + self._proof_skew_ms
        return nonce

    def prove_possession(
        self, token: dict, delegation_key: str, action: str, nonce: Optional[str] = None
    ) -> dict:
        """Mint a proof of possession of the chain's terminal key, bound to action."""
        ts = self._now()
        proof = {
            "ts": ts,
            "sig": sign_proof(delegation_key, token["id"], token["sigs"], ts, action, nonce or ""),
        }
        if nonce is not None:
            proof["nonce"] = nonce
        return proof

    def authorize_as_holder(self, token: dict, action: str, delegation_key: Optional[str]) -> None:
        """Holder path: ``mandate.authorize()`` routes here, minting a PoP."""
        if delegation_key is None:
            raise DelegationError()
        # In-process the engine is its own verifier, so it can self-issue a nonce.
        nonce = self.challenge() if self._require_nonce else None
        self.authorize(token, action, self.prove_possession(token, delegation_key, action, nonce))

    def authorize(self, token: dict, action: str, proof: Optional[dict] = None) -> None:
        """Verify token + proof of possession of the terminal key, then the action.

        ``proof`` is required: it binds the presenter to the exact (untruncated)
        chain and a fresh timestamp, which closes trailing-block truncation and
        stops a serialized token from being a reusable bearer credential."""
        chain = _chain_ids(token)

        def deny(reason: str) -> None:
            self._audit.record(
                mandate_id=chain[-1],
                chain=chain,
                action=action,
                decision="deny",
                reason=reason,
                issuer=token["rootPub"],
            )
            raise AuthorizationError(action, reason)

        # 1. Signature chain integrity (offline, public-key only).
        try:
            self.verify_signature(token)
        except IntegrityError as e:
            return deny(str(e))

        # 2. Proof of possession of the chain's terminal key (anti-truncation).
        if not proof:
            return deny("possession proof required")
        if abs(self._now() - int(proof.get("ts", 0))) > self._proof_skew_ms:
            return deny("stale possession proof")
        # Single-use nonce: consumed on first use, so a captured proof can never
        # be replayed. Mandatory when the engine is configured require_nonce.
        nonce = proof.get("nonce")
        if nonce is not None:
            expiry = self._nonces.get(nonce)
            if expiry is None or self._now() > expiry:
                return deny("unknown or already-used nonce")
            del self._nonces[nonce]
        elif self._require_nonce:
            return deny("nonce required (request one via challenge())")
        terminal = token["blocks"][-1]["nextPub"]
        if not verify_proof(
            terminal, token["id"], token["sigs"], int(proof["ts"]), action, proof["sig"], nonce or ""
        ):
            return deny("invalid possession proof")

        # 3. Revocation + expiry + scope (shared with inspect()).
        ok, reason, matched, _request = self._evaluate(token, action)
        if not ok:
            return deny(reason)

        # 4. Rate limits (sliding window; shareable via the rate store).
        if matched is not None and matched.rate is not None:
            key = f"{chain[0]}|{_request.verb}:{_request.resource}"
            allowed = self._rate.hit(
                key, cap.window_ms(matched.rate.per), matched.rate.value, self._now()
            )
            if not allowed:
                return deny(f"rate limit exceeded ({matched.rate.value:g}/{matched.rate.per})")

        self._audit.record(
            mandate_id=chain[-1], chain=chain, action=action, decision="allow", issuer=token["rootPub"]
        )

    def inspect(self, token: dict, action: str) -> dict:
        """Advisory check (signature + revocation + expiry + scope), no PoP, no
        side effects. Returns {"allowed": bool, "reason": Optional[str]}."""
        ok, reason, _matched, _request = self._evaluate(token, action)
        return {"allowed": ok, "reason": None if ok else reason}

    def _evaluate(self, token: dict, action: str):
        """Shared signature + revocation + expiry + scope check (no PoP/side effects).

        Returns (ok, reason, matched, request)."""
        try:
            self.verify_signature(token)
        except IntegrityError as e:
            return (False, str(e), None, None)
        for cid in _chain_ids(token):
            if self._revocations.is_revoked(cid):
                return (False, f"revoked ({cid})", None, None)
        caveats = _all_caveats(token)
        now = self._now()
        for c in caveats:
            if c["t"] == "expires" and now > c["at"]:
                return (False, "expired", None, None)
        try:
            request = cap.parse(action)
        except Exception as e:  # noqa: BLE001
            return (False, str(e), None, None)
        matched = None
        for c in caveats:
            if c["t"] != "cap":
                continue
            grant = next(
                (g for g in (cap.parse(x) for x in c["can"]) if cap.satisfies(g, request)),
                None,
            )
            if grant is None:
                return (False, f'"{action}" not within granted scope', None, None)
            if grant.rate is not None:
                matched = grant
        return (True, None, matched, request)

    def revoke(self, id: str) -> None:
        self._revocations.revoke(id)

    def audit(self, id: str) -> list[dict]:
        return self._audit.for_mandate(id)

    # ---- helpers ----

    def verify_audit_log(self) -> dict:
        return audit_mod.verify(self._audit.all())

    def import_(self, serialized: str) -> Mandate:
        """Accepts both ``serialize()`` (public token: inspect/verify only) and
        ``serialize_with_key()`` (full holder credential)."""
        pad = "=" * (-len(serialized) % 4)
        raw = base64.urlsafe_b64decode(serialized + pad)
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and "token" in parsed and "key" in parsed:
            return Mandate(parsed["token"], self, parsed["key"])
        return Mandate(parsed, self)

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
