"""The Mandate handle — obtain one via Behalf.grant / attenuate / import."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .behalf import Behalf


class Mandate:
    """A handle to a capability token. Construction is internal.

    A mandate from ``grant``/``attenuate`` carries an in-memory ``delegation_key``
    (the Ed25519 private key authorizing the next block), so it can be further
    attenuated. A mandate restored via ``import_`` has only the public token: it
    can be verified, authorized, and audited, but not delegated.
    """

    def __init__(self, token: dict, engine: "Behalf", delegation_key: Optional[str] = None) -> None:
        self.token = token
        self._engine = engine
        self._delegation_key = delegation_key

    @property
    def _caveats(self) -> list[dict]:
        out: list[dict] = []
        for block in self.token["blocks"]:
            out.extend(block["caveats"])
        return out

    @property
    def chain(self) -> list[str]:
        ids = [self.token["id"]]
        for c in self._caveats:
            if c["t"] == "id":
                ids.append(c["id"])
        return ids

    @property
    def id(self) -> str:
        return self.chain[-1]

    @property
    def principal(self) -> Optional[str]:
        for c in self._caveats:
            if c["t"] == "principal":
                return c["principal"]
        return None

    @property
    def agent(self) -> Optional[str]:
        agent = None
        for c in self._caveats:
            if c["t"] == "agent":
                agent = c["agent"]
        return agent

    @property
    def expires_at(self) -> Optional[int]:
        earliest = None
        for c in self._caveats:
            if c["t"] == "expires":
                earliest = c["at"] if earliest is None else min(earliest, c["at"])
        return earliest

    @property
    def can_delegate(self) -> bool:
        return self._delegation_key is not None

    def authorize(self, action: str) -> None:
        """Prove authority for an action. Requires this mandate's delegation key
        (i.e. it came from grant/attenuate, not import_): authorization includes
        a proof of possession of the chain's terminal key."""
        self._engine.authorize_as_holder(self.token, action, self._delegation_key)

    def prove(self) -> dict:
        """Mint a proof of possession for presenting this mandate across a trust
        boundary. Requires the delegation key (only the holder can produce it)."""
        if self._delegation_key is None:
            raise Exception("cannot prove possession: imported mandate has no key")
        return self._engine.prove_possession(self.token, self._delegation_key)

    def attenuate(
        self,
        *,
        can: Optional[list[str]] = None,
        expires_in: Optional[str | int] = None,
        agent: Optional[str] = None,
    ) -> "Mandate":
        return self._engine.attenuate(
            self.token, self._delegation_key, can=can, expires_in=expires_in, agent=agent
        )

    def revoke(self) -> None:
        self._engine.revoke(self.id)

    def audit(self) -> list[dict]:
        return self._engine.audit(self.id)

    def serialize(self) -> str:
        raw = json.dumps(self.token, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
