"""The Mandate handle — obtain one via Behalf.grant / attenuate / import."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .behalf import Behalf


class Mandate:
    """A handle to a capability token. Construction is internal."""

    def __init__(self, token: dict, engine: "Behalf") -> None:
        self.token = token
        self._engine = engine

    @property
    def chain(self) -> list[str]:
        """Full chain of ids, root -> this mandate. Revoking any kills this one."""
        ids = [self.token["id"]]
        for c in self.token["caveats"]:
            if c["t"] == "id":
                ids.append(c["id"])
        return ids

    @property
    def id(self) -> str:
        return self.chain[-1]

    @property
    def principal(self) -> Optional[str]:
        for c in self.token["caveats"]:
            if c["t"] == "principal":
                return c["principal"]
        return None

    @property
    def agent(self) -> Optional[str]:
        agent = None
        for c in self.token["caveats"]:
            if c["t"] == "agent":
                agent = c["agent"]
        return agent

    @property
    def expires_at(self) -> Optional[int]:
        earliest = None
        for c in self.token["caveats"]:
            if c["t"] == "expires":
                earliest = c["at"] if earliest is None else min(earliest, c["at"])
        return earliest

    def authorize(self, action: str) -> None:
        """Prove authority for a concrete action. Raises AuthorizationError if denied."""
        self._engine.authorize(self.token, action)

    def attenuate(
        self,
        *,
        can: Optional[list[str]] = None,
        expires_in: Optional[str | int] = None,
        agent: Optional[str] = None,
    ) -> "Mandate":
        """Hand a narrowed mandate to a sub-agent. Can only shrink scope."""
        return self._engine.attenuate(self.token, can=can, expires_in=expires_in, agent=agent)

    def revoke(self) -> None:
        """Revoke this mandate and its entire downstream chain."""
        self._engine.revoke(self.id)

    def audit(self) -> list[dict]:
        return self._engine.audit(self.id)

    def serialize(self) -> str:
        raw = json.dumps(self.token, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
