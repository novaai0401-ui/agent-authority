"""Client stores backed by a remote control plane (mirrors TS behalf/remote).

Drop them into ``create_behalf(revocations=..., audit=...)`` and revocation
propagates across every agent pointed at the same control plane, while audit is
retained centrally. Built on urllib — zero dependencies.
"""

from __future__ import annotations

import json
import urllib.request
from urllib.parse import quote
from typing import Optional


class _Base:
    def __init__(self, base_url: str, token: Optional[str] = None) -> None:
        self.base = base_url.rstrip("/")
        self.token = token

    def _headers(self) -> dict:
        h = {"content-type": "application/json"}
        if self.token:
            h["authorization"] = f"Bearer {self.token}"
        return h

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, headers=self._headers(), method=method
        )
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    def _get(self, path: str) -> dict:
        return self._request("GET", path)

    def _post(self, path: str, body: dict) -> dict:
        return self._request("POST", path, body)

    def _put(self, path: str, body: dict) -> dict:
        return self._request("PUT", path, body)


class HttpRevocationStore(_Base):
    """Revocation backed by the control plane — revoke once, propagates to all."""

    def revoke(self, id: str) -> None:
        self._post("/v1/revoke", {"id": id})

    def is_revoked(self, id: str) -> bool:
        return bool(self._get(f"/v1/revoked/{quote(id, safe='')}")["revoked"])


class HttpAuditStore(_Base):
    """Tamper-evident audit retained centrally by the control plane."""

    def record(self, *, mandate_id, chain, action, decision, reason=None) -> dict:
        fields = {
            "mandateId": mandate_id,
            "chain": chain,
            "action": action,
            "decision": decision,
            "reason": reason,
        }
        return self._post("/v1/audit", {"fields": fields})["entry"]

    def append(self, entry: dict) -> None:
        self._post("/v1/audit", {"entry": entry})

    def all(self) -> list[dict]:
        return self._get("/v1/audit")["entries"]

    def for_mandate(self, mandate_id: str) -> list[dict]:
        return self._get(f"/v1/audit/{quote(mandate_id, safe='')}")["entries"]


class ControlPlaneClient(_Base):
    """Typed client for the consent + policy endpoints."""

    def request_consent(self, agent: str, capability: str, context: Optional[dict] = None) -> dict:
        return self._post("/v1/consent", {"agent": agent, "capability": capability, "context": context})

    def get_consent(self, id: str) -> dict:
        return self._get(f"/v1/consent/{quote(id, safe='')}")

    def decide_consent(self, id: str, approve: bool) -> dict:
        return self._post(f"/v1/consent/{quote(id, safe='')}/decision", {"approve": approve})

    def get_policy(self, name: str) -> dict:
        return self._get(f"/v1/policy/{quote(name, safe='')}")

    def put_policy(self, name: str, policy) -> dict:
        return self._put(f"/v1/policy/{quote(name, safe='')}", {"policy": policy})
