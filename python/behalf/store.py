"""Pluggable persistence. Defaults are in-memory and local-first."""

from __future__ import annotations

from typing import Protocol


class RevocationStore(Protocol):
    def revoke(self, id: str) -> None: ...
    def is_revoked(self, id: str) -> bool: ...


class RateStore(Protocol):
    def hit(self, key: str, window_ms: int, limit: float, now: int) -> bool: ...


class AuditStore(Protocol):
    def record(self, *, mandate_id, chain, action, decision, reason=None) -> dict: ...
    def append(self, entry: dict) -> None: ...
    def for_mandate(self, mandate_id: str) -> list[dict]: ...
    def all(self) -> list[dict]: ...


class MemoryRevocationStore:
    def __init__(self) -> None:
        self._revoked: set[str] = set()

    def revoke(self, id: str) -> None:
        self._revoked.add(id)

    def is_revoked(self, id: str) -> bool:
        return id in self._revoked


class MemoryRateStore:
    def __init__(self) -> None:
        self._hits: dict[str, list[int]] = {}

    def hit(self, key: str, window_ms: int, limit: float, now: int) -> bool:
        recent = [t for t in self._hits.get(key, []) if now - t < window_ms]
        if len(recent) + 1 > limit:
            self._hits[key] = recent
            return False
        recent.append(now)
        self._hits[key] = recent
        return True


class MemoryAuditStore:
    def __init__(self) -> None:
        self._entries: list[dict] = []

    def record(self, *, mandate_id, chain, action, decision, reason=None) -> dict:
        from .audit import seal

        entry = seal(
            self._entries[-1] if self._entries else None,
            mandate_id=mandate_id,
            chain=chain,
            action=action,
            decision=decision,
            reason=reason,
        )
        self._entries.append(entry)
        return entry

    def append(self, entry: dict) -> None:
        self._entries.append(entry)

    def for_mandate(self, mandate_id: str) -> list[dict]:
        return [e for e in self._entries if mandate_id in e["chain"]]

    def all(self) -> list[dict]:
        return list(self._entries)
