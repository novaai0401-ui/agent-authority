"""Pluggable persistence. Defaults are in-memory and local-first."""

from __future__ import annotations

from typing import Protocol


class RevocationStore(Protocol):
    def revoke(self, id: str) -> None: ...
    def is_revoked(self, id: str) -> bool: ...


class AuditStore(Protocol):
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


class MemoryAuditStore:
    def __init__(self) -> None:
        self._entries: list[dict] = []

    def append(self, entry: dict) -> None:
        self._entries.append(entry)

    def for_mandate(self, mandate_id: str) -> list[dict]:
        return [e for e in self._entries if mandate_id in e["chain"]]

    def all(self) -> list[dict]:
        return list(self._entries)
