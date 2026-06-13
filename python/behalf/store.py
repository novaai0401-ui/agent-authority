"""Pluggable persistence. Defaults are in-memory and local-first."""

from __future__ import annotations

import time
from typing import Callable, Optional, Protocol


class RevocationStore(Protocol):
    def revoke(self, id: str) -> None: ...
    def is_revoked(self, id: str) -> bool: ...


class RateStore(Protocol):
    def hit(self, key: str, window_ms: int, limit: float, now: int) -> bool: ...


class ConsentStore(Protocol):
    def put(self, record: dict) -> None: ...
    def get(self, id: str) -> Optional[dict]: ...
    def list(self) -> list[dict]: ...


class PolicyStore(Protocol):
    def set(self, name: str, policy) -> None: ...
    def get(self, name: str): ...
    def has(self, name: str) -> bool: ...


class MemoryConsentStore:
    def __init__(self) -> None:
        self._records: dict[str, dict] = {}

    def put(self, record: dict) -> None:
        self._records[record["id"]] = record

    def get(self, id: str) -> Optional[dict]:
        return self._records.get(id)

    def list(self) -> list[dict]:
        return list(self._records.values())


class MemoryPolicyStore:
    def __init__(self) -> None:
        self._policies: dict = {}

    def set(self, name: str, policy) -> None:
        self._policies[name] = policy

    def get(self, name: str):
        return self._policies.get(name)

    def has(self, name: str) -> bool:
        return name in self._policies


class AuditStore(Protocol):
    def record(self, *, mandate_id, chain, action, decision, reason=None, issuer=None) -> dict: ...
    def append(self, entry: dict) -> None: ...
    def for_mandate(self, mandate_id: str) -> list[dict]: ...
    def for_issuer(self, issuer: str) -> list[dict]: ...
    def all(self) -> list[dict]: ...


class MemoryRevocationStore:
    def __init__(self) -> None:
        self._revoked: set[str] = set()

    def revoke(self, id: str) -> None:
        self._revoked.add(id)

    def is_revoked(self, id: str) -> bool:
        return id in self._revoked


class CachingRevocationStore:
    """Bounded cache over another RevocationStore (mirrors the TS version).

    Revocation is monotonic, so a *revoked* answer is cached forever while a
    *not-revoked* answer is cached only for ``ttl_ms`` -- a bounded staleness
    window in exchange for far fewer network checks per authorize()."""

    def __init__(self, inner, *, ttl_ms: int, now: Optional[Callable[[], int]] = None) -> None:
        self._inner = inner
        self._ttl = ttl_ms
        self._now = now or (lambda: int(time.time() * 1000))
        self._revoked: set[str] = set()
        self._fresh: dict[str, int] = {}

    def revoke(self, id: str) -> None:
        self._inner.revoke(id)
        self._revoked.add(id)
        self._fresh.pop(id, None)

    def is_revoked(self, id: str) -> bool:
        if id in self._revoked:
            return True
        until = self._fresh.get(id)
        if until is not None and self._now() < until:
            return False
        revoked = self._inner.is_revoked(id)
        if revoked:
            self._revoked.add(id)
        else:
            self._fresh[id] = self._now() + self._ttl
        return revoked


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


class TokenBucketRateStore:
    """Token-bucket rate limiting — a smoother alternative to MemoryRateStore's
    sliding-count window, for burst shaping. Each key owns a bucket of capacity
    ``limit`` that refills at ``limit / window_ms`` tokens per ms; a hit spends
    one token if available (allow), a rejected hit spends nothing. Permits an
    initial burst up to ``limit`` then a steady long-run rate. Drop-in for any
    RateStore slot (engine ``rate=`` or the control plane)."""

    def __init__(self) -> None:
        self._buckets: dict[str, dict[str, float]] = {}

    def hit(self, key: str, window_ms: int, limit: float, now: int) -> bool:
        if limit <= 0 or window_ms <= 0:
            return False
        refill = limit / window_ms
        b = self._buckets.get(key) or {"tokens": float(limit), "last": float(now)}
        b["tokens"] = min(limit, b["tokens"] + max(0, now - b["last"]) * refill)
        b["last"] = float(now)
        allowed = b["tokens"] >= 1
        if allowed:
            b["tokens"] -= 1
        self._buckets[key] = b
        return allowed


class MemoryAuditStore:
    def __init__(self) -> None:
        self._entries: list[dict] = []

    def record(self, *, mandate_id, chain, action, decision, reason=None, issuer=None) -> dict:
        from .audit import seal

        entry = seal(
            self._entries[-1] if self._entries else None,
            mandate_id=mandate_id,
            chain=chain,
            action=action,
            decision=decision,
            reason=reason,
            issuer=issuer,
        )
        self._entries.append(entry)
        return entry

    def append(self, entry: dict) -> None:
        self._entries.append(entry)

    def for_issuer(self, issuer: str) -> list[dict]:
        return [e for e in self._entries if e.get("issuer") == issuer]

    def for_mandate(self, mandate_id: str) -> list[dict]:
        return [e for e in self._entries if mandate_id in e["chain"]]

    def all(self) -> list[dict]:
        return list(self._entries)
