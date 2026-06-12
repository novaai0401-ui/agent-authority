"""File-backed stores — local-first persistence across restarts (mirrors TS)."""

from __future__ import annotations

import json
import os


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


class FileRevocationStore:
    """Revocation list persisted as a JSON array of ids."""

    def __init__(self, path: str) -> None:
        self.path = path
        _ensure_dir(path)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._revoked = set(json.load(f))
        else:
            self._revoked: set[str] = set()

    def revoke(self, id: str) -> None:
        self._revoked.add(id)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(sorted(self._revoked), f)

    def is_revoked(self, id: str) -> bool:
        return id in self._revoked


class FileAuditStore:
    """Append-only audit log persisted as JSON Lines (one entry per line)."""

    def __init__(self, path: str) -> None:
        self.path = path
        _ensure_dir(path)
        if os.path.exists(path):
            entries = self.all()
            self._last = entries[-1] if entries else None
        else:
            open(path, "w", encoding="utf-8").close()
            self._last = None

    def record(self, *, mandate_id, chain, action, decision, reason=None, issuer=None) -> dict:
        from .audit import seal

        entry = seal(
            self._last,
            mandate_id=mandate_id,
            chain=chain,
            action=action,
            decision=decision,
            reason=reason,
            issuer=issuer,
        )
        self.append(entry)
        return entry

    def append(self, entry: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        self._last = entry

    def all(self) -> list[dict]:
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def for_mandate(self, mandate_id: str) -> list[dict]:
        return [e for e in self.all() if mandate_id in e["chain"]]

    def for_issuer(self, issuer: str) -> list[dict]:
        return [e for e in self.all() if e.get("issuer") == issuer]


class FileConsentStore:
    """Consent records persisted as a JSON object keyed by id."""

    def __init__(self, path: str) -> None:
        self.path = path
        _ensure_dir(path)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._records = json.load(f)
        else:
            self._records: dict = {}

    def _flush(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._records, f)

    def put(self, record: dict) -> None:
        self._records[record["id"]] = record
        self._flush()

    def get(self, id: str):
        return self._records.get(id)

    def list(self) -> list[dict]:
        return list(self._records.values())


class FilePolicyStore:
    """Named policies persisted as a JSON object keyed by name."""

    def __init__(self, path: str) -> None:
        self.path = path
        _ensure_dir(path)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._policies = json.load(f)
        else:
            self._policies: dict = {}

    def _flush(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._policies, f)

    def set(self, name: str, policy) -> None:
        self._policies[name] = policy
        self._flush()

    def get(self, name: str):
        return self._policies.get(name)

    def has(self, name: str) -> bool:
        return name in self._policies


class FileRateStore:
    """Rate-limit windows persisted as a JSON object of key -> hit timestamps."""

    def __init__(self, path: str) -> None:
        self.path = path
        _ensure_dir(path)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._hits = json.load(f)
        else:
            self._hits: dict = {}

    def _flush(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._hits, f)

    def hit(self, key: str, window_ms: int, limit: float, now: int) -> bool:
        recent = [t for t in self._hits.get(key, []) if now - t < window_ms]
        if len(recent) + 1 > limit:
            self._hits[key] = recent
            self._flush()
            return False
        recent.append(now)
        self._hits[key] = recent
        self._flush()
        return True
