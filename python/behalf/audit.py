"""Tamper-evident, hash-chained audit log (mirrors the TypeScript implementation)."""

from __future__ import annotations

import json
import time

from .crypto import sha256_hex
from .store import AuditStore

_GENESIS = "0" * 64


def _body(e: dict) -> str:
    return json.dumps(
        {
            "seq": e["seq"],
            "ts": e["ts"],
            "mandateId": e["mandateId"],
            "chain": e["chain"],
            "action": e["action"],
            "decision": e["decision"],
            "reason": e.get("reason") or "",
            "prevHash": e["prevHash"],
        },
        separators=(",", ":"),
    )


def record(
    store: AuditStore,
    *,
    mandate_id: str,
    chain: list[str],
    action: str,
    decision: str,
    reason: str | None = None,
) -> dict:
    existing = store.all()
    prev = existing[-1] if existing else None
    seq = prev["seq"] + 1 if prev else 0
    prev_hash = prev["hash"] if prev else _GENESIS

    entry = {
        "seq": seq,
        "ts": int(time.time() * 1000),
        "mandateId": mandate_id,
        "chain": chain,
        "action": action,
        "decision": decision,
        "reason": reason,
        "prevHash": prev_hash,
    }
    entry["hash"] = sha256_hex(prev_hash + _body(entry))
    store.append(entry)
    return entry


def verify(entries: list[dict]) -> dict:
    """Replay the hash chain. Returns {"ok": bool, "brokenAt": Optional[int]}."""
    prev_hash = _GENESIS
    for e in entries:
        if e["prevHash"] != prev_hash:
            return {"ok": False, "brokenAt": e["seq"]}
        if sha256_hex(prev_hash + _body(e)) != e["hash"]:
            return {"ok": False, "brokenAt": e["seq"]}
        prev_hash = e["hash"]
    return {"ok": True, "brokenAt": None}
