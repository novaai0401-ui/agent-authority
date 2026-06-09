"""Tamper-evident, hash-chained audit log (mirrors the TypeScript implementation)."""

from __future__ import annotations

import json
import time
from typing import Optional

from .crypto import sha256_hex

GENESIS = "0" * 64
_GENESIS = GENESIS


def _body(e: dict) -> str:
    return json.dumps(
        {
            "seq": e["seq"],
            "ts": e["ts"],
            "mandateId": e["mandateId"],
            "issuer": e.get("issuer") or "",
            "chain": e["chain"],
            "action": e["action"],
            "decision": e["decision"],
            "reason": e.get("reason") or "",
            "prevHash": e["prevHash"],
        },
        separators=(",", ":"),
    )


def seal(
    prev: Optional[dict],
    *,
    mandate_id: str,
    chain: list[str],
    action: str,
    decision: str,
    reason: Optional[str] = None,
    issuer: Optional[str] = None,
) -> dict:
    """Seal a new entry onto the chain after ``prev`` (or None for the first).

    Pure and O(1): the caller supplies the previous entry, so the whole log is
    never re-read per record, and the owning store is the single writer."""
    seq = prev["seq"] + 1 if prev else 0
    prev_hash = prev["hash"] if prev else _GENESIS
    entry = {
        "seq": seq,
        "ts": int(time.time() * 1000),
        "mandateId": mandate_id,
        "issuer": issuer,
        "chain": chain,
        "action": action,
        "decision": decision,
        "reason": reason,
        "prevHash": prev_hash,
    }
    entry["hash"] = sha256_hex(prev_hash + _body(entry))
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
