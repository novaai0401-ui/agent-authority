"""Macaroon-style HMAC chaining (mirrors the TypeScript implementation).

    sig_0 = HMAC(root_key, identifier)
    sig_i = HMAC(sig_{i-1}, serialize(caveat_i))

Appending a caveat needs only the *previous* signature, not the root key — so a
holder can attenuate offline and keylessly, yet can never remove or reorder an
earlier caveat. This structurally closes the delegation-chain splicing weakness.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid

Caveat = dict


def serialize_caveat(c: Caveat) -> str:
    """Deterministic, canonical serialization of a caveat for hashing."""
    t = c["t"]
    if t == "principal":
        return f"principal={c['principal']}"
    if t == "agent":
        return f"agent={c['agent']}"
    if t == "cap":
        return "cap=" + ",".join(sorted(c["can"]))
    if t == "expires":
        return f"expires={c['at']}"
    if t == "id":
        return f"id={c['id']}"
    raise ValueError(f"unknown caveat type {t!r}")


def _hmac(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def chain_signature(root_key: bytes, identifier: str, caveats: list[Caveat]) -> str:
    sig = _hmac(root_key, identifier)
    for c in caveats:
        sig = _hmac(sig, serialize_caveat(c))
    return sig.hex()


def extend_signature(prev_sig: str, caveat: Caveat) -> str:
    return _hmac(bytes.fromhex(prev_sig), serialize_caveat(caveat)).hex()


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def new_id() -> str:
    return str(uuid.uuid4())


def new_root_key() -> bytes:
    return secrets.token_bytes(32)
