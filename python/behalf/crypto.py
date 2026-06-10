"""Asymmetric attenuable tokens (Ed25519 signature chain) — mirrors the TS core.

Block 0 (the root grant) is signed by the issuer's private key; every block
publishes a fresh public key (``nextPub``) and the next block is signed by the
matching private key. Verification needs only public keys, so any relying party
can check a mandate and its whole chain offline without the issuer's secret.

Keys are raw 32-byte Ed25519 values, base64url-encoded for transport. (The TS
port uses SPKI/PKCS8 DER; the JSON token *shape* is identical, only the key
encoding differs between the two reference ports.)
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid

from . import _ed25519

Block = dict


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class KeyPair:
    def __init__(self, private_b64: str, public_b64: str) -> None:
        self.private = private_b64
        self.public = public_b64


def new_key_pair() -> KeyPair:
    seed = secrets.token_bytes(32)
    return KeyPair(_b64(seed), _b64(_ed25519.publickey(seed)))


def canonical_block(block: Block) -> bytes:
    # Sorted-key canonical JSON — byte-identical to the TS port's canonicalJson.
    return json.dumps(
        {"caveats": block["caveats"], "nextPub": block["nextPub"]},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_block(private_b64: str, block: Block) -> str:
    seed = _unb64(private_b64)
    pk = _ed25519.publickey(seed)
    return _b64(_ed25519.signature(canonical_block(block), seed, pk))


def verify_block(public_b64: str, block: Block, sig_b64: str) -> bool:
    try:
        return _ed25519.checkvalid(_unb64(sig_b64), canonical_block(block), _unb64(public_b64))
    except Exception:
        return False


def public_of(private_b64: str) -> str:
    return _b64(_ed25519.publickey(_unb64(private_b64)))


def proof_message(id: str, sigs: list, ts: int, action: str) -> bytes:
    """Proof-of-possession message — byte-identical to the TS port."""
    return f"behalf-pop\n{id}\n{','.join(sigs)}\n{ts}\n{action}".encode("utf-8")


def sign_proof(private_b64: str, id: str, sigs: list, ts: int, action: str) -> str:
    seed = _unb64(private_b64)
    pk = _ed25519.publickey(seed)
    return _b64(_ed25519.signature(proof_message(id, sigs, ts, action), seed, pk))


def verify_proof(public_b64: str, id: str, sigs: list, ts: int, action: str, sig_b64: str) -> bool:
    try:
        return _ed25519.checkvalid(
            _unb64(sig_b64), proof_message(id, sigs, ts, action), _unb64(public_b64)
        )
    except Exception:
        return False


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def new_id() -> str:
    return str(uuid.uuid4())
