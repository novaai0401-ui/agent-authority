"""Sealed holder credentials (defense-in-depth for ``serialize_with_key``).

Encrypts a holder credential to a recipient's X25519 sealing key so only the
intended agent can open it. Wire-compatible with the TypeScript port's ``seal-1``
scheme (ephemeral X25519 -> HKDF-SHA256 -> AES-256-GCM), so a credential sealed
in one port opens in the other.

Unlike the rest of the Python port, sealing requires the ``cryptography`` package
(stdlib has neither X25519 nor AES-GCM). When it isn't importable, the seal/unseal
calls raise :class:`SealUnavailableError` with installation guidance; the rest of
Behalf keeps working dependency-free.
"""

from __future__ import annotations

import json
import os

from .crypto import _b64, _unb64

_INFO = b"behalf-seal-v1"
_AAD = b"behalf-seal-v1"


class SealUnavailableError(Exception):
    """Raised when sealing is used without a crypto backend that supports it."""

    def __init__(self) -> None:
        super().__init__(
            "sealed credentials require the 'cryptography' package "
            "(pip install cryptography); the rest of Behalf is dependency-free"
        )


def _primitives():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except BaseException as e:  # noqa: BLE001 - native lib may fail any way
        raise SealUnavailableError() from e
    return X25519PrivateKey, X25519PublicKey, AESGCM, HKDF, hashes, Encoding, PublicFormat


class SealKeyPair:
    """An X25519 sealing keypair (base64url raw 32-byte keys)."""

    def __init__(self, public_b64: str, private_b64: str) -> None:
        self.public = public_b64
        self.private = private_b64


def new_seal_key_pair() -> SealKeyPair:
    """Generate an X25519 sealing keypair (publish ``public``, keep ``private``)."""
    X25519PrivateKey, _Pub, _A, _H, _Hsh, Encoding, PublicFormat = _primitives()
    priv = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import (
        Encoding as Enc,
        PrivateFormat,
        NoEncryption,
    )

    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_raw = priv.private_bytes(Enc.Raw, PrivateFormat.Raw, NoEncryption())
    return SealKeyPair(_b64(pub_raw), _b64(priv_raw))


def seal(plaintext: str, recipient_public_key: str) -> str:
    """Encrypt ``plaintext`` so only the holder of ``recipient_public_key`` can read it."""
    X25519PrivateKey, X25519PublicKey, AESGCM, HKDF, hashes, Encoding, PublicFormat = _primitives()
    recipient_raw = _unb64(recipient_public_key)
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_raw)
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(recipient_pub)
    eph_pub_raw = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    salt = eph_pub_raw + recipient_raw
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_INFO).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _AAD)  # ct||tag
    wire = {"v": "seal-1", "epk": _b64(eph_pub_raw), "n": _b64(nonce), "ct": _b64(ct)}
    return _b64(json.dumps(wire, separators=(",", ":")).encode("utf-8"))


def unseal(sealed: str, recipient: SealKeyPair) -> str:
    """Decrypt a ``seal-1`` credential with the recipient's sealing keypair."""
    X25519PrivateKey, X25519PublicKey, AESGCM, HKDF, hashes, _Enc, _Pf = _primitives()
    try:
        wire = json.loads(_unb64(sealed))
    except Exception as e:  # noqa: BLE001
        raise ValueError("malformed sealed credential") from e
    if wire.get("v") != "seal-1" or not all(k in wire for k in ("epk", "n", "ct")):
        raise ValueError("unsupported or malformed seal")
    priv = X25519PrivateKey.from_private_bytes(_unb64(recipient.private))
    eph_pub_raw = _unb64(wire["epk"])
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub_raw))
    salt = eph_pub_raw + _unb64(recipient.public)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_INFO).derive(shared)
    pt = AESGCM(key).decrypt(_unb64(wire["n"]), _unb64(wire["ct"]), _AAD)
    return pt.decode("utf-8")
