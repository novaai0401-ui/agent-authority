"""Ed25519 backend selection.

The reference signer in :mod:`_ed25519` is pure Python and dependency-free, but
**not constant-time**. When a hardened native library is importable we prefer it
(constant-time and far faster); otherwise we fall back to the pure-Python
reference. Either way the three primitives keep the same raw-bytes interface, so
the rest of the port is unchanged and tokens stay byte-compatible across both
backends and with the TypeScript port.

Preference order: ``cryptography`` → ``PyNaCl`` → pure Python. Nothing here is a
*required* dependency; install one of the natives for production Python.

Probing is deliberately defensive: a misconfigured native library can fail at
import in surprising ways (e.g. a Rust ``PanicException``, which is a
``BaseException`` rather than ``Exception``), so each probe catches
``BaseException`` and falls through — never letting an optional accelerator break
a working pure-Python install. ``KeyboardInterrupt``/``SystemExit`` are
re-raised so probing stays interruptible.
"""

from __future__ import annotations

import contextlib
import os

from . import _ed25519


@contextlib.contextmanager
def _muffle_stderr():
    """Silence fd-level stderr during probing. A broken native lib can print a
    Rust panic backtrace straight to fd 2 (below Python), which would corrupt
    CLI/MCP-stdio output; we drop it so a failed probe is invisible."""
    try:
        saved = os.dup(2)
    except OSError:
        yield  # no real stderr (e.g. embedded) — nothing to muffle
        return
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, 2)
        yield
    finally:
        os.dup2(saved, 2)
        os.close(devnull)
        os.close(saved)

# Public name describing which implementation is active (introspection / tests).
BACKEND = "pure-python"
publickey = _ed25519.publickey
signature = _ed25519.signature
checkvalid = _ed25519.checkvalid


def _try_cryptography():
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    def publickey(seed: bytes) -> bytes:
        return (
            Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

    def signature(message: bytes, seed: bytes, public_key: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)

    def checkvalid(sig: bytes, message: bytes, public_key: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(sig, message)
            return True
        except InvalidSignature:
            return False

    return publickey, signature, checkvalid


def _try_pynacl():
    from nacl import bindings as na

    def publickey(seed: bytes) -> bytes:
        pk, _sk = na.crypto_sign_seed_keypair(seed)
        return pk

    def signature(message: bytes, seed: bytes, public_key: bytes) -> bytes:
        _pk, sk = na.crypto_sign_seed_keypair(seed)
        return na.crypto_sign(message, sk)[: na.crypto_sign_BYTES]

    def checkvalid(sig: bytes, message: bytes, public_key: bytes) -> bool:
        try:
            na.crypto_sign_open(sig + message, public_key)
            return True
        except Exception:
            return False

    return publickey, signature, checkvalid


def _selfcheck(funcs) -> bool:
    """A backend must round-trip AND interoperate with the reference signer (so a
    buggy/incompatible native lib never silently corrupts cross-port tokens)."""
    pub, sign, check = funcs
    seed = bytes(range(32))
    msg = b"behalf-backend-selfcheck"
    pk = pub(seed)
    if pk != _ed25519.publickey(seed):  # same raw public key as the reference
        return False
    sig = sign(msg, seed, pk)
    # Cross-verify both directions with the pure-Python reference.
    return check(sig, msg, pk) and _ed25519.checkvalid(sig, msg, pk)


with _muffle_stderr():
    for _name, _probe in (("cryptography", _try_cryptography), ("pynacl", _try_pynacl)):
        try:
            _funcs = _probe()
            if _selfcheck(_funcs):
                publickey, signature, checkvalid = _funcs
                BACKEND = _name
                break
        except KeyboardInterrupt:
            raise
        except SystemExit:
            raise
        except BaseException:  # noqa: BLE001 - optional native libs may fail any way
            continue


def is_constant_time() -> bool:
    """True when a hardened native backend is active (not pure Python)."""
    return BACKEND != "pure-python"
