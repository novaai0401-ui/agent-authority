"""Pure-Python Ed25519 (RFC 8032 reference construction).

Kept dependency-free on purpose — the rest of Behalf has zero runtime deps, and
relying on a C-extension crypto package would break that (and, in some
environments, the extension isn't even importable). This is the small, well-known
reference implementation; it is correct but not constant-time, which is an
acceptable trade-off for a reference library. Swap in libsodium for production.
"""

from __future__ import annotations

import hashlib

_b = 256
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(P, Q):
    """Affine point addition (used only where affine output is convenient)."""
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


# Extended twisted-Edwards coordinates (a = -1): a point is (X, Y, Z, T) with
# x = X/Z, y = Y/Z, x*y = T/Z. Addition is inversion-free, so a full scalar
# multiplication costs a single inversion at the end — ~20x faster than the
# affine recursion while computing the same group operation.
def _add_ext(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _q
    B = (Y1 + X1) * (Y2 + X2) % _q
    C = 2 * T1 * _d * T2 % _q
    D = 2 * Z1 * Z2 % _q
    E = (B - A) % _q
    F = (D - C) % _q
    G = (D + C) % _q
    H = (B + A) % _q
    return (E * F % _q, G * H % _q, F * G % _q, E * H % _q)


def _scalarmult(P, e: int):
    """Scalar multiply affine point P by e, returning an affine point."""
    pe = (P[0], P[1], 1, P[0] * P[1] % _q)
    q = (0, 1, 1, 0)  # neutral element
    while e > 0:
        if e & 1:
            q = _add_ext(q, pe)
        pe = _add_ext(pe, pe)
        e >>= 1
    zi = _inv(q[2])
    return (q[0] * zi % _q, q[1] * zi % _q)


def _encodeint(y: int) -> bytes:
    bits = [(y >> i) & 1 for i in range(_b)]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_b // 8))


def _encodepoint(P) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(_b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_b // 8))


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def publickey(sk: bytes) -> bytes:
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(2**i * _bit(h, i) for i in range(3, _b - 2))
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def _Hint(m: bytes) -> int:
    h = _H(m)
    return sum(2**i * _bit(h, i) for i in range(2 * _b))


def signature(m: bytes, sk: bytes, pk: bytes) -> bytes:
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(2**i * _bit(h, i) for i in range(3, _b - 2))
    r = _Hint(h[_b // 8 : _b // 4] + m)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % _l
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodeint(s: bytes) -> int:
    return sum(2**i * _bit(s, i) for i in range(_b))


def _decodepoint(s: bytes):
    y = sum(2**i * _bit(s, i) for i in range(_b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, _b - 1):
        x = _q - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def checkvalid(s: bytes, m: bytes, pk: bytes) -> bool:
    if len(s) != _b // 4 or len(pk) != _b // 8:
        return False
    try:
        R = _decodepoint(s[: _b // 8])
        A = _decodepoint(pk)
    except ValueError:
        return False
    S = _decodeint(s[_b // 8 : _b // 4])
    h = _Hint(_encodepoint(R) + pk + m)
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
