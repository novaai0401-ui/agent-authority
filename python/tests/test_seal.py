"""#8: sealed holder credentials, Python port (mirrors test/seal.test.ts).

Sealing requires the optional ``cryptography`` package; when it is absent these
tests skip (the rest of the port stays dependency-free).
"""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from behalf import create_behalf  # noqa: E402
from behalf.seal import (  # noqa: E402
    SealUnavailableError,
    new_seal_key_pair,
    seal,
    unseal,
)


def _sealing_available() -> bool:
    try:
        new_seal_key_pair()
        return True
    except SealUnavailableError:
        return False


@unittest.skipUnless(_sealing_available(), "cryptography not installed")
class SealTests(unittest.TestCase):
    def test_round_trip(self):
        kp = new_seal_key_pair()
        msg = "holder-credential-" + "x" * 80
        self.assertEqual(unseal(seal(msg, kp.public), kp), msg)

    def test_wrong_recipient_cannot_open(self):
        kp = new_seal_key_pair()
        other = new_seal_key_pair()
        sealed = seal("secret", kp.public)
        with self.assertRaises(Exception):
            unseal(sealed, other)

    def test_tamper_rejected(self):
        kp = new_seal_key_pair()
        sealed = seal("secret", kp.public)
        pad = "=" * (-len(sealed) % 4)
        wire = json.loads(base64.urlsafe_b64decode(sealed + pad))
        ct = bytearray(base64.urlsafe_b64decode(wire["ct"] + "=" * (-len(wire["ct"]) % 4)))
        ct[0] ^= 0xFF
        wire["ct"] = base64.urlsafe_b64encode(bytes(ct)).rstrip(b"=").decode()
        tampered = base64.urlsafe_b64encode(json.dumps(wire).encode()).rstrip(b"=").decode()
        with self.assertRaises(Exception):
            unseal(tampered, kp)

    def test_bad_version_rejected(self):
        kp = new_seal_key_pair()
        bad = base64.urlsafe_b64encode(json.dumps({"v": "seal-9"}).encode()).rstrip(b"=").decode()
        with self.assertRaises(ValueError):
            unseal(bad, kp)

    def test_nondeterministic(self):
        kp = new_seal_key_pair()
        self.assertNotEqual(seal("same", kp.public), seal("same", kp.public))

    def test_end_to_end(self):
        recipient = new_seal_key_pair()
        issuer = create_behalf()
        m = issuer.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        sealed = m.seal_for_recipient(recipient.public)

        verifier = create_behalf(trust=[issuer.public_key])
        opened = verifier.import_sealed(sealed, recipient)
        self.assertTrue(opened.can_delegate)
        self.assertEqual(opened.id, m.id)
        opened.authorize("read:calendar")  # no raise


if __name__ == "__main__":
    unittest.main()
