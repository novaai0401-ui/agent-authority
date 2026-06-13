"""#4: Ed25519 backend selection.

Whichever backend is active (hardened native, or the pure-Python reference) must
produce/verify byte-compatible signatures and interoperate with the reference
implementation — that compatibility is what keeps cross-port tokens valid.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from behalf import _ed25519, crypto  # noqa: E402
from behalf._backend import is_constant_time  # noqa: E402


class BackendTests(unittest.TestCase):
    def test_backend_is_named(self):
        self.assertIn(crypto.backend(), ("cryptography", "pynacl", "pure-python"))

    def test_is_constant_time_matches_backend(self):
        self.assertEqual(is_constant_time(), crypto.backend() != "pure-python")

    def test_expected_backend_when_pinned(self):
        # CI sets BEHALF_EXPECT_BACKEND after installing a native lib, so the
        # native code paths are actually exercised (not just the fallback).
        expected = os.environ.get("BEHALF_EXPECT_BACKEND")
        if expected:
            self.assertEqual(crypto.backend(), expected)
            self.assertTrue(is_constant_time())

    def test_active_backend_round_trips(self):
        kp = crypto.new_key_pair()
        block = {"caveats": [{"t": "cap", "can": ["read:x"]}], "nextPub": kp.public}
        sig = crypto.sign_block(kp.private, block)
        self.assertTrue(crypto.verify_block(kp.public, block, sig))
        other = crypto.new_key_pair()
        self.assertFalse(crypto.verify_block(other.public, block, sig))

    def test_interoperates_with_reference(self):
        # A signature from the active backend must verify under the pure-Python
        # reference, and vice versa — proving byte-for-byte compatibility.
        from behalf.crypto import _b64, _unb64

        kp = crypto.new_key_pair()
        seed = _unb64(kp.private)
        pub = _unb64(kp.public)
        msg = b"behalf-interop-check"
        # Reference public key must match the active backend's.
        self.assertEqual(_ed25519.publickey(seed), pub)
        ref_sig = _ed25519.signature(msg, seed, pub)
        self.assertTrue(crypto.verify_message(kp.public, msg.decode(), _b64(ref_sig)))
        active_sig = _unb64(crypto.sign_message(kp.private, msg.decode()))
        self.assertTrue(_ed25519.checkvalid(active_sig, msg, pub))


if __name__ == "__main__":
    unittest.main()
