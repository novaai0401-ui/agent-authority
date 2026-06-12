"""Issuer key rotation (B5) and signed audit checkpoints (C4)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from behalf import create_behalf  # noqa: E402
from behalf.errors import AuthorizationError, BehalfError  # noqa: E402
from behalf.persist import FileAuditStore  # noqa: E402


class RotationTests(unittest.TestCase):
    def test_rotation_overlap_then_retire(self):
        v1 = create_behalf()
        old_m = v1.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")

        v2 = v1.rotate()
        self.assertNotEqual(v2.public_key, v1.public_key)
        self.assertIn(v1.public_key, v2.trusted_keys)

        # Overlap: old and new both accepted.
        v2.authorize(old_m.token, "read:calendar", old_m.prove("read:calendar"))
        new_m = v2.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        self.assertEqual(new_m.token["rootPub"], v2.public_key)
        new_m.authorize("read:calendar")

        # End the overlap.
        self.assertTrue(v2.untrust_key(v1.public_key))
        with self.assertRaises(AuthorizationError):
            v2.authorize(old_m.token, "read:calendar", old_m.prove("read:calendar"))
        new_m.authorize("read:calendar")

    def test_cannot_untrust_own_key(self):
        e = create_behalf()
        with self.assertRaises(BehalfError):
            e.untrust_key(e.public_key)


class CheckpointTests(unittest.TestCase):
    def test_checkpoint_detects_tail_deletion(self):
        from behalf.crypto import new_key_pair

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            kp = new_key_pair()
            a = create_behalf(root_key_pair=kp, audit=FileAuditStore(path))
            m = a.grant(principal="u", agent="x", can=["read:calendar"], expires_in="1h")
            for _ in range(3):
                m.authorize("read:calendar")

            checkpoint = a.checkpoint_audit()
            self.assertTrue(a.verify_audit_checkpoint(checkpoint)["ok"])

            # Delete the newest entry: bare chain still verifies, checkpoint doesn't.
            with open(path, encoding="utf-8") as f:
                lines = f.read().strip().split("\n")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines[:-1]) + "\n")
            b = create_behalf(root_key_pair=kp, audit=FileAuditStore(path))
            self.assertTrue(b.verify_audit_log()["ok"])
            result = b.verify_audit_checkpoint(checkpoint)
            self.assertFalse(result["ok"])
            self.assertIn("missing or rewritten", result["reason"])

    def test_untrusted_signer_rejected(self):
        a = create_behalf()
        stranger = create_behalf()
        result = a.verify_audit_checkpoint(stranger.checkpoint_audit())
        self.assertFalse(result["ok"])
        self.assertIn("not trusted", result["reason"])


if __name__ == "__main__":
    unittest.main()
