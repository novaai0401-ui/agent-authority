"""#5: token-bucket rate limiting (burst-shaping alternative), Python port.

Mirrors test/token-bucket.test.ts.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_authority import create_behalf  # noqa: E402
from agent_authority.errors import AuthorizationError  # noqa: E402
from agent_authority.store import MemoryRateStore, TokenBucketRateStore  # noqa: E402


class TokenBucketTests(unittest.TestCase):
    def test_initial_burst_then_deny(self):
        rate = TokenBucketRateStore()
        now = 1_000_000
        self.assertTrue(rate.hit("k", 3000, 3, now))
        self.assertTrue(rate.hit("k", 3000, 3, now))
        self.assertTrue(rate.hit("k", 3000, 3, now))
        self.assertFalse(rate.hit("k", 3000, 3, now))

    def test_refills_over_time(self):
        rate = TokenBucketRateStore()
        now = 0
        for _ in range(5):
            self.assertTrue(rate.hit("k", 5000, 5, now))
        self.assertFalse(rate.hit("k", 5000, 5, now))
        now += 1000
        self.assertTrue(rate.hit("k", 5000, 5, now))
        self.assertFalse(rate.hit("k", 5000, 5, now))

    def test_caps_at_capacity_after_idle(self):
        rate = TokenBucketRateStore()
        self.assertTrue(rate.hit("k", 1000, 2, 0))
        n = sum(1 for _ in range(10) if rate.hit("k", 1000, 2, 1_000_000))
        self.assertEqual(n, 2)

    def test_nonpositive_denies(self):
        rate = TokenBucketRateStore()
        self.assertFalse(rate.hit("k", 1000, 0, 0))
        self.assertFalse(rate.hit("k", 0, 5, 0))

    def test_keys_independent(self):
        rate = TokenBucketRateStore()
        self.assertTrue(rate.hit("a", 1000, 1, 0))
        self.assertFalse(rate.hit("a", 1000, 1, 0))
        self.assertTrue(rate.hit("b", 1000, 1, 0))

    def test_drops_into_engine(self):
        t = {"v": 0}
        issuer = create_behalf(rate=TokenBucketRateStore(), now=lambda: t["v"])
        m = issuer.grant(
            principal="u", agent="a", can=["send:email rate<=2/h"], expires_in="1h"
        )
        m.authorize("send:email")
        m.authorize("send:email")
        with self.assertRaisesRegex(AuthorizationError, "rate limit exceeded"):
            m.authorize("send:email")

    def test_interchangeable_interface(self):
        for s in (MemoryRateStore(), TokenBucketRateStore()):
            self.assertTrue(s.hit("k", 1000, 1, 0))
            self.assertFalse(s.hit("k", 1000, 1, 0))


if __name__ == "__main__":
    unittest.main()
