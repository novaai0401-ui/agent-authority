"""Optional improvements: CachingRateStore, require_tenant, audit checkpointing."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_authority import (  # noqa: E402
    CachingRateStore,
    MemoryRateStore,
    create_behalf,
    create_control_plane,
    start_audit_checkpointing,
)
from agent_authority.errors import AuthorizationError  # noqa: E402


class _CountingRate:
    def __init__(self, result: bool) -> None:
        self.calls = 0
        self._result = result

    def hit(self, key, window_ms, limit, now):
        self.calls += 1
        return self._result


class CachingRateStoreTests(unittest.TestCase):
    def test_caches_denial(self):
        inner = _CountingRate(False)
        rate = CachingRateStore(inner, ttl_ms=1000)
        self.assertFalse(rate.hit("k", 1000, 1, 0))
        self.assertEqual(inner.calls, 1)
        self.assertFalse(rate.hit("k", 1000, 1, 500))  # cached
        self.assertEqual(inner.calls, 1)
        self.assertFalse(rate.hit("k", 1000, 1, 1001))  # ttl expired
        self.assertEqual(inner.calls, 2)

    def test_never_caches_allow(self):
        inner = _CountingRate(True)
        rate = CachingRateStore(inner, ttl_ms=1000)
        for t in range(3):
            rate.hit("k", 1000, 5, t)
        self.assertEqual(inner.calls, 3)

    def test_enforces_cap_end_to_end(self):
        clock = {"t": 0}
        rate = CachingRateStore(MemoryRateStore(), ttl_ms=10_000)
        issuer = create_behalf(rate=rate, now=lambda: clock["t"])
        m = issuer.grant(
            principal="u", agent="a", can=["send:email rate<=1/h"], expires_in="1h"
        )
        m.authorize("send:email")
        with self.assertRaisesRegex(AuthorizationError, "rate limit exceeded"):
            m.authorize("send:email")


class RequireTenantTests(unittest.TestCase):
    def test_requires_tenant_token(self):
        import urllib.error
        import urllib.request

        cp = create_control_plane(
            token="admin-secret",
            tenants={"tenant-a": "issuerApub"},
            require_tenant=True,
        )
        port = cp.listen(0)
        base = f"http://127.0.0.1:{port}"

        def status(headers=None):
            req = urllib.request.Request(f"{base}/v1/revoked", headers=headers or {})
            try:
                return urllib.request.urlopen(req).status
            except urllib.error.HTTPError as e:
                return e.code

        try:
            self.assertEqual(status(), 401)  # anonymous
            self.assertEqual(status({"Authorization": "Bearer admin-secret"}), 403)  # admin barred
            self.assertEqual(status({"Authorization": "Bearer tenant-a"}), 200)  # tenant ok
        finally:
            cp.close()


class CheckpointingTests(unittest.TestCase):
    def test_emits_verifiable_checkpoints(self):
        engine = create_behalf()
        m = engine.grant(principal="u", agent="a", can=["read:x"], expires_in="1h")
        m.authorize("read:x")

        got = []
        stop = start_audit_checkpointing(engine, interval_ms=5, sink=got.append)
        time.sleep(0.05)
        stop()
        self.assertGreaterEqual(len(got), 1)
        self.assertTrue(engine.verify_audit_checkpoint(got[-1])["ok"])


if __name__ == "__main__":
    unittest.main()
