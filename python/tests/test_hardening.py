"""Nonce anti-replay (C2), tenant isolation (B1), consent TTL (B3), pagination (B4)."""

import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from behalf import create_behalf  # noqa: E402
from behalf.control_plane import create_control_plane  # noqa: E402
from behalf.crypto import new_key_pair  # noqa: E402
from behalf.errors import AuthorizationError  # noqa: E402
from behalf.remote import ControlPlaneClient, HttpRateStore, HttpRevocationStore  # noqa: E402


class NonceTests(unittest.TestCase):
    def test_nonce_is_single_use(self):
        issuer = create_behalf()
        m = issuer.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        verifier = create_behalf(trust=[issuer.public_key])

        nonce = verifier.challenge()
        proof = m.prove("read:calendar", nonce)
        verifier.authorize(m.token, "read:calendar", proof)
        with self.assertRaises(AuthorizationError):
            verifier.authorize(m.token, "read:calendar", proof)  # replay
        with self.assertRaises(AuthorizationError):
            verifier.authorize(m.token, "read:calendar", m.prove("read:calendar", "fake"))

    def test_require_nonce_refuses_plain_proofs(self):
        issuer = create_behalf()
        m = issuer.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        verifier = create_behalf(trust=[issuer.public_key], require_nonce=True)
        with self.assertRaises(AuthorizationError):
            verifier.authorize(m.token, "read:calendar", m.prove("read:calendar"))
        nonce = verifier.challenge()
        verifier.authorize(m.token, "read:calendar", m.prove("read:calendar", nonce))

    def test_holder_path_self_challenges(self):
        engine = create_behalf(require_nonce=True)
        m = engine.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        m.authorize("read:calendar")


class TenantIsolationTests(unittest.TestCase):
    def test_revocation_and_rate_namespacing(self):
        kp_a, kp_b = new_key_pair(), new_key_pair()
        cp = create_control_plane(
            tenants={"tokA": kp_a.public, "tokB": kp_b.public}, token="admintok"
        )
        port = cp.listen(0)
        base = f"http://127.0.0.1:{port}"
        try:
            rev_a = HttpRevocationStore(base, token="tokA")
            rev_b = HttpRevocationStore(base, token="tokB")
            rev_admin = HttpRevocationStore(base, token="admintok")

            rev_a.revoke("shared-id")
            self.assertTrue(rev_a.is_revoked("shared-id"))
            self.assertFalse(rev_b.is_revoked("shared-id"))  # no cross-tenant DoS
            rev_admin.revoke("global-id")
            self.assertTrue(rev_a.is_revoked("global-id"))
            self.assertTrue(rev_b.is_revoked("global-id"))

            a = create_behalf(root_key_pair=kp_a, rate=HttpRateStore(base, token="tokA"))
            b = create_behalf(root_key_pair=kp_b, rate=HttpRateStore(base, token="tokB"))
            m_a = a.grant(principal="u", agent="x", can=["send:email rate<=1/h"], expires_in="1h")
            m_b = b.grant(principal="u", agent="y", can=["send:email rate<=1/h"], expires_in="1h")
            m_a.authorize("send:email")
            m_b.authorize("send:email")  # own budget despite colliding raw key
            with self.assertRaises(AuthorizationError):
                m_a.authorize("send:email")
        finally:
            cp.close()

    def test_consent_invisible_across_tenants(self):
        cp = create_control_plane(tenants={"tokA": "issuerA", "tokB": "issuerB"})
        port = cp.listen(0)
        base = f"http://127.0.0.1:{port}"
        try:
            a = ControlPlaneClient(base, token="tokA")
            b = ControlPlaneClient(base, token="tokB")
            rec = a.request_consent("agent-a", "write:email")
            with self.assertRaises(urllib.error.HTTPError):
                b.get_consent(rec["id"])
            with self.assertRaises(urllib.error.HTTPError):
                b.decide_consent(rec["id"], True)
            self.assertEqual(a.get_consent(rec["id"])["status"], "pending")
        finally:
            cp.close()


class ConsentTtlTests(unittest.TestCase):
    def test_pending_consent_expires(self):
        cp = create_control_plane(consent_ttl_ms=10)
        port = cp.listen(0)
        base = f"http://127.0.0.1:{port}"
        try:
            client = ControlPlaneClient(base)
            rec = client.request_consent("agent", "write:email")
            time.sleep(0.03)
            self.assertEqual(client.get_consent(rec["id"])["status"], "expired")
            self.assertEqual(client.decide_consent(rec["id"], True)["status"], "expired")
        finally:
            cp.close()


class PaginationTests(unittest.TestCase):
    def test_audit_limit_offset_total(self):
        from behalf.remote import HttpAuditStore

        cp = create_control_plane()
        port = cp.listen(0)
        base = f"http://127.0.0.1:{port}"
        try:
            engine = create_behalf(audit=HttpAuditStore(base))
            m = engine.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
            for _ in range(5):
                m.authorize("read:calendar")
            with urllib.request.urlopen(f"{base}/v1/audit?offset=1&limit=2") as r:
                page = json.loads(r.read())
            self.assertEqual(page["total"], 5)
            self.assertEqual([e["seq"] for e in page["entries"]], [1, 2])
        finally:
            cp.close()


if __name__ == "__main__":
    unittest.main()
