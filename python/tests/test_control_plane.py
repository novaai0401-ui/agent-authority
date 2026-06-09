"""Tests for the Python control plane + client stores (stdlib only)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from behalf import create_behalf  # noqa: E402
from behalf.audit import verify  # noqa: E402
from behalf.control_plane import create_control_plane  # noqa: E402
from behalf.crypto import new_key_pair  # noqa: E402
from behalf.errors import AuthorizationError  # noqa: E402
from behalf.remote import ControlPlaneClient, HttpAuditStore, HttpRevocationStore  # noqa: E402


class ControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.cp = create_control_plane()
        self.port = self.cp.listen(0)
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.cp.close()

    def test_revocation_propagates_across_engines(self):
        kp = new_key_pair()
        a = create_behalf(root_key_pair=kp, revocations=HttpRevocationStore(self.base))
        b = create_behalf(root_key_pair=kp, revocations=HttpRevocationStore(self.base))

        m = a.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        wire = m.serialize()
        b.import_(wire).authorize("read:calendar")  # works before revoke

        a.revoke(m.id)
        with self.assertRaises(AuthorizationError):
            b.import_(wire).authorize("read:calendar")

    def test_audit_retained_centrally(self):
        engine = create_behalf(audit=HttpAuditStore(self.base))
        m = engine.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        m.authorize("read:calendar")
        try:
            m.authorize("write:email")
        except AuthorizationError:
            pass

        remote = HttpAuditStore(self.base)
        trail = remote.for_mandate(m.id)
        self.assertEqual(len(trail), 2)
        self.assertEqual(trail[0]["decision"], "allow")
        self.assertEqual(trail[1]["decision"], "deny")
        self.assertTrue(verify(remote.all())["ok"])

    def test_concurrent_writers_keep_chain_intact(self):
        import threading

        kp = new_key_pair()
        engines = [create_behalf(root_key_pair=kp, audit=HttpAuditStore(self.base)) for _ in range(4)]
        mandates = [
            e.grant(principal="u", agent=f"a{i}", can=["read:calendar"], expires_in="1h")
            for i, e in enumerate(engines)
        ]

        def hammer(m):
            for _ in range(5):
                m.authorize("read:calendar")

        threads = [threading.Thread(target=hammer, args=(m,)) for m in mandates]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        all_entries = HttpAuditStore(self.base).all()
        self.assertEqual(len(all_entries), 20)
        self.assertEqual(sorted(e["seq"] for e in all_entries), list(range(20)))
        self.assertTrue(verify(all_entries)["ok"])

    def test_consent_flow(self):
        client = ControlPlaneClient(self.base)
        created = client.request_consent("agent-1", "write:email", {"to": "x@y.z"})
        self.assertEqual(created["status"], "pending")
        decided = client.decide_consent(created["id"], True)
        self.assertEqual(decided["status"], "approved")
        self.assertEqual(client.get_consent(created["id"])["status"], "approved")

    def test_policy_store(self):
        client = ControlPlaneClient(self.base)
        policy = {"send_email": "write:email"}
        client.put_policy("research-agent", policy)
        self.assertEqual(client.get_policy("research-agent")["policy"], policy)

    def test_dashboard_html(self):
        import urllib.request

        with urllib.request.urlopen(f"{self.base}/") as r:
            self.assertEqual(r.status, 200)
            self.assertIn("Behalf Control Plane", r.read().decode())


class TokenTests(unittest.TestCase):
    def test_bearer_token_enforced(self):
        import urllib.error
        import urllib.request

        cp = create_control_plane(token="s3cret")
        port = cp.listen(0)
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/revoked")
            self.assertEqual(ctx.exception.code, 401)

            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/revoked", headers={"authorization": "Bearer s3cret"}
            )
            with urllib.request.urlopen(req) as r:
                self.assertEqual(r.status, 200)
        finally:
            cp.close()


if __name__ == "__main__":
    unittest.main()
