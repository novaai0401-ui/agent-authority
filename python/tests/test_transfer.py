"""Post-PoP issuance/delegation wiring (A3-A5) + FileRateStore (B2)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from behalf import create_behalf  # noqa: E402
from behalf.errors import AuthorizationError  # noqa: E402
from behalf.mcp import behalf_mcp_tools  # noqa: E402
from behalf.persist import FileRateStore  # noqa: E402


class TransferTests(unittest.TestCase):
    def test_serialize_with_key_transfers_holder_credential(self):
        issuer = create_behalf()
        root = issuer.grant(
            principal="u", agent="orch", can=["read:calendar", "spend:usd<=50"], expires_in="1h"
        )
        child = root.attenuate(can=["spend:usd<=20"], agent="worker")

        worker = create_behalf(trust=[issuer.public_key])
        received = worker.import_(child.serialize_with_key())
        self.assertTrue(received.can_delegate)
        received.authorize("spend:usd=15")
        with self.assertRaises(AuthorizationError):
            received.authorize("spend:usd=30")
        grandchild = received.attenuate(can=["spend:usd<=5"], agent="sub")
        grandchild.authorize("spend:usd=5")

    def test_public_serialize_is_inspect_only(self):
        issuer = create_behalf()
        m = issuer.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        pub = issuer.import_(m.serialize())
        self.assertFalse(pub.can_delegate)
        with self.assertRaises(Exception):
            pub.authorize("read:calendar")
        with self.assertRaises(Exception):
            pub.serialize_with_key()
        self.assertTrue(issuer.inspect(pub.token, "read:calendar")["allowed"])

    def test_mcp_request_mandate_is_usable(self):
        engine = create_behalf()
        request_tool = behalf_mcp_tools(engine)[0]
        issued = request_tool["handler"](
            {"principal": "u", "agent": "a", "can": ["read:calendar"], "expiresIn": "1h"}
        )
        holder = engine.import_(issued["mandate"])
        holder.authorize("read:calendar")
        self.assertFalse(engine.import_(issued["publicToken"]).can_delegate)

    def test_file_rate_store_persists(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "rate.json")
            a = FileRateStore(path)
            self.assertTrue(a.hit("k", 3_600_000, 2, 1000))
            self.assertTrue(a.hit("k", 3_600_000, 2, 2000))
            b = FileRateStore(path)
            self.assertFalse(b.hit("k", 3_600_000, 2, 3000))
            self.assertTrue(b.hit("k", 3_600_000, 2, 3_700_000))


if __name__ == "__main__":
    unittest.main()
