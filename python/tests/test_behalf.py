"""Test suite for the Behalf Python port (stdlib unittest, no deps)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from behalf import create_behalf  # noqa: E402
from behalf.audit import verify  # noqa: E402
from behalf.capability import is_narrowing, parse, permits  # noqa: E402
from behalf.errors import AuthorizationError, IntegrityError, WideningError  # noqa: E402
from behalf.lint import is_clean, lint  # noqa: E402
from behalf.mcp import behalf_mcp_tools, with_behalf  # noqa: E402


class CapabilityTests(unittest.TestCase):
    def test_parse_simple(self):
        c = parse("read:calendar")
        self.assertEqual((c.verb, c.resource), ("read", "calendar"))

    def test_parse_amount(self):
        c = parse("spend:usd<=50")
        self.assertEqual((c.amount.op, c.amount.value), ("<=", 50))

    def test_parse_rate(self):
        c = parse("send:email rate<=10/h")
        self.assertEqual((c.rate.op, c.rate.value, c.rate.per), ("<=", 10, "h"))

    def test_amount_satisfaction(self):
        self.assertTrue(permits("spend:usd<=50", "spend:usd=20"))
        self.assertTrue(permits("spend:usd<=50", "spend:usd=50"))
        self.assertFalse(permits("spend:usd<=50", "spend:usd=51"))

    def test_resource_prefix(self):
        self.assertTrue(permits("write:repo", "write:repo/acme-app"))
        self.assertFalse(permits("write:repo/acme-app", "write:repo/other"))

    def test_wildcard(self):
        self.assertTrue(permits("*", "spend:usd=999"))

    def test_is_narrowing(self):
        self.assertTrue(is_narrowing(["spend:usd<=50"], ["spend:usd<=20"])[0])
        ok, offending = is_narrowing(["spend:usd<=50"], ["spend:usd<=80"])
        self.assertFalse(ok)
        self.assertEqual(offending, "spend:usd<=80")


class MandateTests(unittest.TestCase):
    def test_grant_and_authorize(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar", "spend:usd<=50"], expires_in="1h")
        self.assertEqual(m.principal, "u")
        m.authorize("read:calendar")
        m.authorize("spend:usd=20")

    def test_out_of_scope(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        with self.assertRaises(AuthorizationError):
            m.authorize("write:email")

    def test_over_limit(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["spend:usd<=50"], expires_in="1h")
        with self.assertRaises(AuthorizationError):
            m.authorize("spend:usd=51")

    def test_expiry(self):
        clock = {"now": 1_000_000}
        b = create_behalf(now=lambda: clock["now"])
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        clock["now"] += 3_600_001
        with self.assertRaises(AuthorizationError):
            m.authorize("read:calendar")

    def test_tamper(self):
        import copy

        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        forged = copy.deepcopy(m.token)
        for block in forged["blocks"]:
            for c in block["caveats"]:
                if c["t"] == "cap":
                    c["can"] = ["*"]
        with self.assertRaises(IntegrityError):
            b.verify_signature(forged)

    def test_serialize_roundtrip(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        restored = b.import_(m.serialize())
        self.assertEqual(restored.id, m.id)
        # The restored public token authorizes when the holder presents a proof.
        b.authorize(restored.token, "read:calendar", m.prove("read:calendar"))

    def test_rate_limit(self):
        clock = {"now": 0}
        b = create_behalf(now=lambda: clock["now"])
        m = b.grant(principal="u", agent="a", can=["send:email rate<=2/h"], expires_in="1d")
        m.authorize("send:email")
        m.authorize("send:email")
        with self.assertRaises(AuthorizationError):
            m.authorize("send:email")
        clock["now"] += 3_600_001
        m.authorize("send:email")


class DelegationTests(unittest.TestCase):
    def test_attenuate_narrows(self):
        b = create_behalf()
        parent = b.grant(principal="u", agent="o", can=["read:calendar", "spend:usd<=50"], expires_in="1h")
        child = parent.attenuate(can=["read:calendar"], expires_in="10m", agent="sub")
        self.assertEqual(child.agent, "sub")
        self.assertEqual(child.chain[0], parent.id)
        child.authorize("read:calendar")
        with self.assertRaises(AuthorizationError):
            child.authorize("spend:usd=10")

    def test_cannot_widen(self):
        b = create_behalf()
        parent = b.grant(principal="u", agent="a", can=["spend:usd<=50"], expires_in="1h")
        with self.assertRaises(WideningError):
            parent.attenuate(can=["spend:usd<=80"])

    def test_two_hop_intersection(self):
        b = create_behalf()
        root = b.grant(principal="u", agent="a1", can=["read:calendar", "spend:usd<=50"], expires_in="1h")
        mid = root.attenuate(can=["spend:usd<=30"], agent="a2")
        leaf = mid.attenuate(can=["spend:usd<=10"], agent="a3")
        leaf.authorize("spend:usd=10")
        with self.assertRaises(AuthorizationError):
            leaf.authorize("spend:usd=11")
        with self.assertRaises(AuthorizationError):
            leaf.authorize("read:calendar")

    def test_cannot_flip_bound_direction(self):
        b = create_behalf()
        parent = b.grant(principal="u", agent="a", can=["spend:usd<=50"], expires_in="1h")
        # `>=10` is unbounded above — not a narrowing of `<=50` (M-1).
        with self.assertRaises(WideningError):
            parent.attenuate(can=["spend:usd>=10"])
        parent.attenuate(can=["spend:usd<=20"])  # same-direction tighter is fine

    def test_forged_wider_child_denied(self):
        import copy

        b = create_behalf()
        root = b.grant(principal="u", agent="a1", can=["spend:usd<=10"], expires_in="1h")
        mid = root.attenuate(can=["spend:usd<=10"], agent="a2")
        forged = copy.deepcopy(mid.token)
        forged["blocks"][-1]["caveats"].append({"t": "cap", "can": ["spend:usd<=10000"]})
        # The signature chain no longer verifies, so even an advisory check denies.
        self.assertFalse(b.inspect(forged, "spend:usd=9999")["allowed"])

    def test_truncation_denied(self):
        # C-1 regression: a narrowed child cannot drop its block to regain scope.
        b = create_behalf()
        root = b.grant(
            principal="u", agent="a1", can=["read:calendar", "spend:usd<=50"], expires_in="1h"
        )
        child = root.attenuate(can=["read:calendar"], agent="a2")
        truncated = {
            "v": 2,
            "id": child.token["id"],
            "blocks": [child.token["blocks"][0]],
            "sigs": [child.token["sigs"][0]],
            "rootPub": child.token["rootPub"],
        }
        with self.assertRaises(AuthorizationError):
            b.authorize(truncated, "spend:usd=50", child.prove("spend:usd=50"))


class RevocationTests(unittest.TestCase):
    def test_revoke_self(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        m.authorize("read:calendar")
        m.revoke()
        with self.assertRaises(AuthorizationError):
            m.authorize("read:calendar")

    def test_revoke_root_cascades(self):
        b = create_behalf()
        root = b.grant(principal="u", agent="a1", can=["read:calendar"], expires_in="1h")
        child = root.attenuate(can=["read:calendar"], agent="a2")
        grandchild = child.attenuate(can=["read:calendar"], agent="a3")
        b.revoke(root.id)
        for m in (root, child, grandchild):
            with self.assertRaises(AuthorizationError):
                m.authorize("read:calendar")

    def test_revoke_child_keeps_siblings(self):
        b = create_behalf()
        root = b.grant(principal="u", agent="a1", can=["read:calendar"], expires_in="1h")
        a = root.attenuate(can=["read:calendar"], agent="a2")
        bb = root.attenuate(can=["read:calendar"], agent="a3")
        a.revoke()
        with self.assertRaises(AuthorizationError):
            a.authorize("read:calendar")
        bb.authorize("read:calendar")
        root.authorize("read:calendar")


class AuditTests(unittest.TestCase):
    def test_records_written(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        m.authorize("read:calendar")
        try:
            m.authorize("write:email")
        except AuthorizationError:
            pass
        trail = m.audit()
        self.assertEqual(len(trail), 2)
        self.assertEqual(trail[0]["decision"], "allow")
        self.assertEqual(trail[1]["decision"], "deny")

    def test_tamper_evident(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        m.authorize("read:calendar")
        m.authorize("read:calendar")
        self.assertTrue(b.verify_audit_log()["ok"])
        entries = m.audit()
        entries[0]["decision"] = "deny"
        broken = verify(entries)
        self.assertFalse(broken["ok"])
        self.assertEqual(broken["brokenAt"], 0)


class AsymmetricTests(unittest.TestCase):
    def test_verifier_with_public_key_only(self):
        issuer = create_behalf()
        m = issuer.grant(principal="u", agent="a", can=["spend:usd<=50"], expires_in="1h")
        verifier = create_behalf(trust=[issuer.public_key])
        # Holder presents token + proof of possession; verifier holds no secret.
        verifier.authorize(m.token, "spend:usd=20", m.prove("spend:usd=20"))
        with self.assertRaises(AuthorizationError):
            verifier.authorize(m.token, "spend:usd=60", m.prove("spend:usd=60"))

    def test_untrusted_issuer_rejected(self):
        issuer = create_behalf()
        m = issuer.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        stranger = create_behalf()
        with self.assertRaises(AuthorizationError):
            stranger.authorize(m.token, "read:calendar", m.prove("read:calendar"))

    def test_attenuated_chain_verifies(self):
        issuer = create_behalf()
        root = issuer.grant(principal="u", agent="a1", can=["spend:usd<=50"], expires_in="1h")
        child = root.attenuate(can=["spend:usd<=10"], agent="a2")
        verifier = create_behalf(trust=[issuer.public_key])
        verifier.authorize(child.token, "spend:usd=10", child.prove("spend:usd=10"))
        with self.assertRaises(AuthorizationError):
            verifier.authorize(child.token, "spend:usd=11", child.prove("spend:usd=11"))

    def test_imported_cannot_delegate_or_authorize(self):
        issuer = create_behalf()
        m = issuer.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        self.assertTrue(m.can_delegate)
        imported = issuer.import_(m.serialize())
        self.assertFalse(imported.can_delegate)
        with self.assertRaises(Exception):
            imported.attenuate(can=["read:calendar"])
        with self.assertRaises(Exception):
            imported.authorize("read:calendar")  # no key to prove possession


class CachingRevocationTests(unittest.TestCase):
    def _counting_inner(self, revoked=None):
        revoked = revoked if revoked is not None else set()
        calls = {"is_revoked": 0, "revoke": 0}

        class Inner:
            def revoke(self, id):
                calls["revoke"] += 1
                revoked.add(id)

            def is_revoked(self, id):
                calls["is_revoked"] += 1
                return id in revoked

        return Inner(), calls, revoked

    def test_not_revoked_cached_within_ttl(self):
        from behalf.store import CachingRevocationStore

        clock = {"t": 0}
        inner, calls, _ = self._counting_inner()
        cache = CachingRevocationStore(inner, ttl_ms=1000, now=lambda: clock["t"])
        self.assertFalse(cache.is_revoked("m"))
        self.assertFalse(cache.is_revoked("m"))
        self.assertEqual(calls["is_revoked"], 1)
        clock["t"] = 1001
        self.assertFalse(cache.is_revoked("m"))
        self.assertEqual(calls["is_revoked"], 2)

    def test_revoked_cached_permanently(self):
        from behalf.store import CachingRevocationStore

        inner, calls, revoked = self._counting_inner({"bad"})
        cache = CachingRevocationStore(inner, ttl_ms=1000)
        self.assertTrue(cache.is_revoked("bad"))
        self.assertTrue(cache.is_revoked("bad"))
        self.assertEqual(calls["is_revoked"], 1)

    def test_revoke_write_through_and_invalidate(self):
        from behalf.store import CachingRevocationStore

        inner, calls, _ = self._counting_inner()
        cache = CachingRevocationStore(inner, ttl_ms=60000)
        self.assertFalse(cache.is_revoked("y"))
        cache.revoke("y")
        self.assertTrue(cache.is_revoked("y"))


class LintTests(unittest.TestCase):
    def test_clean_scope(self):
        self.assertEqual(lint(["read:calendar", "spend:usd<=50"]), [])
        self.assertTrue(is_clean(["read:calendar", "spend:usd<=50"]))

    def test_wildcard_warns(self):
        f = lint(["*"])[0]
        self.assertEqual(f.level, "warn")
        self.assertEqual(f.rule, "wildcard")

    def test_unbounded_spend_warns(self):
        f = next(x for x in lint(["spend:usd"]) if x.rule == "unbounded-amount")
        self.assertEqual(f.level, "warn")

    def test_rateless_send_is_info(self):
        findings = lint(["send:email"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].level, "info")
        self.assertTrue(is_clean(["send:email"]))

    def test_unparseable_is_error(self):
        self.assertEqual(lint(["nocolon"])[0].level, "error")

    def test_duplicate_warns(self):
        f = next(x for x in lint(["read:calendar", "read:calendar"]) if x.rule == "duplicate")
        self.assertEqual(f.level, "warn")


class FakeServer:
    def __init__(self):
        self.calls = []

    def call_tool(self, name, args, ctx=None):
        self.calls.append(name)
        return {"ok": True}


class McpTests(unittest.TestCase):
    def test_allows_permitted(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        base = FakeServer()
        guarded = with_behalf(base, policy={"read_calendar": "read:calendar"})
        guarded.call_tool("read_calendar", {}, {"mandate": m})
        self.assertEqual(base.calls, ["read_calendar"])

    def test_denies_out_of_scope(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        base = FakeServer()
        guarded = with_behalf(base, policy={"send_email": "write:email"})
        with self.assertRaises(AuthorizationError):
            guarded.call_tool("send_email", {}, {"mandate": m})
        self.assertEqual(base.calls, [])

    def test_derived_capability(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["spend:usd<=50"], expires_in="1h")
        base = FakeServer()
        guarded = with_behalf(base, policy={"transfer": lambda a: f"spend:usd={a['amount']}"})
        guarded.call_tool("transfer", {"amount": 20}, {"mandate": m})
        with self.assertRaises(AuthorizationError):
            guarded.call_tool("transfer", {"amount": 51}, {"mandate": m})

    def test_prompt_consent(self):
        b = create_behalf()
        m = b.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        base = FakeServer()
        guarded = with_behalf(
            base,
            policy={"send_email": "write:email"},
            on_denied="prompt",
            on_prompt=lambda info: True,
        )
        guarded.call_tool("send_email", {}, {"mandate": m})
        self.assertEqual(base.calls, ["send_email"])

    def test_discovery_tools(self):
        b = create_behalf()
        req, present, check = behalf_mcp_tools(b)
        issued = req["handler"](
            {"principal": "u", "agent": "a", "can": ["read:calendar"], "expiresIn": "1h"}
        )
        self.assertIn("mandate", issued)
        presented = present["handler"]({"mandate": issued["mandate"]})
        self.assertTrue(presented["valid"])
        self.assertTrue(check["handler"]({"mandate": issued["mandate"], "action": "read:calendar"})["allowed"])
        self.assertFalse(check["handler"]({"mandate": issued["mandate"], "action": "write:email"})["allowed"])


if __name__ == "__main__":
    unittest.main()
