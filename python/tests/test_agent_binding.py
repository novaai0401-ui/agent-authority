"""C3: cryptographic agent identity binding (SVID-style), Python port.

Mirrors test/agent-binding.test.ts: a mandate granted with ``bind_agent`` carries
an ``agentKey`` caveat that must be satisfied at authorize by a proof of
possession of the bound agent's private key — so a stolen holder credential
alone is no longer enough to act.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_authority import create_behalf  # noqa: E402
from agent_authority.crypto import new_key_pair  # noqa: E402
from agent_authority.errors import AuthorizationError  # noqa: E402


class AgentBindingTests(unittest.TestCase):
    def test_bound_mandate_authorizes_with_agent_proof(self):
        agent = new_key_pair()
        issuer = create_behalf()
        m = issuer.grant(
            principal="u",
            agent="research-agent",
            can=["read:calendar"],
            expires_in="1h",
            bind_agent=agent.public,
        )
        verifier = create_behalf(trust=[issuer.public_key], agent_key=agent)
        proof = m.prove("read:calendar", agent_keys=[agent])
        verifier.authorize(m.token, "read:calendar", proof)  # no raise

    def test_engine_agent_key_satisfies_in_process_holder(self):
        agent = new_key_pair()
        eng = create_behalf(agent_key=agent)
        self.assertEqual(eng.agent_public_key, agent.public)
        m = eng.grant(
            principal="u", agent="a", can=["read:calendar"], expires_in="1h", bind_agent=agent.public
        )
        m.authorize("read:calendar")  # in-process path proves the agent key

    def test_stolen_credential_without_agent_key_is_denied(self):
        agent = new_key_pair()
        issuer = create_behalf()
        m = issuer.grant(
            principal="u", agent="a", can=["read:calendar"], expires_in="1h", bind_agent=agent.public
        )
        thief = create_behalf(trust=[issuer.public_key])
        stolen = thief.import_(m.serialize_with_key())
        self.assertTrue(stolen.can_delegate)

        with self.assertRaisesRegex(AuthorizationError, "agent identity proof required"):
            thief.authorize(stolen.token, "read:calendar", stolen.prove("read:calendar"))

        wrong = new_key_pair()
        with self.assertRaisesRegex(AuthorizationError, "agent identity proof required"):
            thief.authorize(
                stolen.token, "read:calendar", stolen.prove("read:calendar", agent_keys=[wrong])
            )

    def test_appending_own_binding_does_not_bypass_conjunctive(self):
        agent = new_key_pair()
        issuer = create_behalf()
        m = issuer.grant(
            principal="u", agent="a", can=["read:calendar"], expires_in="1h", bind_agent=agent.public
        )
        thief = create_behalf(trust=[issuer.public_key])
        stolen = thief.import_(m.serialize_with_key())

        thief_agent = new_key_pair()
        re_bound = stolen.attenuate(bind_agent=thief_agent.public)
        proof = re_bound.prove("read:calendar", agent_keys=[thief_agent])
        with self.assertRaisesRegex(AuthorizationError, "agent identity proof required"):
            thief.authorize(re_bound.token, "read:calendar", proof)

        both = re_bound.prove("read:calendar", agent_keys=[agent, thief_agent])
        thief.authorize(re_bound.token, "read:calendar", both)  # conjunction satisfied

    def test_unbound_mandate_unaffected(self):
        issuer = create_behalf()
        m = issuer.grant(principal="u", agent="a", can=["read:calendar"], expires_in="1h")
        verifier = create_behalf(trust=[issuer.public_key])
        verifier.authorize(m.token, "read:calendar", m.prove("read:calendar"))

    def test_binding_survives_attenuation(self):
        agent = new_key_pair()
        issuer = create_behalf()
        m = issuer.grant(
            principal="u",
            agent="a",
            can=["read:calendar", "read:email"],
            expires_in="1h",
            bind_agent=agent.public,
        )
        verifier = create_behalf(trust=[issuer.public_key])
        narrowed = m.attenuate(can=["read:calendar"], expires_in="10m")
        verifier.authorize(
            narrowed.token, "read:calendar", narrowed.prove("read:calendar", agent_keys=[agent])
        )
        with self.assertRaisesRegex(AuthorizationError, "agent identity proof required"):
            verifier.authorize(narrowed.token, "read:calendar", narrowed.prove("read:calendar"))


if __name__ == "__main__":
    unittest.main()
