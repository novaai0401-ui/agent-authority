"""Cross-language test vector — the Python port must verify the SAME committed
fixture as TypeScript, proving both agree on canonicalization, signatures, and
the possession proof (L-1)."""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_authority import create_behalf  # noqa: E402
from agent_authority.errors import AuthorizationError  # noqa: E402

VECTOR_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "vectors", "mandate-vector.json")
with open(VECTOR_PATH, encoding="utf-8") as f:
    VECTOR = json.load(f)


class VectorTests(unittest.TestCase):
    def _verifier(self):
        ts = VECTOR["proof"]["ts"]
        return create_behalf(trust=[VECTOR["pubkey"]], now=lambda: ts)

    def test_committed_vector_authorizes(self):
        self._verifier().authorize(VECTOR["token"], VECTOR["action"], VECTOR["proof"])

    def test_tampered_vector_rejected(self):
        v = self._verifier()
        forged = copy.deepcopy(VECTOR["token"])
        for block in forged["blocks"]:
            for c in block["caveats"]:
                if c["t"] == "cap":
                    c["can"] = ["*"]
        self.assertFalse(v.inspect(forged, VECTOR["action"])["allowed"])

        # A different action than the proof was bound to → possession proof fails.
        with self.assertRaises(AuthorizationError):
            v.authorize(VECTOR["token"], "spend:usd=20", VECTOR["proof"])


if __name__ == "__main__":
    unittest.main()
