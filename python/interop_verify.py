"""Cross-language interop helper: verify + authorize a foreign presentation.

Trusts only the given issuer public key and requires a possession proof. Prints
"ALLOW" or "DENY:<reason>". Usage:

    python3 interop_verify.py <pubkey> <mandate> <action> <proof-json>
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from agent_authority import create_behalf  # noqa: E402
from agent_authority.errors import AuthorizationError  # noqa: E402


def main() -> None:
    pubkey, mandate, action, proof_json = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    verifier = create_behalf(trust=[pubkey])
    m = verifier.import_(mandate)
    try:
        verifier.authorize(m.token, action, json.loads(proof_json))
        print("ALLOW")
    except AuthorizationError as e:
        print("DENY:" + e.reason)


if __name__ == "__main__":
    main()
