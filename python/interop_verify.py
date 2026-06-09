"""Cross-language interop helper: verify + authorize a foreign mandate.

Trusts only the given issuer public key. Prints "ALLOW" or "DENY:<reason>".
Usage:

    python3 interop_verify.py <pubkey> <mandate> <action>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from behalf import create_behalf  # noqa: E402
from behalf.errors import AuthorizationError  # noqa: E402


def main() -> None:
    pubkey, mandate, action = sys.argv[1], sys.argv[2], sys.argv[3]
    verifier = create_behalf(trust=[pubkey])
    m = verifier.import_(mandate)
    try:
        m.authorize(action)
        print("ALLOW")
    except AuthorizationError as e:
        print("DENY:" + e.reason)


if __name__ == "__main__":
    main()
