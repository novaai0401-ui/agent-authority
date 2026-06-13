"""Cross-language interop helper: import a holder credential issued by the other
port, attenuate it (signing a new block with the imported delegation key), and
print the narrowed child + action-bound proofs. This exercises cross-language
*delegation* — a block signed in Python over a chain rooted in TypeScript (or
vice versa) must still verify.

    python3 interop_delegate.py <issuer_pubkey> <credential> <narrow> <action1,action2,...>
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from behalf import create_behalf  # noqa: E402


def main() -> None:
    pubkey = sys.argv[1]
    cred = sys.argv[2]
    narrow = sys.argv[3]
    actions = sys.argv[4].split(",") if len(sys.argv) > 4 else []

    eng = create_behalf(trust=[pubkey])
    mandate = eng.import_(cred)
    child = mandate.attenuate(can=[narrow], expires_in="30m", agent="py-sub")

    print(
        json.dumps(
            {
                "child": child.serialize(),
                "proofs": {a: child.prove(a) for a in actions},
            }
        )
    )


if __name__ == "__main__":
    main()
