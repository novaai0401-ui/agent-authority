"""Cross-language interop helper: issue a mandate as the Python port.

Prints {"mandate", "pubkey", "proof"} as JSON so a TypeScript verifier can check
it: the proof is a possession proof of the chain's terminal key. Usage:

    python3 interop_issue.py <cap> [<narrowed-cap>]
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from behalf import create_behalf  # noqa: E402


def main() -> None:
    cap = sys.argv[1] if len(sys.argv) > 1 else "spend:usd<=50"
    narrow = sys.argv[2] if len(sys.argv) > 2 else None

    issuer = create_behalf()
    mandate = issuer.grant(principal="py", agent="issuer", can=[cap], expires_in="1h")
    if narrow:
        mandate = mandate.attenuate(can=[narrow], expires_in="30m", agent="py-sub")

    print(
        json.dumps(
            {
                "mandate": mandate.serialize(),
                "pubkey": issuer.public_key,
                "proof": mandate.prove(),
            }
        )
    )


if __name__ == "__main__":
    main()
