"""Cross-language interop helper: issue a mandate as the Python port.

Prints {"mandate", "pubkey", "proofs": {action: proof}} as JSON so a TypeScript
verifier can check each action with its action-bound possession proof. Usage:

    python3 interop_issue.py <cap> <narrow|-> <action1,action2,...>
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from agent_authority import create_behalf  # noqa: E402


def main() -> None:
    cap = sys.argv[1] if len(sys.argv) > 1 else "spend:usd<=50"
    narrow = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "-" else None
    actions = sys.argv[3].split(",") if len(sys.argv) > 3 else []

    issuer = create_behalf()
    mandate = issuer.grant(principal="py", agent="issuer", can=[cap], expires_in="1h")
    if narrow:
        mandate = mandate.attenuate(can=[narrow], expires_in="30m", agent="py-sub")

    print(
        json.dumps(
            {
                "mandate": mandate.serialize(),
                # Holder credential (token + delegation key) so the other port can
                # import it and attenuate further — exercises cross-language
                # delegation, not just verification.
                "cred": mandate.serialize_with_key(),
                "pubkey": issuer.public_key,
                "proofs": {a: mandate.prove(a) for a in actions},
            }
        )
    )


if __name__ == "__main__":
    main()
