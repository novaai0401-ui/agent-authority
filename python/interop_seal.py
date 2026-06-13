"""Cross-language interop helper for sealed credentials (#8).

Subcommands:
  avail
      Print "yes" if sealing is available (cryptography installed), else "no".
  keypair
      Print {"pub","priv"} for a fresh X25519 sealing keypair.
  issue_and_seal <recipient_pub>
      Issue a mandate (cap read:x), seal the holder credential to <recipient_pub>,
      and print {"sealed","pubkey"} (pubkey = issuer public key).
  open <issuer_pub> <priv> <pub> <sealed> <action>
      Open a sealed credential with the recipient keypair, import it, authorize
      <action>, and print "ALLOW" or "DENY:<reason>".
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "avail"

    if cmd == "avail":
        try:
            from behalf import new_seal_key_pair

            new_seal_key_pair()
            print("yes")
        except Exception:
            print("no")
        return

    from behalf import create_behalf, new_seal_key_pair
    from behalf.seal import SealKeyPair

    if cmd == "keypair":
        kp = new_seal_key_pair()
        print(json.dumps({"pub": kp.public, "priv": kp.private}))
        return

    if cmd == "issue_and_seal":
        recipient_pub = sys.argv[2]
        issuer = create_behalf()
        m = issuer.grant(principal="py", agent="a", can=["read:x"], expires_in="1h")
        print(json.dumps({"sealed": m.seal_for_recipient(recipient_pub), "pubkey": issuer.public_key}))
        return

    if cmd == "open":
        issuer_pub, priv, pub, sealed, action = sys.argv[2:7]
        eng = create_behalf(trust=[issuer_pub])
        try:
            mandate = eng.import_sealed(sealed, SealKeyPair(pub, priv))
            mandate.authorize(action)
            print("ALLOW")
        except Exception as e:  # noqa: BLE001
            print(f"DENY:{e}")
        return

    print(f"unknown command {cmd}", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
