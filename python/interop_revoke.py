"""Cross-language interop helper: revoke a mandate via a control plane.

Usage:  python3 interop_revoke.py <control-plane-base-url> <mandate-id>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from behalf.remote import HttpRevocationStore  # noqa: E402


def main() -> None:
    base, mandate_id = sys.argv[1], sys.argv[2]
    HttpRevocationStore(base).revoke(mandate_id)
    print("revoked")


if __name__ == "__main__":
    main()
