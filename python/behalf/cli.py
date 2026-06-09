"""`behalf` CLI (Python port; mirrors the TypeScript CLI).

Manages mandates from the terminal. State (issuer keypair, revocation list, audit
log) lives under $BEHALF_HOME (default ~/.behalf), so a mandate issued in one
invocation can be checked and revoked in the next.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from .behalf import create_behalf
from .crypto import KeyPair
from .errors import AuthorizationError
from .lint import lint
from .persist import FileAuditStore, FileRevocationStore
from .quickstart import find_surface, generate_quickstart, list_surfaces

HOME = os.environ.get("BEHALF_HOME") or os.path.join(os.path.expanduser("~"), ".behalf")
KEY_FILE = os.path.join(HOME, "key.json")
REV_FILE = os.path.join(HOME, "revocations.json")
AUDIT_FILE = os.path.join(HOME, "audit.jsonl")

USAGE = f"""behalf — agent authority CLI

Usage:
  behalf pubkey
  behalf grant --principal <id> --agent <id> --can <cap> [--can <cap> ...] --expires <dur>
  behalf inspect <mandate>
  behalf authorize <mandate> <action>
  behalf revoke <mandate-id>
  behalf audit <mandate-id>
  behalf lint <cap> [<cap> ...]
  behalf quickstart <surface>   (e.g. claude-code, cursor, copilot, gpt, gemini)
  behalf quickstart --list

State dir: {HOME}  (override with $BEHALF_HOME)"""


def _load_engine():
    os.makedirs(HOME, exist_ok=True)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, encoding="utf-8") as f:
            kp = json.load(f)
        keys = KeyPair(kp["priv"], kp["pub"])
    else:
        from .crypto import new_key_pair

        keys = new_key_pair()
        with open(KEY_FILE, "w", encoding="utf-8") as f:
            json.dump({"priv": keys.private, "pub": keys.public}, f)
    return create_behalf(
        root_key_pair=keys,
        revocations=FileRevocationStore(REV_FILE),
        audit=FileAuditStore(AUDIT_FILE),
    )


def _parse_args(argv):
    out = {"_": []}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            key = a[2:]
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                val = argv[i + 1]
                i += 1
            else:
                val = "true"
            if key in out and key != "_":
                if isinstance(out[key], list):
                    out[key].append(val)
                else:
                    out[key] = [out[key], val]
            else:
                out[key] = val
        else:
            out["_"].append(a)
        i += 1
    return out


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _run_stateless(cmd, args) -> int:
    if cmd == "lint":
        caps = args["_"]
        if not caps:
            print("lint requires at least one capability", file=sys.stderr)
            return 2
        findings = lint(caps)
        for f in findings:
            print(f"{f.level.upper():<5} {f.capability}  {f.message}")
        print(f"\n{len(findings)} finding(s)")
        return 1 if any(f.level != "info" for f in findings) else 0

    # quickstart
    extra = []
    if args.get("surfaces"):
        try:
            with open(args["surfaces"], encoding="utf-8") as f:
                parsed = json.load(f)
            extra = parsed if isinstance(parsed, list) else [parsed]
        except Exception as e:  # noqa: BLE001
            print(f"could not read surfaces file: {e}", file=sys.stderr)
    if "list" in args or (args["_"] and args["_"][0] == "list"):
        for s in list_surfaces(extra):
            print(f"{s['id']:<16} {s['name']}")
        return 0
    if not args["_"]:
        print("quickstart requires a surface id, or --list", file=sys.stderr)
        return 2
    surface = find_surface(args["_"][0], extra)
    if not surface:
        print(f'unknown surface "{args["_"][0]}". Run: behalf quickstart --list', file=sys.stderr)
        return 2
    command = "python3" if "local" in args else args.get("command")
    cli_args = ["-m", "behalf.mcp_server"] if "local" in args else _as_list(args.get("arg"))
    env = {}
    for e in _as_list(args.get("env")):
        if "=" in e:
            k, v = e.split("=", 1)
            env[k] = v
    qs = generate_quickstart(
        surface,
        name=args.get("name"),
        command=command,
        args=cli_args or None,
        env=env or None,
    )
    print(json.dumps(qs, indent=2) if args.get("format") == "json" else qs["text"])
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("help", "--help"):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]
    args = _parse_args(rest)

    if cmd in ("lint", "quickstart"):
        return _run_stateless(cmd, args)

    engine = _load_engine()

    if cmd == "pubkey":
        print(engine.public_key)
        return 0
    if cmd == "grant":
        principal, agent = args.get("principal"), args.get("agent")
        can = _as_list(args.get("can"))
        expires = args.get("expires", "1h")
        if not principal or not agent or not can:
            print("grant requires --principal, --agent, and at least one --can", file=sys.stderr)
            return 2
        for f in lint(can):
            print(f"[lint:{f.level}] {f.capability}: {f.message}", file=sys.stderr)
        m = engine.grant(principal=principal, agent=agent, can=can, expires_in=expires)
        print(m.serialize())
        return 0
    if cmd == "inspect":
        if not args["_"]:
            print("inspect requires <mandate>", file=sys.stderr)
            return 2
        m = engine.import_(args["_"][0])
        try:
            engine.verify_signature(m.token)
            scope = [c["can"] for b in m.token["blocks"] for c in b["caveats"] if c["t"] == "cap"]
            exp = m.expires_at
            print(json.dumps({
                "valid": True, "id": m.id, "principal": m.principal, "agent": m.agent,
                "expiresAt": datetime.fromtimestamp(exp / 1000, timezone.utc).isoformat() if exp else None,
                "chain": m.chain, "scope": scope,
            }, indent=2))
            return 0
        except Exception as e:  # noqa: BLE001
            print(json.dumps({"valid": False, "reason": str(e)}, indent=2))
            return 1
    if cmd == "authorize":
        if len(args["_"]) < 2:
            print("authorize requires <mandate> <action>", file=sys.stderr)
            return 2
        mandate, action = args["_"][0], args["_"][1]
        # The CLI only has the public token (not the holder's key), so this is an
        # advisory scope check — it does not prove possession.
        result = engine.inspect(engine.import_(mandate).token, action)
        if result["allowed"]:
            print(f"ALLOW  {action}  (advisory; possession not checked)")
            return 0
        print(f"DENY   {action}  ({result['reason']})")
        return 1
    if cmd == "revoke":
        if not args["_"]:
            print("revoke requires <mandate-id>", file=sys.stderr)
            return 2
        engine.revoke(args["_"][0])
        print(f"revoked {args['_'][0]}")
        return 0
    if cmd == "audit":
        if not args["_"]:
            print("audit requires <mandate-id>", file=sys.stderr)
            return 2
        trail = engine.audit(args["_"][0])
        for e in trail:
            ts = datetime.fromtimestamp(e["ts"] / 1000, timezone.utc).isoformat()
            reason = f"  ({e['reason']})" if e.get("reason") else ""
            print(f"{ts}  {e['decision'].upper():<5}  {e['action']}{reason}")
        print(f"\n{len(trail)} record(s)")
        return 0

    print(f'unknown command "{cmd}"\n\n{USAGE}', file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
