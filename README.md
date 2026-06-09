# Behalf

> The reference implementation of agent authority. Behalf gives any AI agent a
> **verifiable, scoped, revocable** identity and delegation chain in five verbs.

Agent authority is becoming required infrastructure: multi-agent systems are
already the norm, yet most tool servers ship with no auth at all. The *standard*
for agent identity and delegation is being defined by NIST, the IETF, and the
Linux Foundation's Agentic AI Foundation. Behalf doesn't try to win that race —
it's the clean, neutral, AI-legible **implementation** of it. The `requests` of
the agent era: the install nobody reinvents.

Everything is one primitive — a **Mandate**: a signed, scoped, time-bound
capability token that proves *who authorized what, within which limits, and
through which chain of agents.*

## Secure an entire agent in ~6 lines

```ts
import { withBehalf } from "behalf/mcp";

const server = withBehalf(myMcpServer, {
  policy: {
    send_email: "write:email",
    read_calendar: "read:calendar",
    transfer_funds: (args) => `spend:usd<=${args.amount}`,
  },
  onDenied: "throw", // or "prompt" for just-in-time user consent
});
```

Every tool call through that server is now automatically checked against the
caller's mandate — scope, limits, expiry, revocation, and audit — with no
per-tool code.

## The five verbs

```ts
import { Behalf } from "behalf";

// 1. GRANT — a user authorizes an agent: scoped, capped, short-lived
const mandate = await Behalf.grant({
  principal: user.id,
  agent: "research-agent",
  can: ["read:calendar", "spend:usd<=50"],
  expiresIn: "1h",
});

// 2. AUTHORIZE — before any action, prove authority (throws if denied)
await mandate.authorize("spend:usd=20");

// 3. ATTENUATE — hand a narrowed mandate to a sub-agent; can only shrink scope
const child = mandate.attenuate({ can: ["read:calendar"], expiresIn: "10m" });

// 4. REVOKE — kill a mandate and its whole downstream chain, instantly
await Behalf.revoke(mandate.id);

// 5. AUDIT — every authorize() already wrote a tamper-evident record
const trail = await Behalf.audit(mandate.id);
```

That's the entire core surface. Five verbs: **grant, authorize, attenuate,
revoke, audit.** There is no sixth.

## Capability grammar

Scopes are both human- and machine-writable:

```
read:calendar           # simple capability
write:repo/acme-app     # resource-scoped (path segments)
spend:usd<=50           # quantitative limit
send:email rate<=10/h   # rate limit
*                       # wildcard (discouraged; lint warns)
```

When authorizing, name a concrete amount — `spend:usd=20` is checked against the
grant's `spend:usd<=50`.

## Design principles (non-negotiable)

1. **Thin & end-of-chain.** Zero runtime dependencies — built on the platform's
   own crypto.
2. **One obvious way.** Exactly one canonical method per task.
3. **AI-legible by default.** Ships with an MCP server, [`llms.txt`](./llms.txt),
   and typed [schemas](./schemas) so coding agents call it correctly.
4. **Standards-tracking, not standards-defining.** A clean facade over
   SPIFFE / OAuth 2.1 OBO / capability tokens.
5. **Neutral.** No cloud, model, or framework lock-in.
6. **Offline-verifiable.** A mandate is checked and narrowed without calling
   home (macaroon-style attenuation). Only revocation needs a network check.

### The intersection rule is structural

A mandate is an **Ed25519 signature chain** (biscuit-style). Block 0 (the root
grant) is signed by the issuer; each block publishes a fresh public key, and the
*next* block is signed by the matching private key. A holder attenuates by
*appending* a narrowing block signed with the key it was handed — keylessly with
respect to the issuer, and offline. An agent's effective authority is always:

```
principal's grant  ∩  every narrowing along the chain
```

A compromised middle agent can never widen scope, and no block can be removed or
spliced. This closes the OAuth "delegation-chain splicing" weakness — see
[`test/delegation.test.ts`](./test/delegation.test.ts).

### Offline, third-party verification (public key only)

Because the chain is asymmetric, **any** relying party can verify a mandate and
its full delegation chain with only the issuer's public key — no shared secret:

```ts
const issuer = createBehalf();
const pub = issuer.publicKey;                 // share this freely

const verifier = createBehalf({ trust: [pub] }); // holds no secret
const m = verifier.import(serializedMandate);
await m.authorize("spend:usd=20");            // verified + checked offline
```

A mandate restored via `import` can be verified, authorized, and audited, but
not delegated (it doesn't carry the private delegation key) — a safe default.

## What maps to the standard underneath

| Behalf concept                  | Standard it tracks                              |
| ------------------------------- | ----------------------------------------------- |
| Mandate (capability token)      | Agentic JWT / capability tokens (IBCT-style)    |
| `attenuate()` (holder narrowing)| DeepMind macaroon-style attenuation             |
| Agent identity                  | SPIFFE / SVID compatible                         |
| Principal → agent grant         | OAuth 2.1 On-Behalf-Of / token exchange (RFC 8693) |
| Audit record                    | provenance / non-repudiation records            |
| Transport bindings              | MCP + A2A authorization layers                  |

Because the 5-line API is a facade, the standard can evolve underneath without
breaking anyone's code.

## Install & develop

```bash
npm install          # dev deps only (typescript, @types/node)
npm run build        # compile to dist/
npm test             # 48 tests: capability/mandate/delegation/revocation/audit/mcp/asymmetric/persist/server
```

Run the reference integrations:

```bash
npm run example:data-access   # a read-only data agent
npm run example:spend         # a budget- and rate-limited spend agent
npm run example:delegation    # two-agent attenuation + cascade revoke
```

### CLI

After `npm run build`, the `behalf` CLI manages mandates from the terminal
(state lives under `$BEHALF_HOME`, default `~/.behalf`):

```bash
node dist/cli.js pubkey
M=$(node dist/cli.js grant --principal alice --agent research \
      --can "read:calendar" --can "spend:usd<=50" --expires 1h)
node dist/cli.js inspect "$M"
node dist/cli.js authorize "$M" "spend:usd=20"   # ALLOW
node dist/cli.js authorize "$M" "spend:usd=99"   # DENY
node dist/cli.js revoke <mandate-id>
node dist/cli.js audit  <mandate-id>
```

### MCP server

A dependency-free stdio MCP server exposes the discovery tools to any MCP client:

```bash
node dist/mcp-server.js      # speaks JSON-RPC 2.0 over stdio
```

```jsonc
// register with an MCP client, e.g.:
{ "mcpServers": { "behalf": { "command": "node", "args": ["dist/mcp-server.js"] } } }
```

### Persistence

`FileRevocationStore` and `FileAuditStore` keep revocation and audit state across
restarts with zero infrastructure:

```ts
import { createBehalf, FileRevocationStore, FileAuditStore } from "behalf";
const behalf = createBehalf({
  revocations: new FileRevocationStore("./revocations.json"),
  audit: new FileAuditStore("./audit.jsonl"),
});
```

### Python

An identical-shape port lives in [`python/`](./python):

```bash
cd python
python3 -m unittest discover -s tests   # 32 tests, zero dependencies
```

```python
from behalf import create_behalf

b = create_behalf()
mandate = b.grant(
    principal="alice", agent="research-agent",
    can=["read:calendar", "spend:usd<=50"], expires_in="1h",
)
mandate.authorize("spend:usd=20")
child = mandate.attenuate(can=["read:calendar"], expires_in="10m")
```

## What ships

- **`behalf`** (npm) — the core TypeScript library, near-zero deps.
- **`behalf/mcp`** + **`behalf/a2a`** — drop-in enforcement middleware.
- **`behalf`** (PyPI) — Python port, identical API shape.
- **MCP server + `llms.txt` + typed schemas** — the agent-adoption kit.
- **Three reference integrations** — data-access, spend-limited, two-agent delegation.

## Status

Beyond the initial MVP, this now includes **Ed25519 asymmetric verification**
(any party verifies offline with just the issuer public key), **file-backed
persistence** for revocation + audit, a **`behalf` CLI**, and a **dependency-free
stdio MCP server**. CI runs both test suites on Node 20/22 and Python 3.9/3.12.

Deferred: deep multi-hop tuning, cross-language wire interop (the TS port uses
SPKI/PKCS8 key encoding, the Python port raw keys — same JSON token shape), and
the Phase-2 hosted control plane (managed revocation propagation + dashboard).

## License

MIT.
