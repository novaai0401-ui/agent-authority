# Behalf

> The reference implementation of agent authority. Behalf gives any AI agent a
> **verifiable, scoped, revocable** identity and delegation chain in five verbs.

Agent authority is becoming required infrastructure: multi-agent systems are
already the norm, yet most tool servers ship with no auth at all. The *standard*
for agent identity and delegation is being defined by NIST, the IETF, and the
Linux Foundation's Agentic AI Foundation. Behalf doesn't try to win that race —
it's the clean, neutral, AI-legible **implementation** of it. The `requests` of
the agent era: MIT-licensed, the install nobody reinvents.

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

// 5. AUDIT — every authorize() already wrote a hash-chained record
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
   and typed [schemas](./schemas) so coding agents discover and call it correctly.
4. **Standards-tracking, not standards-defining.** A clean facade over
   SPIFFE / OAuth 2.1 OBO / capability tokens.
5. **Neutral.** No cloud, model, or framework lock-in.
6. **Offline-verifiable.** Signature chain, scope, expiry, and proof of
   possession are all checked locally (asymmetric, public-key only). Only
   revocation and the shared rate cap need a network check.

### The intersection rule is structural

A mandate is an **Ed25519 signature chain** (biscuit-style). Block 0 (the root
grant) is signed by the issuer; each block publishes a fresh public key, and the
*next* block is signed by the matching private key. A holder attenuates by
*appending* a narrowing block signed with the key it was handed — keylessly with
respect to the issuer, and offline. An agent's effective authority is always:

```
principal's grant  ∩  every narrowing along the chain
```

A compromised middle agent can never widen scope; no block can be edited,
removed from the middle, or **truncated** off the end. Editing/middle-removal is
blocked by the signature chain; truncation is blocked by a **proof of
possession** at authorize time (below). This closes the OAuth
"delegation-chain splicing" weakness — see [`test/delegation.test.ts`](./test/delegation.test.ts)
and [`test/asymmetric.test.ts`](./test/asymmetric.test.ts).

### Authorizing requires proving possession (no bearer tokens)

A serialized mandate is **not** a usable bearer credential. To authorize, the
holder must prove possession of the chain's *terminal* private key — the one each
delegation hands to the next agent. A truncated prefix would need that prefix's
terminal key, which a downstream holder does not have, so it cannot escalate by
dropping its own block.

```ts
// In-process holder: mandate.authorize() mints + checks the proof for you.
await mandate.authorize("spend:usd=20");

// Across a trust boundary, the holder presents the token + a fresh,
// action-bound proof; the verifier needs only the issuer's PUBLIC key:
const verifier = createBehalf({ trust: [issuer.publicKey] });
await verifier.authorize(mandate.token, "spend:usd=20", mandate.prove("spend:usd=20"));
```

For an advisory "would this token's scope allow X?" check that does **not** prove
possession (e.g. tooling/dashboards), use `engine.inspect(token, action)`. Over
HTTP, `behalf/a2a`'s `present()` attaches the proof automatically.

Proofs are bound to the action and fresh within `proofSkewMs` (default 5 min).
For **true single-use anti-replay**, the verifier issues a challenge:
`const nonce = verifier.challenge()` → holder binds it with
`mandate.prove(action, { nonce })` → the verifier consumes it on use. Engines
created with `requireNonce: true` refuse nonce-less proofs entirely.

There are two serializations, and the difference matters:

- **`mandate.serialize()`** — the public token. Safe to show anyone; after
  `import` it can be inspected and verified, but **not** authorized, proved, or
  delegated (it carries no key).
- **`mandate.serializeWithKey()`** — the holder credential (token **+**
  delegation key). This is how you hand a delegated mandate to a sub-agent in
  another process: after `import` it has full holder powers. **Treat it as a
  secret** and deliver it only over a secure channel.

### Binding a mandate to an agent identity (SVID-style)

A holder credential is a secret, so a leak is a real risk. Bind the mandate to a
specific agent identity and a stolen credential is **inert without the agent's
private key** — possession of the credential is no longer sufficient to act.

Grant (or attenuate) with `bindAgent` set to the agent's public key; that adds an
`agentKey` caveat. Authorizing then requires a proof of possession of the
matching private key, in addition to the chain's terminal key:

```ts
const agent = newKeyPair();                       // the agent's long-lived identity
const mandate = issuer.grant({
  principal: user.id,
  agent: "research-agent",
  can: ["spend:usd<=50"],
  expiresIn: "1h",
  bindAgent: exportPublicKey(agent.publicKey),     // ← cryptographic binding
});

// The agent proves BOTH the terminal key and its identity:
await verifier.authorize(
  mandate.token,
  "spend:usd=20",
  mandate.prove("spend:usd=20", { agentKeys: [agent] }),
);
// An engine configured with `agentKey: agent` proves it automatically on the
// in-process path (mandate.authorize(...)) and over A2A via present(..., { agentKeys }).
```

Bindings are **conjunctive**: every `agentKey` caveat in the chain must be
satisfied. A thief who steals the credential cannot strip the caveat (it is
signed into a block) and cannot bypass it by appending their own binding — doing
so only adds another requirement. The agent's private key is provisioned out of
band; Behalf never puts it on the wire.

### Sealing a holder credential (encrypted delivery)

`serializeWithKey()` is a secret. `bindAgent` makes a *stolen* one inert; for the
delivery channel itself, **seal** the credential to the recipient so it's
unreadable to anyone in between:

```ts
import { newSealKeyPair } from "behalf";

const recipient = newSealKeyPair();          // recipient's X25519 sealing key
// ...recipient publishes recipient.publicKey...

const sealed = mandate.sealForRecipient(recipient.publicKey);  // encrypted blob
// ...deliver `sealed` over any channel...
const mine = engine.importSealed(sealed, recipient);           // only the recipient opens it
await mine.authorize("read:calendar");
```

The scheme (`seal-1`) is ephemeral X25519 → HKDF-SHA256 → AES-256-GCM and is
**wire-compatible across both ports** (seal in TypeScript, open in Python or vice
versa). It's native in Node; in Python it needs the optional `cryptography`
package (the rest of the port stays dependency-free, and `importSealed` raises a
clear error if it's missing). The sealing key is X25519 and is *separate* from
the Ed25519 `bindAgent` identity — combine both for delivery + use protection.

### Issuer key rotation (with overlap)

```ts
const v2 = v1.rotate();          // fresh key, same stores, still trusts v1
// 1) distribute v2.publicKey to verifiers (verifier.trustKey(v2.publicKey))
// 2) new grants are signed by v2; old mandates keep verifying
// 3) after the longest outstanding mandate expires:
v2.untrustKey(v1.publicKey);     // end the overlap — old-key mandates retire
```

### Audit checkpoints (anchoring)

The audit log is an unkeyed hash chain — verifiable, but a writer with store
access could rewrite it and tail-deletion is invisible. `checkpointAudit()`
signs the current head; store the checkpoint **out of the writer's reach** and
`verifyAuditCheckpoint(cp)` later detects tail-deletion and rewrites:

```ts
const cp = await engine.checkpointAudit();   // ship to object storage / a ledger
// later, e.g. nightly:
const { ok, reason } = await engine.verifyAuditCheckpoint(cp);
```

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
npm test             # 105 tests across capability/mandate/delegation/revocation/audit/mcp/asymmetric/persist/server/a2a/lint/control-plane/quickstart
```

Run the reference integrations:

```bash
npm run example:data-access     # a read-only data agent
npm run example:spend           # a budget- and rate-limited spend agent
npm run example:delegation      # two-agent attenuation + cascade revoke
npm run example:a2a             # agent-to-agent delegation over HTTP
npm run example:control-plane   # revocation propagation across agents
```

### CLI

After `npm run build`, the `behalf` CLI manages mandates from the terminal
(state lives under `$BEHALF_HOME`, default `~/.behalf`):

```bash
node dist/cli.js pubkey
M=$(node dist/cli.js grant --principal alice --agent research \
      --can "read:calendar" --can "spend:usd<=50" --expires 1h)
# $M is a HOLDER credential (includes the delegation key — keep it secret).
# Add --public to emit the presentation-only token instead.
node dist/cli.js inspect "$M"
node dist/cli.js authorize "$M" "spend:usd=20"   # ALLOW (real check, proof of possession)
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

### Quickstarts for any AI

`behalf quickstart` generates the wiring for any surface — Claude Code, Cursor,
Copilot, Windsurf, Gemini CLI, OpenAI Agents (MCP), and GPT / Gemini APIs
(function tools). Any other AI is configurable via a custom surface file or the
generic MCP template. See [QUICKSTART.md](./QUICKSTART.md).

```bash
behalf quickstart --list
behalf quickstart claude-code
behalf quickstart gpt           # OpenAI function tools
behalf quickstart my-agent --surfaces ./surfaces.json   # bring your own AI
```

### A2A — agent-to-agent over HTTP

`behalf/a2a` carries a verifiable delegation chain across the network. The caller
attaches its mandate (optionally attenuating it first); the callee verifies the
chain offline with only the issuer's public key, then authorizes the action:

```ts
import { behalfFetch, guard } from "behalf/a2a";

// callee: a node:http middleware that authorizes each request
const gate = guard({ engine: callee, capability: () => "spend:usd<=50" });
// ... in your http handler: if (!(await gate(req, res))) return;

// caller: forward the mandate, narrowed so the callee gets strictly less
await behalfFetch(url, mandate, { method: "POST" },
  { attenuate: { can: ["spend:usd<=20"] } });
```

### Capability linting

`lint()` flags loose scopes (`*`, unbounded `spend:`, rate-less `send:`, ...) so
agents and humans write tight capabilities by default:

```ts
import { lint } from "behalf";
lint(["spend:usd", "*"]); // → warnings: add a limit; avoid wildcard
```

Also available as `behalf lint <cap> ...` on the CLI.

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

### Control plane (revocation propagation + audit retention)

For multi-agent deployments, the control plane centralizes revocation (revoke
once, every agent sees it), retains one hash-chained audit log (integrity-
chained; see Limitations for its threat model), and offers a
consent/policy surface with a dashboard at `/`. It's a thin HTTP service over the
same stores — point agents at it with the `behalf/remote` client stores and the
five-verb API is unchanged.

```bash
node dist/control-plane.js     # bin: behalf-control-plane; dashboard at /
```

```ts
import { createBehalf } from "behalf";
import { HttpRevocationStore, HttpAuditStore, HttpRateStore } from "behalf/remote";

const behalf = createBehalf({
  revocations: new HttpRevocationStore("http://localhost:8787"),
  audit: new HttpAuditStore("http://localhost:8787"),
  rate: new HttpRateStore("http://localhost:8787"),
});
// revoke(id) propagates to every agent; audit is sealed centrally (race-free);
// and a `rate<=N/h` cap is enforced ONCE across all agents, not per process.
//
// Multi-tenant: createControlPlane({ tenants: { tokenA: issuerAPubKey } }) — a
// tenant token reads/writes only its own issuer's audit; `token` is admin.

// Optional: cache revocation checks with a bounded staleness window.
// import { CachingRevocationStore } from "behalf";
// revocations: new CachingRevocationStore(new HttpRevocationStore(url), { ttlMs: 5000 })
```

### Cross-language interop

A mandate issued by either reference port verifies in the other: both encode keys
as raw Ed25519 (base64url) and compute **sorted-key canonical JSON** for the
signed bytes, so a TS-issued mandate authorizes under the Python verifier and
vice versa — including attenuated multi-block chains and the action-bound
possession proof. A committed fixture, [`vectors/mandate-vector.json`](./vectors/mandate-vector.json),
is verified by *both* test suites so the wire format can't drift; any third-party
implementation should verify it too.

```bash
npm run test:interop   # PY⇄TS, issue in one port, verify/authorize in the other
```

### Python

An identical-shape port lives in [`python/`](./python):

```bash
cd python
python3 -m unittest discover -s tests   # 85 tests, zero dependencies
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
persistence** for revocation + audit, a **`behalf` CLI**, a **dependency-free
stdio MCP server**, an **A2A HTTP transport** that carries the verifiable chain
between agents, **capability linting**, **cross-language wire interop**
(TS⇄Python mandates verify in either port), and a **control plane** for
revocation propagation, audit retention, and consent/policy with a dashboard, and
**dynamic per-surface quickstarts** that wire Behalf into any AI (Claude Code,
Cursor, Copilot, Gemini, GPT, or a custom surface). CI runs both test suites plus
the interop check on Node 20/22 and Python 3.9/3.12.

All control-plane state can be file-backed for durability — revocation, audit,
and now consent + policy (`FileConsentStore`, `FilePolicyStore`); the
`behalf-control-plane` bin persists everything under `$BEHALF_HOME`. The Python
port has full parity: not just the library and control plane, but the tooling
too — the `behalf` CLI, the `behalf-mcp` stdio server, and the quickstart
generator (`python -m behalf.cli`, or the console scripts after `pip install`).

## Limitations & roadmap

Honest about what this reference implementation does *not* yet do:

- **Tenant isolation requires per-tenant tokens.** With
  `tenants: { token: issuerPub }`, audit, policy, revocation, rate, and consent
  are all namespaced per tenant (admin revocations stay global). Without tenant
  tokens the plane is a single trust domain — run one plane per trust domain in
  that mode.
- **Shared rate checks hit the network each call.** `HttpRateStore` consults the
  control plane on every `authorize()` (the cap is authoritative and can't be
  cached). The plane stamps each hit with its **own clock** and validates the
  window/limit, so a skewed or hostile client can't slide the window; the
  limit/window values themselves still come from the caller's mandate (the
  honest-enforcer model — a node that bypasses its own runtime is out of scope,
  like any client that skips the check). Revocation, by contrast, can be wrapped
  in `CachingRevocationStore` for a bounded staleness window. Signature, scope,
  and expiry are always fully offline.
- **Cross-language delegation works.** A holder credential
  (`serializeWithKey()`) issued in one port can be imported **and attenuated** in
  the other: a block signed in Python over a chain rooted in TypeScript (or vice
  versa) verifies, because both ports use raw Ed25519 keys and byte-identical
  canonical JSON. Pinned by the interop check (`PY->TS->PY` and `TS->PY->TS`
  delegated-chain cases in `scripts/interop.mjs`).
- **Pure-Python Ed25519 is not constant-time — auto-upgraded when possible.** The
  zero-dependency reference signer is correct but not hardened against timing
  side-channels. The Python port now **auto-selects** a hardened native backend
  when one is importable (`cryptography`, then `PyNaCl`), falling back to pure
  Python otherwise; `behalf.crypto.backend()` reports which is active. Install
  `cryptography` for constant-time Python in hostile-adjacency deployments. (Node
  always uses its native, hardened crypto.)
- **Rate limiting offers two strategies.** The default `MemoryRateStore` is a
  sliding-count window (max N per window); `TokenBucketRateStore` is now available
  for **burst shaping** (an initial burst up to the limit, then a steady refill).
  Both are drop-in for any `RateStore` slot (engine `rate:` or the control plane),
  and neither counts rejected attempts.
- **The audit log is an unkeyed hash chain.** It detects edits, reordering, and
  naive single-record tampering — but a writer with full store access can
  recompute the chain, and tail deletion alone isn't detectable. Mitigation
  shipped: `checkpointAudit()` signs the head; store checkpoints out of the
  writer's reach and `verifyAuditCheckpoint()` detects deletion/rewrites.
  WORM/append-only storage remains the strongest option.
- **The `agent` *caveat* is an advisory label** (a string), but cryptographic
  agent-identity binding now ships: grant/attenuate with `bindAgent` to require a
  proof of possession of the agent's key at authorize (SVID-style; see "Binding a
  mandate to an agent identity"). The agent's private key must be provisioned out
  of band — Behalf enforces the binding but does not distribute keys.

None of these affect the core security properties (unforgeable, attenuation-only,
truncation-resistant, offline-verifiable mandates); they are
durability/scaling/hardening trade-offs.

This implementation has not had an independent cryptographic audit — commission
one before any 1.0 / production positioning.

## License

MIT — see [LICENSE](./LICENSE). Open source, use it anywhere, including
commercially. Contributions welcome.
