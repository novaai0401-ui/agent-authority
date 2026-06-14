# Use cases — where and how to use `agent-authority`

**agent-authority** (project name: *Behalf*) is the authorization layer for AI
agents: it answers *"is this agent allowed to do this, right now, and on whose
behalf?"* with a **verifiable, scoped, time-bound, revocable** permission slip (a
**Mandate**). This page shows concretely **who** uses it, **where** it fits, and
**how** — with copy-paste code for each scenario.

- Works in **TypeScript/Node** and **Python**, identical API.
- **Zero runtime dependencies**, offline-verifiable (public-key only).
- Drops into **MCP** tool servers and **agent-to-agent (A2A)** calls.
- Install: `npm install agent-authority` · `pip install agent-authority`

---

## Who it's for

| Audience | Why they use it |
|---|---|
| **App / AI developers** | Stop an autonomous agent from doing more than you intended — scope, cap, expire, and revoke what it can do, in 5 lines. |
| **Platform / infra teams** | One authorization primitive across every agent and tool server; offline verification; a control plane for org-wide revocation + audit. |
| **Enterprises / security & compliance** | Least-privilege delegation, tamper-evident audit trails, multi-tenant isolation, cryptographic agent identity — the controls auditors ask for. |
| **AI agents themselves** | Discover and use it natively over MCP (`request_mandate` / `check_authority`) — see "For AI agents" below. |

---

## Core use cases

### 1. Rein in an autonomous coding / ops agent
**Problem:** an autonomous agent with broad API keys can delete the wrong repo or
run up a bill. **Solution:** give it a mandate, not the keys.

```ts
import { Behalf } from "agent-authority";

const mandate = await Behalf.grant({
  principal: "ci-bot",
  agent: "refactor-agent",
  can: ["read:repo/acme-app", "write:repo/acme-app", "spend:usd<=5"],
  expiresIn: "30m",
});
await mandate.authorize("write:repo/acme-app"); // ok
await mandate.authorize("write:repo/other");     // throws — out of scope
```

### 2. Personal assistant / customer-support agent (per-user scope)
**Problem:** one agent serves many users; it must only touch the *current* user's
data. **Solution:** mint a short-lived mandate scoped to that user per session.

```ts
const mandate = await Behalf.grant({
  principal: user.id,
  agent: "support-agent",
  can: [`read:tickets/${user.id}`, `write:tickets/${user.id}`],
  expiresIn: "15m",
});
```

### 3. Payment / finance agent (spend + rate limits)
**Problem:** an agent that can pay invoices needs hard money limits.
**Solution:** quantitative + rate capabilities, enforced at authorize.

```ts
const mandate = await Behalf.grant({
  principal: user.id,
  agent: "billing-agent",
  can: ["spend:usd<=200", "send:email rate<=5/h"],
  expiresIn: "1h",
});
await mandate.authorize("spend:usd=150"); // ok (≤ 200)
await mandate.authorize("spend:usd=250"); // throws
```

### 4. Multi-agent orchestration (delegation + cascade revoke)
**Problem:** an orchestrator hands work to sub-agents; a sub-agent must never get
*more* power, and you need a kill switch. **Solution:** `attenuate()` only
narrows; revoking the parent kills the whole chain.

```ts
const root = await Behalf.grant({
  principal: user.id, agent: "orchestrator",
  can: ["read:calendar", "read:email", "spend:usd<=50"], expiresIn: "1h",
});
// sub-agent gets strictly less:
const researcher = root.attenuate({ can: ["read:calendar"], expiresIn: "10m" });
await Behalf.revoke(root.id); // researcher's mandate dies too
```

### 5. RAG / data-access agent (read-only, path-scoped)
```ts
const mandate = await Behalf.grant({
  principal: "analytics",
  agent: "rag-indexer",
  can: ["read:docs/public", "read:docs/handbook"],
  expiresIn: "6h",
});
```

### 6. Secure an MCP tool server in ~6 lines
**Problem:** most MCP tool servers ship with no auth. **Solution:** wrap the
server; every tool call is checked against the caller's mandate automatically.

```ts
import { withBehalf } from "agent-authority/mcp";

const server = withBehalf(myMcpServer, {
  policy: {
    send_email: "write:email",
    read_calendar: "read:calendar",
    transfer_funds: (args) => `spend:usd<=${args.amount}`,
  },
  onDenied: "throw", // or "prompt" for just-in-time human consent
});
```

### 7. Agent-to-agent (A2A) calls across services
**Problem:** service A's agent calls service B; B must verify A's authority
offline, without sharing secrets. **Solution:** the verifiable chain travels on
the request; B verifies with only the issuer's public key.

```ts
import { behalfFetch, guard } from "agent-authority/a2a";

// callee: gate every request
const gate = guard({ engine: callee, capability: () => "spend:usd<=50" });
// caller: forward the mandate, narrowed so the callee gets strictly less
await behalfFetch(url, mandate, { method: "POST" },
  { attenuate: { can: ["spend:usd<=20"] } });
```

### 8. SaaS platform hosting many tenants' agents
**Problem:** many customers share your infra; their authority data must never mix.
**Solution:** the control plane with per-tenant tokens + strict isolation.

```ts
import { createControlPlane } from "agent-authority/control-plane";

const plane = createControlPlane({
  tenants: { "tok_acme": acmeIssuerPubKey, "tok_globex": globexIssuerPubKey },
  requireTenant: true, // refuse any non-tenant request
});
await plane.listen(8787); // revoke once → every agent sees it; per-tenant audit
```

### 9. Compliance & audit trails
**Problem:** you must prove what every agent did. **Solution:** every
`authorize()` writes a hash-chained record; sign periodic checkpoints to detect
tampering.

```ts
import { startAuditCheckpointing } from "agent-authority";

const trail = await Behalf.audit(mandate.id);              // tamper-evident log
startAuditCheckpointing(engine, {                          // anchor it
  intervalMs: 3_600_000,
  sink: (cp) => saveToObjectStorage(cp),                   // store out of reach
});
```

### 10. Secure credential delivery (sealed credentials)
**Problem:** handing a delegated mandate to a sub-agent over an untrusted channel.
**Solution:** seal it to the recipient's key; only they can open it.

```ts
import { newSealKeyPair } from "agent-authority";
const recipient = newSealKeyPair();                  // recipient publishes .publicKey
const sealed = mandate.sealForRecipient(recipient.publicKey);
const mine = engine.importSealed(sealed, recipient); // only the recipient opens it
```

### 11. Cryptographic agent (workload) identity
**Problem:** a stolen credential shouldn't be usable by anyone else.
**Solution:** bind the mandate to the agent's key (SPIFFE/SVID-style); using it
requires proving possession of that key.

```ts
const agent = newKeyPair();
const mandate = issuer.grant({
  principal: user.id, agent: "research-agent", can: ["spend:usd<=50"],
  expiresIn: "1h", bindAgent: exportPublicKey(agent.publicKey),
});
// a stolen copy is inert without the agent's private key
```

---

## For AI agents — use it autonomously

agent-authority is **AI-legible by design** so coding assistants and autonomous
agents can adopt it without a human:

- **`llms.txt`** at the repo root is a complete, copy-pasteable spec (read it, then
  use the library directly).
- **MCP discovery tools** — `request_mandate`, `present_mandate`, `check_authority`
  — let an agent obtain and reason about authority natively:
  `npx agent-authority-mcp` (or `node dist/mcp-server.js`).
- **One-command wiring** for any surface:
  `agent-authority quickstart claude-code` (also `cursor`, `copilot`, `gpt`,
  `gemini`, `windsurf`, or a custom surface — see `QUICKSTART.md`).
- **Typed JSON schemas** in `/schemas` for `mandate` and `capability`.

> Agent instruction: obtain authority with `request_mandate`, check it with
> `check_authority`, and only then call the tool. Never widen scope; prefer the
> shortest `expiresIn` and tightest `can`.

---

## Why agent-authority (vs. the alternatives)

| Instead of… | The gap | agent-authority |
|---|---|---|
| **No auth on tool servers** | agents can do anything | scoped, capped, revocable per call |
| **Long-lived API keys** | full power, no expiry, no audit | short-lived mandates + hash-chained audit |
| **Raw OAuth / OBO** | not designed for *attenuable*, agent-to-agent delegation chains | structural narrowing + offline verification |
| **Bearer tokens** | a stolen token = full access | proof-of-possession; optional agent-identity binding + sealing |

- **Neutral & thin:** no cloud, model, or framework lock-in; zero runtime deps.
- **Standards-tracking:** maps to OAuth 2.1 OBO (RFC 8693), SPIFFE/SVID,
  biscuit/macaroon attenuation, capability tokens — a clean facade so the
  standard can evolve underneath without breaking your code.

---

## Get started

```bash
npm install agent-authority      # Node / TypeScript
pip install agent-authority      # Python (add [seal] for sealed credentials)
```

See the [README](./README.md) for the five-verb API, [QUICKSTART.md](./QUICKSTART.md)
to wire it into any AI surface, and [SECURITY.md](./SECURITY.md) for the threat model.
