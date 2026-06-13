# Changelog

All notable changes to Behalf are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to adhere
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- **Proof of possession at authorize (fixes C-1, critical).** A serialized
  mandate is no longer a bearer credential, and a delegatee can no longer
  **truncate** its chain to recover a parent's wider scope. Authorizing now
  requires proving possession of the chain's terminal key: `mandate.authorize()`
  does this in-process; across a boundary the holder presents a proof
  (`mandate.prove()` / `agent-authority/a2a`'s `present()`) and the verifier checks it
  with `engine.authorize(token, action, proof)`. Advisory, no-possession checks
  use the new `engine.inspect(token, action)`.
- **Attenuation operator direction (fixes M-1).** The narrowing check now
  rejects direction flips (e.g. narrowing `spend:usd<=50` to `spend:usd>=10`); a
  bound may only be tightened in the same direction or to an exact value within.
- **Sorted-key canonical JSON (hardens L-1).** Signed bytes use recursively
  sorted-key canonical JSON in both ports, so cross-implementation drift is
  structurally impossible. A committed cross-language fixture
  (`vectors/mandate-vector.json`) is verified by both test suites.

### Security (hardening)

- **Single-use nonce challenges (anti-replay).** `engine.challenge()` issues a
  nonce the holder binds into its proof (`prove(action, { nonce })`); it is
  consumed on use, so a captured proof can never be replayed. Engines created
  with `requireNonce: true` refuse nonce-less proofs.
- **Full per-tenant isolation on the control plane.** Tenant tokens now
  namespace revocation ids, rate keys, and consent records (in addition to
  audit and policy); admin revocations remain global.
- **Consent TTL** (`consentTtlMs`): pending requests expire to a terminal
  "expired" state. **Audit pagination**: `GET /v1/audit?offset&limit` with
  `total`. **FileRateStore**: rate windows survive restarts.
- **Holder credentials.** `serializeWithKey()` / `import` transfer a delegated
  mandate (token + key) across process boundaries; MCP `request_mandate` and
  the CLI now issue usable credentials (post-PoP regression fixes).

### Security (hardening, continued)

- **Issuer key rotation (B5).** `engine.rotate()` returns a fresh-keyed engine
  sharing stores and trusting the old key for an overlap window; end it with
  `untrustKey(oldKey)`. `trustKey`/`trustedKeys` manage the trust set.
- **Signed audit checkpoints (C4).** `checkpointAudit()` /
  `verifyAuditCheckpoint()` anchor the log head under the issuer key, making
  tail-deletion and rewrites detectable when checkpoints are stored out of the
  writer's reach.
- Fixed: `python -m agent_authority.control_plane` exited immediately (missing
  `__main__` guard); the console script was unaffected.
- **Sealed holder credentials (#8).** `mandate.sealForRecipient(pub)` encrypts a
  holder credential to a recipient's X25519 sealing key; `engine.importSealed`
  opens it. Scheme `seal-1` (ephemeral X25519 → HKDF-SHA256 → AES-256-GCM) is
  wire-compatible across both ports — seal in one, open in the other. Native in
  Node; Python uses the optional `cryptography` package and raises a clear error
  if it's absent (the rest of the port stays dependency-free). Defense-in-depth
  for the delivery channel, complementary to `bindAgent`. New helpers
  `newSealKeyPair` / `seal` / `unseal`; pinned by `test/seal.test.ts`,
  `python/tests/test_seal.py`, and a cross-language interop case.
- **Optional hardened crypto backend (Python).** The Python port auto-selects a
  constant-time native Ed25519 backend when importable (`cryptography`, then
  `PyNaCl`), falling back to the pure-Python reference; `agent_authority.crypto.backend()`
  reports the active one. The selector self-checks byte-compatibility with the
  reference (and tolerates a broken native lib, including Rust panics, without
  noise) so cross-port tokens stay valid. No new required dependency.
- **Token-bucket rate limiting.** `TokenBucketRateStore` is a burst-shaping
  alternative to the default sliding-count `MemoryRateStore` — drop-in for any
  `RateStore` slot (engine or control plane).
- **Cross-language delegation verified.** A holder credential
  (`serializeWithKey`) issued in one port can be imported **and attenuated** in
  the other; the interop check now pins `PY->TS->PY` and `TS->PY->TS`
  delegated-chain cases (previously documented as verify-only).
- **Cryptographic agent identity binding (C3, SVID-style).** Grant or attenuate
  with `bindAgent` (the agent's public key) to add an `agentKey` caveat;
  authorize then requires a proof of possession of the matching private key
  (`mandate.prove(action, { agentKeys })`, or an engine configured with
  `agentKey` on the in-process path). A stolen `serializeWithKey` credential can
  no longer act on its own. Bindings are **conjunctive** — every `agentKey`
  caveat must be satisfied — so a thief cannot strip one or shadow it by
  appending their own. Pinned by `test/agent-binding.test.ts` and
  `python/tests/test_agent_binding.py`; `agent` remains an advisory label.

### Added

- **Core (TypeScript + Python).** The five-verb Mandate API — `grant`,
  `authorize`, `attenuate`, `revoke`, `audit` — over one primitive.
- **Capability grammar.** Verbs, resource paths, quantitative limits
  (`spend:usd<=50`) and rate limits (`send:email rate<=10/h`), with linting.
- **Asymmetric, attenuable tokens.** Ed25519 signature chain (biscuit-style):
  offline third-party verification with only the issuer's public key;
  attenuation-only delegation that structurally blocks widening and splicing.
- **Tamper-evident audit.** Hash-chained log with O(1), single-writer sealing
  that stays intact under concurrent writers.
- **MCP + A2A.** `withBehalf` middleware, a dependency-free stdio MCP server, and
  an HTTP A2A transport that carries the verifiable chain between agents.
- **Control plane.** Revocation propagation, central audit retention, shared
  rate limiting, and a consent/policy surface with a dashboard — all over
  pluggable stores (in-memory, file-backed, or HTTP client).
- **Consent wiring.** `controlPlaneConsent` plugs just-in-time human approval
  into the middleware.
- **Per-issuer audit scoping** and a `tenantScoped` control-plane mode.
- **`CachingRevocationStore`** — bounded-staleness revocation cache.
- **Tooling.** `agent-authority` CLI (grant/inspect/authorize/revoke/audit/lint/
  quickstart), `agent-authority-mcp` and `agent-authority-control-plane` binaries, dynamic
  per-surface quickstarts for any AI, `llms.txt`, and JSON schemas.
- **Cross-language wire interop** — a mandate issued in one port verifies in the
  other.

### Notes

This is pre-release (0.x): the five-verb API is stable, but storage interfaces
and the control-plane HTTP surface may still change. See the README's
"Limitations & roadmap" for known trade-offs.

[Unreleased]: https://github.com/novaai0401-ui/agent-authority/commits/main
