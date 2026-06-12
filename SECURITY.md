# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub:
**Security → Report a vulnerability** on this repository (GitHub private
vulnerability reporting), or open an issue asking for a private channel if that
is unavailable. Please do not disclose publicly before a fix is released.

## Status: pre-audit

Behalf is a **0.x reference implementation**. It has had internal security
review (all findings fixed and regression-tested; see `CHANGELOG.md`), but
**no independent cryptographic audit yet**. Do not position it as
production-grade authorization until one has been completed. This document
exists to make that audit efficient.

## Threat model (what Behalf defends against)

The unit of trust is the **Mandate**: a biscuit-style Ed25519 signature chain
of blocks, each carrying caveats and publishing a fresh public key that signs
the next block.

Guarantees, with the mechanism and the test that pins each one:

| Property | Mechanism | Pinned by |
|---|---|---|
| Root/middle blocks cannot be edited or removed | per-block Ed25519 signatures; each block's signer key is published by its predecessor | `test/delegation.test.ts`, `test/mandate.test.ts` |
| Trailing blocks cannot be truncated (no scope recovery) | proof of possession of the **terminal** key at authorize | `test/asymmetric.test.ts` ("truncating the chain…"), `python/tests/test_behalf.py::test_truncation_denied` |
| A serialized token is not a bearer credential | authorize requires the PoP; `serialize()` carries no key | `test/transfer.test.ts` |
| Attenuation only narrows (incl. operator direction) | eager `isNarrowing` + authorize-time intersection of every cap caveat | `test/delegation.test.ts` |
| Proofs cannot be reused for another action | action bound into the proof message | `test/vector.test.ts` |
| Proofs cannot be replayed (opt-in) | verifier-issued single-use nonce (`challenge()` / `requireNonce`) | `test/hardening.test.ts` |
| Untrusted issuers are rejected | explicit `trust` allow-list checked before any use | `test/asymmetric.test.ts` |
| Cross-implementation drift is impossible | sorted-key canonical JSON; shared committed vector verified by both ports | `vectors/mandate-vector.json`, `test/vector.test.ts`, `python/tests/test_vector.py` |
| Revocation cascades to descendants | every chain id checked at authorize | `test/revocation.test.ts` |
| Tenant isolation on a shared control plane | per-tenant bearer tokens namespace audit/policy/revocation/rate/consent | `test/control-plane.test.ts`, `test/hardening.test.ts` |

## Explicit non-goals / accepted limitations

- **Audit log is integrity-chained, not adversary-proof.** An attacker with
  write access to the store can recompute the chain; tail deletion is
  undetectable. Mitigations (signing checkpoints, external anchoring, WORM
  storage) are deliberately left to deployments.
- **`agent` caveat is an advisory label**, not a cryptographic identity binding
  (SPIFFE/SVID-style binding is roadmap).
- **Holder credentials (`serializeWithKey`) are secrets** — Behalf assumes a
  secure delivery channel and does not encrypt them itself.
- **TLS is assumed upstream** for the control plane and A2A transport; without
  a nonce, proof replay is bounded only by `proofSkewMs` (default 5 min).
- **Pure-Python Ed25519 is not constant-time** (timing side-channels); use the
  Node port or swap in libsodium for hostile-adjacency Python deployments.
- **Shared rate limits trust the honest-enforcer model**: limit/window derive
  from the caller's mandate; a runtime that skips its own checks is out of
  scope (as for any client-side enforcement).

## Scope for an external audit

Priority order for an independent cryptographic review:

1. **Token construction** — `src/crypto.ts` / `python/behalf/crypto.py`:
   signature chain, canonicalization, key encoding (raw Ed25519, base64url).
2. **Proof of possession** — message construction (`behalf-pop\n{id}\n{sigs,}\n{ts}\n{action}\n{nonce}`),
   freshness/skew handling, nonce lifecycle.
3. **Authorize pipeline ordering** — `src/behalf.ts authorize()`: signature →
   PoP → revocation → expiry → scope intersection → rate.
4. **Capability grammar** — `src/capability.ts`: `satisfies`, `isNarrowing`,
   `amountNarrows`, resource-prefix coverage (`resourceCovers`).
5. **Control-plane auth** — tenant token resolution and namespacing
   (`src/control-plane.ts route()`).
6. The pure-Python Ed25519 (`python/behalf/_ed25519.py`) — correctness only;
   it is documented as non-constant-time.

Cross-language verifiers should validate against
`vectors/mandate-vector.json` (pin the clock to `proof.ts`).

## Supply chain

Both ports have **zero runtime dependencies** (Node built-ins / Python stdlib
only). Dev dependencies are TypeScript and `@types/node`. The release workflow
publishes with npm provenance and is dry-run unless a version tag and registry
tokens are present.
