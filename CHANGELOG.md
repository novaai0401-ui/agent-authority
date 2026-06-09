# Changelog

All notable changes to Behalf are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to adhere
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- **Tooling.** `behalf` CLI (grant/inspect/authorize/revoke/audit/lint/
  quickstart), `behalf-mcp` and `behalf-control-plane` binaries, dynamic
  per-surface quickstarts for any AI, `llms.txt`, and JSON schemas.
- **Cross-language wire interop** — a mandate issued in one port verifies in the
  other.

### Notes

This is pre-release (0.x): the five-verb API is stable, but storage interfaces
and the control-plane HTTP surface may still change. See the README's
"Limitations & roadmap" for known trade-offs.

[Unreleased]: https://github.com/novaai0401-ui/agent-authority/commits/main
