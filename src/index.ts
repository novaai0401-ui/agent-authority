/**
 * Behalf — the reference implementation of agent authority.
 *
 * Five verbs, one primitive (the Mandate):
 *
 *   import { Behalf } from "agent-authority";
 *
 *   const mandate = await Behalf.grant({               // 1. GRANT
 *     principal: user.id,
 *     agent: "research-agent",
 *     can: ["read:calendar", "spend:usd<=50"],
 *     expiresIn: "1h",
 *   });
 *
 *   await mandate.authorize("spend:usd=20");           // 2. AUTHORIZE
 *   const child = mandate.attenuate({ can: ["read:calendar"], expiresIn: "10m" }); // 3. DELEGATE
 *   await Behalf.revoke(mandate.id);                   // 4. REVOKE
 *   const trail = await Behalf.audit(mandate.id);      // 5. AUDIT
 */

export {
  Behalf,
  createBehalf,
  BehalfDelegationError,
  type BehalfConfig,
} from "./behalf.js";
export { Mandate } from "./mandate.js";
export {
  newKeyPair,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
  type KeyPair,
} from "./crypto.js";
export {
  parse as parseCapability,
  permits,
  isNarrowing,
  type Capability,
} from "./capability.js";
export {
  MemoryRevocationStore,
  MemoryAuditStore,
  MemoryRateStore,
  TokenBucketRateStore,
  MemoryConsentStore,
  MemoryPolicyStore,
  CachingRevocationStore,
  type RevocationStore,
  type AuditStore,
  type RateStore,
  type ConsentStore,
  type PolicyStore,
  type CacheOptions,
} from "./store.js";
export {
  FileRevocationStore,
  FileAuditStore,
  FileConsentStore,
  FilePolicyStore,
  FileRateStore,
} from "./persist.js";
export {
  createControlPlane,
  type ControlPlane,
  type ControlPlaneOptions,
  type ConsentRecord,
} from "./control-plane.js";
export {
  HttpRevocationStore,
  HttpAuditStore,
  HttpRateStore,
  ControlPlaneClient,
  controlPlaneConsent,
  type RemoteOptions,
  type ConsentProviderOptions,
  type ConsentRequest,
} from "./remote.js";
export { newSealKeyPair, seal, unseal, type SealKeyPair } from "./seal.js";
export { verify as verifyAuditLog } from "./audit.js";
export { lint, isClean, type LintFinding, type LintLevel } from "./lint.js";
export {
  generateQuickstart,
  findSurface,
  listSurfaces,
  DEFAULT_SURFACES,
  type Surface,
  type QuickstartOptions,
  type Quickstart,
} from "./quickstart.js";
export {
  present,
  behalfFetch,
  authorizeIncoming,
  guard,
  MANDATE_HEADER,
  type PresentOptions,
  type GuardOptions,
  type GuardedRequest,
} from "./a2a.js";
export {
  BehalfError,
  AuthorizationError,
  WideningError,
  IntegrityError,
  CapabilityParseError,
} from "./errors.js";
export type {
  Caveat,
  Block,
  Proof,
  MandateToken,
  GrantOptions,
  AttenuateOptions,
  AuditEntry,
  AuditIntegrity,
} from "./types.js";
