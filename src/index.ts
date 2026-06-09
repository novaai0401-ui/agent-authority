/**
 * Behalf — the reference implementation of agent authority.
 *
 * Five verbs, one primitive (the Mandate):
 *
 *   import { Behalf } from "behalf";
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
  type RevocationStore,
  type AuditStore,
} from "./store.js";
export { FileRevocationStore, FileAuditStore } from "./persist.js";
export { verify as verifyAuditLog } from "./audit.js";
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
  MandateToken,
  GrantOptions,
  AttenuateOptions,
  AuditEntry,
  AuditIntegrity,
} from "./types.js";
