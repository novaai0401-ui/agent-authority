import { createHmac, createHash, randomBytes, randomUUID } from "node:crypto";
import type { Caveat } from "./types.js";

/**
 * Macaroon-style HMAC chaining.
 *
 *   sig_0 = HMAC(rootKey, identifier)
 *   sig_i = HMAC(sig_{i-1}, serialize(caveat_i))
 *
 * The crucial property: appending a caveat only needs the *previous* signature,
 * not the root key — so a holder can attenuate offline and keylessly, yet can
 * never remove or reorder an earlier caveat (that would change the chain). This
 * is what structurally closes the OAuth "delegation-chain splicing" weakness.
 */
export function chainSignature(
  rootKey: Buffer,
  identifier: string,
  caveats: Caveat[],
): string {
  let sig: Buffer = hmac(rootKey, identifier);
  for (const c of caveats) {
    sig = hmac(sig, serializeCaveat(c));
  }
  return sig.toString("hex");
}

/** Extend an existing signature with one more caveat (the attenuation step). */
export function extendSignature(prevSig: string, caveat: Caveat): string {
  return hmac(Buffer.from(prevSig, "hex"), serializeCaveat(caveat)).toString("hex");
}

/** Deterministic, canonical serialization of a caveat for hashing. */
export function serializeCaveat(c: Caveat): string {
  switch (c.t) {
    case "principal":
      return `principal=${c.principal}`;
    case "agent":
      return `agent=${c.agent}`;
    case "cap":
      // Sort so the same set always hashes identically.
      return `cap=${[...c.can].sort().join(",")}`;
    case "expires":
      return `expires=${c.at}`;
    case "id":
      return `id=${c.id}`;
  }
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

export function newId(): string {
  return randomUUID();
}

export function newRootKey(): Buffer {
  return randomBytes(32);
}
