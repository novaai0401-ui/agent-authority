import {
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createHash,
  createPublicKey,
  createPrivateKey,
  randomUUID,
  type KeyObject,
} from "node:crypto";
import type { Block } from "./types.js";

/**
 * Asymmetric attenuable tokens (biscuit-style Ed25519 signature chain).
 *
 * The token is an ordered list of blocks. Block 0 (the root grant) is signed by
 * the issuer's private key. Every block also publishes a fresh public key
 * (`nextPub`); the *next* block is signed by the matching private key. So:
 *
 *   sig[0]  = sign(rootPriv,        canonical(block[0]))   verify with rootPub
 *   sig[i]  = sign(block[i-1].next, canonical(block[i]))   verify with block[i-1].nextPub
 *
 * Consequences:
 *  - Verification needs only PUBLIC keys — any relying party can check a mandate
 *    and its whole chain offline, without the issuer's secret.
 *  - A holder attenuates by appending a block signed with the private key it was
 *    handed; it never needs the issuer key.
 *  - A block cannot be removed (the next block's signer key was published inside
 *    it) and the root grant cannot be edited (root signature). Widening is
 *    impossible because every block's caveats are intersected at authorize time.
 */

export interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export function newKeyPair(): KeyPair {
  return generateKeyPairSync("ed25519");
}

/** Canonical, deterministic bytes for a block (what gets signed/verified). */
export function canonicalBlock(block: Block): string {
  return JSON.stringify({ caveats: block.caveats, nextPub: block.nextPub });
}

export function signBlock(privateKey: KeyObject, block: Block): string {
  return edSign(null, Buffer.from(canonicalBlock(block), "utf8"), privateKey).toString(
    "base64url",
  );
}

export function verifyBlock(publicKey: KeyObject, block: Block, sig: string): boolean {
  try {
    return edVerify(
      null,
      Buffer.from(canonicalBlock(block), "utf8"),
      publicKey,
      Buffer.from(sig, "base64url"),
    );
  } catch {
    return false;
  }
}

export function exportPublicKey(key: KeyObject): string {
  return key.export({ type: "spki", format: "der" }).toString("base64url");
}

export function importPublicKey(b64: string): KeyObject {
  return createPublicKey({ key: Buffer.from(b64, "base64url"), type: "spki", format: "der" });
}

export function exportPrivateKey(key: KeyObject): string {
  return key.export({ type: "pkcs8", format: "der" }).toString("base64url");
}

export function importPrivateKey(b64: string): KeyObject {
  return createPrivateKey({ key: Buffer.from(b64, "base64url"), type: "pkcs8", format: "der" });
}

export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

export function newId(): string {
  return randomUUID();
}
