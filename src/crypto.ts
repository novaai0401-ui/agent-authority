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
 *  - A block cannot be edited (its signature) or removed from the middle (the
 *    next block's signer key was published inside it). Trailing-block TRUNCATION
 *    is prevented separately, at authorize time, by a proof of possession: the
 *    presenter must sign a fresh challenge with the private key matching the
 *    LAST block's `nextPub`. Each delegation hands a fresh such key downstream,
 *    so a holder cannot produce the proof for any shorter prefix of its chain.
 *  - Widening is impossible because every block's caveats are intersected at
 *    authorize time.
 */

export interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export function newKeyPair(): KeyPair {
  return generateKeyPairSync("ed25519");
}

/**
 * Canonical, deterministic bytes for a block (what gets signed/verified).
 *
 * INVARIANT: this relies on a fixed key order — `caveats` before `nextPub`, and
 * within each caveat the discriminant `t` before its payload — produced
 * identically by both the TypeScript and Python ports (see their respective
 * caveat constructors). Any third-party verifier MUST reproduce this exact byte
 * layout. If you ever add fields, append them in a fixed position in BOTH ports
 * (or switch to sorted-key canonical JSON in both at once).
 */
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
  // Raw 32-byte Ed25519 public key (JWK `x`), base64url — matches the Python
  // port's encoding so tokens verify across both reference implementations.
  const jwk = key.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new Error("not an Ed25519 public key");
  return jwk.x;
}

export function importPublicKey(b64: string): KeyObject {
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64 }, format: "jwk" });
}

export function exportPrivateKey(key: KeyObject): string {
  // Raw 32-byte seed (JWK `d`), base64url.
  const jwk = key.export({ format: "jwk" }) as { d?: string };
  if (!jwk.d) throw new Error("not an Ed25519 private key");
  return jwk.d;
}

export function importPrivateKey(d: string, x: string): KeyObject {
  return createPrivateKey({ key: { kty: "OKP", crv: "Ed25519", x, d }, format: "jwk" });
}

/**
 * Proof of possession (PoP) of the chain's terminal key — closes trailing-block
 * truncation and makes a serialized token NOT a usable bearer credential.
 *
 * The message binds the proof to the EXACT presented chain (id + every block
 * signature) and a timestamp, so it cannot be replayed for a different/truncated
 * token, and only within a short freshness window for the same one. Producing it
 * requires the private key matching `blocks[last].nextPub`, which only the
 * legitimate tail holder has.
 */
export function proofMessage(id: string, sigs: string[], ts: number): string {
  return `behalf-pop\n${id}\n${sigs.join(",")}\n${ts}`;
}

export function signProof(delegationKey: KeyObject, id: string, sigs: string[], ts: number): string {
  return edSign(null, Buffer.from(proofMessage(id, sigs, ts), "utf8"), delegationKey).toString(
    "base64url",
  );
}

export function verifyProof(
  terminalPub: KeyObject,
  id: string,
  sigs: string[],
  ts: number,
  sig: string,
): boolean {
  try {
    return edVerify(
      null,
      Buffer.from(proofMessage(id, sigs, ts), "utf8"),
      terminalPub,
      Buffer.from(sig, "base64url"),
    );
  } catch {
    return false;
  }
}

export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

export function newId(): string {
  return randomUUID();
}
