import {
  generateKeyPairSync,
  diffieHellman,
  createPublicKey,
  createPrivateKey,
  hkdfSync,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  type KeyObject,
} from "node:crypto";

/**
 * Sealed holder credentials (defense-in-depth for `serializeWithKey`).
 *
 * A holder credential is a secret; binding it to an agent identity (`bindAgent`)
 * already makes a *stolen* credential inert, but the credential itself is still
 * sensitive in transit/at rest. Sealing encrypts it to a specific recipient so
 * only the holder of the matching private key can open it.
 *
 * Scheme `seal-1` — a standard ECIES construction over primitives available
 * natively in Node and, in Python, via the `cryptography` backend, so a
 * credential sealed in one port can be opened in the other:
 *
 *   1. ephemeral X25519 keypair `e`
 *   2. shared = X25519(e_priv, recipient_pub)
 *   3. key = HKDF-SHA256(ikm=shared, salt=e_pub‖recipient_pub, info="behalf-seal-v1", 32)
 *   4. ct‖tag = AES-256-GCM(key, nonce=random12, aad="behalf-seal-v1", plaintext)
 *   5. wire = base64url(JSON { v:"seal-1", epk, n, ct })   (ct carries the tag)
 *
 * The recipient's sealing key is an **X25519** keypair, separate from the
 * Ed25519 agent-identity key used by `bindAgent` (different algorithms, different
 * purposes). Generate one with {@link newSealKeyPair} and publish `publicKey`.
 */

const INFO = Buffer.from("behalf-seal-v1");
const AAD = Buffer.from("behalf-seal-v1");

/** An X25519 keypair for sealing, as base64url raw 32-byte keys. */
export interface SealKeyPair {
  publicKey: string;
  privateKey: string;
}

function rawPublic(key: KeyObject): Buffer {
  const jwk = key.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new Error("not an X25519 public key");
  return Buffer.from(jwk.x, "base64url");
}

function importPublic(rawB64: string): KeyObject {
  return createPublicKey({ key: { kty: "OKP", crv: "X25519", x: rawB64 }, format: "jwk" });
}

function importPrivate(kp: SealKeyPair): KeyObject {
  return createPrivateKey({
    key: { kty: "OKP", crv: "X25519", x: kp.publicKey, d: kp.privateKey },
    format: "jwk",
  });
}

/** Generate an X25519 sealing keypair (publish `publicKey`, keep `privateKey`). */
export function newSealKeyPair(): SealKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const pubJwk = publicKey.export({ format: "jwk" }) as { x?: string };
  const privJwk = privateKey.export({ format: "jwk" }) as { d?: string };
  return { publicKey: pubJwk.x!, privateKey: privJwk.d! };
}

/** Encrypt `plaintext` so only the holder of `recipientPublicKey`'s key can read it. */
export function seal(plaintext: string, recipientPublicKey: string): string {
  const recipientPub = importPublic(recipientPublicKey);
  const eph = generateKeyPairSync("x25519");
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
  const ephPubRaw = rawPublic(eph.publicKey);
  const salt = Buffer.concat([ephPubRaw, Buffer.from(recipientPublicKey, "base64url")]);
  const key = Buffer.from(hkdfSync("sha256", shared, salt, INFO, 32));
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(AAD);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const wire = {
    v: "seal-1",
    epk: ephPubRaw.toString("base64url"),
    n: nonce.toString("base64url"),
    ct: Buffer.concat([ct, tag]).toString("base64url"),
  };
  return Buffer.from(JSON.stringify(wire), "utf8").toString("base64url");
}

/** Decrypt a `seal-1` credential with the recipient's sealing keypair. */
export function unseal(sealed: string, recipient: SealKeyPair): string {
  let wire: { v?: string; epk?: string; n?: string; ct?: string };
  try {
    wire = JSON.parse(Buffer.from(sealed, "base64url").toString("utf8"));
  } catch {
    throw new Error("malformed sealed credential");
  }
  if (wire.v !== "seal-1" || !wire.epk || !wire.n || !wire.ct) {
    throw new Error("unsupported or malformed seal");
  }
  const ephPub = importPublic(wire.epk);
  const shared = diffieHellman({ privateKey: importPrivate(recipient), publicKey: ephPub });
  const salt = Buffer.concat([
    Buffer.from(wire.epk, "base64url"),
    Buffer.from(recipient.publicKey, "base64url"),
  ]);
  const key = Buffer.from(hkdfSync("sha256", shared, salt, INFO, 32));
  const data = Buffer.from(wire.ct, "base64url");
  const tag = data.subarray(data.length - 16);
  const ct = data.subarray(0, data.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(wire.n, "base64url"));
  decipher.setAAD(AAD);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}
