import { ed25519 } from "@noble/curves/ed25519.js";
import { ed448 } from "@noble/curves/ed448.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import type { CryptoProvider, HashFunction, SignatureScheme } from "./provider.js";

/**
 * The default, BROWSER-PORTABLE crypto provider, over `@noble/curves` +
 * `@noble/hashes` (pure-JS, audited, raw-key API, zero transitive deps). One
 * `@noble/curves` package covers both Ed25519 (floor) and Ed448 (agility) — the
 * seam is a single dependency here (vs C#'s NSec + BouncyCastle). Profile A-001:
 * chosen for browser portability (the consumable-data-library use case);
 * `node:crypto` (Node-only, zero-dep) is the documented alternative behind the
 * same {@link CryptoProvider} seam.
 *
 * Note the `@noble/curves` v2 argument order: `sign(message, secretKey)` and
 * `verify(signature, message, publicKey)`.
 */

function edScheme(
  curve: typeof ed25519,
  name: string,
  seedLength: number,
  publicKeyLength: number,
  signatureLength: number,
): SignatureScheme {
  return {
    name,
    seedLength,
    publicKeyLength,
    signatureLength,
    sign: (seed, message) => curve.sign(message, seed),
    verify: (publicKey, message, signature) => curve.verify(signature, message, publicKey),
    publicKeyFromSeed: (seed) => curve.getPublicKey(seed),
  };
}

function hashFn(name: string, digestLength: number, fn: (d: Uint8Array) => Uint8Array): HashFunction {
  return { name, digestLength, digest: fn };
}

export const nobleProvider: CryptoProvider = {
  ed25519: edScheme(ed25519, "ed25519", 32, 32, 64),
  ed448: edScheme(ed448 as unknown as typeof ed25519, "ed448", 57, 57, 114),
  sha256: hashFn("sha256", 32, sha256),
  sha384: hashFn("sha384", 48, sha384),
  sha512: hashFn("sha512", 64, sha512),
};
