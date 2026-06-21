/**
 * The crypto-agility seam (the C# `IKeyAlgorithm`-registry analogue). The
 * protocol talks to these interfaces, never to a concrete library — so the
 * provider is swappable (`@noble` default ↔ `node:crypto` alt, A-001) without
 * touching the codec or peer, and agility families (Ed448, SHA-384/512) are
 * registry entries rather than special cases.
 *
 * Everything here is pure-interface; the default implementation
 * ({@link ./noble-provider}) is browser-portable.
 */

/** A digital-signature scheme over raw keys (no DER ceremony). */
export interface SignatureScheme {
  /** Registry name, e.g. "ed25519" / "ed448". */
  readonly name: string;
  /** Raw private-key (seed) length in bytes. */
  readonly seedLength: number;
  /** Raw public-key length in bytes. */
  readonly publicKeyLength: number;
  /** Detached-signature length in bytes. */
  readonly signatureLength: number;
  /** Sign `message` with a raw seed, returning the detached signature. */
  sign(seed: Uint8Array, message: Uint8Array): Uint8Array;
  /** Verify a detached signature against a raw public key. */
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
  /** Derive the raw public key from a raw seed. */
  publicKeyFromSeed(seed: Uint8Array): Uint8Array;
}

/** A cryptographic hash function. */
export interface HashFunction {
  readonly name: string;
  readonly digestLength: number;
  digest(data: Uint8Array): Uint8Array;
}

/**
 * The pluggable crypto backend. A provider supplies the floor (Ed25519 +
 * SHA-256) plus the agility families it can serve.
 */
export interface CryptoProvider {
  readonly ed25519: SignatureScheme;
  readonly ed448: SignatureScheme;
  readonly sha256: HashFunction;
  readonly sha384: HashFunction;
  readonly sha512: HashFunction;
}
