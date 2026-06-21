import { concatBytes, toHex } from "./bytes.js";
import { encode } from "./canonical-cbor.js";
import { ecfPreEncoded, ecfText, ecfMap } from "./ecf-value.js";
import { encodeLeb128 } from "./leb128.js";
import { formatPeerId, parsePeerId, type PeerId } from "./peer-id.js";
import { defaultProvider, type CryptoProvider } from "../crypto/index.js";

/**
 * The Entity Core codec surface: canonical entity encoding, content hashing,
 * peer-id format/parse, and Ed25519 sign/verify. Native, browser-portable
 * (hand-rolled canonical CBOR + `@noble`). The default `0x00`/SHA-256 + Ed25519
 * floor is byte-identical to the conformance corpus; agility families dispatch
 * through the crypto registries (`crypto/index`).
 */

const CONTENT_HASH_DIGEST_LENGTH = 32;

/**
 * Encode an entity (`{data, type}`) to canonical ECF bytes. `canonicalData` is
 * the already-canonical CBOR encoding of the entity's `data` field; it is spliced
 * verbatim (N4 fidelity — never decoded and re-encoded). Map-key order is fixed:
 * "data" and "type" are both length-4, so lexicographic → data before type.
 */
export function encodeEntity(type: string, canonicalData: Uint8Array): Uint8Array {
  return encode(
    ecfMap([
      [ecfText("data"), ecfPreEncoded(canonicalData)],
      [ecfText("type"), ecfText(type)],
    ]),
  );
}

/**
 * The codec-primitive content hash: `LEB128(formatCode) ‖ SHA256(ECF({data,
 * type}))`. The format code contributes only the varint prefix, never the hashed
 * body — so synthetic codes (e.g. the `content_hash.4` `format_code=128`
 * varint-width probe) encode faithfully. Family-selecting format dispatch
 * (SHA-256 vs SHA-384, reject-unknown) is an entity-layer concern (S3), via
 * `crypto/index hashFormatToFunction`.
 */
export function contentHash(
  type: string,
  canonicalData: Uint8Array,
  formatCode = 0n,
  provider: CryptoProvider = defaultProvider,
): Uint8Array {
  const body = encodeEntity(type, canonicalData);
  const digest = provider.sha256.digest(body);
  return concatBytes(encodeLeb128(formatCode), digest.subarray(0, CONTENT_HASH_DIGEST_LENGTH));
}

/** The display form of a content hash: `ecfv1-sha256:<64 hex>` (never on the wire). */
export function contentHashString(digest: Uint8Array): string {
  return `ecfv1-sha256:${toHex(digest)}`;
}

/**
 * Ed25519-sign a message with a 32-byte seed (raw private key), returning the
 * 64-byte detached signature. Ed25519 is deterministic (RFC 8032).
 */
export function sign(seed: Uint8Array, message: Uint8Array, provider: CryptoProvider = defaultProvider): Uint8Array {
  return provider.ed25519.sign(seed, message);
}

/** Verify a 64-byte Ed25519 signature over `message` against a 32-byte raw public key. */
export function verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  provider: CryptoProvider = defaultProvider,
): boolean {
  return provider.ed25519.verify(publicKey, message, signature);
}

/** Derive the 32-byte raw Ed25519 public key from a 32-byte seed. */
export function publicKeyFromSeed(seed: Uint8Array, provider: CryptoProvider = defaultProvider): Uint8Array {
  return provider.ed25519.publicKeyFromSeed(seed);
}

export { formatPeerId, parsePeerId, type PeerId };
