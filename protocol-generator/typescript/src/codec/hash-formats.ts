import { concatBytes } from "./bytes.js";
import { decodeLeb128, encodeLeb128 } from "./leb128.js";
import { hashFormatToFunction } from "../crypto/index.js";
import { type CryptoProvider, defaultProvider } from "../crypto/index.js";
import { EntityCodecError } from "../errors.js";

/**
 * The `content_hash_format` registry (V7 §1.2). A content hash is a flat byte
 * string: a LEB128 varint *format code* followed by the digest the code names.
 * The format code is intrinsic to the hash ("interpretation", not "routing" —
 * v7.68 §1.2 reframe): byte-equality is over the full hash, format code included
 * (§5.3).
 *
 * This is the hash half of the crypto-agility seam (RESYNC v7.56→v7.70 §3).
 * Adding a hash family is a registry entry, not a rewrite. The conformance floor
 * (§9.1) is SHA-256 (`0x00`); SHA-384 (`0x01`) is validated, not required — so a
 * default Ed25519+SHA-256 peer never leaves the `0x00` path and stays
 * byte-identical to the S2 codec. Dispatch itself lives in `crypto/index`
 * ({@link hashFormatToFunction}); this module adds the protocol framing.
 */

/** ECFv1 SHA-256 — production / §9.1 floor. */
export const SHA256_FORMAT = 0x00n;

/** ECFv1 SHA-384 — validated (v7.67), not required. */
export const SHA384_FORMAT = 0x01n;

/** Reserved per §1.2 — never a valid format code. */
export const RESERVED_FORMAT = 0xffn;

/**
 * The hash-format names this peer accepts, for the §4.5 `hello.hash_formats`
 * advertisement. SHA-256 (the §9.1 floor) leads; SHA-384 is the validated
 * agility family.
 */
export const SUPPORTED_HASH_FORMAT_NAMES: readonly string[] = ["ecfv1-sha256", "ecfv1-sha384"];

/** True if `code` names a hash family this peer can interpret. */
export function isSupportedHashFormat(code: bigint): boolean {
  return code === SHA256_FORMAT || code === SHA384_FORMAT;
}

/** Negotiation name for a supported format code (inverse of the advertisement). */
export function hashFormatName(code: bigint): string {
  switch (code) {
    case SHA256_FORMAT:
      return "ecfv1-sha256";
    case SHA384_FORMAT:
      return "ecfv1-sha384";
    default:
      throw new EntityCodecError(`unsupported_content_hash_format: 0x${code.toString(16)}`);
  }
}

/**
 * Build a wire content hash: `LEB128(code) ‖ digest(code, ecfBytes)`. For the
 * default SHA-256 format this is `0x00 ‖ SHA256(ecfBytes)` — 33 bytes,
 * byte-identical to the S2 codec.
 */
export function contentHashForFormat(
  code: bigint,
  ecfBytes: Uint8Array,
  provider: CryptoProvider = defaultProvider,
): Uint8Array {
  const fn = hashFormatToFunction(code, provider);
  if (fn === undefined) {
    throw new EntityCodecError(`unsupported_content_hash_format: 0x${code.toString(16)}`);
  }
  return concatBytes(encodeLeb128(code), fn.digest(ecfBytes));
}

/**
 * Read the leading format-code varint of a wire content hash. Surfaces the
 * multi-byte LEB128 path (the `VARINT-MULTIBYTE-1` agility probe) and the
 * unsupported/reserved rejections (`unsupported_content_hash_format`).
 */
export function readFormatCode(contentHash: Uint8Array): bigint {
  return decodeLeb128(contentHash, 0).value;
}
