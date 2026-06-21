import { bytesEqual, toHex } from "../codec/bytes.js";

/**
 * Helpers for `system/hash` values (V7 §1.2): a flat byte string of a
 * multicodec-style varint format code followed by the digest. For ECFv1-SHA-256
 * (the only format this peer emits) that is the single byte `0x00` followed by a
 * 32-byte SHA-256 digest — 33 bytes total.
 */

/** Length of an ECFv1-SHA-256 content hash: `0x00` + 32-byte digest. */
export const CONTENT_HASH_LENGTH = 33;

/**
 * The reserved zero hash — 33 all-zero bytes. Never a valid content hash, so it
 * is unambiguous as a sentinel (CAS-create marker §3.9; rejected as a cap
 * grantee §3.6 / §5.5).
 */
export function zeroHash(): Uint8Array {
  return new Uint8Array(CONTENT_HASH_LENGTH);
}

/** Byte-wise equality over the full hash bytes, format code included (§5.3). */
export function hashEqual(a: Uint8Array, b: Uint8Array): boolean {
  return bytesEqual(a, b);
}

export function isZeroHash(hash: Uint8Array): boolean {
  for (const b of hash) {
    if (b !== 0) {
      return false;
    }
  }
  return true;
}

/**
 * Lowercase hex of the full hash bytes (format code included) — the
 * invariant-pointer path encoding (§3.5) and the key for in-memory maps.
 */
export function hashHex(hash: Uint8Array): string {
  return toHex(hash);
}
