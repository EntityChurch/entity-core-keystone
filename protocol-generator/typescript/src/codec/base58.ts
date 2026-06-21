import { EntityCodecError } from "../errors.js";

/**
 * Base58 with the Bitcoin alphabet (V7 §8.5). Hand-rolled rather than taking an
 * npm dependency: the algorithm is ~80 lines, pure-JS/browser-safe, and it
 * dodges a supply-chain pin (S11) for a primitive. Used by peer-id format/parse.
 * (Profile `base58_library = "hand-rolled"`; alt `@scure/base` documented.)
 */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const REVERSE: Int8Array = (() => {
  const map = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    map[ALPHABET.charCodeAt(i)] = i;
  }
  return map;
})();

/** Encode bytes (big-endian) to a Base58 string. */
export function base58Encode(input: Uint8Array): string {
  if (input.length === 0) {
    return "";
  }

  // Leading zero bytes each map to a leading '1'.
  let leadingZeros = 0;
  while (leadingZeros < input.length && input[leadingZeros] === 0) {
    leadingZeros++;
  }

  // base-256 → base-58 by repeated division of a big-endian work buffer.
  const digits = new Uint8Array(Math.floor((input.length * 138) / 100) + 1); // ceil(log256/log58)
  let digitCount = 0;
  for (let i = leadingZeros; i < input.length; i++) {
    let carry = input[i]!;
    let j = 0;
    for (let k = digits.length - 1; (carry !== 0 || j < digitCount) && k >= 0; k--, j++) {
      carry += 256 * digits[k]!;
      digits[k] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    digitCount = j;
  }

  // Skip leading zeros in the base-58 buffer.
  let start = digits.length - digitCount;
  while (start < digits.length && digits[start] === 0) {
    start++;
  }

  let out = "1".repeat(leadingZeros);
  for (let i = start; i < digits.length; i++) {
    out += ALPHABET[digits[i]!];
  }
  return out;
}

/** Decode a Base58 string to bytes. Throws on an invalid character. */
export function base58Decode(input: string): Uint8Array {
  if (input.length === 0) {
    return new Uint8Array(0);
  }

  let leadingOnes = 0;
  while (leadingOnes < input.length && input[leadingOnes] === "1") {
    leadingOnes++;
  }

  const bytes = new Uint8Array(Math.floor((input.length * 733) / 1000) + 1); // ceil(log58/log256)
  let byteCount = 0;
  for (let c = 0; c < input.length; c++) {
    const code = input.charCodeAt(c);
    const value = code < 128 ? REVERSE[code]! : -1;
    if (value < 0) {
      throw new EntityCodecError(`invalid Base58 character '${input[c]}'`);
    }
    let carry = value;
    let j = 0;
    for (let k = bytes.length - 1; (carry !== 0 || j < byteCount) && k >= 0; k--, j++) {
      carry += 58 * bytes[k]!;
      bytes[k] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    byteCount = j;
  }

  let start = bytes.length - byteCount;
  while (start < bytes.length && bytes[start] === 0) {
    start++;
  }

  // Leading '1's are leading zero bytes; result is zero-filled there already.
  const out = new Uint8Array(leadingOnes + (bytes.length - start));
  for (let i = start, w = leadingOnes; i < bytes.length; i++, w++) {
    out[w] = bytes[i]!;
  }
  return out;
}
