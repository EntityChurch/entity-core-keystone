import { ByteWriter } from "./bytes.js";
import { EntityCodecError } from "../errors.js";

/**
 * Unsigned LEB128 varint (conformance-invariant N1). Every format-code /
 * key-type / hash-type framing routes through this primitive — never a fixed
 * byte — so synthetic codes ≥ 0x80 widen correctly (forward-compat; the
 * `content_hash.4` / `peer_id.3` corpus probes).
 *
 * `bigint` end-to-end: the surface carries u64 values, which exceed `number`'s
 * 2⁵³ exact-integer ceiling (R1). A `number`-based varint would silently corrupt
 * large codes.
 */

const MASK = 0x7fn;
const CONT = 0x80n;
const U64_MAX = (1n << 64n) - 1n;

/** Encode an unsigned (0 ≤ value ≤ 2⁶⁴−1) value as LEB128. */
export function encodeLeb128(value: bigint): Uint8Array {
  if (value < 0n || value > U64_MAX) {
    throw new EntityCodecError(`LEB128 value out of u64 range: ${value}`);
  }
  const writer = new ByteWriter(10);
  let v = value;
  do {
    let byte = v & MASK;
    v >>= 7n;
    if (v !== 0n) {
      byte |= CONT;
    }
    writer.pushByte(Number(byte));
  } while (v !== 0n);
  return writer.toBytes();
}

/** Result of a LEB128 decode: the value plus the offset just past it. */
export interface Leb128Decoded {
  readonly value: bigint;
  readonly nextOffset: number;
}

/**
 * Decode a LEB128 value starting at `offset`. Throws on truncation or a value
 * exceeding 64 bits.
 */
export function decodeLeb128(input: Uint8Array, offset: number): Leb128Decoded {
  let result = 0n;
  let shift = 0n;
  let pos = offset;
  while (pos < input.length) {
    if (shift >= 64n) {
      throw new EntityCodecError("LEB128 overflow (exceeds 64 bits)");
    }
    const byte = BigInt(input[pos]!);
    pos += 1;
    result |= (byte & MASK) << shift;
    if ((byte & CONT) === 0n) {
      if (result > U64_MAX) {
        throw new EntityCodecError("LEB128 overflow (exceeds 64 bits)");
      }
      return { value: result, nextOffset: pos };
    }
    shift += 7n;
  }
  throw new EntityCodecError("truncated LEB128");
}
