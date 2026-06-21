import { ByteWriter, toHex } from "./bytes.js";
import { EntityCodecError } from "../errors.js";
import { encodeFloatBytes, halfBitsToFloat } from "./float.js";
import {
  type EcfValue,
  ecfArray,
  ecfBool,
  ecfBytes,
  ecfFloat,
  ecfMap,
  ecfNull,
  ecfText,
} from "./ecf-value.js";

/**
 * The canonical-CBOR engine for ECF — hand-rolled, pure-JS, zero-dependency.
 * Encoding implements the §9.1 encoder requirements directly: minimal integer
 * arguments (Rule 1), length-then-lexicographic map-key ordering (Rule 2 / RFC
 * 8949 §4.2.1), definite lengths only (Rule 3), shortest-float (Rule 4/4a via
 * {@link encodeFloatBytes}), no duplicate keys (Rule 5), all fields preserved
 * (Rule 6 — the value model carries every pair, omit-empty is the caller's job).
 *
 * Decoding is strict canonical: it rejects CBOR tags anywhere (N2 / §6.3 — the
 * `400 non_canonical_ecf` path), indefinite lengths, non-minimal integer/length
 * arguments, non-minimal/non-canonical floats (R3), `undefined` and other simple
 * values, duplicate map keys, invalid UTF-8, and trailing bytes.
 *
 * The engine is deliberately hand-rolled rather than layered on `cborg` — see the
 * decision in `status/SPEC-AMBIGUITY-LOG.md` A-005: it gives full control over the
 * `bigint` integer surface (R1), the N4 verbatim-splice (no library raw-bytes
 * token exists), and decode-side minimality (R3); and it keeps the codec core a
 * zero-runtime-dependency, browser-portable module. `cborg` rides along as an
 * independent encode cross-check in the test suite (S8 convergence).
 */

const U64_MAX = (1n << 64n) - 1n;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

// ── encode ──

/** Encode a value tree to canonical ECF bytes. */
export function encode(value: EcfValue): Uint8Array {
  const writer = new ByteWriter();
  writeValue(writer, value);
  return writer.toBytes();
}

function writeValue(writer: ByteWriter, value: EcfValue): void {
  switch (value.kind) {
    case "int":
      writeTypeAndArgument(writer, value.negative ? 1 : 0, value.argument);
      return;
    case "float":
      writer.pushBytes(encodeFloatBytes(value.value));
      return;
    case "bytes":
      writeTypeAndArgument(writer, 2, BigInt(value.value.length));
      writer.pushBytes(value.value);
      return;
    case "text": {
      const utf8 = textEncoder.encode(value.value);
      writeTypeAndArgument(writer, 3, BigInt(utf8.length));
      writer.pushBytes(utf8);
      return;
    }
    case "array":
      writeTypeAndArgument(writer, 4, BigInt(value.items.length));
      for (const item of value.items) {
        writeValue(writer, item);
      }
      return;
    case "map":
      writeMap(writer, value.pairs);
      return;
    case "bool":
      writer.pushByte(value.value ? 0xf5 : 0xf4);
      return;
    case "null":
      writer.pushByte(0xf6);
      return;
    case "preEncoded":
      // Verbatim splice (N4 fidelity): forward opaque canonical bytes unchanged.
      writer.pushBytes(value.value);
      return;
  }
}

function writeMap(writer: ByteWriter, pairs: readonly (readonly [EcfValue, EcfValue])[]): void {
  // Sort by ENCODED key bytes: length-first, then bytewise (Rule 2 / §4.2.1).
  // Reject duplicate keys (Rule 5).
  const encoded = pairs.map(([key, val]) => ({ keyBytes: encode(key), val }));
  encoded.sort((a, b) => compareBytes(a.keyBytes, b.keyBytes));
  for (let i = 1; i < encoded.length; i++) {
    if (compareBytes(encoded[i - 1]!.keyBytes, encoded[i]!.keyBytes) === 0) {
      throw new EntityCodecError(`duplicate map key: ${toHex(encoded[i]!.keyBytes)}`);
    }
  }
  writeTypeAndArgument(writer, 5, BigInt(encoded.length));
  for (const { keyBytes, val } of encoded) {
    writer.pushBytes(keyBytes);
    writeValue(writer, val);
  }
}

/** Write a CBOR head: major type (0–7) + the minimal-length argument. */
function writeTypeAndArgument(writer: ByteWriter, majorType: number, argument: bigint): void {
  if (argument < 0n || argument > U64_MAX) {
    throw new EntityCodecError(`argument out of u64 range: ${argument}`);
  }
  const high = majorType << 5;
  if (argument < 24n) {
    writer.pushByte(high | Number(argument));
  } else if (argument <= 0xffn) {
    writer.pushByte(high | 24);
    writer.pushByte(Number(argument));
  } else if (argument <= 0xffffn) {
    writer.pushByte(high | 25);
    writeBigEndian(writer, argument, 2);
  } else if (argument <= 0xffffffffn) {
    writer.pushByte(high | 26);
    writeBigEndian(writer, argument, 4);
  } else {
    writer.pushByte(high | 27);
    writeBigEndian(writer, argument, 8);
  }
}

function writeBigEndian(writer: ByteWriter, value: bigint, byteCount: number): void {
  for (let i = byteCount - 1; i >= 0; i--) {
    writer.pushByte(Number((value >> BigInt(8 * i)) & 0xffn));
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    return a.length - b.length;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return a[i]! - b[i]!;
    }
  }
  return 0;
}

// ── decode (strict canonical) ──

interface Cursor {
  readonly buf: Uint8Array;
  pos: number;
}

/**
 * Strict canonical decode. Throws {@link EntityCodecError} on any tag, indefinite
 * length, non-canonical encoding, `undefined`/simple value, duplicate key,
 * invalid UTF-8, or trailing input.
 */
export function decode(bytes: Uint8Array): EcfValue {
  const cursor: Cursor = { buf: bytes, pos: 0 };
  const value = readValue(cursor);
  if (cursor.pos !== bytes.length) {
    throw new EntityCodecError(`trailing bytes after top-level item (${bytes.length - cursor.pos} extra)`);
  }
  return value;
}

function readByte(cursor: Cursor): number {
  if (cursor.pos >= cursor.buf.length) {
    throw new EntityCodecError("unexpected end of input");
  }
  return cursor.buf[cursor.pos++]!;
}

function readValue(cursor: Cursor): EcfValue {
  const ib = readByte(cursor);
  const majorType = ib >> 5;
  const ai = ib & 0x1f;

  switch (majorType) {
    case 0:
      return { kind: "int", negative: false, argument: readArgument(cursor, ai) };
    case 1:
      return { kind: "int", negative: true, argument: readArgument(cursor, ai) };
    case 2: {
      const len = Number(readArgument(cursor, ai));
      return ecfBytes(readChunk(cursor, len).slice());
    }
    case 3: {
      const len = Number(readArgument(cursor, ai));
      const raw = readChunk(cursor, len);
      try {
        return ecfText(textDecoder.decode(raw));
      } catch {
        throw new EntityCodecError("invalid UTF-8 in text string");
      }
    }
    case 4: {
      const count = Number(readArgument(cursor, ai));
      const items: EcfValue[] = [];
      for (let i = 0; i < count; i++) {
        items.push(readValue(cursor));
      }
      return ecfArray(items);
    }
    case 5:
      return readMap(cursor, Number(readArgument(cursor, ai)));
    case 6:
      // N2 / §6.3: CBOR major-type-6 tags are forbidden anywhere in ECF.
      throw new EntityCodecError("CBOR tag forbidden in ECF (non_canonical_ecf)");
    case 7:
      return readSimpleOrFloat(cursor, ai);
    default:
      throw new EntityCodecError(`unreachable major type ${majorType}`);
  }
}

/** Read a minimal-length argument for major types 0–5. */
function readArgument(cursor: Cursor, ai: number): bigint {
  if (ai < 24) {
    return BigInt(ai);
  }
  switch (ai) {
    case 24: {
      const v = BigInt(readByte(cursor));
      if (v < 24n) {
        throw new EntityCodecError("non-minimal integer (1-byte arg < 24)");
      }
      return v;
    }
    case 25: {
      const v = readBigEndian(cursor, 2);
      if (v <= 0xffn) {
        throw new EntityCodecError("non-minimal integer (2-byte arg ≤ 0xff)");
      }
      return v;
    }
    case 26: {
      const v = readBigEndian(cursor, 4);
      if (v <= 0xffffn) {
        throw new EntityCodecError("non-minimal integer (4-byte arg ≤ 0xffff)");
      }
      return v;
    }
    case 27: {
      const v = readBigEndian(cursor, 8);
      if (v <= 0xffffffffn) {
        throw new EntityCodecError("non-minimal integer (8-byte arg ≤ 0xffffffff)");
      }
      return v;
    }
    default:
      // 28, 29, 30 reserved; 31 indefinite — both forbidden in canonical ECF.
      throw new EntityCodecError(`non-canonical length encoding (additional info ${ai})`);
  }
}

function readBigEndian(cursor: Cursor, byteCount: number): bigint {
  let value = 0n;
  for (let i = 0; i < byteCount; i++) {
    value = (value << 8n) | BigInt(readByte(cursor));
  }
  return value;
}

function readChunk(cursor: Cursor, length: number): Uint8Array {
  if (length < 0 || cursor.pos + length > cursor.buf.length) {
    throw new EntityCodecError("string/bytes length exceeds input");
  }
  const chunk = cursor.buf.subarray(cursor.pos, cursor.pos + length);
  cursor.pos += length;
  return chunk;
}

function readMap(cursor: Cursor, count: number): EcfValue {
  const pairs: [EcfValue, EcfValue][] = [];
  const seen = new Set<string>();
  for (let i = 0; i < count; i++) {
    const keyStart = cursor.pos;
    const key = readValue(cursor);
    const keyHex = toHex(cursor.buf.subarray(keyStart, cursor.pos));
    if (seen.has(keyHex)) {
      throw new EntityCodecError("duplicate map key");
    }
    seen.add(keyHex);
    const val = readValue(cursor);
    pairs.push([key, val]);
  }
  return ecfMap(pairs);
}

function readSimpleOrFloat(cursor: Cursor, ai: number): EcfValue {
  switch (ai) {
    case 20:
      return ecfBool(false);
    case 21:
      return ecfBool(true);
    case 22:
      return ecfNull();
    case 25:
      return readFloat(cursor, 2);
    case 26:
      return readFloat(cursor, 4);
    case 27:
      return readFloat(cursor, 8);
    default:
      // 23 = undefined (SHOULD NOT use); 24 = 1-byte simple; <20 = small simple;
      // 31 = break. None are canonical ECF values.
      throw new EntityCodecError(`non-canonical simple value (additional info ${ai})`);
  }
}

function readFloat(cursor: Cursor, byteCount: number): EcfValue {
  const start = cursor.pos;
  let value: number;
  if (byteCount === 2) {
    value = halfBitsToFloat(Number(readBigEndian(cursor, 2)));
  } else if (byteCount === 4) {
    const view = new DataView(cursor.buf.buffer, cursor.buf.byteOffset + start, 4);
    cursor.pos += 4;
    value = view.getFloat32(0);
  } else {
    const view = new DataView(cursor.buf.buffer, cursor.buf.byteOffset + start, 8);
    cursor.pos += 8;
    value = view.getFloat64(0);
  }
  // R3: reject non-minimal / non-canonical floats — the canonical encoding of the
  // decoded value MUST reproduce the exact bytes read (also pins canonical NaN).
  const read = cursor.buf.subarray(start, cursor.pos);
  const canonical = encodeFloatBytes(value);
  // `read` is the payload after the 0xf9/fa/fb head; prepend it for comparison.
  if (canonical.length !== read.length + 1) {
    throw new EntityCodecError("non-minimal float encoding");
  }
  for (let i = 0; i < read.length; i++) {
    if (canonical[i + 1] !== read[i]) {
      throw new EntityCodecError("non-canonical float encoding");
    }
  }
  return ecfFloat(value);
}
