import { test } from "node:test";
import assert from "node:assert/strict";
import { encode, decode } from "../src/codec/canonical-cbor.js";
import {
  ecfArray,
  ecfBool,
  ecfBytes,
  ecfFloat,
  ecfInt,
  ecfMap,
  ecfNull,
  ecfText,
} from "../src/codec/ecf-value.js";
import { encodeLeb128, decodeLeb128 } from "../src/codec/leb128.js";
import { base58Encode, base58Decode } from "../src/codec/base58.js";
import { encodeFloatBytes } from "../src/codec/float.js";
import { fromHex, toHex, bytesEqual } from "../src/codec/bytes.js";
import { EntityCodecError } from "../src/errors.js";

// ── LEB128 (N1) — the format-code/key-type varint surface ──
test("leb128: minimal + multi-byte (the ≥0x80 forward-compat probe)", () => {
  assert.equal(toHex(encodeLeb128(0n)), "00");
  assert.equal(toHex(encodeLeb128(1n)), "01");
  assert.equal(toHex(encodeLeb128(127n)), "7f");
  assert.equal(toHex(encodeLeb128(128n)), "8001"); // content_hash.4 / peer_id.3 width probe
  assert.equal(toHex(encodeLeb128(255n)), "ff01");
  assert.equal(toHex(encodeLeb128((1n << 64n) - 1n)), "ffffffffffffffffff01");
});

test("leb128: decode round-trip + overflow/truncation reject", () => {
  for (const v of [0n, 1n, 127n, 128n, 255n, 16384n, (1n << 63n) + 1n, (1n << 64n) - 1n]) {
    const d = decodeLeb128(encodeLeb128(v), 0);
    assert.equal(d.value, v);
  }
  assert.throws(() => decodeLeb128(fromHex("ffffffffffffffffff02"), 0), EntityCodecError); // > u64
  assert.throws(() => decodeLeb128(fromHex("80"), 0), EntityCodecError); // truncated
});

// ── Base58 (peer-id) ──
test("base58: round-trips + leading-zero preservation", () => {
  for (const hex of ["00", "0000ab", "deadbeef", "01020304", "ffffffff"]) {
    const bytes = fromHex(hex);
    assert.ok(bytesEqual(base58Decode(base58Encode(bytes)), bytes), hex);
  }
  assert.throws(() => base58Decode("0OIl"), EntityCodecError); // invalid alphabet chars
});

// ── float (Rule 4 / 4a) ──
test("float: Rule 4a specials are exact bytes", () => {
  assert.equal(toHex(encodeFloatBytes(NaN)), "f97e00");
  assert.equal(toHex(encodeFloatBytes(Infinity)), "f97c00");
  assert.equal(toHex(encodeFloatBytes(-Infinity)), "f9fc00");
  assert.equal(toHex(encodeFloatBytes(0)), "f90000");
  assert.equal(toHex(encodeFloatBytes(-0)), "f98000");
});

test("float: shortest-width selection f16/f32/f64", () => {
  assert.equal(toHex(encodeFloatBytes(1.0)), "f93c00");
  assert.equal(toHex(encodeFloatBytes(1.5)), "f93e00");
  assert.equal(toHex(encodeFloatBytes(32768.0)), "f97800"); // 2^15, still f16
  assert.equal(toHex(encodeFloatBytes(65504.0)), "f97bff"); // max normal f16
  assert.equal(toHex(encodeFloatBytes(65503.0)), "fa477fdf00"); // not f16 → f32
  assert.equal(toHex(encodeFloatBytes(100000.0)), "fa47c35000"); // f32
  assert.equal(toHex(encodeFloatBytes(1.1)), "fb3ff199999999999a"); // f64
});

test("float: decode rejects a non-minimal (f64-encoded f16 value) — R3", () => {
  // 1.0 as float64 (fb 3ff0000000000000) is non-canonical; shortest is f9 3c00.
  assert.throws(() => decode(fromHex("fb3ff0000000000000")), EntityCodecError);
  // non-canonical NaN payload must also reject.
  assert.throws(() => decode(fromHex("f97e01")), EntityCodecError);
});

// ── tag rejection (N2 / §6.3) ──
test("decode: rejects CBOR tags anywhere (N2)", () => {
  assert.throws(() => decode(fromHex("c100")), EntityCodecError); // tag 1 over a uint
  assert.throws(() => decode(fromHex("d9d9f7a0")), EntityCodecError); // tag 55799 over a map
  // tag nested inside a map value
  assert.throws(() => decode(fromHex("a16178c101")), EntityCodecError); // {"x": 1(1)}
});

// ── strict canonical decode rejections ──
test("decode: rejects non-minimal int, indefinite, undefined, trailing, duplicate keys", () => {
  assert.throws(() => decode(fromHex("1817")), EntityCodecError); // 24-as-1-byte (non-minimal)
  assert.throws(() => decode(fromHex("9f01ff")), EntityCodecError); // indefinite array
  assert.throws(() => decode(fromHex("f7")), EntityCodecError); // undefined
  assert.throws(() => decode(fromHex("0000")), EntityCodecError); // trailing byte
  assert.throws(() => decode(fromHex("a2616101616102")), EntityCodecError); // {"a":1,"a":2} dup
});

// ── encode: map key ordering (Rule 2) + round-trip of mixed values ──
test("encode: length-first then lexicographic key sort", () => {
  // {"z":1,"a":2,"bb":3,"aaa":4} → a, z, bb, aaa
  const m = ecfMap([
    [ecfText("z"), ecfInt(1n)],
    [ecfText("a"), ecfInt(2n)],
    [ecfText("bb"), ecfInt(3n)],
    [ecfText("aaa"), ecfInt(4n)],
  ]);
  assert.equal(toHex(encode(m)), "a4616102617a01626262036361616104");
});

test("encode/decode: round-trips a mixed nested structure", () => {
  const v = ecfMap([
    [ecfText("arr"), ecfArray([ecfInt(1n), ecfInt(-1n), ecfBool(true), ecfNull(), ecfFloat(1.5)])],
    [ecfText("b"), ecfBytes(fromHex("deadbeef"))],
    [ecfText("s"), ecfText("hello 世界")],
  ]);
  const round = decode(encode(v));
  assert.ok(bytesEqual(encode(round), encode(v)), "re-encode is byte-stable");
});
