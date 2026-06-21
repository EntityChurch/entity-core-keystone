import { test } from "node:test";
import assert from "node:assert/strict";
import { encode as cborgEncode } from "cborg";
import { encode } from "../src/codec/canonical-cbor.js";
import {
  ecfArray,
  ecfBool,
  ecfBytes,
  ecfFloat,
  ecfInt,
  ecfMap,
  ecfNull,
  ecfText,
  type EcfValue,
} from "../src/codec/ecf-value.js";
import { fromHex, toHex } from "../src/codec/bytes.js";

/**
 * The cborg spike (A-005 evidence). The profile names `cborg` as the CBOR
 * library; A-005 records the decision to hand-roll the codec core instead and
 * keep cborg as this INDEPENDENT encode cross-check (a 5th corroborating ECF
 * producer alongside the cross-blessed Go/Rust/Py/C# corpus — extra S8 signal).
 *
 * Finding: cborg AGREES with the hand-rolled encoder on map-key ordering
 * (length-first then bytewise), minimal-int encoding, the full `bigint`/u64 range
 * (incl. the F7 2⁶³ boundary), byte/text strings, and non-integral floats. It
 * structurally CANNOT serve as the ECF float encoder, because JS `number` erases
 * the int-vs-float distinction (`Number.isInteger(1.0)` is true) — so cborg emits
 * integral-valued floats as CBOR integers. That ambiguity is exactly why the
 * value model carries an explicit `EcfFloat` node distinct from `EcfInt`.
 */

interface AgreePair {
  readonly name: string;
  readonly ecf: EcfValue;
  readonly js: unknown;
}

const AGREE: AgreePair[] = [
  { name: "uint 0", ecf: ecfInt(0n), js: 0n },
  { name: "uint 24", ecf: ecfInt(24n), js: 24n },
  { name: "uint 256", ecf: ecfInt(256n), js: 256n },
  { name: "uint 65536", ecf: ecfInt(65536n), js: 65536n },
  { name: "uint 2^63 (F7)", ecf: ecfInt(1n << 63n), js: 1n << 63n },
  { name: "uint 2^64-1 (u64 max)", ecf: ecfInt((1n << 64n) - 1n), js: (1n << 64n) - 1n },
  { name: "nint -1", ecf: ecfInt(-1n), js: -1n },
  { name: "nint -1000", ecf: ecfInt(-1000n), js: -1000n },
  { name: "text unicode", ecf: ecfText("hello 世界"), js: "hello 世界" },
  { name: "bytes", ecf: ecfBytes(fromHex("deadbeef")), js: fromHex("deadbeef") },
  { name: "bool true", ecf: ecfBool(true), js: true },
  { name: "null", ecf: ecfNull(), js: null },
  { name: "array", ecf: ecfArray([ecfInt(1n), ecfInt(2n), ecfInt(3n)]), js: [1n, 2n, 3n] },
  {
    name: "map (length-first key sort)",
    ecf: ecfMap([
      [ecfText("z"), ecfInt(1n)],
      [ecfText("a"), ecfInt(2n)],
      [ecfText("bb"), ecfInt(3n)],
      [ecfText("aaa"), ecfInt(4n)],
    ]),
    js: { z: 1n, a: 2n, bb: 3n, aaa: 4n },
  },
  {
    name: "nested map",
    ecf: ecfMap([[ecfText("outer"), ecfMap([[ecfText("inner"), ecfMap([[ecfText("deep"), ecfInt(1n)]])]])]]),
    js: { outer: { inner: { deep: 1n } } },
  },
  { name: "non-integral float 1.5", ecf: ecfFloat(1.5), js: 1.5 },
  { name: "non-integral float 1.1", ecf: ecfFloat(1.1), js: 1.1 },
];

for (const { name, ecf, js } of AGREE) {
  test(`cborg cross-check agrees: ${name}`, () => {
    const mine = toHex(encode(ecf));
    const theirs = toHex(cborgEncode(js));
    assert.equal(mine, theirs, `${name}: hand-rolled=${mine} cborg=${theirs}`);
  });
}

test("cborg cross-check: documented divergence on integral-valued floats", () => {
  // cborg sees `1.0` / `65504.0` as integers (JS number ambiguity) and emits
  // CBOR int — NOT the ECF float encoding. The hand-rolled codec, with an explicit
  // float node, produces the canonical shortest float (Rule 4). This is WHY the
  // value model exists and WHY the core is hand-rolled (A-005).
  assert.equal(toHex(cborgEncode(1.0)), "01"); // cborg → integer 1
  assert.equal(toHex(encode(ecfFloat(1.0))), "f93c00"); // ECF-correct float

  assert.equal(toHex(cborgEncode(65504.0)), "19ffe0"); // cborg → integer 65504
  assert.equal(toHex(encode(ecfFloat(65504.0))), "f97bff"); // ECF-correct float
});
