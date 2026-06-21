import { test } from "node:test";
import assert from "node:assert/strict";
import { encode, decode } from "../src/codec/canonical-cbor.js";
import { ecfInt, ecfIntValue, ecfMap, ecfText, type EcfValue } from "../src/codec/ecf-value.js";
import { fromHex, toHex } from "../src/codec/bytes.js";

/**
 * F7 boundary vectors — AUTHORED HERE, not by the oracle.
 *
 * The conformance corpus tops out at i64::MAX (`int.10`, 0x7fff…ffff) with NO
 * probes in `[2⁶³, 2⁶⁴−1]`. So the oracle CANNOT catch a u64 bug above i64::MAX —
 * and TS is the peer most exposed to it, because a `number`-based integer surface
 * silently corrupts everything past 2⁵³ (R1). These vectors are our only guard
 * over that range; they exercise the `bigint` value model end-to-end (encode +
 * strict round-trip). Escalated to arch as F7 (add the corpus probes).
 *
 * Canonical bytes are hand-derived from RFC 8949 §3 (major type 0/1, minimal
 * 8-byte argument). `2⁶³` (0x8000000000000000) is THE critical case — one past
 * i64::MAX, where a signed-64 codec sign-flips.
 */

interface Boundary {
  readonly name: string;
  readonly value: bigint;
  readonly hex: string;
}

const UINT_BOUNDARIES: Boundary[] = [
  { name: "2^53-1 (Number.MAX_SAFE_INTEGER)", value: (1n << 53n) - 1n, hex: "1b001fffffffffffff" },
  { name: "2^53 (first lossy as number)", value: 1n << 53n, hex: "1b0020000000000000" },
  { name: "2^63-1 (i64::MAX, last corpus-covered)", value: (1n << 63n) - 1n, hex: "1b7fffffffffffffff" },
  { name: "2^63 (FIRST past i64::MAX — the F7 gap)", value: 1n << 63n, hex: "1b8000000000000000" },
  { name: "2^64-1 (u64::MAX)", value: (1n << 64n) - 1n, hex: "1bffffffffffffffff" },
];

// Negative analogs (major type 1, argument = -1 - value).
const NINT_BOUNDARIES: Boundary[] = [
  { name: "-(2^63) (i64::MIN)", value: -(1n << 63n), hex: "3b7fffffffffffffff" },
  { name: "-(2^63)-1 (one past i64::MIN)", value: -(1n << 63n) - 1n, hex: "3b8000000000000000" },
  { name: "-(2^64) (most-negative CBOR int)", value: -(1n << 64n), hex: "3bffffffffffffffff" },
];

for (const b of [...UINT_BOUNDARIES, ...NINT_BOUNDARIES]) {
  test(`F7 encode: ${b.name}`, () => {
    const got = toHex(encode(ecfInt(b.value)));
    assert.equal(got, b.hex, `encode(${b.value})`);
  });

  test(`F7 round-trip: ${b.name}`, () => {
    const decoded = decode(fromHex(b.hex));
    assert.equal(decoded.kind, "int");
    assert.equal(decoded.kind === "int" ? ecfIntValue(decoded) : 0n, b.value);
  });

  test(`F7 in-map (the real codec path): ${b.name}`, () => {
    const map: EcfValue = ecfMap([[ecfText("v"), ecfInt(b.value)]]);
    const round = decode(encode(map));
    assert.equal(round.kind, "map");
    if (round.kind === "map") {
      const v = round.pairs[0]![1];
      assert.equal(v.kind === "int" ? ecfIntValue(v) : 0n, b.value);
    }
  });
}

test("F7: 2^63 is NOT i64::MIN under a naive cast (the bug this guards)", () => {
  // A signed-64 codec would read 0x8000000000000000 as -2^63. We must read +2^63.
  const decoded = decode(fromHex("1b8000000000000000"));
  assert.equal(decoded.kind === "int" ? ecfIntValue(decoded) : 0n, 1n << 63n);
  assert.notEqual(decoded.kind === "int" ? ecfIntValue(decoded) : 0n, -(1n << 63n));
});
