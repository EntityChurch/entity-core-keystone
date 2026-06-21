/**
 * Shortest-form IEEE-754 float encoding — ECF Rule 4 (shortest encoding
 * preserving value) + Rule 4a (canonical special values). This is the one
 * canonical obligation no CBOR library performs on both sides: smallest-float on
 * encode AND minimality validation on decode (eval risk R1/R3). Hand-rolled and
 * pure-JS — no `Float16Array` dependency, so it runs on every target.
 *
 * Strategy (matches the Go/Rust/C reference impls' `encode_float`): f16 ⊂ f32 ⊂
 * f64. A value uses the narrowest width that round-trips it EXACTLY. Exactness is
 * proven by decoding the candidate bits back and comparing — so the half-float
 * narrowing only needs truncation, not correct rounding: a non-exact candidate
 * fails the round-trip and falls through to the wider width.
 */

const NAN_BYTES = Uint8Array.of(0xf9, 0x7e, 0x00); // canonical quiet NaN
const POS_INF = Uint8Array.of(0xf9, 0x7c, 0x00);
const NEG_INF = Uint8Array.of(0xf9, 0xfc, 0x00);
const POS_ZERO = Uint8Array.of(0xf9, 0x00, 0x00);
const NEG_ZERO = Uint8Array.of(0xf9, 0x80, 0x00);

const f32View = new DataView(new ArrayBuffer(4));
const f64View = new DataView(new ArrayBuffer(8));

/** Encode a finite/special double as the shortest canonical CBOR float bytes. */
export function encodeFloatBytes(value: number): Uint8Array {
  if (Number.isNaN(value)) {
    return NAN_BYTES;
  }
  if (value === Infinity) {
    return POS_INF;
  }
  if (value === -Infinity) {
    return NEG_INF;
  }
  if (value === 0) {
    return Object.is(value, -0) ? NEG_ZERO : POS_ZERO;
  }

  // Finite, nonzero. f16 ⊂ f32 ⊂ f64 — test f32-exactness first.
  if (Math.fround(value) === value) {
    const half = floatToHalfBits(value);
    if (halfBitsToFloat(half) === value) {
      return Uint8Array.of(0xf9, (half >> 8) & 0xff, half & 0xff);
    }
    f32View.setFloat32(0, value);
    return Uint8Array.of(0xfa, f32View.getUint8(0), f32View.getUint8(1), f32View.getUint8(2), f32View.getUint8(3));
  }

  f64View.setFloat64(0, value);
  const out = new Uint8Array(9);
  out[0] = 0xfb;
  for (let i = 0; i < 8; i++) {
    out[i + 1] = f64View.getUint8(i);
  }
  return out;
}

/**
 * Narrow an f32-exact value to a candidate half-float bit pattern by truncation.
 * Correctness of the *shortest-exact* rule comes from the caller's round-trip
 * equality check, not from rounding here.
 */
export function floatToHalfBits(value: number): number {
  f32View.setFloat32(0, value);
  const x = f32View.getUint32(0);
  const sign = (x >>> 16) & 0x8000;
  const exp = (x >>> 23) & 0xff; // bias 127
  const mant = x & 0x7fffff; // 23-bit

  if (exp === 0) {
    return sign; // f32 subnormal — far below f16 range; round-trip rejects
  }

  const e = exp - 127 + 15; // rebias to f16 (bias 15)
  if (e >= 0x1f) {
    return sign | 0x7c00; // overflow → inf; round-trip rejects a finite value
  }
  if (e <= 0) {
    if (e < -10) {
      return sign; // underflow → zero; round-trip rejects a nonzero value
    }
    const m = mant | 0x800000; // restore implicit leading 1
    return sign | (m >> (14 - e));
  }
  return sign | (e << 10) | (mant >> 13);
}

/** Decode a half-float bit pattern to an exact double. */
export function halfBitsToFloat(bits: number): number {
  const sign = bits & 0x8000 ? -1 : 1;
  const exp = (bits >> 10) & 0x1f;
  const mant = bits & 0x3ff;
  if (exp === 0) {
    return sign * mant * 2 ** -24; // subnormal
  }
  if (exp === 0x1f) {
    return mant ? NaN : sign * Infinity;
  }
  return sign * (1 + mant / 1024) * 2 ** (exp - 15);
}
