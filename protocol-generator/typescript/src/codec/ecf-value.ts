/**
 * In-memory model of a single ECF (Entity Canonical Form) data item — the value
 * tree the canonical codec encodes from and decodes into. A discriminated union
 * (profile `[idiom] prefer_discriminated_unions`), mirroring the reference impls'
 * value model (Go/Rust/C) and C# `EcfValue` so the canonical obligations N1–N4
 * map across languages.
 *
 * THE DEFINING DECISION (R1/F7): integers are `bigint`, in CBOR head form
 * `value = negative ? -1 - argument : argument`. `number` is IEEE-754 f64 — exact
 * only to 2⁵³−1 — and the protocol carries u64/i64. A `number`-based value model
 * silently corrupts anything above 2⁵³. Keeping the full unsigned-64 argument in
 * a `bigint` avoids that with no `Int128`-style hop.
 */

export type EcfValue =
  | EcfInt
  | EcfFloat
  | EcfBytes
  | EcfText
  | EcfArray
  | EcfMap
  | EcfBool
  | EcfNull
  | EcfPreEncoded;

/** A CBOR integer in head form: `value = negative ? -1 - argument : argument`. */
export interface EcfInt {
  readonly kind: "int";
  readonly negative: boolean;
  /** The CBOR head argument, 0 ≤ argument ≤ 2⁶⁴−1. */
  readonly argument: bigint;
}

/** A floating-point value. Encoded with shortest-form minimization (Rule 4). */
export interface EcfFloat {
  readonly kind: "float";
  readonly value: number;
}

/** A CBOR byte string (major type 2). */
export interface EcfBytes {
  readonly kind: "bytes";
  readonly value: Uint8Array;
}

/** A CBOR text string (major type 3), always valid UTF-8. */
export interface EcfText {
  readonly kind: "text";
  readonly value: string;
}

/** A CBOR array (major type 4). */
export interface EcfArray {
  readonly kind: "array";
  readonly items: readonly EcfValue[];
}

/** A CBOR map (major type 5). Key ordering is applied at encode time (Rule 2). */
export interface EcfMap {
  readonly kind: "map";
  readonly pairs: readonly (readonly [EcfValue, EcfValue])[];
}

/** A CBOR boolean (major type 7, simple values 0xF4/0xF5). */
export interface EcfBool {
  readonly kind: "bool";
  readonly value: boolean;
}

/** A CBOR null (major type 7, simple value 0xF6). */
export interface EcfNull {
  readonly kind: "null";
}

/**
 * Already-canonical CBOR bytes spliced verbatim at encode time. The N4 / R2
 * fidelity carrier: opaque entity `data` is forwarded byte-for-byte, never
 * decoded-and-re-encoded (which is not guaranteed byte-identical). The hash path
 * embeds entity data through this variant.
 */
export interface EcfPreEncoded {
  readonly kind: "preEncoded";
  readonly value: Uint8Array;
}

const U64_MAX = (1n << 64n) - 1n;

// ── constructors (terse, idiomatic call sites) ──

/** A CBOR integer from a signed `bigint`. Splits into head form. */
export function ecfInt(value: bigint): EcfInt {
  if (value >= 0n) {
    if (value > U64_MAX) {
      throw new RangeError(`uint exceeds 2⁶⁴−1: ${value}`);
    }
    return { kind: "int", negative: false, argument: value };
  }
  const argument = -1n - value; // value = -1 - argument
  if (argument > U64_MAX) {
    throw new RangeError(`nint exceeds −2⁶⁴: ${value}`);
  }
  return { kind: "int", negative: true, argument };
}

export function ecfFloat(value: number): EcfFloat {
  return { kind: "float", value };
}

export function ecfBytes(value: Uint8Array): EcfBytes {
  return { kind: "bytes", value };
}

export function ecfText(value: string): EcfText {
  return { kind: "text", value };
}

export function ecfArray(items: readonly EcfValue[]): EcfArray {
  return { kind: "array", items };
}

export function ecfMap(pairs: readonly (readonly [EcfValue, EcfValue])[]): EcfMap {
  return { kind: "map", pairs };
}

export function ecfBool(value: boolean): EcfBool {
  return { kind: "bool", value };
}

export function ecfNull(): EcfNull {
  return { kind: "null" };
}

export function ecfPreEncoded(value: Uint8Array): EcfPreEncoded {
  return { kind: "preEncoded", value };
}

/** Reconstruct the signed `bigint` value of an integer node. */
export function ecfIntValue(node: EcfInt): bigint {
  return node.negative ? -1n - node.argument : node.argument;
}
