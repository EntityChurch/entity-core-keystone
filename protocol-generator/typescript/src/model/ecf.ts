import {
  type EcfValue,
  ecfArray,
  ecfBool,
  ecfBytes,
  ecfInt,
  ecfMap,
  ecfNull,
  ecfText,
} from "../codec/ecf-value.js";
import { decode, encode } from "../codec/canonical-cbor.js";
import { EntityProtocolError } from "../errors.js";

/**
 * Ergonomic constructors and accessors over the codec's {@link EcfValue} tree.
 * The peer layer builds protocol entity `data` maps and reads decoded ones
 * through these helpers, so the rest of the peer never touches the raw union
 * variants.
 *
 * Field accessors are strict: a missing or wrong-typed field throws
 * {@link EntityProtocolError}. This keeps malformed wire entities from
 * propagating untyped nulls into the dispatch chain.
 */

// ── builders ──

/** An unsigned integer (the protocol's `ulong` surface; pass a non-negative `bigint`). */
export function uint(value: bigint): EcfValue {
  return ecfInt(value);
}

export function text(value: string): EcfValue {
  return ecfText(value);
}

export function bytes(value: Uint8Array): EcfValue {
  return ecfBytes(value);
}

export function bool(value: boolean): EcfValue {
  return ecfBool(value);
}

/** The CBOR null. */
export const nullValue: EcfValue = ecfNull();

/** The canonical empty map (single byte `0xA0` on the wire — N3). */
export function emptyMap(): EcfValue {
  return ecfMap([]);
}

export function array(items: readonly EcfValue[]): EcfValue {
  return ecfArray(items);
}

/**
 * Build a map from `(key, value)` pairs. A `null` value is dropped — the ECF
 * convention that an absent optional field is encoded by omitting the key
 * entirely (§1.3), so callers pass `null` to mean "absent".
 */
export function map(...pairs: readonly (readonly [string, EcfValue | null])[]): EcfValue {
  const out: [EcfValue, EcfValue][] = [];
  for (const [key, value] of pairs) {
    if (value !== null) {
      out.push([ecfText(key), value]);
    }
  }
  return ecfMap(out);
}

// ── accessors ──

/** Look up a field in a map value; returns null if absent (or explicitly null). */
export function field(value: EcfValue, key: string): EcfValue | null {
  if (value.kind !== "map") {
    throw new EntityProtocolError(`expected a map to read field '${key}'`);
  }
  for (const [k, v] of value.pairs) {
    if (k.kind === "text" && k.value === key) {
      return v.kind === "null" ? null : v;
    }
  }
  return null;
}

export function require(value: EcfValue, key: string): EcfValue {
  const f = field(value, key);
  if (f === null) {
    throw new EntityProtocolError(`missing required field '${key}'`);
  }
  return f;
}

export function asText(value: EcfValue): string {
  if (value.kind !== "text") {
    throw new EntityProtocolError("expected a text string");
  }
  return value.value;
}

export function asUint(value: EcfValue): bigint {
  if (value.kind !== "int" || value.negative) {
    throw new EntityProtocolError("expected an unsigned integer");
  }
  return value.argument;
}

export function asBytes(value: EcfValue): Uint8Array {
  if (value.kind !== "bytes") {
    throw new EntityProtocolError("expected a byte string");
  }
  return value.value;
}

export function asBool(value: EcfValue): boolean {
  if (value.kind !== "bool") {
    throw new EntityProtocolError("expected a boolean");
  }
  return value.value;
}

export function asArray(value: EcfValue): readonly EcfValue[] {
  if (value.kind !== "array") {
    throw new EntityProtocolError("expected an array");
  }
  return value.items;
}

export function requireText(value: EcfValue, key: string): string {
  return asText(require(value, key));
}

export function requireUint(value: EcfValue, key: string): bigint {
  return asUint(require(value, key));
}

export function requireBytes(value: EcfValue, key: string): Uint8Array {
  return asBytes(require(value, key));
}

export function optText(value: EcfValue, key: string): string | null {
  const f = field(value, key);
  return f === null ? null : asText(f);
}

export function optUint(value: EcfValue, key: string): bigint | null {
  const f = field(value, key);
  return f === null ? null : asUint(f);
}

export function optBytes(value: EcfValue, key: string): Uint8Array | null {
  const f = field(value, key);
  return f === null ? null : asBytes(f);
}

export function optBool(value: EcfValue, key: string): boolean | null {
  const f = field(value, key);
  return f === null ? null : asBool(f);
}

/**
 * Enumerate a map's text-keyed entries in their encoded order. Used by the
 * attenuation checks that compare constraint / allowance maps key-by-key.
 */
export function entries(value: EcfValue): readonly (readonly [string, EcfValue])[] {
  if (value.kind !== "map") {
    throw new EntityProtocolError("expected a map");
  }
  const out: [string, EcfValue][] = [];
  for (const [k, v] of value.pairs) {
    if (k.kind === "text") {
      out.push([k.value, v]);
    }
  }
  return out;
}

/** Canonical-encode a value to ECF bytes. */
export function encodeEcf(value: EcfValue): Uint8Array {
  return encode(value);
}

/** Strict canonical decode of ECF bytes (rejects tags, non-canonical). */
export function decodeEcf(bytes: Uint8Array): EcfValue {
  return decode(bytes);
}
