import { decode, encode } from "../src/codec/canonical-cbor.js";
import { contentHash, formatPeerId, sign } from "../src/codec/entity-codec.js";
import { ecfText, ecfIntValue, type EcfValue, type EcfMap } from "../src/codec/ecf-value.js";
import { bytesEqual, toHex } from "../src/codec/bytes.js";
import { EntityCodecError } from "../src/errors.js";

/**
 * Drives the vendored, cross-blessed conformance fixture
 * (`conformance-vectors-v1.cbor`) through the native TS codec and diffs the
 * output byte-for-byte against each vector's baked `canonical` bytes. Twin of the
 * C#/Rust/C `conformance_harness` (S8 convergence). Branches by category exactly
 * as the C# `ConformanceRunner`: Class B vectors (content_hash / peer_id /
 * signature) apply their construction; everything else is a bare canonical encode;
 * `decode_reject` feeds the bytes to the strict decoder and expects rejection.
 */

export interface VectorResult {
  readonly id: string;
  readonly kind: string;
  readonly category: string;
  readonly pass: boolean;
  readonly message?: string;
}

export interface ConformanceReport {
  readonly results: readonly VectorResult[];
  readonly allPass: boolean;
}

export function runConformance(corpusBytes: Uint8Array): ConformanceReport {
  const corpus = decode(corpusBytes);
  if (corpus.kind !== "array") {
    throw new Error("fixture top-level is not a CBOR array");
  }

  const results: VectorResult[] = [];
  for (const item of corpus.items) {
    if (item.kind !== "map") {
      continue;
    }
    const id = textField(item, "id") ?? "<no-id>";
    const kind = textField(item, "kind") ?? "<no-kind>";
    const dot = id.indexOf(".");
    const category = dot >= 0 ? id.slice(0, dot) : id;

    let pass: boolean;
    let message: string | undefined;
    try {
      [pass, message] = runVector(kind, category, item);
    } catch (err) {
      pass = false;
      message = `threw ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`;
    }
    results.push(message === undefined ? { id, kind, category, pass } : { id, kind, category, pass, message });
  }
  return { results, allPass: results.every((r) => r.pass) };
}

function runVector(kind: string, category: string, vector: EcfMap): [boolean, string | undefined] {
  const canonical = bytesField(vector, "canonical");
  if (canonical === undefined) {
    return [false, "missing canonical bytes"];
  }

  if (kind === "decode_reject") {
    try {
      decode(canonical);
    } catch (err) {
      if (err instanceof EntityCodecError) {
        return [true, undefined];
      }
      throw err;
    }
    return [false, "decoder ACCEPTED bytes it must reject"];
  }

  // encode_equal
  const input = field(vector, "input");
  if (input === undefined) {
    return [false, "missing input"];
  }

  let got: Uint8Array;
  switch (category) {
    case "content_hash":
      got = runContentHash(input);
      break;
    case "peer_id":
      got = runPeerId(input);
      break;
    case "signature":
      got = runSignature(input);
      break;
    default:
      // Class A + nested + envelope: bare canonical encode.
      got = encode(input);
      break;
  }

  if (bytesEqual(got, canonical)) {
    return [true, undefined];
  }
  return [false, `got ${toHex(got)} != want ${toHex(canonical)}`];
}

function runContentHash(input: EcfValue): Uint8Array {
  const m = asMap(input);
  const type = textField(m, "type") ?? throwErr("content_hash: missing type");
  const data = field(m, "data") ?? throwErr("content_hash: missing data");
  const formatCode = uintField(m, "format_code") ?? 0n;
  return contentHash(type, encode(data), formatCode);
}

function runPeerId(input: EcfValue): Uint8Array {
  const m = asMap(input);
  const keyType = uintField(m, "key_type") ?? throwErr("peer_id: missing key_type");
  const hashType = uintField(m, "hash_type") ?? throwErr("peer_id: missing hash_type");
  const digest = bytesField(m, "digest") ?? throwErr("peer_id: missing digest");
  return encode(ecfText(formatPeerId(keyType, hashType, digest)));
}

function runSignature(input: EcfValue): Uint8Array {
  const m = asMap(input);
  const seed = bytesField(m, "seed") ?? throwErr("signature: missing seed");
  const entity = field(m, "entity") ?? throwErr("signature: missing entity");
  // Sign the canonical-ECF encoding of the {type, data} entity (matches the C#/
  // Rust/C harness — the signed message is ECF(entity), not its content hash).
  return sign(seed, encode(entity));
}

// ── fixture field accessors over the decoded value tree ──

function asMap(value: EcfValue): EcfMap {
  if (value.kind !== "map") {
    throw new EntityCodecError(`expected a map, got ${value.kind}`);
  }
  return value;
}

function field(map: EcfMap, key: string): EcfValue | undefined {
  for (const [k, v] of map.pairs) {
    if (k.kind === "text" && k.value === key) {
      return v;
    }
  }
  return undefined;
}

function textField(map: EcfMap, key: string): string | undefined {
  const v = field(map, key);
  return v?.kind === "text" ? v.value : undefined;
}

function bytesField(map: EcfMap, key: string): Uint8Array | undefined {
  const v = field(map, key);
  return v?.kind === "bytes" ? v.value : undefined;
}

function uintField(map: EcfMap, key: string): bigint | undefined {
  const v = field(map, key);
  return v?.kind === "int" && !v.negative ? ecfIntValue(v) : undefined;
}

function throwErr(message: string): never {
  throw new EntityCodecError(message);
}
