import { encode, decode } from "../codec/canonical-cbor.js";
import { encodeEntity } from "../codec/entity-codec.js";
import { type EcfValue, ecfBytes, ecfMap, ecfPreEncoded, ecfText } from "../codec/ecf-value.js";
import { SHA256_FORMAT, contentHashForFormat, readFormatCode } from "../codec/hash-formats.js";
import { EntityProtocolError } from "../errors.js";
import * as Ecf from "./ecf.js";
import { hashEqual, hashHex } from "./hashes.js";

/**
 * A materialized entity — `{type, data, content_hash}` (V7 §1.1, §3.4). The
 * fundamental data unit: a typed payload with content-addressed identity.
 *
 * Entity fidelity (§1.8) is load-bearing. An entity decoded from the wire retains
 * its exact original bytes in {@link wireBytes}; forwarding re-emits those bytes
 * verbatim and never re-serializes the decoded structure. The content hash is
 * computed once over `{type, data}` and trusted thereafter.
 */
export class Entity {
  private constructor(
    /** Semantic type path, e.g. `"system/protocol/execute"`. */
    readonly type: string,
    /** Decoded typed payload. */
    readonly data: EcfValue,
    /** 33-byte content hash (format code + SHA-256 digest), validated. */
    readonly contentHash: Uint8Array,
    /**
     * The exact `{type, data, content_hash}` wire bytes. For a locally-built
     * entity these are the canonical encoding; for a decoded entity they are the
     * original received bytes (§1.8 forward-original).
     */
    readonly wireBytes: Uint8Array,
  ) {}

  get contentHashHex(): string {
    return hashHex(this.contentHash);
  }

  /**
   * Build an entity from `{type, data}`: canonical-encode the hashable form,
   * derive the content hash under `contentHashFormat` (default `0x00` SHA-256 —
   * the §9.1 home format), and produce the full wire bytes. A non-default format
   * is the agility path (e.g. a SHA-384 home network).
   */
  static create(type: string, data: EcfValue, contentHashFormat: bigint = SHA256_FORMAT): Entity {
    const canonicalData = encode(data);
    const hashable = encodeEntity(type, canonicalData);
    const contentHash = contentHashForFormat(contentHashFormat, hashable);
    const wire = encode(
      ecfMap([
        [ecfText("type"), ecfText(type)],
        [ecfText("data"), ecfPreEncoded(canonicalData)],
        [ecfText("content_hash"), ecfBytes(contentHash)],
      ]),
    );
    return new Entity(type, data, contentHash, wire);
  }

  /**
   * Decode a wire entity and validate its content hash on receipt (§1.8.1,
   * §7.2). Throws {@link EntityProtocolError} on a hash mismatch or a malformed
   * shape.
   */
  static decode(wireBytes: Uint8Array): Entity {
    const value = decode(wireBytes);
    const type = Ecf.requireText(value, "type");
    const data = Ecf.require(value, "data");
    const declared = Ecf.requireBytes(value, "content_hash");

    // Wire-acceptance carve-out (§7.65): recompute under the format the entity
    // declares, so an entity authored under any supported home format validates.
    const format = readFormatCode(declared);
    const hashable = encodeEntity(type, encode(data));
    const expected = contentHashForFormat(format, hashable);
    if (!hashEqual(expected, declared)) {
      throw new EntityProtocolError(
        `content_hash mismatch on '${type}': computed ${hashHex(expected)}, declared ${hashHex(declared)}`,
      );
    }
    return new Entity(type, data, declared, wireBytes);
  }

  /**
   * Build an entity from an already-decoded envelope sub-value. The envelope is
   * decoded in strict canonical mode, so re-encoding this sub-map reproduces its
   * exact original bytes (ECF canonical form is unique) — non-canonical input was
   * rejected at the envelope boundary. This recovers the per-entity byte
   * boundaries the whole-envelope decode flattened, then validates the hash.
   */
  static fromDecoded(entityMap: EcfValue): Entity {
    return Entity.decode(encode(entityMap));
  }
}
