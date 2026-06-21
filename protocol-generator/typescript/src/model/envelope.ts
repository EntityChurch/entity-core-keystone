import { encode, decode } from "../codec/canonical-cbor.js";
import { ecfBytes, ecfMap, ecfPreEncoded, ecfText } from "../codec/ecf-value.js";
import { EntityProtocolError } from "../errors.js";
import * as Ecf from "./ecf.js";
import { Entity } from "./entity.js";
import { hashEqual, hashHex } from "./hashes.js";

/**
 * A wire envelope (V7 §3.1): a `root` entity plus an `included` map of supporting
 * entities keyed by content hash (capabilities, identities, signatures, and any
 * entity the root references).
 *
 * The `included` map is load-bearing and MUST survive every dispatch surface
 * (N5 / §3.3) — this type preserves it whole. Entities are spliced verbatim on
 * encode (their original {@link Entity.wireBytes}) so forwarding never
 * re-serializes (N4 / §1.8).
 */
export class Envelope {
  readonly #included: Map<string, Entity>;

  constructor(
    /** The primary entity — determines behavior (EXECUTE → process as request). */
    readonly root: Entity,
    included: Iterable<Entity>,
  ) {
    this.#included = new Map();
    for (const entity of included) {
      this.#included.set(entity.contentHashHex, entity);
    }
  }

  /** Supporting entities, keyed by lowercase hex of their content hash. */
  get included(): ReadonlyMap<string, Entity> {
    return this.#included;
  }

  /** Resolve a reference by content hash; undefined on miss. */
  find(contentHash: Uint8Array): Entity | undefined {
    return this.#included.get(hashHex(contentHash));
  }

  /** Encode the envelope to wire bytes, splicing entity originals verbatim. */
  encode(): Uint8Array {
    const includedPairs = [...this.#included.values()].map(
      (entity) => [ecfBytes(entity.contentHash), ecfPreEncoded(entity.wireBytes)] as const,
    );
    return encode(
      ecfMap([
        [ecfText("root"), ecfPreEncoded(this.root.wireBytes)],
        [ecfText("included"), ecfMap(includedPairs)],
      ]),
    );
  }

  /**
   * Decode and validate a wire envelope. Each entity's hash is checked on receipt
   * (§1.8.1), and each included entry's content hash MUST match its map key
   * (§3.1).
   */
  static decode(wireBytes: Uint8Array): Envelope {
    const value = decode(wireBytes);
    const root = Entity.fromDecoded(Ecf.require(value, "root"));

    const included: Entity[] = [];
    const includedValue = Ecf.field(value, "included");
    if (includedValue !== null) {
      if (includedValue.kind !== "map") {
        throw new EntityProtocolError("envelope 'included' must be a map");
      }
      for (const [key, entityValue] of includedValue.pairs) {
        if (key.kind !== "bytes") {
          throw new EntityProtocolError("envelope included map key must be a byte string (§3.1)");
        }
        const entity = Entity.fromDecoded(entityValue);
        if (!hashEqual(key.value, entity.contentHash)) {
          throw new EntityProtocolError("included entity content_hash does not match its map key (§3.1)");
        }
        included.push(entity);
      }
    }
    return new Envelope(root, included);
  }
}
