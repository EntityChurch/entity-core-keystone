import { type EmitBus } from "../emit/index.js";
import { Entity, hashHex } from "../model/index.js";

/**
 * The content store (V7 §1.7): an immutable, deduplicated `Hash → Entity` map.
 * This is the in-memory minimal implementation the core peer ships with; storage
 * backends are implementation-defined (§1.10). Puts are idempotent on content
 * hash (§6.10 store step fires no event on re-put).
 *
 * (Single-threaded JS: the C# `ConcurrentDictionary` collapses to a plain `Map` —
 * synchronous puts/gets are atomic between `await` points.)
 *
 * This is also the in-process DATA SURFACE an extension uses (keystone peer contract
 * `embed.data`): `Peer.contentStore` is the peer's own store, so what it holds is what
 * the authority path resolves by hash.
 */
export class ContentStore {
  readonly #byHash = new Map<string, Entity>();
  readonly #emit: EmitBus | null;

  constructor(emit: EmitBus | null = null) {
    this.#emit = emit;
  }

  /**
   * Store an entity, keyed by its content hash. Idempotent. The §6.10 Store step: a
   * content-store event fires only when the entity is new to the store (a re-put of an
   * existing hash fires nothing). A direct `content_store.put` executes only this step.
   *
   * Returns `false`, stores nothing and fires nothing when the entity's carried hash is
   * not the content hash of its `{type, data}` ({@link Entity.contentHashHolds}): the
   * store never files an entity under a hash it does not have. `true` otherwise, whether
   * or not the entity was already present. (The return value is new; a caller that
   * ignores it — every pre-existing call site — is unaffected.)
   */
  put(entity: Entity): boolean {
    if (!entity.contentHashHolds()) {
      return false;
    }
    if (!this.#byHash.has(entity.contentHashHex)) {
      this.#byHash.set(entity.contentHashHex, entity);
      this.#emit?.emitContentStore(entity);
    }
    return true;
  }

  /** Retrieve an entity by content hash; undefined on miss. */
  get(contentHash: Uint8Array): Entity | undefined {
    return this.#byHash.get(hashHex(contentHash));
  }

  contains(contentHash: Uint8Array): boolean {
    return this.#byHash.has(hashHex(contentHash));
  }
}
