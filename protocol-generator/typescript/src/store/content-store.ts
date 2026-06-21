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
   */
  put(entity: Entity): void {
    if (!this.#byHash.has(entity.contentHashHex)) {
      this.#byHash.set(entity.contentHashHex, entity);
      this.#emit?.emitContentStore(entity);
    }
  }

  /** Retrieve an entity by content hash; undefined on miss. */
  get(contentHash: Uint8Array): Entity | undefined {
    return this.#byHash.get(hashHex(contentHash));
  }

  contains(contentHash: Uint8Array): boolean {
    return this.#byHash.has(hashHex(contentHash));
  }
}
