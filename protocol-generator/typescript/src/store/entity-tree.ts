import { type EmitBus, type EmitContext } from "../emit/index.js";
import { Entity, hashEqual, isZeroHash } from "../model/index.js";
import { ContentStore } from "./content-store.js";

/** One entry in a tree listing (V7 §3.9): an optional bound hash and a child-path flag. */
export interface ListingEntry {
  readonly hash: Uint8Array | null;
  readonly hasChildren: boolean;
}

/**
 * The entity tree (V7 §1.7): the mutable `URI → Hash` location index over the
 * immutable {@link ContentStore}. Paths are stored absolute (`/{peer_id}/rest`,
 * §1.4). Entity binding and child-path existence are independent dimensions
 * (§1.7) — a path may be both bound and a prefix.
 */
export class EntityTree {
  readonly #index = new Map<string, Uint8Array>();
  readonly #emit: EmitBus | null;

  constructor(
    readonly contentStore: ContentStore,
    emit: EmitBus | null = null,
  ) {
    this.#emit = emit;
  }

  /**
   * Store + bind, threading an optional §6.8a execution `context` onto the Bind-step
   * tree-change event. A `tree_put` runs the §6.10 emit pathway: the Store step (via
   * {@link ContentStore.put}) then the Bind step (a tree-change event when the binding
   * actually changes — no event on a re-bind to the current hash). Core writes pass null.
   *
   * Returns `false` and binds nothing (no store write, no event) when the entity's
   * carried hash is not its content hash — the same refusal as {@link ContentStore.put},
   * so a path never resolves to an entity filed under a hash it does not have. An
   * extension binding through this in-process surface passes its dispatch's
   * `emitContext()` so a consumer sees the caller (keystone peer contract `embed.data`).
   */
  put(path: string, entity: Entity, context: EmitContext | null = null): boolean {
    if (!this.contentStore.put(entity)) {
      return false; // §6.10 Store step refused (fires a content-store event if new otherwise).
    }
    const previous = this.#index.get(path) ?? null;
    const changed = previous === null || !hashEqual(previous, entity.contentHash);
    this.#index.set(path, entity.contentHash);
    if (changed) {
      this.#emit?.emitTreeChange(path, previous, entity.contentHash, context);
    }
    return true;
  }

  /**
   * Remove the binding at `path`, firing a §6.10 `deleted` tree-change event (carrying
   * `context`) when a binding existed. Returns whether one did.
   */
  remove(path: string, context: EmitContext | null = null): boolean {
    const previous = this.#index.get(path) ?? null;
    if (this.#index.delete(path)) {
      this.#emit?.emitTreeChange(path, previous, null, context);
      return true;
    }
    return false;
  }

  /** Get the entity bound at `path`; undefined if unbound. */
  get(path: string): Entity | undefined {
    const hash = this.#index.get(path);
    return hash === undefined ? undefined : this.contentStore.get(hash);
  }

  /** Get the content hash bound at `path`; undefined if unbound. */
  getHash(path: string): Uint8Array | undefined {
    return this.#index.get(path);
  }

  isBound(path: string): boolean {
    return this.#index.has(path);
  }

  /**
   * Conditional bind (CAS, §3.9). `expectedHash` null = unconditional; zero =
   * create-only (must be unbound); non-zero = must match the current binding.
   * Returns false on a CAS miss, and — like {@link put} — for an entity whose carried
   * hash is not its content hash (nothing is stored or bound).
   */
  compareAndPut(
    path: string,
    entity: Entity,
    expectedHash: Uint8Array | null,
    context: EmitContext | null = null,
  ): boolean {
    if (expectedHash !== null) {
      const current = this.#index.get(path);
      if (isZeroHash(expectedHash)) {
        if (current !== undefined) {
          return false; // create-only, but a binding exists
        }
      } else if (current === undefined || !hashEqual(current, expectedHash)) {
        return false;
      }
    }
    const previous = this.#index.get(path) ?? null;
    if (!this.contentStore.put(entity)) {
      return false;
    }
    const changed = previous === null || !hashEqual(previous, entity.contentHash);
    this.#index.set(path, entity.contentHash);
    if (changed) {
      this.#emit?.emitTreeChange(path, previous, entity.contentHash, context);
    }
    return true;
  }

  /**
   * One level of entries under `prefix` (a path ending in `/`). Each name maps to
   * its bound hash (if any) and whether deeper child paths exist (§3.9).
   */
  list(prefix: string): Map<string, ListingEntry> {
    const normalized = prefix.endsWith("/") ? prefix : prefix + "/";
    const directHash = new Map<string, Uint8Array>();
    const hasChildren = new Set<string>();

    for (const [key, value] of this.#index) {
      if (!key.startsWith(normalized)) {
        continue;
      }
      const rest = key.slice(normalized.length);
      if (rest.length === 0) {
        continue;
      }
      const slash = rest.indexOf("/");
      if (slash < 0) {
        directHash.set(rest, value); // direct binding at prefix/name
      } else {
        hasChildren.add(rest.slice(0, slash)); // a deeper path exists under prefix/name
      }
    }

    const entries = new Map<string, ListingEntry>();
    for (const name of new Set([...directHash.keys(), ...hasChildren])) {
      entries.set(name, {
        hash: directHash.get(name) ?? null,
        hasChildren: hasChildren.has(name),
      });
    }
    return entries;
  }
}
