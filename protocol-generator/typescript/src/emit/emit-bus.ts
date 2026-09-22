import { type EcfValue } from "../codec/ecf-value.js";
import { type Entity } from "../model/index.js";

/**
 * The execution-context core fields (V7 §6.8a / SYSTEM-COMPOSITION C3) — the RESERVED
 * field *names* (the collision contract) carried on a tree-change event's `context`.
 * Representation is impl-defined (§9.4); this is the TS idiom (S6). On a core peer most
 * slots are inert. (`capability` was dropped as redundant with `callerCapability` /
 * `handlerGrant`.)
 */
export interface EmitContext {
  readonly chainId?: string;
  readonly parentChainId?: string;
  readonly author?: Uint8Array;
  readonly callerCapability?: Uint8Array;
  readonly requestId?: string;
  readonly bounds?: EcfValue;
  readonly cascadeDepth?: bigint;
  readonly handlerGrant?: Uint8Array;
  readonly handlerPattern?: string;
  readonly operation?: string;
}

/** Content-store event (V7 §6.10 Store step): carries `(hash, entity)` ONLY — NO execution context. */
export interface ContentStoreEvent {
  readonly hash: Uint8Array;
  readonly entity: Entity;
}

/**
 * Tree-change event (V7 §6.10 Bind step / v7.74 §6.13(c) B2). Field inventory is the
 * normative contract; TS field names are idiomatic (S6). `eventType` ∈
 * {`created`, `modified`, `deleted`} per the null-hash derivation. A bind to a
 * `system/deletion-marker` fires `modified`, NOT `deleted` — classification keys on a
 * null `newHash` only, never on the bound entity's type.
 */
export interface TreeChangeEvent {
  readonly eventType: string;
  readonly path: string;
  readonly newHash: Uint8Array | null;
  readonly previousHash: Uint8Array | null;
  readonly context: EmitContext | null;
}

/** The three tree-change event kinds and the §6.10 null-hash derivation rule. */
export const TreeChangeKind = {
  Created: "created",
  Modified: "modified",
  Deleted: "deleted",
  /** `created` iff previous is null; `deleted` iff new is null; else `modified`. */
  derive(previousHash: Uint8Array | null, newHash: Uint8Array | null): string {
    return previousHash === null ? "created" : newHash === null ? "deleted" : "modified";
  },
} as const;

/**
 * An emit consumer (V7 §6.10 consumer-registration primitive) — the bare primitive: a
 * callable plus identifying metadata (`name`). Delivery mode (sync-inline vs
 * async-broadcast) is impl-defined per §9.4; the core peer delivers sync-inline.
 */
export interface EmitConsumer {
  readonly name: string;
  onContentStore(ev: ContentStoreEvent): void;
  onTreeChange(ev: TreeChangeEvent): void;
}

/** A tree-change consumer callable (§6.10 Bind step). Invoked synchronously, in registration order. */
export type TreeChangeConsumer = (ev: TreeChangeEvent) => void;

/** A content-store consumer callable (§6.10 Store step). Invoked synchronously, in registration order. */
export type ContentStoreConsumer = (ev: ContentStoreEvent) => void;

/**
 * The handle a consumer registration returns; pass it to {@link EmitBus.unregisterConsumer}.
 * Opaque — compare, never compute.
 */
export type ConsumerId = number & { readonly __consumerId: unique symbol };

interface ConsumerEntry {
  readonly id: ConsumerId;
  readonly onTree: TreeChangeConsumer | null;
  readonly onContent: ContentStoreConsumer | null;
}

/**
 * The emit pathway (V7 §6.10 / v7.74 §6.13(c)). Tree writes produce events; this bus
 * delivers them to registered consumers. The hook is LIVE even with zero consumers —
 * events are produced and discarded — so a future extension can register a consumer
 * ({@link EmitBus.registerConsumer}) without the peer being rebuilt. A core-only peer
 * registers zero consumers; the pathway is still reachable, which is the §6.13(c) MUST.
 * Delivery is sync-inline (impl-defined per §9.4).
 *
 * Consumers can be registered at any time — including after construction, which is
 * when an extension installs — and removed again (keystone peer contract
 * `install.consumer`; `SYSTEM-COMPOSITION` §1.2 names registration only "during peer
 * initialization"). All consumers share ONE registration order whichever kind they are;
 * a write's content-store event always precedes its tree-change event, because the Store
 * step runs before the Bind step. Delivery iterates a snapshot, so a consumer that
 * registers or unregisters during delivery affects the next event, not this one.
 */
export class EmitBus {
  readonly #consumers: ConsumerEntry[] = [];
  #nextId = 1;

  /**
   * Register an emit consumer that receives both event kinds (§6.10). Reachable at any
   * time, incl. post-bootstrap. Returns its {@link ConsumerId} (new; ignoring it — as
   * every pre-existing caller does — is fine).
   */
  registerConsumer(consumer: EmitConsumer): ConsumerId {
    return this.#add(
      (ev) => consumer.onTreeChange(ev),
      (ev) => consumer.onContentStore(ev),
    );
  }

  /** Register a tree-change consumer (§6.10 Bind step). */
  registerTreeConsumer(consumer: TreeChangeConsumer): ConsumerId {
    return this.#add(consumer, null);
  }

  /** Register a content-store consumer (§6.10 Store step). */
  registerContentConsumer(consumer: ContentStoreConsumer): ConsumerId {
    return this.#add(null, consumer);
  }

  /**
   * Stop delivering events to the consumer `id` names. Idempotent: `false` when it is
   * not registered (already removed, or never was).
   */
  unregisterConsumer(id: ConsumerId): boolean {
    const i = this.#consumers.findIndex((c) => c.id === id);
    if (i < 0) {
      return false;
    }
    this.#consumers.splice(i, 1);
    return true;
  }

  #add(onTree: TreeChangeConsumer | null, onContent: ContentStoreConsumer | null): ConsumerId {
    const id = this.#nextId++ as ConsumerId;
    this.#consumers.push({ id, onTree, onContent });
    return id;
  }

  get hasConsumers(): boolean {
    return this.#consumers.length > 0;
  }

  /** Fire the §6.10 Store-step content-store event (hash + entity only). */
  emitContentStore(entity: Entity): void {
    if (this.#consumers.length === 0) {
      return;
    }
    const ev: ContentStoreEvent = { hash: entity.contentHash, entity };
    for (const c of [...this.#consumers]) {
      c.onContent?.(ev);
    }
  }

  /** Fire the §6.10 Bind-step tree-change event, deriving `eventType` from the hashes. */
  emitTreeChange(
    path: string,
    previousHash: Uint8Array | null,
    newHash: Uint8Array | null,
    context: EmitContext | null,
  ): void {
    if (this.#consumers.length === 0) {
      return;
    }
    const ev: TreeChangeEvent = {
      eventType: TreeChangeKind.derive(previousHash, newHash),
      path,
      newHash,
      previousHash,
      context,
    };
    for (const c of [...this.#consumers]) {
      c.onTree?.(ev);
    }
  }
}
