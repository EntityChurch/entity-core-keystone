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

/**
 * The emit pathway (V7 §6.10 / v7.74 §6.13(c)). Tree writes produce events; this bus
 * delivers them to registered consumers. The hook is LIVE even with zero consumers —
 * events are produced and discarded — so a future extension can register a consumer
 * ({@link EmitBus.registerConsumer}) without the peer being rebuilt. A core-only peer
 * registers zero consumers; the pathway is still reachable, which is the §6.13(c) MUST.
 * Delivery is sync-inline (impl-defined per §9.4).
 */
export class EmitBus {
  readonly #consumers: EmitConsumer[] = [];

  /** Register an emit consumer (§6.10). Reachable at any time, incl. post-bootstrap. */
  registerConsumer(consumer: EmitConsumer): void {
    this.#consumers.push(consumer);
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
    for (const c of this.#consumers) {
      c.onContentStore(ev);
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
    for (const c of this.#consumers) {
      c.onTreeChange(ev);
    }
  }
}
