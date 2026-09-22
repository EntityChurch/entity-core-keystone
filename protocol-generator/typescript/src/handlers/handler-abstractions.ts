import {
  type Entity,
  type Execute,
  type ExecuteResponse,
  type Envelope,
  type ResourceTarget,
  Status,
} from "../model/index.js";
import { type PeerIdentity } from "../identity/index.js";
import { type CapabilityToken } from "../capability/index.js";
import { type ContentStore, type EntityTree } from "../store/index.js";
import { type EmitBus, type EmitContext } from "../emit/index.js";
import { type ConnectionState } from "./connection-state.js";

/**
 * The outcome of a handler operation: a status, a result entity (the operation's
 * declared output type), and any entities the handler bundles into the response
 * envelope's `included` map (protocol entities — capabilities, identities,
 * signatures, §3.1).
 */
export class HandlerResult {
  constructor(
    readonly status: number,
    readonly result: Entity,
    readonly included: readonly Entity[],
  ) {}

  static ok(result: Entity, included: readonly Entity[] = []): HandlerResult {
    return new HandlerResult(Status.Ok, result, included);
  }

  static of(status: number, result: Entity, included: readonly Entity[] = []): HandlerResult {
    return new HandlerResult(status, result, included);
  }
}

/**
 * Peer-level services a handler dispatches against (V7 §6.8). The handler acts as
 * the local peer for its sub-requests; its authority is its own grant, not the
 * caller's capability (§6.8 "no silent escalation").
 */
export interface PeerServices {
  readonly localPeerId: string;
  readonly localIdentity: PeerIdentity;
  readonly tree: EntityTree;
  readonly contentStore: ContentStore;
  /** The §6.10 emit pathway — where an extension registers a consumer (§6.13(c)). */
  readonly emit: EmitBus;
  /** Current time, ms since epoch (the clock used for temporal checks). */
  readonly nowMs: bigint;
  /**
   * The peer's configured default frame budget (§1.6). This is the fallback for a
   * dispatch with no connection; the budget a handler should actually size its
   * response against is {@link HandlerContext.frameBudget}, which prefers the
   * *connection's* value.
   */
  readonly maxFrameBytes: number;
}

/**
 * The authority a handler presents on an outbound EXECUTE (V7 §5.8 chain inclusion):
 * the capability the target peer accepts, its granter identity, and the capability
 * signature. The handler dispatches under its own authority (§6.8 — no silent
 * escalation of the caller's), so it supplies the bundle it holds for the target.
 */
export interface OutboundAuthority {
  readonly capability: CapabilityToken;
  /**
   * PLURAL (GUIDE-CONFORMANCE §7a.1, 0.8.2.19) so a K-of-N root can present every
   * granter identity and every link signature; the ordinary single-granter case is a
   * list of one. Every member goes into `included` because §5.5's chain walk resolves
   * granters and signers BY HASH out of that map — a granter left out is a link the
   * verifier cannot reach, which fails closed and reads as the peer refusing the
   * credential form rather than as a carrier we truncated.
   */
  readonly granterPeers: readonly Entity[];
  readonly capabilitySignatures: readonly Entity[];
}

/**
 * The handler-facing outbound-dispatch seam (V7 §6.13(b)): a handler servicing an
 * inbound EXECUTE may initiate an outbound EXECUTE, routed through the §6.11 transport
 * reentry contract (reader-task + `request_id` correlation). Present on every peer even
 * though no *core* handler originates — a handler registered at runtime (§6.13(a)) may.
 */
export interface OutboundDispatch {
  /**
   * Build, sign (as the local peer), and send an authenticated outbound EXECUTE; await
   * the correlated EXECUTE_RESPONSE. The full authority chain travels in `included`.
   */
  execute(
    uri: string,
    operation: string,
    paramsEntity: Entity,
    resource: ResourceTarget | null,
    /**
     * `null` is §1.4's PD-2 AMBIENT arm: the sub-dispatch is authorized by the
     * executing handler's own grant and carries no credential at all. The EXECUTE then
     * carries no `capability` field — an empty hash would NOT do, since that is a
     * present field resolving to nothing, which §5.2 reads as an unresolvable
     * capability rather than as its absence.
     */
    authority: OutboundAuthority | null,
    timeoutMs: number,
  ): Promise<ExecuteResponse>;
}

/**
 * Per-request execution context handed to a handler (V7 §6.5 step 7, §6.8). Holds
 * the EXECUTE, the resolved pattern/suffix, the caller's verified capability, the
 * handler's own grant, the envelope (for `included` resolution, N5), and — for
 * connection-path dispatch — the per-connection state.
 */
export class HandlerContext {
  readonly peer: PeerServices;
  readonly execute: Execute;
  readonly envelope: Envelope;
  /** Peer-relative handler pattern, e.g. `"system/tree"`. */
  readonly pattern: string;
  /** URI remainder after the handler pattern (for internal routing, §6.4). */
  readonly suffix: string;
  readonly callerCapability: CapabilityToken | null;
  readonly handlerGrant: CapabilityToken | null;
  readonly author: Uint8Array | null;
  /** Per-connection state — present only for connection-path dispatch (§4). */
  readonly connection: ConnectionState | null;
  /**
   * The §6.13(b) handler-facing outbound-dispatch seam — non-null when the request
   * arrived over a reentrant connection. A handler originates an outbound EXECUTE
   * through here; it routes via §6.11 transport reentry. Core handlers do not originate.
   */
  readonly outbound: OutboundDispatch | null;

  constructor(init: {
    peer: PeerServices;
    execute: Execute;
    envelope: Envelope;
    pattern: string;
    suffix: string;
    callerCapability: CapabilityToken | null;
    handlerGrant: CapabilityToken | null;
    author: Uint8Array | null;
    connection: ConnectionState | null;
    outbound?: OutboundDispatch | null;
  }) {
    this.peer = init.peer;
    this.execute = init.execute;
    this.envelope = init.envelope;
    this.pattern = init.pattern;
    this.suffix = init.suffix;
    this.callerCapability = init.callerCapability;
    this.handlerGrant = init.handlerGrant;
    this.author = init.author;
    this.connection = init.connection;
    this.outbound = init.outbound ?? null;
  }

  get operation(): string {
    return this.execute.operation;
  }

  get params(): Entity {
    return this.execute.params;
  }

  /**
   * The §6.8a execution context for a §6.10 tree-change event, built from what this
   * dispatch actually holds (SYSTEM-COMPOSITION §1.4 field inventory).
   *
   * WHY THIS EXISTS. `EmitContext` was declared with the full inventory and **never
   * constructed** — `EntityTree.put`/`remove` defaulted it to null and `compareAndPut`
   * hardcoded null — so every tree-change event reached a consumer with no context.
   * That is not a neutral absence: an event with no context is indistinguishable from
   * an AUTONOMOUS write, so a recorder implementing `EXTENSION-HISTORY` §2.1 (where
   * `author` and `capability` are non-optional and §9.1 makes recording them a MUST)
   * correctly falls back to the autonomous reading and then attributes a REMOTE
   * caller's write to the local peer. §7.2 calls `capability` the answer to "under what
   * authority?", and the answer was always "its own". Routed by `entity-system-generator`
   * (H8) out of building HISTORY v1.7; the four `history` oracle checks that cover these
   * fields are PRESENCE checks, so a peer scores on them either way.
   *
   * `capability` is deliberately not a separate slot: it is redundant with
   * `callerCapability` / `handlerGrant`, which distinguish the two authorities a write
   * runs under. Capability-shaped slots carry the token's CONTENT HASH, which is the
   * reference an event consumer can resolve against the store. The four §1.4 slots a
   * core request does not carry are read from the wire (see `Execute`) and are
   * `undefined` when absent rather than invented.
   */
  emitContext(): EmitContext {
    return {
      ...(this.execute.chainId !== null ? { chainId: this.execute.chainId } : {}),
      ...(this.execute.parentChainId !== null ? { parentChainId: this.execute.parentChainId } : {}),
      ...(this.author !== null ? { author: this.author } : {}),
      ...(this.callerCapability !== null ? { callerCapability: this.callerCapability.contentHash } : {}),
      requestId: this.execute.requestId,
      ...(this.execute.bounds !== null ? { bounds: this.execute.bounds } : {}),
      ...(this.execute.cascadeDepth !== null ? { cascadeDepth: this.execute.cascadeDepth } : {}),
      ...(this.handlerGrant !== null ? { handlerGrant: this.handlerGrant.contentHash } : {}),
      handlerPattern: this.pattern,
      operation: this.execute.operation,
    };
  }

  get resource(): ResourceTarget | null {
    return this.execute.resource;
  }

  get localPeerId(): string {
    return this.peer.localPeerId;
  }

  /**
   * The frame budget in force for THIS request, in bytes — the connection's configured
   * budget when the request arrived over a connection, the peer's default otherwise (an
   * in-process dispatch has no connection, and a body still needs a defined number).
   *
   * A handler whose ideal response would exceed this MUST return a partial result
   * rather than a frame the transport will refuse. Consult it at response-construction
   * time; a hardcoded literal is wrong even when it happens to equal the default,
   * because a peer may configure or negotiate the budget per connection.
   */
  frameBudget(): number {
    return this.connection?.maxFrameBytes ?? this.peer.maxFrameBytes;
  }
}

/**
 * The body a §6.13(a) entity-native handler was registered with, plus the EXECUTE
 * being dispatched against it — the input to an {@link ExpressionEvaluator}.
 */
export interface ExpressionRequest {
  /** Absolute canonical path the handler's `expression_path` resolved to. */
  readonly expressionPath: string;
  /** The entity bound at that path: the handler's body. */
  readonly expression: Entity;
  /** The EXECUTE being dispatched. */
  readonly execute: Execute;
}

/**
 * The evaluator seam for entity-native handler bodies (V7 §6.13(a); §9.4 leaves the
 * mechanism impl-private, so what is contracted here is that a mechanism *exists*).
 *
 * A core peer evaluates the minimal `compute/literal` shape in-process and answers
 * `501 unsupported_expression` to anything richer. Installing an evaluator through
 * `Peer.setExpressionEvaluator` is what lets a community ship its own compute
 * semantics: without one the peer's answer is unchanged, and with one every body the
 * built-in path cannot evaluate is routed here instead of refused.
 *
 * Return `null` for a body this evaluator does not recognise — the peer then answers
 * its own `501`, so evaluators compose rather than having to claim every shape.
 */
export interface ExpressionEvaluator {
  evaluate(request: ExpressionRequest): Promise<HandlerResult | null> | HandlerResult | null;
}

/**
 * One operation's declared shape (V7 §3.7 `system/handler/operation-spec`).
 *
 * Both fields are optional in the spec, so an operation declared by name alone is
 * well-formed — but §3.7 makes the naming convention (`{handler-path}/{op}-request`
 * / `-result`) the thing *"tooling and code generators rely on to derive op shapes
 * without per-extension knowledge"*, which they cannot do if the shapes are never
 * published.
 */
export interface OperationSpec {
  /** Canonical input type name, e.g. `system/content/put-request`. */
  readonly inputType?: string;
  /** Canonical output type name, e.g. `system/content/put-result`. */
  readonly outputType?: string;
}

/**
 * A handler's declared operations — either bare names, or names mapped to their
 * §3.7 specs.
 *
 * The bare-name form renders each operation as an empty `operation-spec`, which is
 * what every bootstrap handler here does and is byte-unchanged. The mapped form is
 * for a handler that knows its own op shapes: without it, `registerHandler` could
 * publish operation NAMES only, so an extension installed in-process had to re-write
 * its own interface entity afterwards to say what its operations take and return —
 * while the *wire* register op (§6.2) has always passed a full manifest through.
 * The in-process surface was the narrower of the two.
 */
export type HandlerOperations = readonly string[] | Readonly<Record<string, OperationSpec>>;

/** A registered handler's executable contract (V7 §6.1). The dispatch target. */
export interface Handler {
  /** Peer-relative pattern path this handler is registered at. */
  readonly pattern: string;
  /** Human-readable handler name (for the interface entity, §3.7). */
  readonly name: string;
  /** Operations this handler declares (for the interface entity, §3.7). */
  readonly operations: HandlerOperations;
  handle(ctx: HandlerContext): Promise<HandlerResult>;
}
