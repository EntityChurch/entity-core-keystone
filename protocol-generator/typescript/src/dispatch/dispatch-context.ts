import { EntityCoreError } from "../errors.js";
import { type Entity, type Envelope, type Execute, type ResourceTarget } from "../model/index.js";
import { type CapabilityToken, ChainVerifier } from "../capability/index.js";
import { type EmitContext } from "../emit/index.js";
import {
  type ConnectionState,
  type HandlerResult,
  type OutboundDispatch,
  type PeerServices,
} from "../handlers/index.js";
import { type ReentrantSender } from "../transport/reentrant-sender.js";

/**
 * An EXECUTE a handler body issues to a LOCAL handler, in-process, with
 * {@link DispatchContext.dispatchExecute} (keystone peer contract `context.dispatch`).
 */
export interface LocalExecute {
  /**
   * A local URI: peer-relative (`system/tree`), absolute (`/{local}/…`) or
   * `entity://{local}/…`. A foreign namespace answers `400 invalid_request` — reaching
   * another peer is the §6.13(b) outbound seam, which runs under different authority.
   */
  readonly uri: string;
  readonly operation: string;
  readonly params: Entity;
  /** The §3.2 resource target. Absent sends none: a sub-dispatch inherits nothing from the parent's resource. */
  readonly resource?: ResourceTarget | null;
  /**
   * The capability the sub-dispatch is authorized under. Absent means the CALLER's
   * verified capability. Admissible: the caller's capability, this handler's own grant,
   * or a token this peer issued (granter = the local identity, signature verifiable at
   * the §3.5 pointer, inside its temporal bounds, unrevoked). Anything else answers
   * `403 capability_denied`.
   */
  readonly capability?: CapabilityToken | null;
}

/** Maximum nesting of {@link DispatchContext.dispatchExecute} calls within one wire request; past it `429 bounds_exceeded`. */
export const MAX_LOCAL_DISPATCH_DEPTH = 16;

/**
 * Thrown when anything other than the peer's dispatcher tries to construct a
 * {@link DispatchContext} (keystone peer contract `context.unforgeable`).
 */
export class ContextForgeryError extends EntityCoreError {
  constructor(message: string) {
    super(message);
    this.name = "ContextForgeryError";
    Object.setPrototypeOf(this, ContextForgeryError.prototype);
  }
}

/** @internal What the dispatcher hands a context. Never reachable from a context instance. */
export interface DispatchContextState {
  readonly peer: PeerServices;
  readonly execute: Execute;
  readonly envelope: Envelope;
  readonly pattern: string;
  readonly suffix: string;
  readonly callerCapability: CapabilityToken | null;
  readonly handlerGrant: CapabilityToken | null;
  readonly author: Uint8Array | null;
  readonly connection: ConnectionState | null;
  readonly outbound: OutboundDispatch | null;
  /** The §6.11 reentrant sender the outbound seam wraps, so a sub-dispatch keeps it. */
  readonly sender: ReentrantSender | null;
  readonly depth: number;
  readonly dispatchLocal: (request: LocalExecute) => Promise<HandlerResult>;
}

/**
 * THE CONSTRUCTION TOKEN. Module-private: it is not exported from this module, so no
 * import — through the package's `exports` map or by a filesystem path to this compiled
 * file — can name it, and it is never stored on an instance, so no reflection over a
 * context can recover it.
 */
const TOKEN: unique symbol = Symbol("DispatchContext construction token");
let factoryClaimed = false;

/**
 * The context a `Peer.registerHandler(spec, body)` body receives (§6.5 step 7, §6.8;
 * `SDK-OPERATIONS` §11.4; keystone peer contract `context.contents`,
 * `context.dispatch`, `context.frame_budget`, `context.authority_chain`,
 * `event.context`).
 *
 * **Only the dispatcher constructs one** (`context.unforgeable`). TypeScript has no
 * enforced visibility, so this is a RUNTIME token, and its strength is stated here
 * rather than implied:
 *
 * - The constructor requires a module-private `symbol`; any other argument throws
 *   {@link ContextForgeryError}. A subclass cannot reach the parent constructor without
 *   it, and `Reflect.construct` is the same call.
 * - The only way to obtain a constructing function is {@link claimDispatchContextFactory},
 *   which answers exactly ONCE per module instance and is claimed by the dispatcher
 *   module as it loads. It is not re-exported from the package. A program that imports
 *   this compiled file by path and claims it before the peer loads makes the peer fail
 *   to load — loudly, not with a forged context.
 * - All state lives in an ES private field, so an object made with
 *   `Object.create(DispatchContext.prototype)` has no usable state: every accessor
 *   throws `TypeError`.
 *
 * It is NOT a boundary against code that can rewrite the peer's files on disk, run
 * under the inspector, or is handed a genuine context by a body (reusing a real context
 * is not forging one). Within one process, from code that holds only the package, a
 * context cannot be made.
 */
export class DispatchContext {
  readonly #state: DispatchContextState;

  /** @internal Throws {@link ContextForgeryError} unless called by the dispatcher. */
  constructor(token: symbol, state: DispatchContextState) {
    if (token !== TOKEN) {
      throw new ContextForgeryError(
        "a DispatchContext is constructed only by the peer's dispatcher (keystone peer contract context.unforgeable)",
      );
    }
    this.#state = state;
  }

  /** The operation being dispatched. */
  get operation(): string {
    return this.#state.execute.operation;
  }

  /** The request's `params` entity. */
  get params(): Entity {
    return this.#state.execute.params;
  }

  /** The request's §3.2 resource target, or `null`. */
  get resource(): ResourceTarget | null {
    return this.#state.execute.resource;
  }

  /** The resolved handler pattern, peer-relative (`app/notes`). */
  get pattern(): string {
    return this.#state.pattern;
  }

  /** The URI remainder after the pattern, with no leading `/` (`sub/x`; `""` for the pattern itself). */
  get suffix(): string {
    return this.#state.suffix;
  }

  /** The request author's identity hash (already authenticated), or `null`. */
  get author(): Uint8Array | null {
    return this.#state.author;
  }

  /** The capability this request was verified and authorized under, or `null`. */
  get callerCapability(): CapabilityToken | null {
    return this.#state.callerCapability;
  }

  /** This handler's own self-issued grant (§6.8), or `null`. */
  get handlerGrant(): CapabilityToken | null {
    return this.#state.handlerGrant;
  }

  /** The request's EXECUTE. */
  get execute(): Execute {
    return this.#state.execute;
  }

  /** The request envelope (for `included` resolution). */
  get envelope(): Envelope {
    return this.#state.envelope;
  }

  /** The peer's services: tree, content store, emit bus, identity, clock. */
  get peer(): PeerServices {
    return this.#state.peer;
  }

  get localPeerId(): string {
    return this.#state.peer.localPeerId;
  }

  /** The §6.13(b) outbound seam — non-null when the request arrived over a reentrant connection. */
  get outbound(): OutboundDispatch | null {
    return this.#state.outbound;
  }

  /**
   * The frame budget in force for this request's connection, in bytes; the peer's
   * configured default for an in-process dispatch with no connection. Read it when
   * sizing a response — a literal is wrong even when it equals the default.
   */
  frameBudget(): number {
    return this.#state.connection?.maxFrameBytes ?? this.#state.peer.maxFrameBytes;
  }

  /**
   * The §6.8a execution context for a tree write this request causes. Pass it to
   * `EntityTree.put` / `remove` so an emit consumer sees the caller rather than an
   * autonomous write.
   */
  emitContext(): EmitContext {
    const s = this.#state;
    const x = s.execute;
    return {
      ...(x.chainId !== null ? { chainId: x.chainId } : {}),
      ...(x.parentChainId !== null ? { parentChainId: x.parentChainId } : {}),
      ...(s.author !== null ? { author: s.author } : {}),
      ...(s.callerCapability !== null ? { callerCapability: s.callerCapability.contentHash } : {}),
      requestId: x.requestId,
      ...(x.bounds !== null ? { bounds: x.bounds } : {}),
      ...(x.cascadeDepth !== null ? { cascadeDepth: x.cascadeDepth } : {}),
      ...(s.handlerGrant !== null ? { handlerGrant: s.handlerGrant.contentHash } : {}),
      handlerPattern: s.pattern,
      operation: x.operation,
    };
  }

  /**
   * `SDK-OPERATIONS` §11.3 SEC-3 — whether this request's AUTHOR is a granter in the
   * verified authority chain of the capability `capHash` names. `false` without an
   * author, and for anything unresolvable or unverifiable.
   */
  identityInAuthorityChain(capHash: Uint8Array): boolean {
    const s = this.#state;
    if (s.author === null) {
      return false;
    }
    return ChainVerifier.identityInAuthorityChain(
      s.envelope,
      s.peer.contentStore,
      s.peer.localPeerId,
      capHash,
      s.author,
      s.peer.nowMs,
    );
  }

  /**
   * Dispatch an EXECUTE to a LOCAL handler, in-process, through the same §6.6
   * resolution, §5.2 `check_permission`, handler-grant validation and body selection a
   * wire EXECUTE takes — under `request.capability`, or the caller's capability by
   * default, and never past it (see {@link LocalExecute.capability}). The EXECUTE
   * signature check is not repeated: the author is this request's, already
   * authenticated. Every failure is a status: `400 invalid_request` (foreign namespace,
   * connect path, malformed uri), `403 capability_denied`, `404 handler_not_found`,
   * `429 bounds_exceeded` past {@link MAX_LOCAL_DISPATCH_DEPTH}.
   */
  dispatchExecute(request: LocalExecute): Promise<HandlerResult> {
    return this.#state.dispatchLocal(request);
  }

  /** @internal The nesting depth of this dispatch (0 for a wire request). */
  get depth(): number {
    return this.#state.depth;
  }
}

/**
 * @internal Hand out the constructing function — ONCE. The dispatcher module claims it as
 * it loads; every later call throws {@link ContextForgeryError}. Not re-exported from the
 * package.
 */
export function claimDispatchContextFactory(): (state: DispatchContextState) => DispatchContext {
  if (factoryClaimed) {
    throw new ContextForgeryError("the DispatchContext factory has already been claimed by the dispatcher");
  }
  factoryClaimed = true;
  return (state) => new DispatchContext(TOKEN, state);
}
