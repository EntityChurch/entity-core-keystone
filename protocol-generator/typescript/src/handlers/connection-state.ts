import { type Entity } from "../model/index.js";

/** The remote peer's hello data (id + nonce) learned from an inbound hello (§3.8). */
export interface RemoteHelloInfo {
  readonly peerId: string;
  readonly nonce: Uint8Array;
}

/**
 * A promise plus its external resolver — the JS analogue of .NET's
 * `TaskCompletionSource`. Continuations always fire on the microtask queue
 * (`RunContinuationsAsynchronously` is the only JS behavior).
 */
export class Deferred<T> {
  readonly promise: Promise<T>;
  #resolve!: (value: T) => void;
  #reject!: (reason: unknown) => void;
  #settled = false;

  constructor() {
    this.promise = new Promise<T>((resolve, reject) => {
      this.#resolve = resolve;
      this.#reject = reject;
    });
    // A Deferred is often awaited without a local catch (e.g. failed before its
    // consumer attaches); swallow the unhandled-rejection noise — real consumers
    // still see the rejection through `.promise`.
    this.promise.catch(() => {});
  }

  /** Resolve once; later calls are no-ops (the `TrySetResult` semantics). */
  resolve(value: T): void {
    if (!this.#settled) {
      this.#settled = true;
      this.#resolve(value);
    }
  }

  /** Reject once; later calls are no-ops (the `TrySetException` semantics). */
  reject(reason: unknown): void {
    if (!this.#settled) {
      this.#settled = true;
      this.#reject(reason);
    }
  }
}

/**
 * Per-connection handshake state (V7 §4). The connection handler enforces ordering
 * against this — `hello` before `authenticate` (§4.2) — and rejects further
 * connection requests once {@link established} (status 409). Connection state is
 * per-connection; a new connection needs a fresh handshake.
 *
 * (Single-threaded JS: the C# `lock`-guarded booleans are plain mutable fields —
 * no two callbacks run concurrently on one connection.)
 */
export class ConnectionState {
  /** True once a valid `hello` has been processed on this connection. */
  helloReceived = false;

  /** True once authentication completed and the initial capability was issued. */
  established = false;

  /** The remote peer's id, learned from its `hello` / `authenticate`. */
  remotePeerId: string | null = null;

  /** The remote peer's `system/peer` entity, learned at authenticate. */
  remotePeerEntity: Entity | null = null;

  /**
   * The nonce this peer put in its own `hello` on this connection (the challenge).
   * The remote's `authenticate` MUST echo it back; verifying the echo binds the
   * proof-of-possession to *this* connection's challenge (§3.8, §4.6 PoP step 1)
   * and defeats cross-connection signature replay (F12).
   */
  sentNonce: Uint8Array | null = null;

  /**
   * Completed by the connect handler when an inbound `hello` is processed
   * (responder role). The reverse-direction handshake driver awaits this to learn
   * the remote's nonce before sending its own `authenticate` (§4.1 E3).
   */
  readonly inboundHello = new Deferred<RemoteHelloInfo>();

  /**
   * Completed after this peer (responder role) has written the EXECUTE_RESPONSE to
   * the initiator's `authenticate` (§4.1 leg 2). The reverse-direction handshake
   * driver awaits this before sending its own `authenticate` EXECUTE (leg 3), so
   * leg 3 never races ahead of leg 2's response on the wire — the §4.1 ordering a
   * sequential initiator (e.g. validate-peer) depends on.
   */
  readonly authResponseSent = new Deferred<void>();
}
