import { type Socket } from "node:net";
import { ConnectionBrokenError, EntityCoreError, EntityProtocolError, RecvTimeoutError } from "../errors.js";
import { decodeSalvage } from "../codec/canonical-cbor.js";
import { Ecf, Envelope, Execute, ExecuteResponse, TypeNames } from "../model/index.js";
import { type ConnectionState, Deferred } from "../handlers/index.js";
import { type Dispatcher } from "../dispatch/index.js";
import { DEFAULT_MAX_FRAME_BYTES, readFrames, writeFrame } from "./frame-codec.js";

/**
 * A single peer-to-peer connection over a socket. Implements the §6.11 transport
 * reentry contract: one reader loop demultiplexes inbound frames, routing
 * EXECUTE_RESPONSEs to awaiting callers by `request_id` (N7) and dispatching
 * inbound EXECUTEs *concurrently* with outbound sends (N6) — inbound processing
 * never blocks on outbound dispatch. Per-request deadlines are enforced at the
 * request layer, not via a connection-wide deadline (§6.11(c)).
 *
 * (Single-threaded JS: the C# `SemaphoreSlim` write lock becomes a promise-chain
 * mutex; the `ConcurrentDictionary` of pending requests becomes a plain `Map`.)
 */
export class PeerConnection {
  readonly #socket: Socket;
  readonly #dispatcher: Dispatcher;
  readonly #state: ConnectionState;
  readonly #maxFrameBytes: number;
  readonly #pending = new Map<string, Deferred<Envelope>>();
  #requestCounter = 0;
  #closed = false;
  #writeTail: Promise<void> = Promise.resolve();
  #readerDone: Promise<void> = Promise.resolve();

  constructor(socket: Socket, dispatcher: Dispatcher, state: ConnectionState, maxFrameBytes = DEFAULT_MAX_FRAME_BYTES) {
    this.#socket = socket;
    this.#dispatcher = dispatcher;
    this.#state = state;
    this.#maxFrameBytes = maxFrameBytes;
  }

  get state(): ConnectionState {
    return this.#state;
  }

  /** Generate a connection-scoped unique request id (§6.11 informative). */
  nextRequestId(): string {
    return "req-" + ++this.#requestCounter;
  }

  /** Begin the reader loop. Returns immediately; reading proceeds in the background. */
  start(): void {
    this.#readerDone = this.#readLoop();
  }

  /**
   * Send an EXECUTE envelope and await its correlated EXECUTE_RESPONSE (§6.11).
   * Rejects with {@link RecvTimeoutError} on deadline, or {@link
   * ConnectionBrokenError} if the connection drops first.
   */
  async sendRequest(request: Envelope, timeoutMs: number): Promise<Envelope> {
    const requestId = new Execute(request.root).requestId;
    if (this.#pending.has(requestId)) {
      throw new EntityProtocolError(`duplicate in-flight request_id '${requestId}'`);
    }
    const deferred = new Deferred<Envelope>();
    this.#pending.set(requestId, deferred);

    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await this.#write(request);
      timer = setTimeout(
        () => deferred.reject(new RecvTimeoutError(`no response for request '${requestId}' within ${timeoutMs}ms`)),
        timeoutMs,
      );
      return await deferred.promise;
    } finally {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      this.#pending.delete(requestId);
    }
  }

  async #write(envelope: Envelope): Promise<void> {
    const bytes = envelope.encode();
    // Promise-chain mutex: each write awaits the previous one's release, so frames
    // never interleave on the wire even under concurrent inbound + outbound sends.
    const prev = this.#writeTail;
    let release!: () => void;
    this.#writeTail = new Promise<void>((r) => {
      release = r;
    });
    await prev;
    try {
      await writeFrame(this.#socket, bytes);
    } finally {
      release();
    }
  }

  async #readLoop(): Promise<void> {
    try {
      for await (const frame of readFrames(this.#socket, this.#maxFrameBytes)) {
        let envelope: Envelope;
        try {
          envelope = Envelope.decode(frame);
        } catch (e) {
          if (e instanceof EntityCoreError) {
            // §6.3: "Rejection returns `400 non_canonical_ecf`" — the frame is
            // refused (above), and that refusal MUST be a STATUS, not silence.
            // This used to `break`, closing the connection: one bad frame then took
            // every later request on it with it, which is where this peer's 81
            // cascade FAILs came from. §4.9(c) deliver-or-signal says the same from
            // the other direction. Answer, then keep serving.
            await this.#rejectNonCanonical(frame);
            continue;
          }
          throw e;
        }

        const rootType = envelope.root.type;
        if (rootType === TypeNames.ExecuteResponse) {
          this.#routeResponse(envelope);
        } else if (rootType === TypeNames.Execute) {
          // N6: dispatch concurrently — do NOT block the reader on the handler.
          void this.#dispatchInbound(envelope);
        } else {
          break; // neither EXECUTE nor EXECUTE_RESPONSE → invalid, close (§3.3)
        }
      }
    } catch {
      // Read error → close.
    } finally {
      this.#failPending(new ConnectionBrokenError("connection closed"));
      this.#destroy();
    }
  }

  #routeResponse(envelope: Envelope): void {
    try {
      const requestId = new ExecuteResponse(envelope.root).requestId;
      this.#pending.get(requestId)?.resolve(envelope);
    } catch (e) {
      if (!(e instanceof EntityProtocolError)) {
        throw e;
      }
      // Malformed response root — no request_id to route to; drop.
    }
  }

  async #dispatchInbound(request: Envelope): Promise<void> {
    try {
      const establishedBefore = this.#state.established;
      // Pass this connection as the §6.11 reentry sender so a handler servicing this
      // inbound EXECUTE can originate an outbound EXECUTE back over it (§6.13(b), §4.8).
      const response = await this.#dispatcher.dispatch(request, this.#state, this);
      await this.#write(response);

      // §4.1 ordering signal: historically gated the responder's own reverse
      // authenticate (leg 3) so it never raced ahead of leg 2's response on the
      // wire. Leg 3 is no longer sent proactively (see Peer#onInbound — §4.1
      // pins it OPTIONAL/reachability-gated, and a responder that sends it
      // unconditionally corrupts a client-style initiator's next read, which is
      // exactly the RT-6 handshake_nonce_single_use failure this connection type
      // hit: the oracle's probe reads the unsolicited leg-3 EXECUTE instead of
      // its own replay's response and disconnects before the real response is
      // written). Kept resolved for any future consumer; currently has none.
      if (!establishedBefore && this.#state.established) {
        this.#state.authResponseSent.resolve();
      }
    } catch {
      // A failed write or dispatch crash tears the connection down rather than
      // hanging it (V7 §6.5 finding 1: an inbound EXECUTE must never hang the
      // peer). This catch is intentionally silent on the wire/production path,
      // but that silence is exactly what made the RT-6 leg-3 collision above
      // hard to root-cause — if you're chasing a mystery connection-close here,
      // temporarily log `e` rather than assuming there's nothing to see.
      this.#destroy();
    }
  }

  /**
   * Answer a frame the strict decoder rejected with `400 non_canonical_ecf` (§6.3),
   * recovering ONLY the `request_id` so the sender can correlate the refusal.
   *
   * The frame stays rejected: nothing is built from it, nothing is stored, and the tag
   * is never interpreted — the salvage decode exists solely to read back the correlation
   * key. If even the request_id is unrecoverable there is nobody to answer, so the frame
   * is dropped; that is the one case where silence is all that is available.
   */
  async #rejectNonCanonical(frame: Uint8Array): Promise<void> {
    let requestId: string;
    try {
      // envelope → root (an entity wrapper: {type, data, content_hash}) → data →
      // request_id. The envelope and entity-wrapper shapes are fixed maps with no
      // legal tag position, so a frame whose ONLY defect is a tag inside some
      // entity's `data` still has a structurally sound root — which is exactly the
      // case worth recovering, and the one CAP-6a's >2^64 half arrives as.
      const salvaged = decodeSalvage(frame);
      const root = Ecf.require(salvaged, "root");
      requestId = Ecf.requireText(Ecf.require(root, "data"), "request_id");
    } catch {
      return; // no correlatable request_id — nothing to answer
    }
    try {
      const response = ExecuteResponse.error(
        requestId,
        400,
        "non_canonical_ecf",
        "frame is not canonical ECF (§6.3): CBOR tags are forbidden anywhere in an entity",
      );
      await this.#write(new Envelope(response.entity, []));
    } catch {
      // A write failure here is a dead socket, not a protocol decision; the read
      // loop's own error handling tears the connection down on the next iteration.
    }
  }

  #failPending(error: Error): void {
    for (const deferred of this.#pending.values()) {
      deferred.reject(error);
    }
    this.#pending.clear();
  }

  #destroy(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#socket.destroy();
  }

  async dispose(): Promise<void> {
    this.#destroy();
    try {
      await this.#readerDone;
    } catch {
      // Reader teardown errors are expected during close.
    }
  }
}
