import { type Socket } from "node:net";
import { ConnectionBrokenError, EntityCoreError, EntityProtocolError, RecvTimeoutError } from "../errors.js";
import { decodeSalvage } from "../codec/canonical-cbor.js";
import { Ecf, Envelope, Execute, ExecuteResponse, TypeNames } from "../model/index.js";
import { type ConnectionState, Deferred } from "../handlers/index.js";
import { type Dispatcher } from "../dispatch/index.js";
import {
  DEFAULT_MAX_FRAME_BYTES,
  framingRefusal,
  preAdmissionRefusal,
  readFrames,
  writeFrame,
} from "./frame-codec.js";

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
    // Publish the budget on the connection state so a handler body can read the limit
    // its response will actually be measured against. Written here rather than passed
    // to `ConnectionState`'s constructor because this is the only object that knows
    // the effective value.
    this.#state.maxFrameBytes = maxFrameBytes;
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
            // A COMPLETE frame the decoder refused. The framing is intact, so we answer
            // and KEEP SERVING — and the refusal MUST be a status rather than silence
            // (§4.11; §4.9(c) says the same from the other direction). This used to
            // `break`, closing the connection: one bad frame then took every later
            // request on it with it, which is where this peer's 81 cascade FAILs came
            // from.
            //
            // THE CODE IS THE CAUSE'S (§4.11, §5.2a). This answered `non_canonical_ecf`
            // for every cause until 0.8.2.24/.25 pinned them apart: a mis-keyed
            // `included` entry is `400 hash_mismatch` (its encoding is canonical — what
            // is false is the claim the key makes), a tag-policy violation keeps
            // `non_canonical_ecf`, and everything else that never becomes an Envelope is
            // `400 invalid_request`.
            await this.#refusePreAdmission(this.#salvageRequestId(frame), preAdmissionRefusal(e));
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
          // §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
          // invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare
          // close — that is indistinguishable from a network fault."
          //
          // §3.3 read "the connection MUST be closed", assigning no code and requiring
          // no frame, and this loop did exactly that: a bare `break`. This is a
          // PRE-ADMISSION refusal — the root is not an EXECUTE, so nothing was ever
          // admitted and §4.9(c) does not reach it. §9.1's floor row that MANDATED the
          // bare close was REPLACED at the same revision (N18).
          //
          // The request_id is read best-effort: an arbitrary root type is under no
          // obligation to carry one, and §4.11 licenses the uncorrelated frame exactly
          // there. We do NOT close — on a multiplexed connection that would cost every
          // ADMITTED in-flight request its response, and §4.11 leaves the close to us.
          await this.#refusePreAdmission(Ecf.optText(envelope.root.data, "request_id") ?? "", {
            status: 400,
            code: "invalid_request",
            message: "root entity is neither EXECUTE nor EXECUTE_RESPONSE",
          });
        }
      }
    } catch (e) {
      // The stream is desynchronized on both REFUSABLE arms — an oversize body was never
      // drained, a truncated one never arrived — so the coded frame goes out and THEN the
      // connection closes. §4.11 makes the frame mandatory and leaves the close to us;
      // closing is the only sound choice once the framing is lost, and it is a CHOICE
      // rather than an alternative to answering. An ordinary hangup is not a refusal and
      // gets nothing, which is what `framingRefusal` separates.
      if (framingRefusal(e)) {
        // §4.11's best-effort UNCORRELATED form: no request_id can be recovered from a
        // frame whose body never arrived, and guessing one would correlate the refusal to
        // somebody else's in-flight request.
        await this.#refusePreAdmission("", preAdmissionRefusal(e));
      }
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
   * Recover ONLY the `request_id` from a frame the strict decoder rejected, so the refusal
   * can be delivered CORRELATED rather than as §4.11's uncorrelated best-effort frame.
   * `""` when nothing is recoverable.
   *
   * The frame stays rejected: nothing is built from it, nothing is stored, and a tag is
   * never interpreted — the salvage decode exists solely to read back the correlation key.
   * The envelope and entity-wrapper shapes are fixed maps with no legal tag position, so a
   * frame whose ONLY defect is a tag inside some entity's `data` still has a structurally
   * sound root — which is exactly the case worth recovering, and the one CAP-6a's `>2^64`
   * half arrives as (a bignum can only reach a peer as a major-type-6 tag).
   */
  #salvageRequestId(frame: Uint8Array): string {
    try {
      const salvaged = decodeSalvage(frame);
      const root = Ecf.require(salvaged, "root");
      return Ecf.requireText(Ecf.require(root, "data"), "request_id");
    } catch {
      return "";
    }
  }

  /**
   * Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
   * refused BEFORE it becomes an admitted request.
   *
   * *"A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
   * wire `[MUST]` — correlated by `request_id` where the id is available, and otherwise as
   * a best-effort coded frame carrying no correlation."*
   *
   * §4.9(c)'s deliver-or-signal rule is scoped to *"every request the peer ADMITS"* and
   * therefore reaches none of these, which is why §4.11 exists. Both of the non-conformant
   * behaviours it names separately were present on this peer: DROPPING the frame (the
   * un-salvageable decode arm and the partial trailing frame, *"the weaker of the two
   * precisely because nothing surfaces it"*) and CLOSING with no coded frame (the oversize
   * arm and the non-EXECUTE root's bare `break`).
   *
   * AN EMPTY `requestId` IS THE BEST-EFFORT FORM, not a bug: it is what the section
   * prescribes where no id can be recovered.
   */
  async #refusePreAdmission(
    requestId: string,
    refusal: { status: number; code: string; message: string },
  ): Promise<void> {
    try {
      const response = ExecuteResponse.error(requestId, refusal.status, refusal.code, refusal.message);
      await this.#write(new Envelope(response.entity, []));
    } catch {
      // A write failure here is a dead socket, not a protocol decision; the read loop's
      // own error handling tears the connection down on the next iteration.
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
