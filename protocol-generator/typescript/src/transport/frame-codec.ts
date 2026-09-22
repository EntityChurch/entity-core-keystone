// `import type` — not `import { type Socket }`. The inline-type form leaves the
// STATEMENT a value import, so tsc emits a side-effect `import {} from "node:net"`
// into dist/, and esbuild's BROWSER bundle then cannot resolve a Node builtin. That
// is the whole of turbowarp's "bundle build failed": the one peer nobody could
// measure was blocked by an emitted no-op import of a type this file only names.
import type { Socket } from "node:net";
import { concatBytes } from "../codec/bytes.js";
import { HashMismatchError, TagRejectedError, WireProtocolError } from "../errors.js";

/**
 * TCP wire framing (V7 §1.6): a 4-byte big-endian length prefix followed by that
 * many bytes of CBOR payload. A default 16 MiB frame limit bounds inbound
 * allocation (§1.6 SHOULD).
 *
 * This is the one Node-coupled corner of the wire path (the codec/crypto layers
 * stay pure-JS); a browser build swaps the {@link Socket} for a WebSocket without
 * touching the framing rule.
 */

/** Default maximum frame payload size (§1.6) — bounds inbound allocation. */
export const DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024;

/**
 * A length prefix over the connection's bound (§4.10(a)).
 *
 * Distinguished from {@link TruncatedFrameError} because §4.11 gives the two DIFFERENT
 * codes: this one is `413 payload_too_large`, and since 0.8.2.25 (N14) emitting it is a
 * MUST rather than a SHOULD — the condition is detected at the length prefix with the
 * connection intact and nothing spent, so the permissive mood had nothing to license.
 */
export class FrameTooLargeError extends WireProtocolError {
  constructor(message: string) {
    super(message);
    this.name = "FrameTooLargeError";
    Object.setPrototypeOf(this, FrameTooLargeError.prototype);
  }
}

/**
 * A frame that never completed: a prefix declaring `n` bytes followed by fewer, or a
 * partial length prefix. §4.11's framing arm names this input outright — *"un-parseable,
 * truncated or non-canonical CBOR, or a length prefix that never completes"* →
 * `400 invalid_request`.
 *
 * A SEPARATE TYPE FROM A CLEAN EOF BECAUSE THE TWO ARE DIFFERENT EVENTS AND THE SOCKET
 * ITERATOR COLLAPSES THEM. A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed
 * nothing; a stream that ends MID-FRAME is a REFUSAL and is owed a coded frame. Both end
 * the `for await`, so the distinction can only be made here, where the frame boundary is
 * known — and getting it wrong in the other direction would answer a 400 to every peer that
 * simply hangs up. This generator previously dropped a partial trailing frame in silence,
 * which is §4.11's other named non-conformant behaviour.
 */
export class TruncatedFrameError extends WireProtocolError {
  constructor(message: string) {
    super(message);
    this.name = "TruncatedFrameError";
    Object.setPrototypeOf(this, TruncatedFrameError.prototype);
  }
}

/** Write a single length-prefixed frame and resolve once it is flushed to the kernel. */
export function writeFrame(socket: Socket, payload: Uint8Array): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const prefix = new Uint8Array(4);
    new DataView(prefix.buffer).setUint32(0, payload.length, false);
    socket.write(prefix);
    socket.write(payload, (err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Yield complete frames from a socket, buffering partial reads across `data` chunks.
 *
 * The generator ends cleanly ONLY on an EOF at a frame boundary (the peer closed and owes
 * nothing). A stream that ends MID-FRAME throws {@link TruncatedFrameError}, and an
 * over-limit length prefix throws {@link FrameTooLargeError} — both are §4.11 REFUSALS owed
 * a coded response, and the caller emits it. The partial trailing frame used to be dropped
 * in silence, which is the weaker of §4.11's two named non-conformant behaviours precisely
 * because nothing surfaces it.
 */
export async function* readFrames(socket: Socket, maxFrameBytes: number): AsyncGenerator<Uint8Array> {
  let buffer = new Uint8Array(0);
  // `destroyOnReturn: false` IS LOAD-BEARING FOR §4.11, and the default silently defeats
  // the whole section. A bare `for await (const chunk of socket)` installs Node's default
  // async iterator, whose cleanup DESTROYS the stream when the loop body throws — so the
  // refusals below tore the socket down before the caller could answer, AND the resulting
  // `ERR_STREAM_PREMATURE_CLOSE` replaced the thrown error, erasing the CAUSE as well.
  // Measured by instrumenting the caller's catch: it saw `Error/ERR_STREAM_PREMATURE_CLOSE`
  // with `socket.destroyed === true`, never `FrameTooLargeError`. Both halves of §4.11 —
  // "put a coded frame on the wire" and "the code belongs to the cause" — were lost to one
  // defaulted option, and a source read of the throw sites shows nothing wrong.
  for await (const chunk of socket.iterator({ destroyOnReturn: false })) {
    buffer = concatBytes(buffer, chunk as Uint8Array);
    while (buffer.length >= 4) {
      const length = new DataView(buffer.buffer, buffer.byteOffset, 4).getUint32(0, false);
      if (length > maxFrameBytes) {
        throw new FrameTooLargeError(`frame length ${length} exceeds limit ${maxFrameBytes}`);
      }
      if (buffer.length < 4 + length) {
        break; // wait for more bytes
      }
      yield buffer.slice(4, 4 + length);
      buffer = buffer.slice(4 + length);
    }
  }
  // The socket ended. Anything still buffered is a frame that never completed — including
  // a partial length prefix, which is why the test is "any bytes left", not "4 or more".
  if (buffer.length > 0) {
    throw new TruncatedFrameError(`stream ended mid-frame with ${buffer.length} buffered byte(s)`);
  }
}

/**
 * The `(status, code, message)` §4.11 assigns a pre-admission failure's CAUSE.
 *
 * *"The frame obligation belongs to the class; the CODE belongs to the cause `[MUST]`"* — a
 * single code for the class would answer an honest caller under the wrong reason and send
 * them to the wrong layer.
 *
 * | cause | answer | stated at |
 * |---|---|---|
 * | connect-auth proof-of-possession | `401 authentication_failed` | §4.6/§4.7 — the connect handler's, not this function's |
 * | envelope over the configured max | `413 payload_too_large` | §4.10(a), N14 |
 * | resolution integrity (mis-keyed `included`) | `400 hash_mismatch` | §5.2a, §1.8 |
 * | framing / never becomes an Envelope | `400 invalid_request` | §4.7, §4.11 |
 * | root is neither EXECUTE nor EXECUTE_RESPONSE | `400 invalid_request` | §3.3, §4.11 — in the reader, not here |
 *
 * THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that code
 * non-conformant *"on the framing arm"* and gives its reason in the same sentence:
 * `ENTITY-CBOR-ENCODING` *"defines that code for CBOR tag-policy violations specifically"*,
 * which that document still MUSTs at decode time (§6.3). The two rows are disjoint by CAUSE
 * rather than in conflict, and §6.3 says so itself: a tag in a DATA-FIELD position is the
 * policy violation with its own code, while *"the envelope and entity-wrapper CBOR shapes
 * are fixed maps and contain no positions where a tag could legally be placed; any tag
 * encountered in those structures is a structurally invalid frame rejected by ordinary
 * decoder validation"* — i.e. the framing arm. Everything else this decoder calls
 * non-canonical (a non-minimal head, an indefinite length, mis-ordered keys) is genuinely
 * "non-canonical CBOR that never becomes an Envelope" and takes `invalid_request`.
 *
 * ORDER IS LOAD-BEARING: each pair below is subclass/superclass, so the specific arm must
 * be tested first or it can never be reached.
 *
 * The messages are a FIXED TABLE, never the internal exception text: a wire-visible string
 * must stay ASCII (two peers in this cohort have been killed at runtime by a non-ASCII byte
 * in an encoded string, on two unrelated compilers), the internal texts carry section
 * signs, and nothing here echoes attacker-supplied bytes back.
 */
export function preAdmissionRefusal(e: unknown): { status: number; code: string; message: string } {
  if (e instanceof FrameTooLargeError) {
    return { status: 413, code: "payload_too_large", message: "inbound frame exceeds the configured maximum size" };
  }
  if (e instanceof HashMismatchError) {
    return { status: 400, code: "hash_mismatch", message: "an entity was addressed by a hash that does not bind to it" };
  }
  if (e instanceof TagRejectedError) {
    return { status: 400, code: "non_canonical_ecf", message: "CBOR tags are forbidden anywhere in an entity data field" };
  }
  return { status: 400, code: "invalid_request", message: "frame did not decode into an envelope" };
}

/**
 * Whether a {@link readFrames} failure is a REFUSAL owed a coded frame (§4.11) rather than
 * an ordinary end of connection. A closed or reset socket is not a refusal of anything and
 * there is nobody left to answer.
 */
export function framingRefusal(e: unknown): boolean {
  return e instanceof FrameTooLargeError || e instanceof TruncatedFrameError;
}
