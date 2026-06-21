import { type Socket } from "node:net";
import { concatBytes } from "../codec/bytes.js";
import { WireProtocolError } from "../errors.js";

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
 * Yield complete frames from a socket, buffering partial reads across `data`
 * chunks. The generator ends on a clean EOF at a frame boundary (the peer closed);
 * a partial trailing frame is silently dropped (the connection is gone). Throws
 * {@link WireProtocolError} on an over-limit length prefix.
 */
export async function* readFrames(socket: Socket, maxFrameBytes: number): AsyncGenerator<Uint8Array> {
  let buffer = new Uint8Array(0);
  for await (const chunk of socket) {
    buffer = concatBytes(buffer, chunk as Uint8Array);
    while (buffer.length >= 4) {
      const length = new DataView(buffer.buffer, buffer.byteOffset, 4).getUint32(0, false);
      if (length > maxFrameBytes) {
        throw new WireProtocolError(`frame length ${length} exceeds limit ${maxFrameBytes}`);
      }
      if (buffer.length < 4 + length) {
        break; // wait for more bytes
      }
      yield buffer.slice(4, 4 + length);
      buffer = buffer.slice(4 + length);
    }
  }
}
