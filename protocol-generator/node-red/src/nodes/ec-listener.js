"use strict";
/**
 * ec-listener — the AUTHORED transport ingress/egress (§1.6 framing + the TCP
 * server). This is the "one transport-coupled corner"; TurboWarp swaps exactly
 * this node for a WebSocket variant (the A-NR-transport separability evidence).
 *
 * Owns: net.createServer on the peer port; per-connection frame buffering (4-byte
 * BE length prefix, 16 MiB cap §1.6); per-connection state (handshake progress).
 * Emits one msg per complete inbound frame: { payload:<cbor Buffer>, conn:<id>,
 * _connState, _reply }. Receives response msgs on its input (payload+conn) and
 * writes a framed response to that connection.
 *
 * The codec/crypto is NOT here — payload bytes flow on to the authored decode →
 * dispatch graph, which delegates de/encode to the bridge (global.get("ec")).
 */

const net = require("node:net");
const path = require("node:path");
const { createKernel } = require(path.join(__dirname, "..", "lib", "peer-kernel.js"));
const { newSession } = require(path.join(__dirname, "..", "lib", "session.js"));
// The two §4.11 framing causes. This node OWNS the length prefix, so it is the only
// place that can detect them — and it hands them to the delegated classification table
// (via session.refuseFramingBytes) rather than hard-coding two more codes beside it.
const ec = require(path.join(__dirname, "..", "lib", "codec-bridge.js"));

const MAX_FRAME_BYTES = 16 * 1024 * 1024; // §1.6 SHOULD

// One delegated kernel (peer identity + §6.5 engine) shared across connections.
let sharedKernel = null;
function kernelFor(settings) {
  if (sharedKernel === null) {
    sharedKernel = createKernel({
      peerName: settings.peerName,
      validate: settings.validate !== false,
      debugOpenGrants: settings.debugOpenGrants === true,
    });
  }
  return sharedKernel;
}

module.exports = function (RED) {
  function EcListenerNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    const settings = RED.settings.entityCore || {};
    const port = Number(config.port) || settings.port || 7801;
    const host = "127.0.0.1";
    const kernel = kernelFor(settings);

    // conn id -> { socket, buffer, state }
    const conns = new Map();
    let nextId = 1;

    function writeFrame(socket, payload) {
      // Single concat write: one syscall, and the prefix+payload are inherently
      // contiguous on the wire (no interleave window) under concurrent dispatch.
      const framed = Buffer.allocUnsafe(4 + payload.length);
      framed.writeUInt32BE(payload.length, 0);
      payload.copy(framed, 4);
      socket.write(framed);
    }

    // `allowHalfOpen: true` IS A §4.11 REQUIREMENT ON NODE, NOT A TUNING KNOB. A
    // truncated frame is only knowable at END-OF-STREAM, and Node's default ends the
    // server's write side the moment the client's FIN arrives — so the runtime REFUSES
    // the mandatory coded response with "This socket has been ended by the other party"
    // and no line of this file is wrong. Go's TCPConn has the behaviour by default,
    // which is exactly why neither 0.8.2.25 vanguard needed the line and neither would
    // have predicted it; the BEAM spells the same requirement `exit_on_close: false`.
    // The cost is that WE now own the close, which every arm below does explicitly.
    /**
     * Put §4.11's best-effort UNCORRELATED coded frame on the wire for a framing refusal.
     *
     * There is no request_id by construction — no frame ever arrived — and §4.11
     * PRESCRIBES the uncorrelated form for exactly that case rather than tolerating it:
     * an uncorrelated coded frame still tells the sender its frame was REFUSED rather
     * than lost, which is the distinction a silent drop destroys.
     *
     * The write may fail on the truncation arm, because the client has already sent FIN
     * and may be gone. That is why the result is not checked: the obligation is to EMIT.
     */
    function refuse(entry, err) {
      try {
        const bytes = entry.session.refuseFramingBytes(err);
        if (bytes) writeFrame(entry.socket, Buffer.from(bytes));
      } catch (_) {
        /* best-effort: the socket may already be gone */
      }
    }

    const server = net.createServer({ allowHalfOpen: true }, (socket) => {
      socket.setNoDelay(true);
      const id = "c" + nextId++;
      // Per-connection session (registered by id in the shared registry). sendFrame
      // is the authored transport egress used both for responses and for direct
      // originations (leg-3, dispatch-outbound).
      const session = newSession(kernel, id, (bytes) => writeFrame(socket, Buffer.from(bytes)));
      const entry = { socket, buffer: Buffer.alloc(0), session };
      conns.set(id, entry);
      // §4.1: leg-3 (the responder's own reverse authenticate) is OPTIONAL and
      // reachability-gated — a responder MUST NOT proactively send it to an
      // initiator that hasn't indicated it accepts inbound dispatch. Sending it
      // unconditionally on every accept corrupts a client-style (request/response-
      // only) initiator's next read, e.g. the RT-6 replay probe reads the
      // unsolicited leg-3 EXECUTE instead of its real response and scores a
      // status=0 decode failure. session.start() stays defined for when the
      // deferred reachability-signal mechanism lands; do not call it here.

      socket.on("data", (chunk) => {
        entry.buffer = Buffer.concat([entry.buffer, chunk]);
        // Split complete frames (authored framing, mirrors frame-codec.ts readFrames).
        while (entry.buffer.length >= 4) {
          const length = entry.buffer.readUInt32BE(0);
          if (length > MAX_FRAME_BYTES) {
            // §4.11 + §4.10(a) N14: the coded frame goes out and THEN the connection
            // closes. This used to be a bare `socket.destroy()` — a close with no frame,
            // which §4.11 names as one of its two separately-non-conformant behaviours
            // and which is indistinguishable from a network fault (§4.6). §4.10(a)'s
            // "SHOULD ... and otherwise MAY close after a best-effort coded frame" became
            // a MUST precisely because this condition is detected AT THE LENGTH PREFIX
            // with the connection intact and nothing spent: the peer has not allocated,
            // has not buffered, and has every resource it needs to answer.
            //
            // The body was never drained, so the framing is lost and closing is still the
            // only sound choice. §4.11 makes it a choice IN ADDITION to answering rather
            // than INSTEAD of it.
            node.error("frame length " + length + " exceeds limit " + MAX_FRAME_BYTES, {});
            refuse(entry, new ec.FrameTooLargeError(
              "frame length " + length + " exceeds limit " + MAX_FRAME_BYTES));
            socket.destroy();
            return;
          }
          if (entry.buffer.length < 4 + length) break; // wait for more
          const payload = entry.buffer.subarray(4, 4 + length);
          entry.buffer = entry.buffer.subarray(4 + length);
          // Emit the frame into the authored graph. Only clone-safe primitives on
          // msg: the CBOR bytes (Buffer) + the connection id (string). Nodes resolve
          // the session from the shared registry by msg.conn.
          node.send({ payload: Buffer.from(payload), conn: id });
        }
      });
      // FIN FROM THE CLIENT. A CLEAN CLOSE AT A FRAME BOUNDARY AND A STREAM THAT ENDED
      // MID-FRAME ARE DIFFERENT EVENTS, and only the frame boundary knows which: the
      // first is an ordinary hangup, owed nothing and answered with nothing; the second
      // is a TRUNCATED frame, which §4.11's framing arm names in as many words ("a length
      // prefix that never completes") and answers `400 invalid_request`. The
      // discriminator is whether any bytes are still buffered — a partial prefix or a
      // partial body means a frame was begun and never finished.
      //
      // Answering both would be worse than answering neither: it turns every ordinary
      // disconnect into a refusal of nothing. This event only exists as a separate hook
      // because `allowHalfOpen` above keeps our write side alive to reach it.
      socket.on("end", () => {
        if (entry.buffer.length > 0) {
          refuse(entry, new ec.TruncatedFrameError(
            "stream ended mid-frame with " + entry.buffer.length + " buffered byte(s)"));
        }
        socket.destroy(); // we own the close now that the runtime does not
      });
      socket.on("error", () => { entry.session.dispose(); conns.delete(id); });
      socket.on("close", () => { entry.session.dispose(); conns.delete(id); });
    });

    server.on("error", (e) => node.error("listener error: " + e.message, {}));
    server.listen(port, host, () => {
      // The readiness line run-s4.sh greps for (mirrors the TS host's LISTENING line).
      node.log("LISTENING " + port);
      // Also to stdout so the harness sees it regardless of Node-RED log routing.
      process.stdout.write("LISTENING " + port + "\n");
      node.status({ fill: "green", shape: "dot", text: "listening :" + port });
    });

    // Input: a response msg from the tail of the dispatch graph (encoded bytes).
    node.on("input", (msg, send, done) => {
      try {
        const entry = msg && msg.conn ? conns.get(msg.conn) : undefined;
        if (entry && msg.payload) {
          writeFrame(entry.socket, Buffer.from(msg.payload));
          // §4.1 leg-3 latch: resolve authResponseSent only AFTER leg-2's response
          // is on the wire, so the reverse authenticate never races it.
          if (msg.flipped) entry.session.afterResponseWritten(true);
        }
        done();
      } catch (e) {
        done(e);
      }
    });

    node.on("close", (done) => {
      for (const { socket } of conns.values()) { try { socket.destroy(); } catch (_) {} }
      conns.clear();
      server.close(() => done());
    });
  }

  RED.nodes.registerType("ec-listener", EcListenerNode);
};
