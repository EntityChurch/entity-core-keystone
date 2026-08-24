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

    const server = net.createServer((socket) => {
      socket.setNoDelay(true);
      const id = "c" + nextId++;
      // Per-connection session (registered by id in the shared registry). sendFrame
      // is the authored transport egress used both for responses and for direct
      // originations (leg-3, dispatch-outbound).
      const session = newSession(kernel, id, (bytes) => writeFrame(socket, Buffer.from(bytes)));
      const entry = { socket, buffer: Buffer.alloc(0), session };
      conns.set(id, entry);
      session.start(); // kick the delegated responder handshake driver (leg 3)

      socket.on("data", (chunk) => {
        entry.buffer = Buffer.concat([entry.buffer, chunk]);
        // Split complete frames (authored framing, mirrors frame-codec.ts readFrames).
        while (entry.buffer.length >= 4) {
          const length = entry.buffer.readUInt32BE(0);
          if (length > MAX_FRAME_BYTES) {
            node.error("frame length " + length + " exceeds limit " + MAX_FRAME_BYTES, {});
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
