/**
 * ws-tcp-bridge — the WebSocket↔TCP multiplexing bridge that makes a SANDBOXED
 * TurboWarp/Scratch peer reachable by the TCP `validate-peer` oracle (the A-NR-transport
 * resolution). This is the same shape browser-Rust/WASM uses: the sandboxed side can
 * only WebSocket OUT, so the bridge listens on TCP (the oracle dials it) and relays each
 * TCP connection to the peer over one WebSocket, multiplexed by a connection id.
 *
 * Wire between bridge and peer (binary WS messages): [4-byte connId BE][payload].
 *   • payload length > 0  → data (raw TCP bytes, either direction; §1.6 framing is the
 *     peer's job, exactly as over real TCP)
 *   • payload length == 0 → close that logical connection
 *
 * TCP side (oracle):   listens on EC_PORT (default 7801).
 * WS side (peer):      listens on WS_PORT (default 7802); the peer connects OUT to it.
 */

import net from "node:net";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { WebSocketServer } = require("ws");

const EC_PORT = Number(process.env.EC_PORT || 7801);
const WS_PORT = Number(process.env.WS_PORT || 7802);
const HOST = "127.0.0.1";

const sockets = new Map(); // connId -> tcp socket
let nextId = 1;
let peer = null; // the single connected TurboWarp peer WS

function encode(connId, payload) {
  const msg = Buffer.allocUnsafe(4 + payload.length);
  msg.writeUInt32BE(connId >>> 0, 0);
  if (payload.length) payload.copy(msg, 4);
  return msg;
}

function toPeer(connId, payload) {
  if (peer && peer.readyState === peer.OPEN) peer.send(encode(connId, payload));
}

// ---- WS side: the TurboWarp peer connects here ----
const wss = new WebSocketServer({ host: HOST, port: WS_PORT });
wss.on("connection", (ws) => {
  peer = ws;
  process.stdout.write("PEER-CONNECTED\n");
  ws.on("message", (data) => {
    // [connId][payload] from the peer → write to that TCP socket (or close).
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (buf.length < 4) return;
    const connId = buf.readUInt32BE(0);
    const payload = buf.subarray(4);
    const sock = sockets.get(connId);
    if (!sock) return;
    // The peer asking to close. `destroy` rather than `end`: with allowHalfOpen the
    // runtime no longer tears the socket down for us, so an `end` alone would leave the
    // read half open on a connection the peer has already disposed.
    if (payload.length === 0) { sock.destroy(); sockets.delete(connId); }
    else sock.write(payload);
  });
  ws.on("close", () => { if (peer === ws) peer = null; });
  ws.on("error", () => { if (peer === ws) peer = null; });
});

// ---- TCP side: the oracle dials here ----
// `allowHalfOpen: true` IS A §4.11 REQUIREMENT ON NODE, NOT A TUNING KNOB — and it is
// needed HERE rather than in the peer because this is the process that owns the TCP
// socket. A truncated frame is only knowable at END-OF-STREAM, and Node's default ends
// this side's write half the moment the client's FIN arrives, so the peer's `400
// invalid_request` would be composed, shipped over the WebSocket, and then refused by the
// runtime with "This socket has been ended by the other party". Go's TCPConn has the
// behaviour by default, which is why neither 0.8.2.25 vanguard needed the line; the BEAM
// spells the same requirement `exit_on_close: false`. Third peer in this cohort to need it.
const server = net.createServer({ allowHalfOpen: true }, (sock) => {
  sock.setNoDelay(true);
  const connId = nextId++;
  sockets.set(connId, sock);
  sock.on("data", (chunk) => toPeer(connId, chunk));            // raw bytes → peer
  // FIN: signal end-of-stream to the peer and KEEP THE SOCKET. The peer decides whether
  // anything is owed — a partial frame in its buffer means a truncation refusal is on its
  // way back through this socket, and deleting the entry here (as the old `close` handler
  // did) would drop that answer on the floor with no error anywhere.
  sock.on("end", () => { toPeer(connId, Buffer.alloc(0)); });
  sock.on("close", () => { sockets.delete(connId); });
  sock.on("error", () => { sockets.delete(connId); });
});
server.on("error", (e) => { process.stderr.write("bridge tcp error: " + e.message + "\n"); process.exit(1); });
server.listen(EC_PORT, HOST, () => {
  process.stdout.write("BRIDGE-LISTENING tcp:" + EC_PORT + " ws:" + WS_PORT + "\n");
});
