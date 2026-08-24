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
    if (payload.length === 0) { sock.end(); sockets.delete(connId); }
    else sock.write(payload);
  });
  ws.on("close", () => { if (peer === ws) peer = null; });
  ws.on("error", () => { if (peer === ws) peer = null; });
});

// ---- TCP side: the oracle dials here ----
const server = net.createServer((sock) => {
  sock.setNoDelay(true);
  const connId = nextId++;
  sockets.set(connId, sock);
  sock.on("data", (chunk) => toPeer(connId, chunk));            // raw bytes → peer
  sock.on("close", () => { toPeer(connId, Buffer.alloc(0)); sockets.delete(connId); }); // close signal
  sock.on("error", () => { sockets.delete(connId); });
});
server.on("error", (e) => { process.stderr.write("bridge tcp error: " + e.message + "\n"); process.exit(1); });
server.listen(EC_PORT, HOST, () => {
  process.stdout.write("BRIDGE-LISTENING tcp:" + EC_PORT + " ws:" + WS_PORT + "\n");
});
