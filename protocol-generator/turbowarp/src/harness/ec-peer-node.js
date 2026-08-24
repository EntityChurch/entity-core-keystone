// ec-peer-node — a HEADLESS stand-in for the TurboWarp peer, used to prove the
// sandboxed-peer-via-bridge architecture against the real oracle BEFORE authoring the
// .sb3. It does exactly what the Scratch custom extension will do:
//   • connect OUT to the bridge over a WebSocket (the only transport a sandbox has)
//   • use the browser-bundle core (createKernel / newSession) — the SAME delegated
//     engine the extension loads
//   • §1.6-frame the per-connId byte streams and route via the session (§6.5 dispatch /
//     §6.11 reentry)
// The Scratch blocks author the same calls; the stage adds the visualization.
//
// Run (node24, after the bundle is built and the bridge is up):
//   WS_URL=ws://127.0.0.1:7802 node harness/ec-peer-node.js

// Load the SELF-CONTAINED browser bundle (esbuild IIFE, @noble inlined) — the exact
// artifact the Scratch extension loads — rather than the source (which would need
// @noble resolvable in node_modules). Proves the shipped bundle, not just the source.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const __dirname = dirname(fileURLToPath(import.meta.url));
(0, eval)(readFileSync(join(__dirname, "..", "dist", "ec-core-browser.js"), "utf8"));
const { createKernel, newSession } = globalThis.EntityCore;

const WS_URL = process.env.WS_URL || "ws://127.0.0.1:7802";
const kernel = createKernel({ debugOpenGrants: true, validate: true });

// connId -> { session, buffer }
const conns = new Map();

const ws = new WebSocket(WS_URL);
ws.binaryType = "arraybuffer";

function sendToBridge(connId, payload) {
  const msg = Buffer.allocUnsafe(4 + payload.length);
  msg.writeUInt32BE(connId >>> 0, 0);
  if (payload.length) Buffer.from(payload).copy(msg, 4);
  ws.send(msg);
}

function connFor(connId) {
  let c = conns.get(connId);
  if (!c) {
    // sendFrame for this logical connection: §1.6-frame + tag with connId + ship over WS.
    const sendFrame = (bytes) => {
      const b = Buffer.from(bytes);
      const framed = Buffer.allocUnsafe(4 + b.length);
      framed.writeUInt32BE(b.length, 0);
      b.copy(framed, 4);
      sendToBridge(connId, framed);
    };
    c = { session: newSession(kernel, sendFrame), buffer: Buffer.alloc(0) };
    conns.set(connId, c);
  }
  return c;
}

async function onFrame(c, connId, frame) {
  const kind = c.session.classify(frame);
  if (kind === "execute") {
    try {
      const { responseBytes, flipped } = await c.session.dispatch(frame);
      const b = Buffer.from(responseBytes);
      const framed = Buffer.allocUnsafe(4 + b.length);
      framed.writeUInt32BE(b.length, 0);
      b.copy(framed, 4);
      sendToBridge(connId, framed);
      // No reverse-auth leg needed: the oracle is always the initiator (proven in the
      // Node-RED peer — connectivity passes without it), so `flipped` needs no latch here.
      void flipped;
    } catch (_) { /* §6.5: a dispatch fault must not hang the peer */ }
  } else if (kind === "response") {
    c.session.routeResponse(frame);
  }
  // invalid → drop
}

ws.addEventListener("open", () => process.stdout.write("PEER-WS-OPEN\n"));
ws.addEventListener("message", (ev) => {
  const buf = Buffer.from(ev.data);
  if (buf.length < 4) return;
  const connId = buf.readUInt32BE(0);
  const payload = buf.subarray(4);
  if (payload.length === 0) { // close
    const c = conns.get(connId);
    if (c) { c.session.dispose(); conns.delete(connId); }
    return;
  }
  const c = connFor(connId);
  c.buffer = Buffer.concat([c.buffer, payload]);
  // Extract complete §1.6 frames from the per-connId byte stream.
  while (c.buffer.length >= 4) {
    const len = c.buffer.readUInt32BE(0);
    if (c.buffer.length < 4 + len) break;
    const frame = Buffer.from(c.buffer.subarray(4, 4 + len));
    c.buffer = c.buffer.subarray(4 + len);
    void onFrame(c, connId, frame);
  }
});
ws.addEventListener("error", (e) => process.stderr.write("peer ws error: " + (e && e.message) + "\n"));
ws.addEventListener("close", () => process.stdout.write("PEER-WS-CLOSE\n"));
