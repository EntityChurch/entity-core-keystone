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
const { createKernel, newSession, FrameTooLargeError, TruncatedFrameError } = globalThis.EntityCore;

// §1.6/§4.10(a): a FINITE maximum inbound payload, checked at the LENGTH PREFIX before
// any body is buffered. There was no cap here at all — a prefix declaring 4 GiB simply
// accumulated forever and the peer answered nothing, which reads as a hang rather than as
// a missing bound. §4.10(a)'s "reject BEFORE fully buffering" is the whole point: the
// condition is knowable from four bytes.
const MAX_FRAME_BYTES = 16 * 1024 * 1024;

const WS_URL = process.env.WS_URL || "ws://127.0.0.1:7802";

// `--debug-open-grants` IS READ FROM argv RATHER THAN HARDCODED, and that is a
// MEASURABILITY fix, not a feature. It was `debugOpenGrants: true` in the source, so this
// harness carried no such flag on its command line — and `tools/arc-probe/run.sh` makes
// exactly one edit to a peer's harness (remove that flag) and REFUSES to run a peer that
// does not carry it rather than guess at its grant configuration. So this peer was the one
// row no arc-probe family reached, published as `not_driven`, and the gap read as a
// property of the substrate when it was a property of one hardcoded boolean.
//
// It stays ON by default here only because run-s4.sh now passes it, exactly as every other
// harness in the cohort does: the census configuration is unchanged and the flag is now
// removable, which is the whole point.
const argv = process.argv.slice(2);
const kernel = createKernel({
  debugOpenGrants: argv.includes("--debug-open-grants"),
  validate: !argv.includes("--no-validate"),
});

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
  } else {
    // §4.11 (0.8.2.25): BOTH remaining kinds are refusals owed a CODED
    // EXECUTE_RESPONSE, and this used to be `// invalid → drop` for both. A silent drop
    // is the weaker of §4.11's two named non-conformant behaviours precisely because
    // nothing surfaces it: the sender blocks to its own §6.11(c) deadline and cannot tell
    // a refusal from a dead peer.
    //
    // The two take DIFFERENT codes. An undecodable frame takes the code its CAUSE is
    // assigned (§5.2a pins a mis-keyed `included` entry to `hash_mismatch` and rules
    // `non_canonical_ecf` non-conformant there); a frame that DECODED and is simply not a
    // request takes `400 invalid_request` and is correlatable, because its request_id is
    // right there in a root we read successfully.
    const bytes = kind === "undecodable"
      ? c.session.refusePreAdmissionBytes(frame)
      : c.session.refuseNonExecuteRootBytes(frame);
    if (bytes) sendFramed(connId, bytes);
  }
}

/** §1.6-frame a response payload and ship it to the bridge for this logical conn. */
function sendFramed(connId, bytes) {
  const b = Buffer.from(bytes);
  const framed = Buffer.allocUnsafe(4 + b.length);
  framed.writeUInt32BE(b.length, 0);
  b.copy(framed, 4);
  sendToBridge(connId, framed);
}

ws.addEventListener("open", () => process.stdout.write("PEER-WS-OPEN\n"));
ws.addEventListener("message", (ev) => {
  const buf = Buffer.from(ev.data);
  if (buf.length < 4) return;
  const connId = buf.readUInt32BE(0);
  const payload = buf.subarray(4);
  if (payload.length === 0) { // the bridge's end-of-stream signal
    const c = conns.get(connId);
    if (c) {
      // A CLEAN CLOSE AT A FRAME BOUNDARY AND A STREAM THAT ENDED MID-FRAME ARE DIFFERENT
      // EVENTS, and only the frame boundary knows which. The first is an ordinary hangup,
      // owed nothing. The second is a TRUNCATED frame, which §4.11's framing arm names in
      // as many words ("a length prefix that never completes") and answers `400
      // invalid_request`. The discriminator is whether any bytes are still buffered.
      //
      // Answering both would be worse than answering neither: every ordinary disconnect
      // would become a refusal of nothing.
      if (c.buffer.length > 0) {
        const bytes = c.session.refuseFramingBytes(new TruncatedFrameError(
          "stream ended mid-frame with " + c.buffer.length + " buffered byte(s)"));
        if (bytes) sendFramed(connId, bytes);
      }
      c.session.dispose();
      conns.delete(connId);
    }
    return;
  }
  const c = connFor(connId);
  c.buffer = Buffer.concat([c.buffer, payload]);
  // Extract complete §1.6 frames from the per-connId byte stream.
  while (c.buffer.length >= 4) {
    const len = c.buffer.readUInt32BE(0);
    if (len > MAX_FRAME_BYTES) {
      // §4.11 + §4.10(a) N14: emit, THEN tear the logical connection down. A bare close
      // is §4.11's other named non-conformant behaviour and is indistinguishable from a
      // network fault (§4.6). The condition is detected at the length prefix with the
      // connection intact and nothing spent, which is exactly why the SHOULD became a
      // MUST — and the body was never drained, so the framing is lost and closing is
      // still right. It is a choice IN ADDITION to answering, not instead of it.
      const bytes = c.session.refuseFramingBytes(new FrameTooLargeError(
        "frame length " + len + " exceeds limit " + MAX_FRAME_BYTES));
      if (bytes) sendFramed(connId, bytes);
      sendToBridge(connId, Buffer.alloc(0)); // ask the bridge to close this conn
      c.session.dispose();
      conns.delete(connId);
      return;
    }
    if (c.buffer.length < 4 + len) break;
    const frame = Buffer.from(c.buffer.subarray(4, 4 + len));
    c.buffer = c.buffer.subarray(4 + len);
    void onFrame(c, connId, frame);
  }
});
ws.addEventListener("error", (e) => process.stderr.write("peer ws error: " + (e && e.message) + "\n"));
ws.addEventListener("close", () => process.stdout.write("PEER-WS-CLOSE\n"));
