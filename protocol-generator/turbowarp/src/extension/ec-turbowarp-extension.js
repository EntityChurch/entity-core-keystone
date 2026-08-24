// ec-turbowarp-extension — the TurboWarp/Scratch custom extension you LOAD in the
// editor. esbuild bundles this (with ec-core-browser inlined → @noble, cborg, the
// §6.5 engine) into ONE self-contained file: dist/entitycore.js. In TurboWarp:
// Add Extension → "Load from URL/file" → entitycore.js. The blocks then appear in the
// palette; wire them on the stage to SEE the protocol run.
//
// The extension owns the transport (WebSocket out to the WS↔TCP bridge — the sandbox
// can't do raw TCP) + §1.6 framing + the delegated §6.5 dispatch, and EXPOSES observable
// state (peer id, open connections, established count, last dispatched path, dispatch
// count) + a "protocol event" edge so the STAGE visualizes the protocol as it runs.
// The .sb3 authors the visualization (sprites/costumes reacting to these reporters).

import { createKernel, newSession, codec } from "./ec-core-browser.js";

class EntityCoreExtension {
  constructor(runtime) {
    this.runtime = runtime;
    this.kernel = null;
    this.ws = null;
    this.conns = new Map(); // connId -> { session, buffer }
    this.state = { peerId: "", open: 0, established: 0, lastPath: "", lastStatus: "", dispatches: 0, tick: 0 };
    this._eventPending = false;
  }

  getInfo() {
    return {
      id: "entitycore",
      name: "entity-core",
      color1: "#7fd4c1",
      color2: "#5bb8a3",
      blocks: [
        { opcode: "connect", blockType: "command", text: "start peer, connect to bridge [URL]",
          arguments: { URL: { type: "string", defaultValue: "ws://localhost:7802" } } },
        { opcode: "disconnect", blockType: "command", text: "stop peer" },
        "---",
        { opcode: "peerId", blockType: "reporter", text: "peer id" },
        { opcode: "openConns", blockType: "reporter", text: "open connections" },
        { opcode: "established", blockType: "reporter", text: "established connections" },
        { opcode: "dispatches", blockType: "reporter", text: "dispatch count" },
        { opcode: "lastPath", blockType: "reporter", text: "last dispatched path" },
        { opcode: "lastStatus", blockType: "reporter", text: "last response status" },
        "---",
        { opcode: "whenEvent", blockType: "hat", text: "when protocol event", isEdgeActivated: false },
        { opcode: "isEstablished", blockType: "Boolean", text: "any connection established?" },
      ],
    };
  }

  // ---- transport + delegated dispatch (mechanical) ----
  connect(args) {
    if (this.ws) return;
    this.kernel = createKernel({ debugOpenGrants: true, validate: true });
    this.state.peerId = this.kernel.identity.peerId;
    const url = args.URL;
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    this.ws = ws;
    ws.addEventListener("message", (ev) => this._onWs(new Uint8Array(ev.data)));
    ws.addEventListener("close", () => { this.ws = null; this.conns.clear(); this._refresh(); });
    ws.addEventListener("error", () => {});
  }

  disconnect() { if (this.ws) { try { this.ws.close(); } catch (_) {} this.ws = null; } this.conns.clear(); this._refresh(); }

  _sendToBridge(connId, payload) {
    const msg = new Uint8Array(4 + payload.length);
    new DataView(msg.buffer).setUint32(0, connId >>> 0, false);
    msg.set(payload, 4);
    if (this.ws && this.ws.readyState === 1) this.ws.send(msg);
  }

  _frame(bytes) {
    const framed = new Uint8Array(4 + bytes.length);
    new DataView(framed.buffer).setUint32(0, bytes.length, false);
    framed.set(bytes, 4);
    return framed;
  }

  _connFor(connId) {
    let c = this.conns.get(connId);
    if (!c) {
      const sendFrame = (bytes) => this._sendToBridge(connId, this._frame(new Uint8Array(bytes)));
      c = { session: newSession(this.kernel, sendFrame), buffer: new Uint8Array(0) };
      this.conns.set(connId, c);
    }
    return c;
  }

  _onWs(buf) {
    if (buf.length < 4) return;
    const connId = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false);
    const payload = buf.subarray(4);
    if (payload.length === 0) { const c = this.conns.get(connId); if (c) { c.session.dispose(); this.conns.delete(connId); } this._refresh(); return; }
    const c = this._connFor(connId);
    const merged = new Uint8Array(c.buffer.length + payload.length);
    merged.set(c.buffer); merged.set(payload, c.buffer.length);
    c.buffer = merged;
    // Extract §1.6 frames.
    while (c.buffer.length >= 4) {
      const len = new DataView(c.buffer.buffer, c.buffer.byteOffset, 4).getUint32(0, false);
      if (c.buffer.length < 4 + len) break;
      const frame = c.buffer.slice(4, 4 + len);
      c.buffer = c.buffer.slice(4 + len);
      this._handle(connId, c, frame);
    }
    this._refresh();
  }

  async _handle(connId, c, frame) {
    const kind = c.session.classify(frame);
    if (kind === "execute") {
      // observe the dispatch path for the stage
      try { this.state.lastPath = new codec.Execute(codec.Envelope.decode(frame).root).uri; } catch (_) {}
      try {
        const { responseBytes } = await c.session.dispatch(frame);
        this.state.dispatches++;
        try { this.state.lastStatus = String(new codec.ExecuteResponse(codec.Envelope.decode(responseBytes).root).status); } catch (_) {}
        this._sendToBridge(connId, this._frame(new Uint8Array(responseBytes)));
        this._event();
      } catch (_) {}
    } else if (kind === "response") {
      c.session.routeResponse(frame);
    }
  }

  _refresh() {
    this.state.open = this.conns.size;
    let est = 0; for (const c of this.conns.values()) if (c.session.connState.established) est++;
    this.state.established = est;
  }

  _event() { this.state.tick++; this._eventPending = true; if (this.runtime && this.runtime.startHats) this.runtime.startHats("entitycore_whenEvent"); }

  // ---- reporters / hats for the stage ----
  peerId() { return this.state.peerId; }
  openConns() { return this.state.open; }
  established() { return this.state.established; }
  dispatches() { return this.state.dispatches; }
  lastPath() { return this.state.lastPath; }
  lastStatus() { return this.state.lastStatus; }
  isEstablished() { return this.state.established > 0; }
  whenEvent() { if (this._eventPending) { this._eventPending = false; return true; } return false; }
}

// TurboWarp/Scratch registration.
if (typeof Scratch !== "undefined" && Scratch.extensions) {
  Scratch.extensions.register(new EntityCoreExtension(Scratch.vm && Scratch.vm.runtime));
} else if (typeof globalThis !== "undefined") {
  globalThis.EntityCoreExtension = EntityCoreExtension; // headless smoke
}
