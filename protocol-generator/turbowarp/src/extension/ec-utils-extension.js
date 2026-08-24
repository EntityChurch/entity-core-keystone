// ec-utils-extension — the FFI/UTILITY SEAM, and ONLY the seam.
//
// The whole point of this rebuild: the entity-core PROTOCOL LOGIC (the §6.5 dispatch
// sequence, the 401/403/404 branching, handler routing, response construction, the
// §4 handshake) is authored as SCRATCH BLOCKS in the .sb3 — readable, editable,
// studyable in the language. This extension exposes ONLY the things Scratch physically
// cannot express, as small utility blocks:
//   • the socket (Scratch has no raw WebSocket/TCP) + §1.6 framing
//   • canonical CBOR encode/decode (Scratch has no byte type)
//   • Ed25519 / SHA-256 verdicts + the capability-chain verdict (the crypto "tricky bits")
//   • reading fields off / building entities (Scratch has no map type)
//
// Values that Scratch can't hold (envelopes, entities, hashes) travel through the blocks
// as OPAQUE HANDLES (short string ids into a JS table); the readable fields (uri,
// request_id, author-present) are plain reporter blocks. Scratch owns every branch.
//
// There is deliberately NO `dispatch` block here — that logic lives in Scratch. If you
// find yourself adding one, stop: it belongs on the canvas.

import { createKernel, newSession, codec } from "./ec-core-browser.js";
import { ChainVerifier, Permissions, Paths, CapabilityToken, GrantEntry, Attenuation, SeedPolicy } from "../../../typescript/dist/src/capability/index.js";
import { verifySignature, signatureSigner, PeerIdentity, buildPeerEntity } from "../../../typescript/dist/src/identity/index.js";
import { Status, hashEqual, hashHex, Protocols } from "../../../typescript/dist/src/model/index.js";
import { HandlerContext } from "../../../typescript/dist/src/handlers/index.js";
import { buildHello } from "../../../typescript/dist/src/handlers/connect-handler.js";
import { OutboundDispatchImpl } from "../../../typescript/dist/src/dispatch/index.js";
import { isZeroHash } from "../../../typescript/dist/src/model/index.js";
import { ecfMap, ecfText } from "../../../typescript/dist/src/codec/ecf-value.js";
import { parsePeerId } from "../../../typescript/dist/src/codec/peer-id.js";
import { isSupportedKeyType, isHandshakeSupportedKeyType, keyAlgorithmByName } from "../../../typescript/dist/src/codec/key-types.js";
import { SUPPORTED_HASH_FORMAT_NAMES } from "../../../typescript/dist/src/codec/hash-formats.js";
import { EntityCodecError } from "../../../typescript/dist/src/errors.js";

const { Envelope, Execute, ExecuteResponse, Entity, Ecf, TypeNames } = codec;

class EntityCoreUtils {
  static MAX_FRAME = 16 * 1024 * 1024; // §1.6 SHOULD

  constructor(runtime) {
    this.runtime = runtime;
    this.kernel = null;
    this.ws = null;
    this.conns = new Map(); // connId -> { buffer, established }
    this.h = new Map();     // handle id -> JS object (Envelope / Execute / Entity / CapabilityToken)
    this.hseq = 0;
    this.inbound = { conn: "", exec: "" }; // current EXECUTE slot the `when execute arrives` hat reads
    this.queue = [];        // pending inbound EXECUTEs (conn, handle) — processed one hat at a time
    this._busy = false;
  }

  // ---- handle table (opaque crypto/entity objects Scratch can't hold) ----
  _ref(obj) { const id = "h" + ++this.hseq; this.h.set(id, obj); return id; }
  _exec(id) { const o = this.h.get(id); return o && o._exec ? o : null; }

  getInfo() {
    return {
      id: "ecutils",
      name: "entity-core utils",
      color1: "#7fd4c1", color2: "#5bb8a3",
      blocks: [
        // — transport (the socket + §1.6 framing; Scratch can't open sockets) —
        { opcode: "connect", blockType: "command", text: "start peer, connect to bridge [URL]",
          arguments: { URL: { type: "string", defaultValue: "ws://localhost:7802" } } },
        { opcode: "disconnect", blockType: "command", text: "stop peer" },
        { opcode: "whenExecute", blockType: "hat", text: "when execute arrives", isEdgeActivated: false },
        { opcode: "inboundConn", blockType: "reporter", text: "inbound conn" },
        { opcode: "inboundExec", blockType: "reporter", text: "inbound execute" },
        { opcode: "sendResponse", blockType: "command", text: "send response [RESP] to conn [CONN]",
          arguments: { RESP: { type: "string" }, CONN: { type: "string" } } },
        "---",
        // — reading fields off an entity (Scratch has no map type) —
        { opcode: "uriOf", blockType: "reporter", text: "uri of [H]", arguments: { H: { type: "string" } } },
        { opcode: "requestIdOf", blockType: "reporter", text: "request id of [H]", arguments: { H: { type: "string" } } },
        { opcode: "dispatchPathOf", blockType: "reporter", text: "dispatch path of [H]", arguments: { H: { type: "string" } } },
        { opcode: "paramsOf", blockType: "reporter", text: "params of [H]", arguments: { H: { type: "string" } } },
        { opcode: "hasAuthor", blockType: "Boolean", text: "author present in [H]", arguments: { H: { type: "string" } } },
        { opcode: "hasCapability", blockType: "Boolean", text: "capability present in [H]", arguments: { H: { type: "string" } } },
        "---",
        // — the crypto verdicts (the "tricky bits": Ed25519, SHA-256, chain math) —
        // §5.2 verify_request, one sub-verdict per block so the Scratch ladder authors the
        // exact sequence + status codes (single-401 carve-out, depth-before-authz, revocation).
        { opcode: "signatureValid", blockType: "Boolean", text: "signature valid in [H]", arguments: { H: { type: "string" } } },
        { opcode: "capabilityResolves", blockType: "Boolean", text: "capability resolves in [H]", arguments: { H: { type: "string" } } },
        { opcode: "granteeResolves", blockType: "Boolean", text: "grantee resolves in [H]", arguments: { H: { type: "string" } } },
        { opcode: "granteeIsAuthor", blockType: "Boolean", text: "grantee is author in [H]", arguments: { H: { type: "string" } } },
        { opcode: "chainWithinDepth", blockType: "Boolean", text: "chain within depth in [H]", arguments: { H: { type: "string" } } },
        { opcode: "chainVerifies", blockType: "Boolean", text: "capability chain verifies in [H]", arguments: { H: { type: "string" } } },
        { opcode: "capabilityRevoked", blockType: "Boolean", text: "capability revoked in [H]", arguments: { H: { type: "string" } } },
        // §6.6 handler resolution — the WALK is authored on the canvas (repeat-until, longest prefix
        // first); these are only the per-prefix store lookup + the byte-level path slice the substrate
        // can't do. `handlerRegisteredAt` = is a system/handler entity bound at this exact prefix;
        // `parentPrefix` = drop the last path segment ("" past the peer root); `patternAt` = the
        // peer-relative pattern of a prefix.
        { opcode: "handlerRegisteredAt", blockType: "Boolean", text: "handler registered at [P]", arguments: { P: { type: "string" } } },
        { opcode: "parentPrefix", blockType: "reporter", text: "parent prefix of [P]", arguments: { P: { type: "string" } } },
        { opcode: "patternAt", blockType: "reporter", text: "handler pattern at [P]", arguments: { P: { type: "string" } } },
        { opcode: "capabilityPermits", blockType: "Boolean", text: "capability permits handler [PATTERN] in [H]",
          arguments: { PATTERN: { type: "string" }, H: { type: "string" } } },
        { opcode: "isConnectPath", blockType: "Boolean", text: "is connect path [PATH]", arguments: { PATH: { type: "string" } } },
        { opcode: "established", blockType: "Boolean", text: "conn [CONN] established?", arguments: { CONN: { type: "string" } } },
        "---",
        // — building responses (Scratch has no byte/map type; canonical CBOR is JS) —
        { opcode: "okResponse", blockType: "reporter", text: "ok response for [H] result [RESULT]",
          arguments: { H: { type: "string" }, RESULT: { type: "string" } } },
        { opcode: "errorResponse", blockType: "reporter", text: "error response for [H] status [S] code [C] message [M]",
          arguments: { H: { type: "string" }, S: { type: "number", defaultValue: 400 }, C: { type: "string" }, M: { type: "string" } } },
        // Runs ONLY the resolved handler's BODY (the store-reading/writing mechanics) —
        // the §6.5 routing/verify/permission AROUND it is the Scratch logic, not this.
        { opcode: "runHandlerBody", blockType: "reporter", text: "run handler body [PATTERN] for [H] on conn [CONN]",
          arguments: { PATTERN: { type: "string" }, H: { type: "string" }, CONN: { type: "string" } } },
        "---",
        // — §6.3 tree-handler mechanics (store iteration / path / CAS Scratch can't do); the
        //   get/put/operation control flow is authored on the canvas —
        { opcode: "operationOf", blockType: "reporter", text: "operation of [H]", arguments: { H: { type: "string" } } },
        { opcode: "hasSingleTarget", blockType: "Boolean", text: "has single target in [H]", arguments: { H: { type: "string" } } },
        { opcode: "singleTarget", blockType: "reporter", text: "single target of [H]", arguments: { H: { type: "string" } } },
        { opcode: "validTarget", blockType: "Boolean", text: "valid target [T]", arguments: { T: { type: "string" } } },
        { opcode: "isListing", blockType: "Boolean", text: "is listing target [T]", arguments: { T: { type: "string" } } },
        { opcode: "canonicalize", blockType: "reporter", text: "canonicalize [T]", arguments: { T: { type: "string" } } },
        { opcode: "pathPermits", blockType: "Boolean", text: "cap permits op [OP] path [PATH] handler [PAT] in [H]",
          arguments: { OP: { type: "string" }, PATH: { type: "string" }, PAT: { type: "string" }, H: { type: "string" } } },
        { opcode: "treeHas", blockType: "Boolean", text: "tree has [PATH]", arguments: { PATH: { type: "string" } } },
        { opcode: "modeOf", blockType: "reporter", text: "mode of [H]", arguments: { H: { type: "string" } } },
        { opcode: "treeEntityResult", blockType: "reporter", text: "tree entity at [PATH]", arguments: { PATH: { type: "string" } } },
        { opcode: "treeHashResult", blockType: "reporter", text: "tree hash at [PATH]", arguments: { PATH: { type: "string" } } },
        { opcode: "treeListingResult", blockType: "reporter", text: "tree listing [T] handler [PAT] in [H]",
          arguments: { T: { type: "string" }, PAT: { type: "string" }, H: { type: "string" } } },
        { opcode: "treeWrite", blockType: "reporter", text: "tree write [PATH] from [H]", arguments: { PATH: { type: "string" }, H: { type: "string" } } },
        { opcode: "emptyAck", blockType: "reporter", text: "empty ack" },
        "---",
        // — §6.2 handlers-handler mechanics (the 5 normative register writes / reversal); the
        //   operation switch + resource validation + status codes are on the canvas —
        { opcode: "handlerResourceValid", blockType: "Boolean", text: "handler resource valid in [H]", arguments: { H: { type: "string" } } },
        { opcode: "handlerPatternOf", blockType: "reporter", text: "handler pattern of [H]", arguments: { H: { type: "string" } } },
        { opcode: "isRegisterRequest", blockType: "Boolean", text: "is register-request in [H]", arguments: { H: { type: "string" } } },
        { opcode: "registerHandler", blockType: "reporter", text: "register handler [PATTERN] from [H]", arguments: { PATTERN: { type: "string" }, H: { type: "string" } } },
        { opcode: "unregisterHandler", blockType: "reporter", text: "unregister handler [PATTERN]", arguments: { PATTERN: { type: "string" } } },
        "---",
        // — §6.2 capability-handler mechanics (token minting/signing, scope attenuation math,
        //   policy/revocation store writes); the operation switch + guard ladders + status
        //   codes are authored on the canvas —
        { opcode: "authorInIncluded", blockType: "Boolean", text: "author resolves in included in [H]", arguments: { H: { type: "string" } } },
        { opcode: "requestScopeWithinAuthority", blockType: "Boolean", text: "requested scope within caller authority in [H]", arguments: { H: { type: "string" } } },
        { opcode: "capabilityRequestResponse", blockType: "reporter", text: "issue capability grant response for [H]", arguments: { H: { type: "string" } } },
        { opcode: "isPolicyEntryParams", blockType: "Boolean", text: "params is policy-entry in [H]", arguments: { H: { type: "string" } } },
        { opcode: "validPolicyPattern", blockType: "Boolean", text: "policy peer_pattern valid in [H]", arguments: { H: { type: "string" } } },
        { opcode: "policyHasGrants", blockType: "Boolean", text: "policy has at least one grant in [H]", arguments: { H: { type: "string" } } },
        { opcode: "configurePolicy", blockType: "reporter", text: "bind capability policy from [H]", arguments: { H: { type: "string" } } },
        { opcode: "revokeTokenValid", blockType: "Boolean", text: "revoke token non-zero in [H]", arguments: { H: { type: "string" } } },
        { opcode: "writeRevocation", blockType: "reporter", text: "write capability revocation from [H]", arguments: { H: { type: "string" } } },
        "---",
        // — §4 connect-handshake mechanics (per-conn state, nonce/PoP crypto, key derivation,
        //   seed-cap minting); the hello/authenticate operation switch + negotiation guards +
        //   status codes are authored on the canvas —
        { opcode: "isHelloParams", blockType: "Boolean", text: "params is hello in [H]", arguments: { H: { type: "string" } } },
        { opcode: "helloKeyTypeSupported", blockType: "Boolean", text: "hello peer_id key_type supported in [H]", arguments: { H: { type: "string" } } },
        { opcode: "protocolCompatible", blockType: "Boolean", text: "protocol version common in [H]", arguments: { H: { type: "string" } } },
        { opcode: "hashFormatCompatible", blockType: "Boolean", text: "hash_format common in [H]", arguments: { H: { type: "string" } } },
        { opcode: "keyTypesCompatible", blockType: "Boolean", text: "key_types accept responder in [H]", arguments: { H: { type: "string" } } },
        { opcode: "helloResponse", blockType: "reporter", text: "process hello from [H] on conn [CONN], reply", arguments: { H: { type: "string" }, CONN: { type: "string" } } },
        { opcode: "helloReceivedOn", blockType: "Boolean", text: "hello received on conn [CONN]", arguments: { CONN: { type: "string" } } },
        { opcode: "isAuthenticateParams", blockType: "Boolean", text: "params is authenticate in [H]", arguments: { H: { type: "string" } } },
        { opcode: "authNonceEchoes", blockType: "Boolean", text: "authenticate echoes challenge nonce in [H] on conn [CONN]", arguments: { H: { type: "string" }, CONN: { type: "string" } } },
        { opcode: "authKeyTypeSupported", blockType: "Boolean", text: "authenticate key_type supported in [H]", arguments: { H: { type: "string" } } },
        { opcode: "authIdentityMatches", blockType: "Boolean", text: "authenticate public_key matches peer_id in [H]", arguments: { H: { type: "string" } } },
        { opcode: "authSignatureValid", blockType: "Boolean", text: "authenticate signature valid in [H]", arguments: { H: { type: "string" } } },
        { opcode: "authenticateResponse", blockType: "reporter", text: "authenticate [H] on conn [CONN], mint initial capability", arguments: { H: { type: "string" }, CONN: { type: "string" } } },
        "---",
        { opcode: "peerId", blockType: "reporter", text: "peer id" },
        { opcode: "statusOk", blockType: "reporter", text: "status OK (200)" },
      ],
    };
  }

  // ================= transport (JS: socket + framing) =================
  connect(args) {
    if (this.ws) return;
    this.kernel = createKernel({ debugOpenGrants: true, validate: true });
    const ws = new WebSocket(args.URL);
    ws.binaryType = "arraybuffer";
    this.ws = ws;
    ws.addEventListener("message", (ev) => this._onWs(new Uint8Array(ev.data)));
    ws.addEventListener("close", () => { this.ws = null; this.conns.clear(); });
    ws.addEventListener("error", () => {});
  }
  disconnect() { if (this.ws) { try { this.ws.close(); } catch (_) {} this.ws = null; } this.conns.clear(); }

  _sendToBridge(connId, payload) {
    const msg = new Uint8Array(4 + payload.length);
    new DataView(msg.buffer).setUint32(0, (connId >>> 0), false);
    msg.set(payload, 4);
    if (this.ws && this.ws.readyState === 1) this.ws.send(msg);
  }
  _frame(bytes) {
    const framed = new Uint8Array(4 + bytes.length);
    new DataView(framed.buffer).setUint32(0, bytes.length, false);
    framed.set(bytes, 4);
    return framed;
  }
  _onWs(buf) {
    if (buf.length < 4) return;
    const connId = String(new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false));
    const payload = buf.subarray(4);
    let c = this.conns.get(connId);
    if (!c) {
      // Per-conn session: the §6.11 ReentrantSender (nextRequestId + sendRequest, sending
      // via the bridge) + connState. Transport-level; the DISPATCH stays authored in Scratch.
      const sendFrame = (bytes) => this._sendToBridge(connId, this._frame(new Uint8Array(bytes)));
      c = { buffer: new Uint8Array(0), session: newSession(this.kernel, sendFrame) };
      this.conns.set(connId, c);
    }
    if (payload.length === 0) { this.conns.delete(connId); return; }
    const merged = new Uint8Array(c.buffer.length + payload.length);
    merged.set(c.buffer); merged.set(payload, c.buffer.length); c.buffer = merged;
    while (c.buffer.length >= 4) {
      const len = new DataView(c.buffer.buffer, c.buffer.byteOffset, 4).getUint32(0, false);
      // §1.6 16 MiB frame cap — reject oversize BEFORE buffering it (else the single JS
      // peer stalls concatenating a huge frame, timing out every later connection). Close
      // the offending connection (mirrors the Node-RED listener's socket.destroy).
      if (len > EntityCoreUtils.MAX_FRAME) { this._sendToBridge(connId, new Uint8Array(0)); this.conns.delete(connId); return; }
      if (c.buffer.length < 4 + len) break;
      const frame = c.buffer.slice(4, 4 + len);
      c.buffer = c.buffer.slice(4 + len);
      this._ingest(connId, c, frame);
    }
  }
  // Decode a frame; EXECUTE → the Scratch logic via the hat; EXECUTE_RESPONSE → §6.11 reentry
  // (route to the parked origination on this conn's session).
  _ingest(connId, c, frame) {
    let env; try { env = Envelope.decode(frame); } catch (_) { return; }
    if (env.root.type === TypeNames.ExecuteResponse) { c.session.routeResponse(frame); return; }
    if (env.root.type !== TypeNames.Execute) return;
    let execute; try { execute = new Execute(env.root); } catch (_) { return; }
    const handle = this._ref({ _exec: true, env, execute });
    this.queue.push({ conn: connId, exec: handle });
    this._pump();
  }
  _pump() {
    if (this._busy || this.queue.length === 0) return;
    const item = this.queue.shift();
    this.inbound = item;
    this._busy = true;
    if (this.runtime && this.runtime.startHats) this.runtime.startHats("ecutils_whenExecute");
    // Release after the current tick so the Scratch script runs; the queue drains on the next.
    setTimeout(() => { this._busy = false; this._pump(); }, 0);
  }

  // ================= inbound slot (read by the hat) =================
  whenExecute() { return false; } // fired via startHats; not polled
  inboundConn() { return this.inbound.conn; }
  inboundExec() { return this.inbound.exec; }

  // ================= reading fields (JS: no map type in Scratch) =================
  uriOf(a) { const o = this._exec(a.H); try { return o ? o.execute.uri : ""; } catch (_) { return ""; } }
  requestIdOf(a) { const o = this._exec(a.H); try { return o ? o.execute.requestId : ""; } catch (_) { return ""; } }
  dispatchPathOf(a) {
    const o = this._exec(a.H); if (!o) return "";
    try { return Paths.dispatchPath(o.execute.uri, this.kernel.identity.peerId); } catch (_) { return ""; }
  }
  paramsOf(a) {
    const o = this._exec(a.H); if (!o) return "";
    try { const p = o.execute.params; return p ? this._ref({ _entity: true, entity: p }) : ""; } catch (_) { return ""; }
  }
  hasAuthor(a) { const o = this._exec(a.H); return !!(o && o.execute.author !== null); }
  hasCapability(a) { const o = this._exec(a.H); return !!(o && o.execute.capability !== null); }

  // ================= crypto verdicts (the tricky bits) =================
  signatureValid(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      const { env, execute } = o;
      const sig = ChainVerifier.findSignature(env, execute.entity.contentHash);
      if (sig === null || execute.author === null) return false;
      if (!hashEqual(signatureSigner(sig), execute.author)) return false;
      const author = env.find(execute.author);
      return author !== undefined && verifySignature(sig, author);
    } catch (_) { return false; }
  }
  // §5.2 verify sub-verdicts — each a single dispatcher.ts#verifyRequest step, so the
  // Scratch ladder can branch to the exact status code the spec pins to each.
  _cap(o) { const h = o.execute.capability; return h === null ? null : o.env.find(h); } // capability entity, or undefined/null
  capabilityResolves(a) { const o = this._exec(a.H); if (!o) return false; try { return this._cap(o) !== undefined && this._cap(o) !== null; } catch (_) { return false; } }
  granteeResolves(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { const cap = new CapabilityToken(this._cap(o)); const g = o.env.find(cap.grantee); return g !== undefined && g.type === TypeNames.Peer; } catch (_) { return false; }
  }
  granteeIsAuthor(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { const cap = new CapabilityToken(this._cap(o)); return o.execute.author !== null && hashEqual(cap.grantee, o.execute.author); } catch (_) { return false; }
  }
  chainWithinDepth(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { return !ChainVerifier.exceedsMaxDepth(new CapabilityToken(this._cap(o)), o.env); } catch (_) { return false; }
  }
  chainVerifies(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { return ChainVerifier.verifyCapabilityChain(new CapabilityToken(this._cap(o)), o.env, this.kernel.identity.peerId, this.kernel.services.nowMs); } catch (_) { return false; }
  }
  // §5.1 is_revoked over the full authority chain (port of Dispatcher#isChainRevoked).
  capabilityRevoked(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      let current = new CapabilityToken(this._cap(o)); let depth = 0; const peerId = this.kernel.identity.peerId;
      while (current !== null && depth <= 64) {
        if (this.kernel.services.tree.get("/" + peerId + "/system/capability/revocations/" + current.contentHashHex) !== undefined) return true;
        if (current.parent === null) break;
        const parent = o.env.find(current.parent);
        if (parent === undefined) break;
        current = new CapabilityToken(parent); depth++;
      }
      return false;
    } catch (_) { return false; }
  }
  // §6.6 resolution primitives — the WALK (longest-prefix-first) is authored on the canvas; these
  // are only the per-prefix store lookup + byte-level path slice. `handlerRegisteredAt`: a
  // system/handler entity bound at exactly this absolute prefix. `parentPrefix`: drop the last
  // "/"-segment, returning "" once past the peer-root (1 segment) so the walk terminates. `patternAt`:
  // the peer-relative pattern of a matched prefix (mirrors HandlerRegistry#stripPeer).
  handlerRegisteredAt(a) {
    try { const e = this.kernel.services.tree.get(String(a.P)); return e !== undefined && e.type === TypeNames.Handler; } catch (_) { return false; }
  }
  parentPrefix(a) {
    const segs = String(a.P).replace(/^\/+/, "").split("/");
    return segs.length <= 1 ? "" : "/" + segs.slice(0, segs.length - 1).join("/");
  }
  patternAt(a) {
    const prefix = "/" + this.kernel.identity.peerId + "/";
    const p = String(a.P);
    return p.startsWith(prefix) ? p.slice(prefix.length) : p.replace(/^\/+/, "");
  }
  capabilityPermits(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      const { env, execute } = o;
      const cap = new CapabilityToken(env.find(execute.capability));
      const granter = Permissions.resolveGranterPeerId(cap, env, this.kernel.identity.peerId);
      return Permissions.checkPermission(execute, cap, a.PATTERN, this.kernel.identity.peerId, granter);
    } catch (_) { return false; }
  }
  isConnectPath(a) { return typeof a.PATH === "string" && a.PATH.endsWith("/system/protocol/connect"); } // §4.2 ConnectPath
  established(a) { const c = this.conns.get(a.CONN); return !!(c && c.session && c.session.connState.established); }

  // ================= building responses (JS: canonical CBOR) =================
  okResponse(a) {
    const o = this._exec(a.H); if (!o) return "";
    try {
      const result = a.RESULT ? (this.h.get(a.RESULT) || {}).entity : undefined;
      const resp = ExecuteResponse.build(o.execute.requestId, Status.Ok, result);
      return this._ref({ _resp: true, env: new Envelope(resp.entity, []) });
    } catch (_) { return ""; }
  }
  errorResponse(a) {
    const o = this._exec(a.H);
    const rid = o ? (() => { try { return o.execute.requestId; } catch (_) { return ""; } })() : "";
    try {
      const resp = ExecuteResponse.error(rid, Number(a.S), String(a.C), String(a.M));
      return this._ref({ _resp: true, env: new Envelope(resp.entity, []) });
    } catch (_) { return ""; }
  }
  // Runs ONLY the resolved handler's BODY — the store read/write mechanics of a single
  // handler (tree/capability/connect/…). The §6.5 routing/verify/permission AROUND it is
  // the Scratch logic; this does NOT re-dispatch. The handler bodies are the next layer to
  // pull onto the canvas; the pipeline (the black box you flagged) is already there.
  async runHandlerBody(a) {
    const o = this._exec(a.H); if (!o) return "";
    try {
      const { env, execute } = o;
      const res = this.kernel.registry.resolve(a.PATTERN.startsWith("/") ? a.PATTERN : Paths.dispatchPath(execute.uri, this.kernel.identity.peerId));
      if (res === null || res.native === null) return "";
      const conn = this.conns.get(a.CONN);
      const session = conn ? conn.session : newSession(this.kernel, () => {});
      const cap = execute.capability !== null ? new CapabilityToken(env.find(execute.capability)) : null;
      const ctx = new HandlerContext({
        peer: this.kernel.services, execute, envelope: env,
        pattern: res.pattern, suffix: res.suffix,
        callerCapability: cap, handlerGrant: this.kernel.registry.resolveGrant(res.pattern),
        author: execute.author, connection: session.connState,
        // §6.13(b) outbound seam → §6.11 reentry on this conn's session (drives dispatch-outbound).
        outbound: new OutboundDispatchImpl(this.kernel.identity, session),
      });
      const result = await res.native.handle(ctx);
      const resp = ExecuteResponse.build(execute.requestId, result.status, result.result);
      return this._ref({ _resp: true, env: new Envelope(resp.entity, result.included) });
    } catch (_) { return ""; }
  }

  // ---- §6.3 tree-handler mechanics (the store/path/CAS the Scratch tree logic calls) ----
  operationOf(a) { const o = this._exec(a.H); try { return o ? o.execute.operation : ""; } catch (_) { return ""; } }
  hasSingleTarget(a) { const o = this._exec(a.H); try { const r = o.execute.resource; return !!(r && r.targets.length === 1); } catch (_) { return false; } }
  singleTarget(a) { const o = this._exec(a.H); try { const r = o.execute.resource; return r && r.targets.length === 1 ? r.targets[0] : ""; } catch (_) { return ""; } }
  validTarget(a) { try { Paths.validateCallerTarget(String(a.T)); return true; } catch (_) { return false; } }
  isListing(a) { const t = String(a.T); return t.length === 0 || t.endsWith("/"); }
  canonicalize(a) { try { return Paths.canonicalize(String(a.T), this.kernel.identity.peerId); } catch (_) { return ""; } }
  pathPermits(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      const cap = o.execute.capability !== null ? new CapabilityToken(o.env.find(o.execute.capability)) : null;
      return cap !== null && Permissions.checkPathPermission(String(a.OP), String(a.PATH), cap, String(a.PAT), this.kernel.identity.peerId);
    } catch (_) { return false; }
  }
  treeHas(a) { try { return this.kernel.services.tree.getHash(String(a.PATH)) !== undefined; } catch (_) { return false; } }
  modeOf(a) { const o = this._exec(a.H); try { return Ecf.optText(o.execute.params.data, "mode") ?? "entity"; } catch (_) { return "entity"; } }
  treeEntityResult(a) { try { const e = this.kernel.services.tree.get(String(a.PATH)); return e ? this._ref({ _entity: true, entity: e }) : ""; } catch (_) { return ""; } }
  treeHashResult(a) {
    try {
      const h = this.kernel.services.tree.getHash(String(a.PATH));
      return h === undefined ? "" : this._ref({ _entity: true, entity: Entity.create(TypeNames.PrimitiveAny, Ecf.bytes(h)) });
    } catch (_) { return ""; }
  }
  emptyAck() { return this._ref({ _entity: true, entity: Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap()) }); }
  // The §6.3 listing branch (per-entry capability filter + deletion-marker handling) — pure
  // store iteration, faithfully mirroring TreeHandler#get's listing path.
  treeListingResult(a) {
    const o = this._exec(a.H); if (!o) return "";
    try {
      const tree = this.kernel.services.tree, peerId = this.kernel.identity.peerId;
      const cap = o.execute.capability !== null ? new CapabilityToken(o.env.find(o.execute.capability)) : null;
      const prefix = Paths.canonicalize(String(a.T).replace(/\/+$/, ""), peerId);
      const entries = [];
      for (const [name, entry] of tree.list(prefix)) {
        const entryPath = (prefix.endsWith("/") ? prefix : prefix + "/") + name;
        if (!(cap !== null && Permissions.checkPathPermission("get", entryPath, cap, String(a.PAT), peerId))) continue;
        if (entry.hash !== null && tree.get(entryPath)?.type === TypeNames.DeletionMarker) {
          if (!entry.hasChildren) continue;
          entries.push([name, Ecf.map(["hash", null], ["has_children", Ecf.bool(true)])]);
          continue;
        }
        entries.push([name, Ecf.map(["hash", entry.hash === null ? null : Ecf.bytes(entry.hash)], ["has_children", Ecf.bool(entry.hasChildren)])]);
      }
      const listing = Entity.create("system/tree/listing", Ecf.map(
        ["path", Ecf.text(prefix)],
        ["entries", ecfMap(entries.map(([n, v]) => [ecfText(n), v]))],
        ["count", Ecf.uint(BigInt(entries.length))],
        ["offset", Ecf.uint(0n)],
      ));
      return this._ref({ _entity: true, entity: listing });
    } catch (_) { return ""; }
  }
  // The §6.3 write (entity put OR remove, CAS on expected_hash) — returns "ok" | "conflict".
  treeWrite(a) {
    const o = this._exec(a.H); if (!o) return "error";
    try {
      const tree = this.kernel.services.tree, path = String(a.PATH), data = o.execute.params.data;
      const entityField = Ecf.field(data, "entity");
      const expectedHash = Ecf.optBytes(data, "expected_hash");
      if (entityField === null) {
        if (expectedHash !== null && !isZeroHash(expectedHash)) {
          const current = tree.getHash(path);
          if (current === undefined || !hashEqual(current, expectedHash)) return "conflict";
        }
        tree.remove(path); return "ok";
      }
      return tree.compareAndPut(path, Entity.fromDecoded(entityField), expectedHash) ? "ok" : "conflict";
    } catch (_) { return "error"; }
  }

  // ---- §6.2 handlers-handler mechanics (the register/unregister store writes) ----
  handlerResourceValid(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { const r = o.execute.resource; if (!r || r.targets.length !== 1) return false; const t = r.targets[0]; return t.startsWith("system/handler/") && t.length > "system/handler/".length; } catch (_) { return false; }
  }
  handlerPatternOf(a) { const o = this._exec(a.H); try { return o.execute.resource.targets[0].slice("system/handler/".length); } catch (_) { return ""; } }
  isRegisterRequest(a) { const o = this._exec(a.H); try { return o.execute.params.type === TypeNames.HandlerRegisterRequest; } catch (_) { return false; } }
  // §6.2 / §6.13(a) register: the five normative writes. Returns the HandlerRegisterResult.
  registerHandler(a) {
    const o = this._exec(a.H); if (!o) return "";
    try {
      const peer = this.kernel.services, peerId = this.kernel.identity.peerId, local = this.kernel.identity;
      const pattern = String(a.PATTERN), req = o.execute.params.data, abs = (rel) => "/" + peerId + "/" + rel;
      const manifest = Ecf.require(req, "manifest");
      const name = Ecf.optText(manifest, "name") ?? pattern;
      const operations = Ecf.field(manifest, "operations") ?? Ecf.emptyMap();
      const expressionPath = Ecf.optText(manifest, "expression_path");
      const maxScope = Ecf.field(manifest, "max_scope");
      const internalScope = Ecf.field(manifest, "internal_scope");
      const grantScopeEcf = Ecf.field(req, "requested_scope") ?? internalScope;
      const grantScope = grantScopeEcf === null ? [] : Ecf.asArray(grantScopeEcf).map((g) => GrantEntry.fromEcf(g));
      const interfaceRelPath = "system/handler/" + pattern;
      const handlerEntity = Entity.create(TypeNames.Handler, Ecf.map(
        ["interface", Ecf.text(interfaceRelPath)], ["max_scope", maxScope], ["internal_scope", internalScope],
        ["expression_path", expressionPath === null ? null : Ecf.text(expressionPath)]));
      const { token: grant, signature: grantSig } = CapabilityToken.createRoot(local, local.identityHash, grantScope, peer.nowMs);
      const ifaceEntity = Entity.create(TypeNames.HandlerInterface, Ecf.map(["pattern", Ecf.text(pattern)], ["name", Ecf.text(name)], ["operations", operations]));
      peer.tree.put(abs(pattern), handlerEntity);                                       // 1. manifest
      const types = Ecf.field(req, "types");                                            // 2. types
      if (types !== null) for (const [tn, td] of Ecf.entries(types)) peer.tree.put(abs("system/type/" + tn), Entity.create(TypeNames.Type, td));
      peer.tree.put(abs("system/capability/grants/" + pattern), grant.entity);          // 3. grant
      peer.tree.put(abs("system/signature/" + grant.contentHashHex), grantSig);         // 4. grant-signature
      peer.tree.put(abs(interfaceRelPath), ifaceEntity);                                // 5. interface
      return this._ref({ _entity: true, entity: Entity.create(TypeNames.HandlerRegisterResult, Ecf.map(["pattern", Ecf.text(pattern)], ["grant", grant.entity.data])) });
    } catch (_) { return ""; }
  }
  // §6.2 unregister: reverse all five writes. Returns the empty ack.
  unregisterHandler(a) {
    try {
      const peer = this.kernel.services, peerId = this.kernel.identity.peerId, pattern = String(a.PATTERN), abs = (rel) => "/" + peerId + "/" + rel;
      const grant = peer.tree.get(abs("system/capability/grants/" + pattern));
      if (grant !== undefined) {
        const gh = new CapabilityToken(grant).contentHashHex;
        peer.tree.remove(abs("system/signature/" + gh));
        peer.tree.remove(abs("system/capability/grants/" + pattern));
      }
      peer.tree.remove(abs(pattern));
      peer.tree.remove(abs("system/handler/" + pattern));
      return this._ref({ _entity: true, entity: Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap()) });
    } catch (_) { return ""; }
  }

  // ---- §6.2 capability-handler mechanics (token mint/sign, scope math, policy/revocation writes) ----
  // The requested grant scope parsed off params.data — shared by the scope-verdict and the mint.
  _requestedGrants(execute) { return Ecf.asArray(Ecf.require(execute.params.data, "grants")).map((g) => GrantEntry.fromEcf(g)); }
  _callerCap(o) { return o.execute.capability !== null ? new CapabilityToken(o.env.find(o.execute.capability)) : null; }
  // §6.2: the request author (grantee-to-be) MUST resolve to an included entity → else 400.
  authorInIncluded(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { return o.execute.author !== null && o.env.find(o.execute.author) !== undefined; } catch (_) { return false; }
  }
  // §6.2 / §5.6 attenuation-on-issue: the issued grant MUST NOT exceed the caller's presented
  // authority. No presented capability ⇒ nothing to exceed (the peer grants from its own root).
  requestScopeWithinAuthority(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      const cap = this._callerCap(o);
      if (cap === null) return true;
      return Attenuation.grantsWithinAuthority(this._requestedGrants(o.execute), cap.grants, this.kernel.identity.peerId);
    } catch (_) { return false; }
  }
  // Mint the (now-bounded) root token, sign it, assemble the included set, return the 200 response
  // handle. The peer is the sole root for caps it issues (§5.5); crypto + CBOR live here.
  capabilityRequestResponse(a) {
    const o = this._exec(a.H); if (!o) return "";
    try {
      const { env, execute } = o, peer = this.kernel.services, local = this.kernel.identity;
      const granteePeer = env.find(execute.author);
      const requested = this._requestedGrants(execute);
      const ttlMs = Ecf.optUint(execute.params.data, "ttl_ms");
      const expiresAt = ttlMs === null ? null : peer.nowMs + ttlMs;
      const { token, signature } = CapabilityToken.createRoot(local, granteePeer.contentHash, requested, peer.nowMs, expiresAt);
      const grant = Entity.create(TypeNames.CapabilityGrant, Ecf.map(["token", Ecf.bytes(token.contentHash)]));
      const included = [token.entity, local.peerEntity, granteePeer, signature];
      const resp = ExecuteResponse.build(execute.requestId, Status.Ok, grant);
      return this._ref({ _resp: true, env: new Envelope(resp.entity, included) });
    } catch (_) { return ""; }
  }
  // §6.2 configure — a policy entry MUST be a policy-entry type, carry a valid peer_pattern
  // (v7.62 §4 / v7.65 §3.6), and at least one grant. Each verdict is its own block so the
  // 400 invalid_params guards read on the canvas.
  isPolicyEntryParams(a) { const o = this._exec(a.H); try { return o.execute.params.type === TypeNames.CapabilityPolicyEntry; } catch (_) { return false; } }
  validPolicyPattern(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { const p = Ecf.optText(o.execute.params.data, "peer_pattern"); return p !== null && isValidPolicyPattern(p); } catch (_) { return false; }
  }
  policyHasGrants(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { return Ecf.asArray(Ecf.require(o.execute.params.data, "grants")).length > 0; } catch (_) { return false; }
  }
  configurePolicy(a) {
    const o = this._exec(a.H); if (!o) return "";
    try {
      const peer = this.kernel.services, peerId = this.kernel.identity.peerId, params = o.execute.params;
      const peerPattern = Ecf.requireText(params.data, "peer_pattern");
      peer.tree.put(Paths.canonicalize("system/capability/policy/" + peerPattern, peerId), params);
      return this._ref({ _entity: true, entity: Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap()) });
    } catch (_) { return ""; }
  }
  // §6.2 revoke — the token MUST be present and non-zero (v7.62 §10); write a revocation marker.
  revokeTokenValid(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { const t = Ecf.optBytes(o.execute.params.data, "token"); return t !== null && !isZeroHash(t); } catch (_) { return false; }
  }
  writeRevocation(a) {
    const o = this._exec(a.H); if (!o) return "";
    try {
      const peer = this.kernel.services, peerId = this.kernel.identity.peerId, data = o.execute.params.data;
      const token = Ecf.optBytes(data, "token"), reason = Ecf.optText(data, "reason");
      const marker = Entity.create(TypeNames.CapabilityRevocation, Ecf.map(
        ["token", Ecf.bytes(token)],
        ["reason", reason === null ? null : Ecf.text(reason)],
        ["revoked_at", Ecf.uint(peer.nowMs)]));
      peer.tree.put(Paths.canonicalize("system/capability/revocations/" + hashHex(token), peerId), marker);
      return this._ref({ _entity: true, entity: Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap()) });
    } catch (_) { return ""; }
  }

  // ---- §4 connect-handshake mechanics (per-conn state, PoP/nonce crypto, key derivation, seed cap) ----
  // The ConnectionState for a conn lives in its per-conn session (created lazily on first frame).
  _connState(id) { const c = this.conns.get(id); return c && c.session ? c.session.connState : null; }
  // — hello (§4.4/§4.5): the type + negotiation verdicts, one block per spec check —
  isHelloParams(a) { const o = this._exec(a.H); try { return o.execute.params.type === TypeNames.Hello; } catch (_) { return false; } }
  // §4.7 / v7.66 §4.4: an undecodable peer_id falls through (shape validation owns it); only a
  // decodable-but-unnegotiable key family (not Ed25519/Ed448) is rejected here.
  helloKeyTypeSupported(a) {
    const o = this._exec(a.H); if (!o) return true;
    try {
      const pid = Ecf.optText(o.execute.params.data, "peer_id");
      if (pid === null) return true;
      try { return isHandshakeSupportedKeyType(parsePeerId(pid).keyType); }
      catch (e) { if (e instanceof EntityCodecError) return true; throw e; }
    } catch (_) { return true; }
  }
  protocolCompatible(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { return Ecf.asArray(Ecf.require(o.execute.params.data, "protocols")).map((p) => Ecf.asText(p)).includes(Protocols.Version); } catch (_) { return false; }
  }
  hashFormatCompatible(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      const f = Ecf.field(o.execute.params.data, "hash_formats");
      if (f === null) return true;
      const their = new Set(Ecf.asArray(f).map((v) => Ecf.asText(v)));
      return their.size === 0 || SUPPORTED_HASH_FORMAT_NAMES.some((n) => their.has(n));
    } catch (_) { return false; }
  }
  keyTypesCompatible(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      const kt = Ecf.field(o.execute.params.data, "key_types");
      if (kt === null) return true;
      const their = new Set(Ecf.asArray(kt).map((v) => Ecf.asText(v)));
      return their.size === 0 || their.has(this.kernel.identity.keyTypeName);
    } catch (_) { return false; }
  }
  // §4.4: record the remote hello (peer_id/nonce), retain our own challenge nonce for the
  // authenticate echo, and return our hello as the 200 result. Mutates the per-conn state.
  helloResponse(a) {
    const o = this._exec(a.H); if (!o) return "";
    try {
      const conn = this._connState(a.CONN); if (conn === null) return "";
      const hello = o.execute.params, peer = this.kernel.services;
      conn.remotePeerId = Ecf.requireText(hello.data, "peer_id");
      conn.helloReceived = true;
      conn.inboundHello.resolve({ peerId: conn.remotePeerId, nonce: Ecf.requireBytes(hello.data, "nonce") });
      const response = buildHello(peer.localIdentity, peer.nowMs);
      conn.sentNonce = Ecf.requireBytes(response.data, "nonce");
      return this._ref({ _entity: true, entity: response });
    } catch (_) { return ""; }
  }
  // — authenticate (§4.6): the sequence + PoP verdicts —
  helloReceivedOn(a) { const conn = this._connState(a.CONN); return !!(conn && conn.helloReceived); }
  isAuthenticateParams(a) { const o = this._exec(a.H); try { return o.execute.params.type === TypeNames.Authenticate; } catch (_) { return false; } }
  // §4.6 PoP step 1: the authenticate MUST echo this connection's challenge nonce (defeats F12 replay).
  authNonceEchoes(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      const conn = this._connState(a.CONN); if (conn === null || conn.sentNonce === null) return false;
      const echoed = Ecf.optBytes(o.execute.params.data, "nonce") ?? new Uint8Array(0);
      return hashEqual(echoed, conn.sentNonce);
    } catch (_) { return false; }
  }
  authKeyTypeSupported(a) {
    const o = this._exec(a.H); if (!o) return false;
    try { keyAlgorithmByName(Ecf.optText(o.execute.params.data, "key_type") ?? "ed25519"); return true; }
    catch (e) { if (e instanceof EntityCodecError) return false; return false; }
  }
  authIdentityMatches(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      const data = o.execute.params.data;
      const kt = keyAlgorithmByName(Ecf.optText(data, "key_type") ?? "ed25519");
      return PeerIdentity.derivePeerId(Ecf.requireBytes(data, "public_key"), kt) === Ecf.requireText(data, "peer_id");
    } catch (_) { return false; }
  }
  // §4.6: verify the authenticate signature via target-matching against the remote peer entity.
  authSignatureValid(a) {
    const o = this._exec(a.H); if (!o) return false;
    try {
      const data = o.execute.params.data;
      const kt = keyAlgorithmByName(Ecf.optText(data, "key_type") ?? "ed25519");
      const remotePeer = buildPeerEntity(kt, Ecf.requireBytes(data, "public_key"));
      const sig = ChainVerifier.findSignature(o.env, o.execute.params.contentHash);
      return sig !== null && hashEqual(signatureSigner(sig), remotePeer.contentHash) && verifySignature(sig, remotePeer);
    } catch (_) { return false; }
  }
  // §4.4 / §6.9a: mint the initial capability (seed-policy scope UNION §4.4 discovery floor), mark
  // the connection established, and return the 200 grant with its included token/signature/peers.
  authenticateResponse(a) {
    const o = this._exec(a.H); if (!o) return "";
    try {
      const conn = this._connState(a.CONN); if (conn === null) return "";
      const data = o.execute.params.data, peer = this.kernel.services, local = peer.localIdentity;
      const kt = keyAlgorithmByName(Ecf.optText(data, "key_type") ?? "ed25519");
      const remotePeer = buildPeerEntity(kt, Ecf.requireBytes(data, "public_key"));
      const claimedPeerId = Ecf.requireText(data, "peer_id");
      conn.remotePeerEntity = remotePeer;
      conn.remotePeerId = claimedPeerId;
      const grants = this._deriveSeedGrants(remotePeer, claimedPeerId);
      const { token, signature: capSignature } = CapabilityToken.createRoot(local, remotePeer.contentHash, grants, peer.nowMs);
      conn.established = true;
      const grant = Entity.create(TypeNames.CapabilityGrant, Ecf.map(["token", Ecf.bytes(token.contentHash)]));
      const included = [token.entity, local.peerEntity, remotePeer, capSignature];
      const resp = ExecuteResponse.build(o.execute.requestId, Status.Ok, grant);
      return this._ref({ _resp: true, env: new Envelope(resp.entity, included) });
    } catch (_) { return ""; }
  }
  // §6.9a seed-policy derivation (v7.64 dual-form lookup hex→Base58→default, UNION the §4.4 floor).
  _deriveSeedGrants(remotePeer, remotePeerId) {
    const peer = this.kernel.services, peerId = this.kernel.identity.peerId;
    const base = "/" + peerId + "/system/capability/policy/";
    const entry = peer.tree.get(base + hashHex(remotePeer.contentHash)) ?? peer.tree.get(base + remotePeerId) ?? peer.tree.get(base + "default");
    const floor = SeedPolicy.discoveryFloor();
    const policyGrants = entry === undefined ? [] : this._seedEntryGrants(entry);
    return policyGrants.length === 0 ? floor : [...floor, ...policyGrants];
  }
  // A matched seed entry is either a capability token (trusted only after its self-signature
  // verifies at system/signature/{hash}) or a policy-entry (grants read directly). §6.9a.0.
  _seedEntryGrants(entry) {
    const peer = this.kernel.services, peerId = this.kernel.identity.peerId;
    if (entry.type === TypeNames.CapabilityToken) {
      const token = new CapabilityToken(entry);
      const sig = peer.tree.get("/" + peerId + "/system/signature/" + token.contentHashHex);
      if (sig === undefined || !verifySignature(sig, peer.localIdentity.peerEntity)) return [];
      return [...token.grants];
    }
    if (entry.type === TypeNames.CapabilityPolicyEntry) {
      return Ecf.asArray(Ecf.require(entry.data, "grants")).map((g) => GrantEntry.fromEcf(g));
    }
    return [];
  }

  sendResponse(a) {
    const r = this.h.get(a.RESP);
    if (!r || !r._resp) return;
    try { this._sendToBridge(a.CONN, this._frame(new Uint8Array(r.env.encode()))); } catch (_) {}
  }

  peerId() { try { return this.kernel ? this.kernel.identity.peerId : ""; } catch (_) { return ""; } }
  statusOk() { return Status.Ok; }
}

// A valid policy `peer_pattern` (v7.62 §4 + v7.65 §3.6 rule 3): the literal "default"; a
// canonical hex content hash (66-char SHA-256 / 98-char SHA-384); or a decodable Base58
// wire-form peer_id. Glob/partial-prefix patterns are rejected. Port of CapabilityHandler's.
function isValidPolicyPattern(pattern) {
  if (pattern === "default") return true;
  if (pattern.includes("*")) return false;
  if (pattern.length === 66 || pattern.length === 98) {
    for (const c of pattern) {
      const hex = (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
      if (!hex) return false;
    }
    return true;
  }
  try { const pid = parsePeerId(pattern); return isSupportedKeyType(pid.keyType) && pid.digest.length > 0; }
  catch (e) { if (e instanceof EntityCodecError) return false; throw e; }
}

// TurboWarp/Scratch registration.
if (typeof Scratch !== "undefined" && Scratch.extensions) {
  Scratch.extensions.register(new EntityCoreUtils(Scratch.vm && Scratch.vm.runtime));
} else if (typeof globalThis !== "undefined") {
  globalThis.EntityCoreUtils = EntityCoreUtils; // headless smoke
}
