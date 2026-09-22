// ec-core-browser — the DELEGATED core, bundled for the browser (esbuild → IIFE).
//
// This is the TurboWarp analogue of the Node-RED lib/{codec-bridge,peer-kernel,
// session}. It imports ONLY the pure-JS surface of the TypeScript peer (codec,
// model, identity, capability, store, emit, types, dispatch) — deliberately NOT
// transport (node:net) or the fs/os seed loader — so esbuild produces a
// self-contained browser bundle with zero Node dependencies. Transport is authored
// separately as a WebSocket (the sandbox can't do raw TCP).
//
// The bundle exposes `globalThis.EntityCore` = { createKernel, newSession, codec }.
// The Scratch custom extension (ec-extension.js) wraps these as blocks; the .sb3
// authors dispatch routing + handshake + the stage visualization.
//
// Paths resolve to the compiled TS peer's ESM dist at bundle time.
const TSD = "../../../typescript/dist/src";

import { Envelope, Execute, ExecuteResponse, TypeNames } from "../../../typescript/dist/src/model/index.js";
import { PeerIdentity } from "../../../typescript/dist/src/identity/index.js";
import { ContentStore, EntityTree } from "../../../typescript/dist/src/store/index.js";
import {
  HandlerRegistry,
  ConnectHandler,
  TreeHandler,
  HandlersHandler,
  CapabilityHandler,
  ValidateEchoHandler,
  ValidateDispatchOutboundHandler,
  ConnectionState,
} from "../../../typescript/dist/src/handlers/index.js";
import { CapabilityToken, SeedPolicy } from "../../../typescript/dist/src/capability/index.js";
import { EmitBus } from "../../../typescript/dist/src/emit/index.js";
import { Dispatcher } from "../../../typescript/dist/src/dispatch/index.js";
import { seedCoreTypes } from "../../../typescript/dist/src/types/index.js";
import { Entity, Ecf, hashHex } from "../../../typescript/dist/src/model/index.js";
// §4.11's cause-to-code table (0.8.2.25). `transport/frame-codec.js` is the one
// Node-coupled corner of the TS wire path, and this pulls in the half that ISN'T: its
// compiled output imports only `codec/bytes.js` and `errors.js`, so the classification
// and the two framing error classes bundle for the browser with no Node dependency.
// (Checked in the built dist rather than assumed — an `import { type Socket }` that is
// still a VALUE import emits `import {} from "node:net"` and kills this bundle, which is
// exactly what once made this peer the one nobody could measure.) The table is delegated
// rather than restated for the same reason the codec is: a second reading of which error
// means which code drifts on the first revision that adds a cause.
import {
  preAdmissionRefusal,
  FrameTooLargeError,
  TruncatedFrameError,
} from "../../../typescript/dist/src/transport/frame-codec.js";
// The LENIENT reader, used ONLY to read back a correlation key from a frame the strict
// decoder has already rejected. It may never reach an ingestion path: its only caller
// builds a 400 and discards everything else it read.
import { decodeSalvage } from "../../../typescript/dist/src/codec/canonical-cbor.js";

const DEFAULT_SEED = new Uint8Array(32).fill(0x11); // stable conformance peer_id

function policyEntryEntity(peerPattern, grants) {
  return Entity.create(
    TypeNames.CapabilityPolicyEntry,
    Ecf.map(["peer_pattern", Ecf.text(peerPattern)], ["grants", Ecf.array(grants.map((g) => g.toEcf()))]),
  );
}

// Mirrors peer-kernel.createKernel, but seed is passed in (no fs) and no node deps.
function createKernel(opts = {}) {
  const seed = opts.seed || DEFAULT_SEED;
  const identity = PeerIdentity.fromSeed(seed);
  const seedPolicy = opts.debugOpenGrants ? SeedPolicy.debugOpen() : SeedPolicy.standard();
  const emit = new EmitBus();
  const store = new ContentStore(emit);
  const tree = new EntityTree(store, emit);

  const services = {
    get localPeerId() { return identity.peerId; },
    get localIdentity() { return identity; },
    get tree() { return tree; },
    get contentStore() { return store; },
    get emit() { return emit; },
    get nowMs() { return BigInt(Date.now()); },
  };

  const registry = new HandlerRegistry(services);
  const dispatcher = new Dispatcher(services, registry);

  registry.register(new ConnectHandler());
  registry.register(new TreeHandler());
  registry.register(new HandlersHandler());
  registry.register(new CapabilityHandler());

  tree.put("/" + identity.peerId + "/system/peer/self", identity.peerEntity);
  seedCoreTypes(tree, identity.peerId);

  const policyBase = "/" + identity.peerId + "/system/capability/policy/";
  const { token: ownerCap, signature: ownerSig } = CapabilityToken.createRoot(
    identity, identity.identityHash, SeedPolicy.ownerGrants(identity.peerId), services.nowMs,
  );
  tree.put(policyBase + hashHex(identity.identityHash), ownerCap.entity);
  tree.put("/" + identity.peerId + "/system/signature/" + ownerCap.contentHashHex, ownerSig);
  tree.put(policyBase + "default", policyEntryEntity("default", seedPolicy.defaultGrants));
  for (const entry of seedPolicy.namedEntries) {
    tree.put(policyBase + entry.key, policyEntryEntity(entry.key, entry.grants));
  }

  if (opts.validate) {
    registry.register(new ValidateEchoHandler());
    registry.register(new ValidateDispatchOutboundHandler());
  }

  return { identity, services, registry, dispatcher, ConnectionState };
}

// A per-connection session: the §6.11 correlation + granular byte steps, browser-safe.
function newSession(kernel, sendFrame) {
  const connState = new kernel.ConnectionState();
  const pending = new Map();
  let counter = 0;

  const session = {
    connState,
    nextRequestId() { return "tw-" + ++counter; },
    async sendRequest(envelope, timeoutMs) {
      const reqId = new Execute(envelope.root).requestId;
      if (pending.has(reqId)) throw new Error("dup request_id " + reqId);
      let resolve, reject;
      const p = new Promise((res, rej) => { resolve = res; reject = rej; });
      pending.set(reqId, { resolve, reject });
      const timer = setTimeout(() => { if (pending.delete(reqId)) reject(new Error("timeout " + reqId)); }, timeoutMs);
      try { sendFrame(envelope.encode()); } catch (e) { clearTimeout(timer); pending.delete(reqId); throw e; }
      try { return await p; } finally { clearTimeout(timer); pending.delete(reqId); }
    },
    // "undecodable" and "invalid" ARE DIFFERENT ANSWERS AND THIS USED TO COLLAPSE THEM.
    // A frame the strict decoder rejects takes the code its CAUSE is assigned (§4.11,
    // §5.2a); a frame that DECODED and whose root is neither EXECUTE nor EXECUTE_RESPONSE
    // is §3.3's case and takes `400 invalid_request`. Both used to return "invalid" and
    // the caller dropped both, which is the silent half of §4.11 — the weaker of its two
    // named non-conformant behaviours precisely because nothing surfaces it.
    classify(bytes) {
      let env; try { env = Envelope.decode(bytes); } catch (_) { return "undecodable"; }
      const t = env.root.type;
      return t === TypeNames.Execute ? "execute" : t === TypeNames.ExecuteResponse ? "response" : "invalid";
    },

    /**
     * §4.11 (0.8.2.25): the coded EXECUTE_RESPONSE owed for a frame the strict decoder
     * rejected — CORRELATED where a request_id is recoverable, best-effort uncorrelated
     * where it is not. §4.9(c)'s deliver-or-signal rule is scoped to requests the peer
     * ADMITS and reaches none of these, which is why §4.11 exists.
     *
     * The frame stays rejected: the salvage decode reads back the correlation key and
     * nothing else. An unrecoverable id yields the UNCORRELATED frame rather than
     * silence — §4.11 prescribes that form rather than tolerating it, because an
     * uncorrelated answer still tells the sender its frame was REFUSED rather than lost.
     */
    refusePreAdmissionBytes(bytes) {
      let err;
      try { Envelope.decode(bytes); return null; } catch (e) { err = e; }
      const { status, code, message } = preAdmissionRefusal(err);
      let requestId = "";
      try {
        const salvaged = decodeSalvage(bytes);
        const root = Ecf.require(salvaged, "root");
        requestId = Ecf.requireText(Ecf.require(root, "data"), "request_id");
      } catch (_) { requestId = ""; }
      return new Envelope(ExecuteResponse.error(requestId, status, code, message).entity, []).encode();
    },

    /** §3.3/§4.11: a frame that DECODED and is not a request. The caller is correlatable. */
    refuseNonExecuteRootBytes(bytes) {
      let requestId = "";
      try {
        const env = Envelope.decode(bytes);
        requestId = Ecf.optText(env.root.data, "request_id") || "";
      } catch (_) { return null; }
      return new Envelope(ExecuteResponse.error(requestId, 400, "invalid_request",
        "root is neither an EXECUTE nor an EXECUTE_RESPONSE").entity, []).encode();
    },

    /**
     * §4.11's best-effort UNCORRELATED frame for a FRAMING refusal the transport seam
     * detected itself. There is no request_id by construction — no frame ever arrived.
     */
    refuseFramingBytes(err) {
      const { status, code, message } = preAdmissionRefusal(err);
      return new Envelope(ExecuteResponse.error("", status, code, message).entity, []).encode();
    },
    async dispatch(bytes) {
      const env = Envelope.decode(bytes);
      const before = connState.established;
      const response = await kernel.dispatcher.dispatch(env, connState, session);
      return { responseBytes: response.encode(), flipped: !before && connState.established };
    },
    routeResponse(bytes) {
      let env; try { env = Envelope.decode(bytes); } catch (_) { return; }
      try { const reqId = new ExecuteResponse(env.root).requestId; const d = pending.get(reqId); if (d) d.resolve(env); } catch (_) {}
    },
    afterResponseWritten(flipped) { if (flipped) connState.authResponseSent.resolve(); },
    dispose() {
      for (const d of pending.values()) d.reject(new Error("closed"));
      pending.clear();
      connState.inboundHello.reject(new Error("closed"));
      connState.authResponseSent.reject(new Error("closed"));
    },
  };
  return session;
}

const codec = {
  decode: (bytes) => Envelope.decode(bytes),
  encode: (env) => env.encode(),
  Envelope, Execute, ExecuteResponse, Entity, Ecf, TypeNames,
};

// The two §4.11 FRAMING causes travel with the bundle because the transport seam — the
// harness here, the WebSocket blocks in the .sb3 — owns the length prefix and is the only
// place that can detect them. Exporting the error CLASSES rather than two more status/code
// pairs is what keeps `preAdmissionRefusal` the single table.
const EntityCore = { createKernel, newSession, codec, FrameTooLargeError, TruncatedFrameError };
if (typeof globalThis !== "undefined") globalThis.EntityCore = EntityCore;
export { createKernel, newSession, codec, FrameTooLargeError, TruncatedFrameError };
export default EntityCore;
