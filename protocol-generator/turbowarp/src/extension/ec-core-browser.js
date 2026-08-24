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
    classify(bytes) {
      let env; try { env = Envelope.decode(bytes); } catch (_) { return "invalid"; }
      const t = env.root.type;
      return t === TypeNames.Execute ? "execute" : t === TypeNames.ExecuteResponse ? "response" : "invalid";
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

const EntityCore = { createKernel, newSession, codec };
if (typeof globalThis !== "undefined") globalThis.EntityCore = EntityCore;
export { createKernel, newSession, codec };
export default EntityCore;
