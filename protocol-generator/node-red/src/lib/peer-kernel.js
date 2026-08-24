"use strict";
/**
 * peer-kernel — the DELEGATED protocol engine, mirroring the TS peer's
 * Peer.#bootstrap from PUBLIC building blocks (identity, tree/store, the bootstrap
 * handlers, the §6.5 Dispatcher, the seed-authority bootstrap). This is the
 * verified, mechanical core (like the codec) — the Node-RED flow does NOT
 * re-derive canonical CBOR, Ed25519, the capability-chain math, or the §5.2
 * verify sequence; it delegates them here and AUTHORS the surrounding graph:
 * transport, framing, the §6.11 demux, reentry correlation, response routing, and
 * the handler-dispatch decomposition (see FLOW-DESIGN.md + PHASE-S1 for the honest
 * authored-vs-delegated boundary; ADR-0012: a green result here is
 * cohort-consistent, not independent convergence).
 *
 * Per-connection, the flow gets a `session` implementing the §6.11 ReentrantSender
 * (nextRequestId + sendRequest) so the delegated respond()/dispatch-outbound can
 * originate over the flow-owned socket. The flow feeds inbound frames to the
 * session's granular methods (classify / dispatch / routeResponse) — those calls
 * are the visible nodes.
 */

const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");

const TS_DIST =
  process.env.EC_TS_DIST ||
  path.resolve(__dirname, "..", "..", "..", "typescript", "dist", "src");
const load = (rel) => require(path.join(TS_DIST, rel));

const { PeerIdentity, verifySignature, signatureSigner, signatureTarget, peerEntityId } =
  load("identity/index.js");
const { ContentStore, EntityTree } = load("store/index.js");
const handlers = load("handlers/index.js");
const {
  HandlerRegistry,
  ConnectHandler,
  TreeHandler,
  HandlersHandler,
  CapabilityHandler,
  ValidateEchoHandler,
  ValidateDispatchOutboundHandler,
  ConnectionState,
  HandlerContext,
} = handlers;
const { CapabilityToken, SeedPolicy, ChainVerifier, Permissions, Paths } =
  load("capability/index.js");
const { EmitBus } = load("emit/index.js");
const { Entity, Ecf, TypeNames, hashHex, hashEqual, Status, Protocols, Envelope, Execute, ExecuteResponse } =
  load("model/index.js");
const { Dispatcher, OutboundDispatchImpl } = load("dispatch/index.js");
const { seedCoreTypes } = load("types/index.js");
const { respond } = load("transport/index.js");
const { EntityProtocolError } = load("errors.js");

/**
 * The DELEGATED leaf primitives the AUTHORED §6.5 dispatch chain (in session.js)
 * calls — the verified crypto/verdict math (Ed25519 verify, capability-chain
 * verdict, permission verdict) + the model/path helpers. The Node-RED flow AUTHORS
 * the §6.5 sequence (decode → target → connect-preauth → author → capability →
 * verify → resolve → permission → handler) as visible nodes; each node calls one of
 * these. The full Dispatcher is no longer used by the flow (see FLOW-DESIGN.md).
 */
const prim = {
  Paths, Permissions, ChainVerifier, CapabilityToken,
  verifySignature, signatureSigner, signatureTarget, peerEntityId,
  HandlerContext, OutboundDispatchImpl,
  Entity, Ecf, TypeNames, Status, Protocols, Envelope, Execute, ExecuteResponse,
  hashHex, hashEqual, EntityProtocolError,
};

const DEFAULT_SEED = new Uint8Array(32).fill(0x11); // matches host default (peer_id stable)
const HANDSHAKE_TIMEOUT_MS = 10_000;

/** Load the 32-byte seed from ~/.entity/peers/NAME/keypair (Go peer-manager convention). */
function loadSeed(name) {
  if (!name) return DEFAULT_SEED;
  const kp = path.join(os.homedir(), ".entity", "peers", name, "keypair");
  try {
    const text = fs.readFileSync(kp, "utf8");
    const body = text
      .split(/\r?\n/)
      .filter((l) => l && !l.startsWith("-----"))
      .join("");
    const seed = new Uint8Array(Buffer.from(body, "base64"));
    if (seed.length === 32) return seed;
  } catch (_) {
    /* fall through to default */
  }
  return DEFAULT_SEED;
}

/** Build a system/capability/policy-entry (mirrors peer.ts policyEntryEntity). */
function policyEntryEntity(peerPattern, grants) {
  return Entity.create(
    TypeNames.CapabilityPolicyEntry,
    Ecf.map(["peer_pattern", Ecf.text(peerPattern)], ["grants", Ecf.array(grants.map((g) => g.toEcf()))]),
  );
}

/**
 * Build the delegated kernel (PeerServices + registry + dispatcher). Mirrors
 * Peer.#bootstrap / #seedAuthorityBootstrap exactly.
 */
function createKernel(opts = {}) {
  const identity = PeerIdentity.fromSeed(loadSeed(opts.peerName));
  const seedPolicy = opts.debugOpenGrants ? SeedPolicy.debugOpen() : SeedPolicy.standard();
  const emit = new EmitBus();
  const store = new ContentStore(emit);
  const tree = new EntityTree(store, emit);

  // PeerServices surface the Dispatcher + handlers read.
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

  // Bootstrap handlers (§6.9): connect + tree + handlers + capability (MUST).
  registry.register(new ConnectHandler());
  registry.register(new TreeHandler());
  registry.register(new HandlersHandler());
  registry.register(new CapabilityHandler());

  // Local peer entity at system/peer/self (§3.13).
  tree.put("/" + identity.peerId + "/system/peer/self", identity.peerEntity);

  // Core type registry → system/type/* (53 types; §8–§10).
  seedCoreTypes(tree, identity.peerId);

  // §6.9a Peer Authority Bootstrap L0 write-set.
  const policyBase = "/" + identity.peerId + "/system/capability/policy/";
  const { token: ownerCap, signature: ownerSig } = CapabilityToken.createRoot(
    identity,
    identity.identityHash,
    SeedPolicy.ownerGrants(identity.peerId),
    services.nowMs,
  );
  tree.put(policyBase + hashHex(identity.identityHash), ownerCap.entity);
  tree.put("/" + identity.peerId + "/system/signature/" + ownerCap.contentHashHex, ownerSig);
  tree.put(policyBase + "default", policyEntryEntity("default", seedPolicy.defaultGrants));
  for (const entry of seedPolicy.namedEntries) {
    tree.put(policyBase + entry.key, policyEntryEntity(entry.key, entry.grants));
  }

  // §7a conformance handlers (opt-in; drives echo + dispatch-outbound probes).
  if (opts.validate) {
    registry.register(new ValidateEchoHandler());
    registry.register(new ValidateDispatchOutboundHandler());
  }

  return { identity, services, registry, dispatcher, ConnectionState, respond, HANDSHAKE_TIMEOUT_MS, prim };
}

module.exports = { createKernel, TS_DIST };
