"use strict";
/**
 * codec-bridge — the DELEGATED half of the Node-RED peer (profile codec_strategy
 * = "interop"). This is the ONLY place the flow-graph reaches into the compiled
 * TypeScript peer (#2); everything else — dispatch, handshake, capability flow,
 * §6.11 reentry — is authored as nodes + wires.
 *
 * It require()s the TS peer's compiled `dist/src/**` (same Node.js runtime → the
 * codec is byte-exact by construction, 71/71 wire-conformance @ 9695b1f1). No
 * canonical-CBOR / Ed25519 / SHA-256 / float ladder is re-implemented here — that
 * is the whole point of interop (the operator's intent: skip the libraries,
 * author the logic).
 *
 * The bridge exposes a small, flow-friendly surface: bytes<->envelope, sign,
 * verify, and the ECF value/model constructors the handler nodes build responses
 * with. Loaded once into Node-RED's functionGlobalContext (see settings.js) so any
 * `function` node reaches it as `global.get("ec")`, and the custom nodes import it
 * directly.
 */

const path = require("node:path");

// Resolve the compiled TS peer relative to this file:
//   protocol-generator/node-red/src/lib/codec-bridge.js
//   protocol-generator/typescript/dist/src/**
// Overridable via EC_TS_DIST for a relocated/installed layout.
const TS_DIST =
  process.env.EC_TS_DIST ||
  path.resolve(__dirname, "..", "..", "..", "typescript", "dist", "src");

function load(rel) {
  return require(path.join(TS_DIST, rel));
}

// The delegated modules named in profile.toml [codec].interop_modules.
const codec = load("codec/entity-codec.js");
const model = load("model/index.js");
const identity = load("identity/index.js");
const capability = load("capability/index.js");

const { Ecf, Entity, Envelope, Execute, ExecuteResponse, Status, Protocols, TypeNames } = model;

/**
 * Decode a CBOR frame payload (the bytes AFTER the 4-byte length prefix — framing
 * is authored in the flow's frame-codec node, not here) into an Envelope.
 * Throws on malformed / non-canonical input; the dispatch flow routes the throw
 * to its error-envelope wire (400 invalid_request), never hanging the peer (§6.5).
 */
function decodeEnvelope(payload) {
  return Envelope.decode(payload); // static; canonical CBOR decode + non-canonical reject
}

/** Encode an Envelope back to canonical CBOR bytes for the frame-codec egress node. */
function encodeEnvelope(envelope) {
  return envelope.encode(); // instance method; canonical CBOR encode
}

module.exports = {
  TS_DIST,
  // delegated codec
  decodeEnvelope,
  encodeEnvelope,
  // delegated model/value constructors the authored handler nodes use to build
  // responses (they build LOGIC with these; they do not touch bytes)
  Ecf,
  Entity,
  Envelope,
  Execute,
  ExecuteResponse,
  Status,
  Protocols,
  TypeNames,
  // delegated crypto/identity + capability verification (Layer-1 deterministic
  // verdict) — the authored verify-request node calls these, it does not
  // re-implement signature or chain math
  identity,
  capability,
  raw: { codec, model, identity, capability },
};
