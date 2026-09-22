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
const canonicalCbor = load("codec/canonical-cbor.js");
const model = load("model/index.js");
const identity = load("identity/index.js");
const capability = load("capability/index.js");
// §4.11's cause-to-code table (0.8.2.25), delegated for the same reason the codec is:
// it is a CLASSIFICATION OF DECODER FAILURES, so re-deriving it in the flow graph
// would mean maintaining a second reading of which error means which code — and the
// two would drift on exactly the revision that adds a cause. `FrameTooLargeError` and
// `TruncatedFrameError` come with it because the AUTHORED framing node detects those
// two conditions itself (it owns the length prefix) and must be able to hand them to
// the same table rather than hard-coding two more codes beside it.
const frameCodec = load("transport/frame-codec.js");

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

/**
 * Salvage-decode a frame the STRICT decoder has already rejected, to recover its
 * `request_id` and nothing else (§6.3). Delegated, like every other codec call here:
 * re-implementing a lenient CBOR reader in the flow graph is exactly what interop
 * exists to avoid, and a second reader is a second thing to keep in step.
 *
 * This may NEVER reach an ingestion path. Its only caller builds a 400 and discards
 * everything else it read.
 */
function decodeSalvage(payload) {
  return canonicalCbor.decodeSalvage(payload);
}

/** Encode an Envelope back to canonical CBOR bytes for the frame-codec egress node. */
function encodeEnvelope(envelope) {
  return envelope.encode(); // instance method; canonical CBOR encode
}

module.exports = {
  TS_DIST,
  // delegated codec
  decodeEnvelope,
  decodeSalvage,
  encodeEnvelope,
  // delegated §4.11 classification (0.8.2.25) — one table, two callers: the strict-decode
  // refusal in session.js and the framing refusals in the ec-listener node.
  preAdmissionRefusal: frameCodec.preAdmissionRefusal,
  FrameTooLargeError: frameCodec.FrameTooLargeError,
  TruncatedFrameError: frameCodec.TruncatedFrameError,
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
