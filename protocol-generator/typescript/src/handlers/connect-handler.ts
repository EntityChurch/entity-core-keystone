import { parsePeerId } from "../codec/peer-id.js";
import {
  SUPPORTED_KEY_TYPE_NAMES,
  isHandshakeSupportedKeyType,
  keyAlgorithmByName,
} from "../codec/key-types.js";
import { SUPPORTED_HASH_FORMAT_NAMES } from "../codec/hash-formats.js";
import { EntityCodecError, EntityProtocolError } from "../errors.js";
import { Entity, Ecf, Protocols, Status, TypeNames, hashEqual, hashHex } from "../model/index.js";
import { PeerIdentity, buildPeerEntity, signatureSigner, verifySignature } from "../identity/index.js";
import { CapabilityToken, ChainVerifier, GrantEntry, SeedPolicy } from "../capability/index.js";
import { type Handler, type HandlerContext, HandlerResult } from "./handler-abstractions.js";
import { ConnectionState, type RemoteHelloInfo } from "./connection-state.js";

/**
 * The connection handler at `system/protocol/connect` (V7 §4, §6.2) — the sole
 * pre-authorized path. Services the `hello` and `authenticate` operations of
 * connection establishment. Note these are *operations*, not wire message types
 * (F3): the only wire messages are EXECUTE / EXECUTE_RESPONSE.
 */
export class ConnectHandler implements Handler {
  readonly pattern = Protocols.ConnectPath;
  readonly name = "connect";
  readonly operations: readonly string[] = ["hello", "authenticate"];

  async handle(ctx: HandlerContext): Promise<HandlerResult> {
    const conn = ctx.connection;
    if (conn === null) {
      throw new EntityProtocolError("connection handler requires connection state");
    }
    switch (ctx.operation) {
      case "hello":
        return this.#hello(ctx, conn);
      case "authenticate":
        return this.#authenticate(ctx, conn);
      default:
        // §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
        // 400 invalid_request — not the 501 every other handler answers, and NOT
        // the connection_sequence_error this arm used to carry. The table separates
        // a STATE conflict from an UNKNOWN operation because they select different
        // remedies: "an unknown connect operation is not out of order at all; it
        // exists in no state", so connection_sequence_error points the caller at
        // its ORDERING when the defect is its OPERATION NAME. Row 10 is scoped "in
        // any state", so this arm covers pre-handshake AND established.
        //
        // SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
        // (§3.3's 501 row, §6.2) is a different contract and is separately gated.
        return errorEntity(Status.BadRequest, "invalid_request", `unknown connect operation '${ctx.operation}'`);
    }
  }

  #hello(ctx: HandlerContext, conn: ConnectionState): HandlerResult {
    // §4.2: "After connection is established, subsequent connection requests on
    // the same connection MUST be rejected with status 409." `authenticate` gets
    // its own more specific 401 invalid_nonce (RT-6, §4.6 — a replayed nonce
    // under-signals as a generic 409); every other connect op, `hello` included,
    // keeps the general 409 here.
    if (conn.established) {
      return errorEntity(Status.Conflict, "connection_already_established", "connection already established");
    }

    // §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
    // HALF-OPEN connection (hello done, authenticate not yet) is an operation we
    // implement arriving in a state that forbids it — the same class as
    // connection_already_established above, taking the same 409. A half-open
    // connection is NOT established, so the guard above cannot reach it; §4.7 names
    // this gap explicitly because two adjacent rules each look like they cover it
    // and neither does.
    if (conn.helloReceived) {
      return errorEntity(Status.Conflict, "connection_sequence_error", "hello already received on this connection");
    }

    const hello = ctx.params;
    if (hello.type !== TypeNames.Hello) {
      return errorEntity(Status.BadRequest, "connection_sequence_error", "expected a hello entity");
    }

    // v7.66 §4.4 surface 6 / V7 §4.7: reject an unsupported peer_id key_type at the
    // earliest handshake boundary — before protocol/format negotiation. A family
    // this peer cannot sign/verify with (anything but Ed25519/Ed448) is
    // unnegotiable → 400 unsupported_key_type. A malformed peer_id falls through.
    const helloPeerId = Ecf.optText(hello.data, "peer_id");
    if (helloPeerId !== null) {
      try {
        const decoded = parsePeerId(helloPeerId);
        if (!isHandshakeSupportedKeyType(decoded.keyType)) {
          return errorEntity(
            Status.BadRequest,
            "unsupported_key_type",
            `unsupported peer_id key_type 0x${decoded.keyType.toString(16)}; this peer signs/verifies Ed25519 (0x01) and Ed448 (0x02) only`,
          );
        }
      } catch (e) {
        if (!(e instanceof EntityCodecError)) {
          throw e;
        }
        // Undecodable peer_id — not a key_type rejection; let §3.8 shape validation surface it.
      }
    }

    // Negotiation (§4.5). `protocols` is the one negotiated field Required with NO
    // default, so there is no floor to fall back to, and its two failure modes carry
    // different codes on purpose (§4.5 table row / §4.7 row 1):
    //
    //   absent or empty     -> 400 invalid_request       (a malformed hello)
    //   non-empty, disjoint -> 400 incompatible_protocol (we compared)
    //
    // "a caller that named no version cannot be told the comparison failed" — the
    // remedies differ (send the field vs change the version) and §4.7 exists so the
    // code selects the remedy. This peer had the comparison and not the distinction,
    // so an EMPTY set was answered incompatible_protocol: the right status reached by
    // a check that was never asked.
    const protocolsField = Ecf.field(hello.data, "protocols");
    const protocols =
      protocolsField === null ? [] : Ecf.asArray(protocolsField).map((p) => Ecf.asText(p));
    if (protocols.length === 0) {
      return errorEntity(Status.BadRequest, "invalid_request", "hello: protocols absent or empty");
    }
    if (!protocols.includes(Protocols.Version)) {
      return errorEntity(Status.BadRequest, "incompatible_protocol", "no common protocol version");
    }

    // §4.5: a non-empty hash_formats advertisement with no overlap → 400.
    const helloFormats = Ecf.field(hello.data, "hash_formats");
    if (helloFormats !== null) {
      const theirFormats = new Set(Ecf.asArray(helloFormats).map((v) => Ecf.asText(v)));
      if (theirFormats.size > 0 && !SUPPORTED_HASH_FORMAT_NAMES.some((n) => theirFormats.has(n))) {
        return errorEntity(Status.BadRequest, "incompatible_hash_format", "no common content_hash_format");
      }
    }

    // §4.5: a key_types accept-set that excludes our signing key_type → 400.
    const helloKeyTypes = Ecf.field(hello.data, "key_types");
    if (helloKeyTypes !== null) {
      const theirKeyTypes = new Set(Ecf.asArray(helloKeyTypes).map((v) => Ecf.asText(v)));
      if (theirKeyTypes.size > 0 && !theirKeyTypes.has(ctx.peer.localIdentity.keyTypeName)) {
        return errorEntity(Status.BadRequest, "unsupported_key_type", "key_types accept-set excludes responder key_type");
      }
    }

    const remotePeerId = Ecf.requireText(hello.data, "peer_id");
    const remoteNonce = Ecf.requireBytes(hello.data, "nonce");
    conn.remotePeerId = remotePeerId;
    conn.helloReceived = true;
    const info: RemoteHelloInfo = { peerId: remotePeerId, nonce: remoteNonce };
    conn.inboundHello.resolve(info);

    // Respond with the local peer's own hello data (§4.4). Retain the challenge
    // nonce so the inbound authenticate's echo can be verified (§4.6).
    const response = buildHello(ctx.peer.localIdentity, ctx.peer.nowMs);
    conn.sentNonce = Ecf.requireBytes(response.data, "nonce");
    return HandlerResult.ok(response);
  }

  #authenticate(ctx: HandlerContext, conn: ConnectionState): HandlerResult {
    if (conn.established) {
      // RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
      // single-use nonce. The anti-replay property is the MUST and the mechanism
      // (established-state tracking) is impl-defined, but the STATUS is pinned to
      // 401 invalid_nonce — a 409 state-conflict under-signals the replay.
      return errorEntity(Status.Unauthorized, "invalid_nonce", "authenticate replayed on an already-established connection");
    }
    if (!conn.helloReceived) {
      // FM-1 (§4.2, §4.7 row 6, 0.8.2.1): an authenticate arriving before any
      // hello nonce was issued is the SAME input as the replay handled directly
      // above — a captured authenticate replayed onto a fresh connection is
      // exactly this — so it is an authentication failure, not a malformed
      // request. §4.7's out-of-order row explicitly no longer names it.
      return errorEntity(Status.Unauthorized, "invalid_nonce", "authenticate before hello");
    }

    const authenticate = ctx.params;
    if (authenticate.type !== TypeNames.Authenticate) {
      return errorEntity(Status.BadRequest, "connection_sequence_error", "expected an authenticate entity");
    }

    const publicKey = Ecf.requireBytes(authenticate.data, "public_key");
    const claimedPeerId = Ecf.requireText(authenticate.data, "peer_id");

    // PoP step 1 (§4.6 / §3.8): the authenticate MUST echo the nonce this peer
    // issued in its own hello on this connection (defeats cross-connection replay, F12).
    const echoedNonce = Ecf.optBytes(authenticate.data, "nonce") ?? new Uint8Array(0);
    if (conn.sentNonce === null || !hashEqual(echoedNonce, conn.sentNonce)) {
      return errorEntity(Status.Unauthorized, "invalid_nonce", "authenticate nonce does not echo the challenge");
    }

    // Resolve the remote's announced key family (§1.5); default to the §9.1 floor.
    const keyTypeName = Ecf.optText(authenticate.data, "key_type") ?? "ed25519";
    let remoteKeyType;
    try {
      remoteKeyType = keyAlgorithmByName(keyTypeName);
    } catch (e) {
      if (e instanceof EntityCodecError) {
        return errorEntity(Status.BadRequest, "unsupported_key_type", `unsupported key_type '${keyTypeName}'`);
      }
      throw e;
    }

    // Public key must match the claimed peer id under its key family (§4.7).
    if (PeerIdentity.derivePeerId(publicKey, remoteKeyType) !== claimedPeerId) {
      return errorEntity(Status.Unauthorized, "identity_mismatch", "public key does not match peer_id");
    }

    // Verify the authenticate signature via target-matching (§4.6).
    const remotePeer = buildPeerEntity(remoteKeyType, publicKey);
    const signature = ChainVerifier.findSignature(ctx.envelope, authenticate.contentHash);
    if (
      signature === null ||
      !hashEqual(signatureSigner(signature), remotePeer.contentHash) ||
      !verifySignature(signature, remotePeer)
    ) {
      // §4.7 row 7: a non-verifying authenticate signature is
      // 401 authentication_failed. `invalid_signature` is a minted spelling — the
      // (code, status) pair is a normative MUST-emit contract, and a caller told
      // "invalid_signature" is pointed at the same remedy under a name no other
      // implementation answers.
      return errorEntity(Status.Unauthorized, "authentication_failed", "authenticate signature invalid");
    }

    // §4.7 row 8, the OTHER input on the same row: the derivation above proves the
    // claimed peer_id is self-consistent with its public_key and says nothing about
    // whether it is the identity this connection GREETED as. Without this a caller
    // may greet as one peer and authenticate as another, and every seed-policy
    // lookup after it resolves against the second. `conn.remotePeerId` is set by
    // #hello, so it holds the greeted identity at this point.
    if (conn.remotePeerId !== null && conn.remotePeerId !== claimedPeerId) {
      return errorEntity(Status.Unauthorized, "identity_mismatch", "authenticate peer_id differs from the hello's peer_id");
    }

    conn.remotePeerEntity = remotePeer;
    conn.remotePeerId = claimedPeerId;

    // Mint the initial capability for the authenticating peer (§4.4 / §6.9a). The scope
    // is derived from the declared seed policy read from the tree — NOT a hardcoded
    // initialGrants()/openGrants() fork (§6.9a declares that non-conformant). The matched
    // policy scope is UNION'd with the §4.4 discovery floor (v7.62 §8).
    const local = ctx.peer.localIdentity;
    const grants = deriveSeedGrants(ctx, remotePeer, claimedPeerId);
    const { token, signature: capSignature } = CapabilityToken.createRoot(
      local,
      remotePeer.contentHash,
      grants,
      ctx.peer.nowMs,
    );

    conn.established = true;

    const grant = Entity.create(TypeNames.CapabilityGrant, Ecf.map(["token", Ecf.bytes(token.contentHash)]));
    const included = [token.entity, local.peerEntity, remotePeer, capSignature];
    return HandlerResult.ok(grant, included);
  }
}

/** Build the local peer's `hello` entity with a fresh nonce (§3.8). */
export function buildHello(local: PeerIdentity, nowMs: bigint): Entity {
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  return Entity.create(
    TypeNames.Hello,
    Ecf.map(
      ["peer_id", Ecf.text(local.peerId)],
      ["nonce", Ecf.bytes(nonce)],
      ["protocols", Ecf.array([Ecf.text(Protocols.Version)])],
      // §4.5 negotiation advertisement: the accepted content_hash_format + key_type families.
      ["hash_formats", Ecf.array(SUPPORTED_HASH_FORMAT_NAMES.map((n) => Ecf.text(n)))],
      ["key_types", Ecf.array(SUPPORTED_KEY_TYPE_NAMES.map((n) => Ecf.text(n)))],
      ["timestamp", Ecf.uint(nowMs)],
    ),
  );
}

/**
 * §6.9a authenticate-time derivation: resolve the seed-policy scope for the
 * authenticating identity via the v7.64 dual-form lookup (`hex → Base58 → default`),
 * then UNION it with the §4.4 discovery floor (v7.62 §8). The matched policy entry may
 * be a `system/capability/token` (the §6.9a.0 detached-signature shape — e.g. the `self`
 * owner cap, whose detached signature is verified at the §3.5 invariant pointer before
 * its grants are trusted) or a `system/capability/policy-entry` (the scope-template shape
 * — e.g. the `default` entry). When nothing matches, the floor alone is minted.
 */
function deriveSeedGrants(ctx: HandlerContext, remotePeer: Entity, remotePeerId: string): GrantEntry[] {
  const base = "/" + ctx.localPeerId + "/system/capability/policy/";
  const hexKey = hashHex(remotePeer.contentHash);

  // v7.64 dual-form lookup: hex (canonical) → Base58 (pre-contact) → default sentinel.
  const entry =
    ctx.peer.tree.get(base + hexKey) ?? ctx.peer.tree.get(base + remotePeerId) ?? ctx.peer.tree.get(base + "default");

  const floor = SeedPolicy.discoveryFloor();
  const policyGrants = entry === undefined ? [] : seedEntryGrants(ctx, entry);

  // v7.62 §8 UNION: grant entries are independent — dispatch matches if ANY entry
  // covers, so the union is the concatenation of the floor and the policy scope.
  return policyGrants.length === 0 ? floor : [...floor, ...policyGrants];
}

/**
 * Extract the grant scope from a matched seed-policy entry, handling both §6.9a.0
 * artifact shapes. A capability token (detached-signature shape) is trusted only after
 * its self-signature verifies at `system/signature/{cap_hash}`; a policy-entry yields
 * its grants directly.
 */
function seedEntryGrants(ctx: HandlerContext, entry: Entity): GrantEntry[] {
  if (entry.type === TypeNames.CapabilityToken) {
    const token = new CapabilityToken(entry);
    const sig = ctx.peer.tree.get("/" + ctx.localPeerId + "/system/signature/" + token.contentHashHex);
    if (sig === undefined || !verifySignature(sig, ctx.peer.localIdentity.peerEntity)) {
      return []; // unverifiable seed cap → no authority
    }
    return [...token.grants];
  }
  if (entry.type === TypeNames.CapabilityPolicyEntry) {
    return Ecf.asArray(Ecf.require(entry.data, "grants")).map((g) => GrantEntry.fromEcf(g));
  }
  return [];
}

function errorEntity(status: number, code: string, message: string): HandlerResult {
  const error = Entity.create(TypeNames.Error, Ecf.map(["code", Ecf.text(code)], ["message", Ecf.text(message)]));
  return HandlerResult.of(status, error);
}
