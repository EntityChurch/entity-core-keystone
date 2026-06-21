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
        return errorEntity(Status.BadRequest, "connection_sequence_error", `unknown connect operation '${ctx.operation}'`);
    }
  }

  #hello(ctx: HandlerContext, conn: ConnectionState): HandlerResult {
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

    // Negotiation (§4.5): protocols intersection must be non-empty.
    const protocols = Ecf.asArray(Ecf.require(hello.data, "protocols")).map((p) => Ecf.asText(p));
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
      return errorEntity(Status.Conflict, "connection_already_established", "connection already established");
    }
    if (!conn.helloReceived) {
      return errorEntity(Status.BadRequest, "connection_sequence_error", "authenticate before hello");
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
      return errorEntity(Status.Unauthorized, "invalid_signature", "authenticate signature invalid");
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
