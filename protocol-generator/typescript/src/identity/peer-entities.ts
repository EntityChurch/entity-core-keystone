import { formatPeerId } from "../codec/peer-id.js";
import { type KeyAlgorithm, canonicalPeerIdParts, keyAlgorithmByName } from "../codec/key-types.js";
import { EntityProtocolError } from "../errors.js";
import { Entity, Ecf } from "../model/index.js";

/**
 * Build and read `system/peer` entities (V7 §3.5, §7.65). The canonical peer
 * entity is `{key_type, public_key}` — a pure function of the keypair.
 *
 * v7.65 canonicalization: `peer_id` is *not* part of the hashable basis (it is a
 * projection of the public key, not canonical), so it is dropped from the entity.
 * `content_hash(system/peer)` is therefore a pure function of `(public_key,
 * key_type)`, and the same identity yields the same hash regardless of which
 * address universe its peer_id projects into.
 */

/** Materialize a `system/peer` entity from a key family and raw public key. */
export function buildPeerEntity(keyType: KeyAlgorithm, publicKey: Uint8Array): Entity {
  return Entity.create(
    "system/peer",
    Ecf.map(["key_type", Ecf.text(keyType.name)], ["public_key", Ecf.bytes(publicKey)]),
  );
}

/** Read the raw public key from a `system/peer` entity. */
export function peerPublicKey(peer: Entity): Uint8Array {
  if (peer.type !== "system/peer") {
    throw new EntityProtocolError(`expected system/peer entity, got '${peer.type}'`);
  }
  return Ecf.requireBytes(peer.data, "public_key");
}

/** Resolve the key family of a `system/peer` entity from its `key_type` name. */
export function peerKeyAlgorithm(peer: Entity): KeyAlgorithm {
  return keyAlgorithmByName(Ecf.requireText(peer.data, "key_type"));
}

/**
 * Derive the canonical Base58 `peer_id` of a `system/peer` entity (§1.5 / §7.65).
 * The peer_id is no longer stored in the entity — it is a projection of
 * `(public_key, key_type)` under the size-cutoff rule.
 */
export function peerEntityId(peer: Entity): string {
  const keyType = peerKeyAlgorithm(peer);
  const publicKey = peerPublicKey(peer);
  const { hashType, digest } = canonicalPeerIdParts(publicKey);
  return formatPeerId(keyType.wireCode, hashType, digest);
}
