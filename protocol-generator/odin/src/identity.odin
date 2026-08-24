package entity_core

import "core:slice"
import "core:strings"

// Identity (L1) — a peer's keypair and the entities derived from it (§1.5, §3.5,
// §7.3). The peer identity is a 32-byte Ed25519 seed; everything else derives:
//
//   public_key    = Ed25519 pub of seed                          (32 bytes)
//   peer_id       = Base58(varint(1) ‖ varint(0) ‖ public_key)   (§1.5
//                   identity-multihash canonical form — hash_type 0x00, digest =
//                   the raw public_key for a <=32-byte key)
//   peer entity   = system/peer { public_key, key_type }         (§3.5 — NO
//                   peer_id in the hashable basis)
//   identity_hash = content_hash(peer entity)                    (33 bytes)
//
// The canonical identity-multihash form (hash_type=0x00, digest = raw pubkey) is
// what the oracle expects at handshake — corroborates the Zig/OCaml arrival.
// Signing is over the full 33-byte content_hash.

Identity :: struct {
	seed:          [32]u8,
	public_key:    [32]u8,
	peer_id:       string, // owned Base58
	peer_entity:   Entity, // owned
	identity_hash: []u8, // borrows peer_entity.hash
}

identity_destroy :: proc(id: Identity, allocator := context.allocator) {
	delete(id.peer_id, allocator)
	entity_destroy(id.peer_entity, allocator)
}

// peer_entity_of_pubkey builds the system/peer entity for a public key (§3.5 —
// no peer_id field). Owned.
peer_entity_of_pubkey :: proc(
	public_key: []u8,
	allocator := context.allocator,
) -> (Entity, Codec_Error) {
	pairs := make([]Ec_Pair, 2, allocator)
	pairs[0] = Ec_Pair{text_val("public_key", allocator), bytes_val(public_key, allocator)}
	pairs[1] = Ec_Pair{text_val("key_type", allocator), text_val("ed25519", allocator)}
	return entity_make("system/peer", Ec_Map(pairs), allocator)
}

// peer_id_of_pubkey derives the canonical Ed25519 peer_id (§1.5 identity-
// multihash: key_type 0x01, hash_type 0x00, digest = raw pubkey). Owned.
peer_id_of_pubkey :: proc(public_key: []u8, allocator := context.allocator) -> string {
	return peer_id_format(0x01, 0x00, public_key, allocator)
}

identity_of_seed :: proc(seed: [32]u8, allocator := context.allocator) -> (Identity, Codec_Error) {
	seed_copy := seed
	pk_slice, perr := signature_public_key(seed_copy[:], allocator)
	if perr != .None {
		return Identity{}, perr
	}
	defer delete(pk_slice, allocator)
	pk: [32]u8
	copy(pk[:], pk_slice)

	peer_entity, eerr := peer_entity_of_pubkey(pk[:], allocator)
	if eerr != .None {
		return Identity{}, eerr
	}
	pid := peer_id_of_pubkey(pk[:], allocator)

	return Identity{
		seed = seed,
		public_key = pk,
		peer_id = pid,
		peer_entity = peer_entity,
		identity_hash = peer_entity.hash,
	}, .None
}

// sign_entity signs an entity's content_hash and produces the system/signature
// entity (§3.5). Owned.
sign_entity :: proc(
	id: Identity,
	target: Entity,
	allocator := context.allocator,
) -> (Entity, Codec_Error) {
	if len(target.hash) != 33 {
		return Entity{}, .Bad_Entity
	}
	seed := id.seed
	sig_bytes, serr := signature_sign_raw(seed[:], target.hash, allocator)
	if serr != .None {
		return Entity{}, serr
	}
	defer delete(sig_bytes, allocator)
	pairs := make([]Ec_Pair, 4, allocator)
	pairs[0] = Ec_Pair{text_val("target", allocator), bytes_val(target.hash, allocator)}
	pairs[1] = Ec_Pair{text_val("signer", allocator), bytes_val(id.identity_hash, allocator)}
	pairs[2] = Ec_Pair{text_val("algorithm", allocator), text_val("ed25519", allocator)}
	pairs[3] = Ec_Pair{text_val("signature", allocator), bytes_val(sig_bytes, allocator)}
	return entity_make("system/signature", Ec_Map(pairs), allocator)
}

// verify_signature verifies a system/signature entity against the signer's
// system/peer entity (the §5.2 signer-hash binding is the caller's job).
verify_signature :: proc(signature: Entity, signer_peer: Entity) -> bool {
	target, has_t := entity_bytes(signature, "target")
	sig_bytes, has_s := entity_bytes(signature, "signature")
	pub_bytes, has_p := entity_bytes(signer_peer, "public_key")
	if !has_t || !has_s || !has_p {
		return false
	}
	if len(sig_bytes) != 64 || len(pub_bytes) != 32 {
		return false
	}
	return signature_verify_raw(pub_bytes, target, sig_bytes)
}

// ── small helpers shared by the capability + dispatch layers ──────────────────

bytes_eq :: proc(a, b: []u8) -> bool {
	return slice.equal(a, b)
}

starts_with :: proc(s, prefix: string) -> bool {
	return strings.has_prefix(s, prefix)
}
