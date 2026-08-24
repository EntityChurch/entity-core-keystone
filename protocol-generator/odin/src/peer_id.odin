package entity_core

// Peer-id formatting/parsing (§1.5):
//
//   peer_id = Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)
//
// key_type and hash_type are multicodec-style LEB128 varints (N1), so a
// synthetic key_type >= 0x80 (corpus peer_id.3 = 128) extends to multiple bytes.
// The §1.5 canonical-form derivation: a key <= 32 bytes is identity-multihash
// (hash_type 0x00, digest = the key itself); a larger key is SHA-256-form
// (hash_type 0x01, digest = SHA-256(key)). The corpus pins the Base58 String,
// which the harness then ECF-encodes as a text string.

// peer_id_format returns the Base58 peer-id string from its components (owned).
peer_id_format :: proc(
	key_type: u64,
	hash_type: u64,
	digest: []u8,
	allocator := context.allocator,
) -> string {
	raw := make([dynamic]u8, 0, 40, context.temp_allocator)
	defer delete(raw)
	varint_encode(key_type, &raw)
	varint_encode(hash_type, &raw)
	append(&raw, ..digest)
	return base58_encode(raw[:], allocator)
}

// peer_id_parse decodes a Base58 peer-id string back to (key_type, hash_type,
// digest). The digest slice is owned by the caller.
peer_id_parse :: proc(
	s: string,
	allocator := context.allocator,
) -> (key_type: u64, hash_type: u64, digest: []u8, err: Codec_Error) {
	raw := base58_decode(s, context.temp_allocator) or_return
	defer delete(raw, context.temp_allocator)

	kt, n1 := varint_decode(raw) or_return
	rest := raw[n1:]
	ht, n2 := varint_decode(rest) or_return
	dig := rest[n2:]

	out := make([]u8, len(dig), allocator)
	copy(out, dig)
	return kt, ht, out, .None
}

// peer_id_from_public_key derives a peer-id from a raw public key (§1.5 size
// cutoff). Ed25519 (32 B) → (key_type, 0x00, pubkey); a larger key →
// (key_type, 0x01, SHA-256(pubkey)).
peer_id_from_public_key :: proc(
	public_key: []u8,
	key_type: u64,
	allocator := context.allocator,
) -> string {
	if len(public_key) <= 32 {
		return peer_id_format(key_type, 0, public_key, allocator)
	}
	digest := sha256(public_key)
	return peer_id_format(key_type, 1, digest[:], allocator)
}
