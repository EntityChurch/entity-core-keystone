package entity_core

import "core:crypto/ed25519"

// Ed25519 sign/verify over canonical-ECF-encoded entities, via NATIVE pure-Odin
// core:crypto/ed25519 (RFC 8032 / FIPS 186-5). PureEdDSA is deterministic — a
// fixed 32-byte seed + fixed message yields fixed 64-byte signature bytes, so
// the corpus can byte-pin them (signature.1..3). No FFI, no libsodium — the
// crypto floor is self-contained (A-ODIN-004: unaudited but oracle-gated).
//
// core:crypto/ed25519 takes the 32-byte SEED as the "private key" and derives
// the SHA-512 expansion internally (private_key_set_bytes), matching the RFC
// 8032 seed→key derivation the corpus assumes.

// signature_sign_raw signs an already-serialized message with a 32-byte seed.
// Returns the 64-byte signature (owned).
signature_sign_raw :: proc(
	seed: []u8,
	message: []u8,
	allocator := context.allocator,
) -> ([]u8, Codec_Error) {
	if len(seed) != ed25519.PRIVATE_KEY_SIZE {
		return nil, .Bad_Seed
	}
	priv: ed25519.Private_Key
	defer ed25519.private_key_clear(&priv)
	if !ed25519.private_key_set_bytes(&priv, seed) {
		return nil, .Bad_Seed
	}
	sig := make([]u8, ed25519.SIGNATURE_SIZE, allocator)
	ed25519.sign(&priv, message, sig)
	return sig, .None
}

// signature_sign signs the canonical ECF encoding of `entity` with a seed.
signature_sign :: proc(
	seed: []u8,
	entity: Ec_Value,
	allocator := context.allocator,
) -> (sig: []u8, err: Codec_Error) {
	msg := cbor_encode(entity, context.temp_allocator) or_return
	defer delete(msg, context.temp_allocator)
	return signature_sign_raw(seed, msg, allocator)
}

// signature_verify_raw verifies a signature over an already-serialized message.
signature_verify_raw :: proc(public_key: []u8, message: []u8, sig: []u8) -> bool {
	if len(public_key) != ed25519.PUBLIC_KEY_SIZE || len(sig) != ed25519.SIGNATURE_SIZE {
		return false
	}
	pub: ed25519.Public_Key
	if !ed25519.public_key_set_bytes(&pub, public_key) {
		return false
	}
	return ed25519.verify(&pub, message, sig)
}

// signature_public_key derives the raw public key from a 32-byte seed (owned).
signature_public_key :: proc(
	seed: []u8,
	allocator := context.allocator,
) -> ([]u8, Codec_Error) {
	if len(seed) != ed25519.PRIVATE_KEY_SIZE {
		return nil, .Bad_Seed
	}
	priv: ed25519.Private_Key
	defer ed25519.private_key_clear(&priv)
	if !ed25519.private_key_set_bytes(&priv, seed) {
		return nil, .Bad_Seed
	}
	pk := make([]u8, ed25519.PUBLIC_KEY_SIZE, allocator)
	ed25519.private_key_public_bytes(&priv, pk)
	return pk, .None
}
