package entity_core

import "core:crypto/sha2"

// Content-hash construction (§4.2):
//
//   content_hash = varint(format_code) ‖ hash_alg(ECF({type, data}))
//
// The default format code 0x00 is ecfv1-sha256; 0x01 is ecfv1-sha384. The
// format_code is NOT part of the hashed entity — only {"type", "data"} is
// hashed (§4.2 "What is NOT hashed"). The varint prefix is multicodec-style
// LEB128 (N1), so a code >= 0x80 (corpus content_hash.4 = 128) extends to
// multiple bytes.
//
// Construction-vs-verification asymmetry (§4.7, v7.73): the construction path
// serialises WHATEVER format_code the caller supplies and does not gate on the
// registry (content_hash.4 exercises code 128 with a SHA-256 digest). Digest
// algorithm: code 0x01 → SHA-384; everything else (incl. the synthetic high
// code) → SHA-256, the required floor.

// content_hash computes varint(format_code) ‖ digest over {type, data} extracted
// from `entity`. The result is owned by the caller.
content_hash :: proc(
	entity: Ec_Value,
	format_code: u64,
	allocator := context.allocator,
) -> (result: []u8, err: Codec_Error) {
	typ, has_type := map_get(entity, "type")
	data, has_data := map_get(entity, "data")
	if !has_type || !has_data {
		return nil, .Bad_Entity
	}

	// Build the {type, data} preimage map (insertion order; the encoder sorts).
	preimage := Ec_Map(
		[]Ec_Pair{{Ec_Text("type"), typ}, {Ec_Text("data"), data}},
	)
	ecf := cbor_encode(preimage, context.temp_allocator) or_return
	defer delete(ecf, context.temp_allocator)

	out := make([dynamic]u8, 0, 34, allocator)
	varint_encode(format_code, &out)

	if format_code == 1 {
		digest: [sha2.DIGEST_SIZE_384]u8
		ctx: sha2.Context_512
		sha2.init_384(&ctx)
		sha2.update(&ctx, ecf)
		sha2.final(&ctx, digest[:])
		append(&out, ..digest[:])
	} else {
		digest: [sha2.DIGEST_SIZE_256]u8
		ctx: sha2.Context_256
		sha2.init_256(&ctx)
		sha2.update(&ctx, ecf)
		sha2.final(&ctx, digest[:])
		append(&out, ..digest[:])
	}
	return out[:], .None
}

// sha256 is a small convenience over core:crypto/sha2 (used by the signature
// preimage path indirectly and available for the peer layer).
sha256 :: proc(data: []u8) -> [32]u8 {
	digest: [sha2.DIGEST_SIZE_256]u8
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, data)
	sha2.final(&ctx, digest[:])
	return digest
}
