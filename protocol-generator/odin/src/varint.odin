package entity_core

// Multicodec-style unsigned LEB128 varints (§1.5 / §7.3, invariant N1).
//
// Used for the content-hash format-code prefix and the peer-id key_type /
// hash_type framing. Every currently-allocated code is < 0x80 (a single byte),
// but the framing routes through a REAL LEB128 primitive so a synthetic code
// >= 0x80 (corpus content_hash.4 = 128, peer_id.3 = 128) extends to multiple
// bytes instead of silently truncating (N1 — the bug class that bit reference
// impls). Fixed 7-bit-per-byte continuation encoding.

// varint_encode appends the unsigned LEB128 encoding of n to buf.
varint_encode :: proc(n: u64, buf: ^[dynamic]u8) {
	n := n
	for {
		b := u8(n & 0x7F)
		n >>= 7
		if n == 0 {
			append(buf, b)
			return
		}
		append(buf, b | 0x80)
	}
}

// varint_decode reads an unsigned LEB128 varint from the front of src. Returns
// the value, the number of bytes consumed, and an error. Truncation (a
// continuation bit set on the last available byte) is Codec_Error.Truncated.
varint_decode :: proc(src: []u8) -> (value: u64, consumed: int, err: Codec_Error) {
	shift: uint = 0
	i := 0
	for {
		if i >= len(src) {
			return 0, 0, .Truncated
		}
		b := src[i]
		i += 1
		value |= u64(b & 0x7F) << shift
		if b & 0x80 == 0 {
			return value, i, .None
		}
		shift += 7
	}
}
