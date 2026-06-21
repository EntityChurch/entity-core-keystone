// Package varint implements the unsigned LEB128 ("multicodec-style") varint
// used by the Entity Core Protocol for hash format codes (V7 §1.2), peer-id
// key_type/hash_type fields (§1.5) and other framing codes (§7.3, NORMATIVE).
//
// This is the N1 invariant: format/key/hash codes are LEB128 varints, NOT
// fixed-width bytes. Every currently-allocated code is < 0x80 and so encodes as
// a single byte — byte-identical to a fixed field today — but the framing MUST
// route through a real varint primitive so codes >= 0x80 (2+ bytes) work and
// non-minimal encodings are rejected on decode. (Note: stdlib encoding/binary's
// Uvarint is the same unsigned-LEB128 wire form, but we own it here so the
// minimal-encoding rejection and the §7.3 framing are explicit and local.)
package varint

import "errors"

// ErrNonMinimal is returned when a decoded varint uses more bytes than the
// minimal encoding of its value (a canonicalisation violation).
var ErrNonMinimal = errors.New("varint: non-minimal encoding")

// ErrTruncated is returned when the input ends mid-varint.
var ErrTruncated = errors.New("varint: truncated")

// ErrOverflow is returned when a varint does not fit in a uint64.
var ErrOverflow = errors.New("varint: value overflows uint64")

// Encode appends the unsigned LEB128 encoding of v to dst and returns the
// extended slice.
func Encode(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// EncodeTo returns the unsigned LEB128 encoding of v.
func EncodeTo(v uint64) []byte {
	return Encode(make([]byte, 0, 10), v)
}

// Decode reads one minimal unsigned LEB128 varint from b, returning the value
// and the number of bytes consumed. A non-minimal encoding (a trailing 0x00
// continuation group that does not contribute value) is rejected with
// ErrNonMinimal — canonical framing requires the shortest form.
func Decode(b []byte) (value uint64, n int, err error) {
	var shift uint
	for i := 0; i < len(b); i++ {
		c := b[i]
		if i == 9 && c > 0x01 {
			// The 10th byte may only contribute the top bit of a uint64.
			return 0, 0, ErrOverflow
		}
		value |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			// Last byte: reject a non-minimal terminator (a zero byte
			// that adds nothing, except the single-byte value 0 itself).
			if c == 0 && i != 0 {
				return 0, 0, ErrNonMinimal
			}
			return value, i + 1, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, 0, ErrOverflow
		}
	}
	return 0, 0, ErrTruncated
}
