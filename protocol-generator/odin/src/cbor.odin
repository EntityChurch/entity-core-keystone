package entity_core

import "core:mem"
import "core:slice"
import "core:unicode/utf8"

// Entity Canonical Form (ECF) — hand-rolled canonical CBOR encoder + decoder
// (ENTITY-CBOR-ENCODING.md v1.5). NO stdlib CBOR: `core:encoding/cbor` is
// canonical-AWARE but its map sort is BYTEWISE (not ECF length-then-lex) and it
// has no decode-side major-type-6 tag reject (A-ODIN-001), so the canonical
// layer is owned here regardless. Byte-exact against the 71-vector corpus.
//
// The codec core is a []u8 cursor, never a `string` (profile
// [idiom].byte_slices_for_wire). Encode writes into a caller-owned dynamic
// buffer; decode returns an owned Ec_Value tree (value_destroy frees it).

MAX_DEPTH :: 64 // §10.2

// ═══════════════════════════════════════════════════════════════════════════
// Encode
// ═══════════════════════════════════════════════════════════════════════════

// cbor_encode encodes value to canonical ECF bytes. The returned slice is owned
// by the caller (delete with the same allocator).
cbor_encode :: proc(value: Ec_Value, allocator := context.allocator) -> ([]u8, Codec_Error) {
	buf := make([dynamic]u8, 0, 64, allocator)
	if err := encode_into(value, &buf); err != .None {
		delete(buf)
		return nil, err
	}
	return buf[:], .None
}

encode_into :: proc(value: Ec_Value, buf: ^[dynamic]u8) -> Codec_Error {
	switch v in value {
	case Ec_Null:
		append(buf, 0xF6)
	case Ec_Bool:
		append(buf, 0xF5 if bool(v) else 0xF4)
	case Ec_Uint:
		head(0, u64(v), buf)
	case Ec_Nint:
		head(1, u64(v), buf) // stored n already == -1 - value
	case Ec_Float:
		encode_float(f64(v), buf)
	case Ec_Bytes:
		b := ([]u8)(v)
		head(2, u64(len(b)), buf)
		append(buf, ..b)
	case Ec_Text:
		s := transmute([]u8)(string(v))
		head(3, u64(len(s)), buf)
		append(buf, ..s)
	case Ec_Array:
		items := ([]Ec_Value)(v)
		head(4, u64(len(items)), buf)
		for item in items {
			encode_into(item, buf) or_return
		}
	case Ec_Map:
		return encode_map(([]Ec_Pair)(v), buf)
	case:
		return .Unsupported_Value
	}
	return .None
}

// CBOR head byte + minimal argument (majors 0-5). Minimal-length argument per
// Rule 1 — never a wider encoding than the value needs. Full u64 range (the
// [2^63, 2^64-1] band lives in the minor-27 branch — head-form self-test).
head :: proc(major: u8, n: u64, buf: ^[dynamic]u8) {
	mt := major << 5
	switch {
	case n < 24:
		append(buf, mt | u8(n))
	case n < 0x100:
		append(buf, mt | 24, u8(n))
	case n < 0x1_0000:
		append(buf, mt | 25, u8(n >> 8), u8(n))
	case n < 0x1_0000_0000:
		append(buf, mt | 26, u8(n >> 24), u8(n >> 16), u8(n >> 8), u8(n))
	case:
		append(
			buf,
			mt | 27,
			u8(n >> 56), u8(n >> 48), u8(n >> 40), u8(n >> 32),
			u8(n >> 24), u8(n >> 16), u8(n >> 8), u8(n),
		)
	}
}

// Map (major 5) — keys sorted by ENCODED bytes, length-first then lexicographic
// (Rule 2 / §4.2.1 length-then-lex, NOT plain bytewise). Each pair is encoded
// into its own buffer so the sort key is the key's encoded form; duplicate
// encoded keys are a Rule-5 error.
Encoded_Pair :: struct {
	key:   []u8,
	value: []u8,
}

encode_map :: proc(pairs: []Ec_Pair, buf: ^[dynamic]u8) -> Codec_Error {
	tmp := make([dynamic]Encoded_Pair, 0, len(pairs), context.temp_allocator)
	defer {
		for ep in tmp {
			delete(ep.key, context.temp_allocator)
			delete(ep.value, context.temp_allocator)
		}
		delete(tmp)
	}

	for pair in pairs {
		ek := cbor_encode(pair.key, context.temp_allocator) or_return
		ev := cbor_encode(pair.value, context.temp_allocator) or_return
		append(&tmp, Encoded_Pair{ek, ev})
	}

	slice.sort_by(tmp[:], proc(a, b: Encoded_Pair) -> bool {
		return key_less(a.key, b.key)
	})

	// Rule 5: reject duplicate keys (identical encoded key bytes; sorted so
	// duplicates are adjacent).
	for i in 1 ..< len(tmp) {
		if slice.equal(tmp[i - 1].key, tmp[i].key) {
			return .Duplicate_Key
		}
	}

	head(5, u64(len(pairs)), buf)
	for ep in tmp {
		append(buf, ..ep.key)
		append(buf, ..ep.value)
	}
	return .None
}

// Length-then-lexicographic ordering over ENCODED key bytes (Rule 2).
key_less :: proc(a, b: []u8) -> bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	// same length → byte-wise lexicographic
	n := len(a)
	for i in 0 ..< n {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// ── float ladder (Rule 4 / 4a) ───────────────────────────────────────────────
//
// Shortest form preserving value: -0.0/specials → fixed f16 bytes, else try
// f16, then f32, else f64, by round-trip bit-equality (an all-ones candidate
// exponent is an overflow-to-Inf, not an exact value → reject the narrower
// form). Ported bit-for-bit from the Ruby reference (§4.1 Rule 4).

encode_float :: proc(f: f64, buf: ^[dynamic]u8) {
	bits := transmute(u64)f
	exp := (bits >> 52) & 0x7FF
	mant52 := bits & 0xF_FFFF_FFFF_FFFF

	// NaN → canonical quiet NaN 0x7e00 (Rule 4a).
	if exp == 0x7FF && mant52 != 0 {
		append(buf, 0xF9, 0x7E, 0x00)
		return
	}
	// ±Inf (Rule 4a).
	if exp == 0x7FF {
		if bits >> 63 == 1 {
			append(buf, 0xF9, 0xFC, 0x00)
		} else {
			append(buf, 0xF9, 0x7C, 0x00)
		}
		return
	}
	// -0.0 (sign bit set, all else zero) → 0xf98000 (Rule 4a).
	if bits == 0x8000_0000_0000_0000 {
		append(buf, 0xF9, 0x80, 0x00)
		return
	}

	if h16, ok := fits_f16(f); ok {
		append(buf, 0xF9, u8(h16 >> 8), u8(h16))
		return
	}
	if b32, ok := fits_f32(f); ok {
		append(buf, 0xFA, u8(b32 >> 24), u8(b32 >> 16), u8(b32 >> 8), u8(b32))
		return
	}
	append(
		buf,
		0xFB,
		u8(bits >> 56), u8(bits >> 48), u8(bits >> 40), u8(bits >> 32),
		u8(bits >> 24), u8(bits >> 16), u8(bits >> 8), u8(bits),
	)
}

// Returns the 16-bit half pattern if f is an EXACT finite f16 value (not an
// all-ones exponent — that would be a silent overflow to Inf).
fits_f16 :: proc(f: f64) -> (u16, bool) {
	bits := transmute(u64)f
	sign := u16((bits >> 63) & 0x1)
	exp := i64((bits >> 52) & 0x7FF)
	mant := bits & 0xF_FFFF_FFFF_FFFF

	// +0.0 (the -0.0 case is handled by the caller).
	if exp == 0 && mant == 0 {
		return sign << 15, true
	}

	unbiased := exp - 1023
	// f16 normal exponent range is [-14, 15]; outside → not a finite f16.
	if unbiased < -14 || unbiased > 15 {
		return 0, false
	}
	// f16 keeps 10 mantissa bits; f64 has 52, so the low 42 must be zero.
	if mant & 0x3FF_FFFF_FFFF != 0 {
		return 0, false
	}
	half_mant := u16(mant >> 42)
	half_exp := u16(unbiased + 15)
	return (sign << 15) | (half_exp << 10) | half_mant, true
}

// Returns the 32-bit single pattern if f round-trips exactly through binary32
// without becoming Inf (all-ones-exponent guard), else false.
fits_f32 :: proc(f: f64) -> (u32, bool) {
	c := f32(f)
	bits := transmute(u32)c
	exp := (bits >> 23) & 0xFF
	if exp == 0xFF { // would be Inf/NaN — overflow, not exact
		return 0, false
	}
	if f64(c) != f {
		return 0, false
	}
	return bits, true
}

// ═══════════════════════════════════════════════════════════════════════════
// Decode
// ═══════════════════════════════════════════════════════════════════════════

Cursor :: struct {
	data: []u8,
	pos:  int,
	// keep_tags makes decode_value yield the tag's INNER item instead of returning
	// .Tag_Rejected. It exists for ONE caller -- cbor_decode_salvage -- and is never
	// set on the strict path. See that proc for why this is not a weakening of §6.3.
	keep_tags: bool,
}

// cbor_decode decodes canonical ECF bytes to an owned Ec_Value tree. Rejects any
// non-canonical input: a CBOR tag (major 6 — N2/§6.3), indefinite length,
// non-minimal argument, reserved additional-info, duplicate map key, over-depth,
// invalid UTF-8, or trailing bytes.
cbor_decode :: proc(data: []u8, allocator := context.allocator) -> (Ec_Value, Codec_Error) {
	cur := Cursor{data, 0, false}
	value, err := decode_value(&cur, 0, allocator)
	if err != .None {
		return nil, err
	}
	if cur.pos != len(cur.data) {
		value_destroy(value, allocator)
		return nil, .Non_Canonical_Ecf // trailing bytes
	}
	return value, .None
}

// cbor_decode_salvage decodes `data` for the sole purpose of REPORTING a rejection,
// not of accepting one. Identical to cbor_decode except that a major-type-6 tag
// yields the item it wrapped rather than .Tag_Rejected.
//
// Why this exists (§6.3, a conformance requirement rather than a convenience): the tag
// rule is "Implementations MUST reject any received protocol frame containing a CBOR
// tag on a data field. Rejection returns 400 non_canonical_ecf." Rejecting by dropping
// the frame on the floor satisfies the first sentence and violates the second -- the
// peer owes the sender a status, and §4.9(c) deliver-or-signal says the same from the
// other direction. But the status must ride a response correlated by request_id, and
// the strict decoder cannot reach the request_id in a frame it refuses to parse. This
// recovers exactly that much and nothing more.
//
// This is NOT a weakening of the tag reject. The frame stays rejected: the value this
// returns is never converted to an Entity, never stored, never forwarded and never
// interpreted, so §6.3's MUST NOT silently strip / MUST NOT preserve / MUST NOT
// attempt to interpret all still hold. The strict cbor_decode path that every real
// ingestion route uses is unchanged, which is what keeps the tag_reject
// wire-conformance vectors meaningful.
cbor_decode_salvage :: proc(data: []u8, allocator := context.allocator) -> (Ec_Value, Codec_Error) {
	cur := Cursor{data, 0, true}
	value, err := decode_value(&cur, 0, allocator)
	if err != .None {
		return nil, err
	}
	if cur.pos != len(cur.data) {
		value_destroy(value, allocator)
		return nil, .Non_Canonical_Ecf
	}
	return value, .None
}

read_byte :: proc(cur: ^Cursor) -> (u8, Codec_Error) {
	if cur.pos >= len(cur.data) {
		return 0, .Truncated
	}
	b := cur.data[cur.pos]
	cur.pos += 1
	return b, .None
}

read_slice :: proc(cur: ^Cursor, n: int) -> ([]u8, Codec_Error) {
	if n < 0 || cur.pos + n > len(cur.data) {
		return nil, .Truncated
	}
	s := cur.data[cur.pos:cur.pos + n]
	cur.pos += n
	return s, .None
}

decode_value :: proc(
	cur: ^Cursor,
	depth: int,
	allocator: mem.Allocator,
) -> (result: Ec_Value, err: Codec_Error) {
	if depth > MAX_DEPTH {
		return nil, .Depth_Exceeded
	}
	ib := read_byte(cur) or_return
	major := ib >> 5
	info := ib & 0x1F

	switch major {
	case 0:
		n := read_argument(info, cur) or_return
		return Ec_Uint(n), .None
	case 1:
		n := read_argument(info, cur) or_return
		return Ec_Nint(n), .None // stores n; wire value = -1 - n
	case 2:
		length := read_argument(info, cur) or_return
		src := read_slice(cur, int(length)) or_return
		out := make([]u8, len(src), allocator)
		copy(out, src)
		return Ec_Bytes(out), .None
	case 3:
		length := read_argument(info, cur) or_return
		src := read_slice(cur, int(length)) or_return
		if !utf8.valid_string(string(src)) {
			return nil, .Non_Canonical_Ecf
		}
		out := make([]u8, len(src), allocator)
		copy(out, src)
		return Ec_Text(string(out)), .None
	case 4:
		length := read_argument(info, cur) or_return
		return decode_array(cur, int(length), depth + 1, allocator)
	case 5:
		length := read_argument(info, cur) or_return
		return decode_map(cur, int(length), depth + 1, allocator)
	case 6:
		// Invariant N2 / §6.3 — tags MUST be rejected anywhere in the input.
		if !cur.keep_tags {
			return nil, .Tag_Rejected
		}
		// Salvage path only (cbor_decode_salvage): consume the tag head and yield the
		// item it wrapped, so the caller can locate the request_id and SIGNAL the
		// rejection. The frame is still rejected -- the tag is never interpreted and
		// the value never reaches an Entity.
		read_argument(info, cur) or_return
		return decode_value(cur, depth + 1, allocator)
	case 7:
		return decode_simple(info, cur)
	}
	return nil, .Non_Canonical_Ecf
}

// Argument decode for majors 0-5. Enforces MINIMAL-length encoding (a value that
// fits a shorter form encoded in a longer form is non-canonical), rejects
// reserved additional-info (28-30) and indefinite length (31).
read_argument :: proc(info: u8, cur: ^Cursor) -> (value: u64, err: Codec_Error) {
	switch {
	case info < 24:
		return u64(info), .None
	case info == 24:
		b := read_byte(cur) or_return
		if b < 24 {
			return 0, .Non_Canonical_Ecf
		}
		return u64(b), .None
	case info == 25:
		s := read_slice(cur, 2) or_return
		n := u64(s[0]) << 8 | u64(s[1])
		if n < 0x100 {
			return 0, .Non_Canonical_Ecf
		}
		return n, .None
	case info == 26:
		s := read_slice(cur, 4) or_return
		n := u64(s[0]) << 24 | u64(s[1]) << 16 | u64(s[2]) << 8 | u64(s[3])
		if n < 0x1_0000 {
			return 0, .Non_Canonical_Ecf
		}
		return n, .None
	case info == 27:
		s := read_slice(cur, 8) or_return
		n :=
			u64(s[0]) << 56 | u64(s[1]) << 48 | u64(s[2]) << 40 | u64(s[3]) << 32 |
			u64(s[4]) << 24 | u64(s[5]) << 16 | u64(s[6]) << 8 | u64(s[7])
		if n < 0x1_0000_0000 {
			return 0, .Non_Canonical_Ecf
		}
		return n, .None
	case info == 31:
		return 0, .Non_Canonical_Ecf // indefinite length
	case:
		return 0, .Non_Canonical_Ecf // reserved 28, 29, 30
	}
}

decode_array :: proc(
	cur: ^Cursor,
	length: int,
	depth: int,
	allocator: mem.Allocator,
) -> (Ec_Value, Codec_Error) {
	items := make([]Ec_Value, length, allocator)
	built := 0
	for built < length {
		v, err := decode_value(cur, depth, allocator)
		if err != .None {
			for i in 0 ..< built {
				value_destroy(items[i], allocator)
			}
			delete(items, allocator)
			return nil, err
		}
		items[built] = v
		built += 1
	}
	return Ec_Array(items), .None
}

decode_map :: proc(
	cur: ^Cursor,
	length: int,
	depth: int,
	allocator: mem.Allocator,
) -> (Ec_Value, Codec_Error) {
	pairs := make([]Ec_Pair, length, allocator)
	built := 0
	cleanup :: proc(pairs: []Ec_Pair, built: int, allocator: mem.Allocator) {
		for i in 0 ..< built {
			value_destroy(pairs[i].key, allocator)
			value_destroy(pairs[i].value, allocator)
		}
		delete(pairs, allocator)
	}
	for built < length {
		k, kerr := decode_value(cur, depth, allocator)
		if kerr != .None {
			cleanup(pairs, built, allocator)
			return nil, kerr
		}
		// Rule 5: duplicate-key detection over the DECODED keys (encoded-equal
		// keys decode equal). O(n^2) is fine at conformance scale.
		for i in 0 ..< built {
			if value_equal(pairs[i].key, k) {
				value_destroy(k, allocator)
				cleanup(pairs, built, allocator)
				return nil, .Duplicate_Key
			}
		}
		v, verr := decode_value(cur, depth, allocator)
		if verr != .None {
			value_destroy(k, allocator)
			cleanup(pairs, built, allocator)
			return nil, verr
		}
		pairs[built] = Ec_Pair{k, v}
		built += 1
	}
	return Ec_Map(pairs), .None
}

decode_simple :: proc(info: u8, cur: ^Cursor) -> (result: Ec_Value, err: Codec_Error) {
	switch info {
	case 20:
		return Ec_Bool(false), .None
	case 21:
		return Ec_Bool(true), .None
	case 22:
		return Ec_Null{}, .None
	case 25:
		s := read_slice(cur, 2) or_return
		return Ec_Float(f16_to_f64(u16(s[0]) << 8 | u16(s[1]))), .None
	case 26:
		s := read_slice(cur, 4) or_return
		bits := u32(s[0]) << 24 | u32(s[1]) << 16 | u32(s[2]) << 8 | u32(s[3])
		return Ec_Float(f64(transmute(f32)bits)), .None
	case 27:
		s := read_slice(cur, 8) or_return
		bits :=
			u64(s[0]) << 56 | u64(s[1]) << 48 | u64(s[2]) << 40 | u64(s[3]) << 32 |
			u64(s[4]) << 24 | u64(s[5]) << 16 | u64(s[6]) << 8 | u64(s[7])
		return Ec_Float(transmute(f64)bits), .None
	case:
		return nil, .Non_Canonical_Ecf // undefined (23), reserved simples, indefinite (31)
	}
}

// Exact f16 → f64 (specials surface as native NaN / ±Inf).
f16_to_f64 :: proc(h: u16) -> f64 {
	sign := (h >> 15) & 0x1
	exp := (h >> 10) & 0x1F
	mant := h & 0x3FF
	s: f64 = -1.0 if sign == 1 else 1.0

	if exp == 0x1F {
		if mant != 0 {
			return transmute(f64)u64(0x7FF8_0000_0000_0000) // quiet NaN
		}
		return s * (transmute(f64)u64(0x7FF0_0000_0000_0000)) // ±Inf
	}
	if exp == 0 {
		// subnormal: 2^-14 * (mant/1024)
		return s * (f64(mant) / 1024.0) * pow2(-14)
	}
	return s * (1.0 + f64(mant) / 1024.0) * pow2(int(exp) - 15)
}

pow2 :: proc(e: int) -> f64 {
	// Exact integer powers of two within the f16-representable range.
	r: f64 = 1.0
	e := e
	if e >= 0 {
		for _ in 0 ..< e {
			r *= 2.0
		}
	} else {
		for _ in 0 ..< -e {
			r /= 2.0
		}
	}
	return r
}

// ── structural value equality (duplicate-key detection) ──────────────────────

value_equal :: proc(a, b: Ec_Value) -> bool {
	switch av in a {
	case Ec_Uint:
		bv, ok := b.(Ec_Uint)
		return ok && av == bv
	case Ec_Nint:
		bv, ok := b.(Ec_Nint)
		return ok && av == bv
	case Ec_Bool:
		bv, ok := b.(Ec_Bool)
		return ok && av == bv
	case Ec_Null:
		_, ok := b.(Ec_Null)
		return ok
	case Ec_Float:
		bv, ok := b.(Ec_Float)
		return ok && av == bv
	case Ec_Bytes:
		bv, ok := b.(Ec_Bytes)
		return ok && slice.equal(([]u8)(av), ([]u8)(bv))
	case Ec_Text:
		bv, ok := b.(Ec_Text)
		return ok && string(av) == string(bv)
	case Ec_Array:
		bv, ok := b.(Ec_Array)
		if !ok || len(([]Ec_Value)(av)) != len(([]Ec_Value)(bv)) {
			return false
		}
		for i in 0 ..< len(([]Ec_Value)(av)) {
			if !value_equal((([]Ec_Value)(av))[i], (([]Ec_Value)(bv))[i]) {
				return false
			}
		}
		return true
	case Ec_Map:
		bv, ok := b.(Ec_Map)
		if !ok || len(([]Ec_Pair)(av)) != len(([]Ec_Pair)(bv)) {
			return false
		}
		for i in 0 ..< len(([]Ec_Pair)(av)) {
			p := (([]Ec_Pair)(av))[i]
			q := (([]Ec_Pair)(bv))[i]
			if !value_equal(p.key, q.key) || !value_equal(p.value, q.value) {
				return false
			}
		}
		return true
	}
	return false
}
