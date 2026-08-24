package entity_core

// Ec_Value — the ECF value model (a tagged union). Entity `data` is an
// ARBITRARY ECF value, not necessarily a map (§1.1 / A-JAVA-010), so this is the
// single tree type the codec encodes/decodes and the corpus `input` decodes to.
//
// Integer model (fixed-width class — profile [idiom].native_fixed_width_int).
// Integers carry the FULL unsigned 64-bit pattern + the head form is a
// derived artifact of the value, not stored:
//   - Ec_Uint  is major type 0; the u64 IS the value (covers [0, 2^64-1]).
//   - Ec_Nint  is major type 1; the stored u64 is `n` where the wire value is
//              `-1 - n`. So Ec_Nint(0) == -1 and Ec_Nint(2^64-1) == -2^64.
// This covers the whole spec range including the [2^63, 2^64-1] band that a
// signed i64 cannot hold — the head-form self-test exercises exactly that band.
//
// Text (mt3) vs bytes (mt2) are DISTINCT variants (never collapsed to one
// "string") — the wire distinction is load-bearing for ECF (map-key sort,
// content-hash preimage, `data` raw-byte fidelity N4).
//
// Ownership (no-GC — profile [memory]): a decoded Ec_Value OWNS its byte/text
// slices and its array/map children. `value_destroy(v, allocator)` frees the
// whole tree. Encoding borrows the tree and allocates only the output buffer.

Ec_Value :: union {
	Ec_Uint,
	Ec_Nint,
	Ec_Bytes,
	Ec_Text,
	Ec_Array,
	Ec_Map,
	Ec_Bool,
	Ec_Null,
	Ec_Float,
}

Ec_Uint  :: distinct u64 // major 0, value = n
Ec_Nint  :: distinct u64 // major 1, wire value = -1 - n; stores n
Ec_Bytes :: distinct []u8 // major 2 (owned)
Ec_Text  :: distinct string // major 3, UTF-8 (owned)
Ec_Array :: distinct []Ec_Value // major 4 (owned)
Ec_Bool  :: distinct bool
Ec_Null  :: struct {} // major 7, simple 22
Ec_Float :: distinct f64 // major 7, float16/32/64 (shortest on encode)

// A map key-value pair. Keys keep INSERTION order in the tree; the encoder sorts
// a COPY of the encoded keys length-then-lex at emit time (Rule 2). Decode
// order is preserved so a re-encode is idempotent and duplicate-key detection is
// order-independent.
Ec_Pair :: struct {
	key:   Ec_Value,
	value: Ec_Value,
}

Ec_Map :: distinct []Ec_Pair // major 5 (owned)

// ── recursive free (owned decode tree) ───────────────────────────────────────

value_destroy :: proc(v: Ec_Value, allocator := context.allocator) {
	#partial switch t in v {
	case Ec_Bytes:
		delete(([]u8)(t), allocator)
	case Ec_Text:
		delete(string(t), allocator)
	case Ec_Array:
		for child in ([]Ec_Value)(t) {
			value_destroy(child, allocator)
		}
		delete(([]Ec_Value)(t), allocator)
	case Ec_Map:
		for pair in ([]Ec_Pair)(t) {
			value_destroy(pair.key, allocator)
			value_destroy(pair.value, allocator)
		}
		delete(([]Ec_Pair)(t), allocator)
	}
}

// ── small accessors used by the conformance harness ──────────────────────────

// map_get returns the value for a TEXT key, or nil + false if absent / not a map.
map_get :: proc(v: Ec_Value, key: string) -> (Ec_Value, bool) {
	m, is_map := v.(Ec_Map)
	if !is_map {
		return nil, false
	}
	for pair in ([]Ec_Pair)(m) {
		if t, ok := pair.key.(Ec_Text); ok && string(t) == key {
			return pair.value, true
		}
	}
	return nil, false
}

// as_uint coerces an Ec_Uint to u64 (used for format_code / key_type / hash_type
// pulled out of the decoded corpus input maps).
as_uint :: proc(v: Ec_Value) -> (u64, bool) {
	u, ok := v.(Ec_Uint)
	return u64(u), ok
}

// as_bytes returns the raw []u8 of an Ec_Bytes (digest / seed corpus fields).
as_bytes :: proc(v: Ec_Value) -> ([]u8, bool) {
	b, ok := v.(Ec_Bytes)
	return ([]u8)(b), ok
}
