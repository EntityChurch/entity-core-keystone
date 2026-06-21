// Package cbor implements the Entity Canonical Form (ECF) CBOR codec for the
// Entity Core Protocol, V7 (ENTITY-CBOR-ENCODING.md v1.5).
//
// This is a hand-rolled canonical CBOR encoder/decoder. It owns the canonical
// layer outright (length-then-lex map ordering per Rule 2, shortest-float incl.
// float16 specials per Rule 4/4a, minimal integers per Rule 1, definite lengths
// per Rule 3, duplicate-key rejection per Rule 5, recursive major-type-6 tag
// rejection per §6.3) rather than delegating any of it to a third-party library.
// See protocol-generator/go/arch/PROFILE-RATIONALE.md and SPEC-AMBIGUITY-LOG
// A-GO-001 for why the canonical layer is owned, not borrowed.
package cbor

// Value is an ECF value: an arbitrary CBOR data item modelled with enough type
// fidelity to round-trip and re-encode byte-identically. The entity data field
// is an arbitrary ECF Value (NOT necessarily a map) — see A-JAVA-010.
//
// The Kind discriminator preserves the distinctions that idiomatic Go types
// would erase: uint vs nint vs float (Go's float64 cannot represent an exact
// integer's int-vs-float identity, and the full nint band [-2^64,-1] does not
// fit int64 — see A-GO-003).
type Value struct {
	Kind Kind

	// Uint carries a major-type-0 unsigned integer in its full [0, 2^64-1]
	// range. Native uint64 (no BigInt ceremony — [idiom].uint64_native).
	Uint uint64

	// Nint carries a major-type-1 negative integer as the encoded magnitude
	// n, where the value is -1-n. Carries the full [-2^64,-1] band that does
	// not fit int64 (A-GO-003): value -1 => Nint 0, value -2^64 => Nint
	// 2^64-1 (uint64 max).
	Nint uint64

	// Float carries a major-type-7 IEEE-754 value. Encoded with shortest
	// form preserving value (Rule 4) and the exact special bytes (Rule 4a).
	Float float64

	// Bool carries the major-type-7 simple values true (0xF5) / false (0xF4).
	Bool bool

	// Text carries a major-type-3 UTF-8 text string.
	Text string

	// Bytes carries a major-type-2 byte string.
	Bytes []byte

	// Array carries major-type-4 elements in order.
	Array []Value

	// Map carries major-type-5 key/value pairs. Keys are themselves Values
	// (text or byte strings in ECF). The slice preserves the decoded order;
	// canonical encoding re-sorts by Rule 2.
	Map []Pair

	// Tag carries a major-type-6 tag number. Tags are never valid in ECF data
	// positions (§6.3) — this field exists only so the decoder can detect and
	// reject them. The decoder never produces a Tag Value to a caller for a
	// data field; the recursive scan rejects first.
	Tag     uint64
	TagItem *Value
}

// Pair is a single map entry (preserving decoded order until canonicalisation).
type Pair struct {
	Key Value
	Val Value
}

// Kind discriminates the CBOR major type / simple value of a Value.
type Kind uint8

const (
	KindUint Kind = iota
	KindNint
	KindFloat
	KindBool
	KindNull
	KindText
	KindBytes
	KindArray
	KindMap
	KindTag
)

// Constructors for the common ECF value shapes (idiomatic call sites).

func Uint(v uint64) Value   { return Value{Kind: KindUint, Uint: v} }
func Text(s string) Value   { return Value{Kind: KindText, Text: s} }
func Bytes(b []byte) Value  { return Value{Kind: KindBytes, Bytes: b} }
func Bool(b bool) Value     { return Value{Kind: KindBool, Bool: b} }
func Float(f float64) Value { return Value{Kind: KindFloat, Float: f} }

// Null is the ECF null value (0xF6).
func Null() Value { return Value{Kind: KindNull} }

// Int constructs an integer Value from a signed int64, choosing major type 0
// (uint) for non-negatives and major type 1 (nint) for negatives. The full
// out-of-int64 negative band is reachable only via the Nint field directly.
func Int(v int64) Value {
	if v >= 0 {
		return Value{Kind: KindUint, Uint: uint64(v)}
	}
	// value = -1 - n  =>  n = -1 - value = -(value+1). For v in [-2^63, -1],
	// -(v+1) fits uint64 cleanly.
	return Value{Kind: KindNint, Nint: uint64(-(v + 1))}
}

// NewMap builds a map Value from ordered pairs (order is normalised at encode).
func NewMap(pairs ...Pair) Value { return Value{Kind: KindMap, Map: pairs} }

// Entry is a convenience for a text-keyed map pair.
func Entry(key string, val Value) Pair { return Pair{Key: Text(key), Val: val} }
