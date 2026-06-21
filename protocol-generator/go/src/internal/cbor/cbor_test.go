package cbor

import (
	"bytes"
	"math"
	"testing"
)

// TestBeyondCorpusIntRange covers the [2^63, 2^64-1] uint band and the full
// nint band [-2^64, -1] that the corpus int.* vectors do NOT reach (they top
// out at i64::MAX / -256). This is the A-GO-003 watch-item and the codec-review
// heuristic blind spot (a signed-int decode would silently overflow here).
func TestBeyondCorpusIntRange(t *testing.T) {
	cases := []struct {
		name string
		v    Value
		want []byte
	}{
		{"uint 2^63", Uint(1 << 63), []byte{0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0}},
		{"uint 2^64-1", Uint(math.MaxUint64), []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		// nint magnitude n, value = -1-n. n=2^63 => value -(2^63)-1.
		{"nint n=2^63", Value{Kind: KindNint, Nint: 1 << 63}, []byte{0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0}},
		// n=2^64-1 => value -2^64 (the extreme nint).
		{"nint n=2^64-1", Value{Kind: KindNint, Nint: math.MaxUint64}, []byte{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Encode(c.v)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, c.want) {
				t.Fatalf("encode: got %x want %x", got, c.want)
			}
			// Round-trip: decode must recover the same Value.
			back, err := Decode(got)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if back.Kind != c.v.Kind || back.Uint != c.v.Uint || back.Nint != c.v.Nint {
				t.Fatalf("round-trip mismatch: got %+v want %+v", back, c.v)
			}
		})
	}
}

// TestEmptyMapIsA0 pins the N3 invariant: the empty CBOR map is the single byte
// 0xA0.
func TestEmptyMapIsA0(t *testing.T) {
	got, err := Encode(NewMap())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xa0}) {
		t.Fatalf("empty map: got %x want a0", got)
	}
}

// TestRejectNonMinimalInt confirms the decoder rejects a non-minimal integer
// encoding (e.g. 0x1800 = value 0 written with a 1-byte argument).
func TestRejectNonMinimalInt(t *testing.T) {
	for _, b := range [][]byte{
		{0x18, 0x00},                   // uint 0 in 2 bytes
		{0x18, 0x17},                   // uint 23 in 2 bytes
		{0x19, 0x00, 0xff},             // uint 255 in 3 bytes
		{0x1a, 0x00, 0x00, 0xff, 0xff}, // uint 65535 in 5 bytes
	} {
		if _, err := Decode(b); err == nil {
			t.Fatalf("non-minimal %x was accepted", b)
		}
	}
}

// TestRejectIndefinite confirms indefinite-length items are rejected (Rule 3).
func TestRejectIndefinite(t *testing.T) {
	for _, b := range [][]byte{
		{0x9f, 0xff},       // indefinite array
		{0xbf, 0xff},       // indefinite map
		{0x5f, 0x40, 0xff}, // indefinite byte string
		{0x7f, 0x60, 0xff}, // indefinite text string
	} {
		if _, err := Decode(b); err == nil {
			t.Fatalf("indefinite %x was accepted", b)
		}
	}
}

// TestRejectDuplicateKeys confirms Rule 5 on both encode and decode.
func TestRejectDuplicateKeys(t *testing.T) {
	// decode: map(2) with two "a" keys.
	dup := []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02}
	if _, err := Decode(dup); err != ErrDuplicateKey {
		t.Fatalf("decode dup keys: got %v want ErrDuplicateKey", err)
	}
	// encode: a map Value carrying two identical keys.
	m := NewMap(Entry("a", Uint(1)), Entry("a", Uint(2)))
	if _, err := Encode(m); err != ErrDuplicateKey {
		t.Fatalf("encode dup keys: got %v want ErrDuplicateKey", err)
	}
}

// TestRejectTopLevelTag confirms a bare tag is rejected (§6.3 / N2).
func TestRejectTopLevelTag(t *testing.T) {
	if _, err := Decode([]byte{0xc0, 0x60}); err != ErrTagRejected {
		t.Fatalf("top-level tag: got %v want ErrTagRejected", err)
	}
}

// TestFloatRoundTripShortest exercises shortest-float selection across the
// f16/f32/f64 boundary and the Rule 4a specials.
func TestFloatRoundTripShortest(t *testing.T) {
	cases := []struct {
		f    float64
		want []byte
	}{
		{0.0, []byte{0xf9, 0x00, 0x00}},
		{math.Copysign(0, -1), []byte{0xf9, 0x80, 0x00}},
		{1.0, []byte{0xf9, 0x3c, 0x00}},
		{1.5, []byte{0xf9, 0x3e, 0x00}},
		{math.Inf(1), []byte{0xf9, 0x7c, 0x00}},
		{math.Inf(-1), []byte{0xf9, 0xfc, 0x00}},
		{65504.0, []byte{0xf9, 0x7b, 0xff}},                                 // max normal f16
		{65503.0, []byte{0xfa, 0x47, 0x7f, 0xdf, 0x00}},                     // f32
		{1.1, []byte{0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a}}, // f64
		{5.960464477539063e-08, []byte{0xf9, 0x00, 0x01}},                   // smallest subnormal f16
	}
	for _, c := range cases {
		got, err := Encode(Float(c.f))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, c.want) {
			t.Fatalf("float %v: got %x want %x", c.f, got, c.want)
		}
	}
	// NaN canonicalisation (compared separately — NaN != NaN).
	got, _ := Encode(Float(math.NaN()))
	if !bytes.Equal(got, []byte{0xf9, 0x7e, 0x00}) {
		t.Fatalf("NaN: got %x want f97e00", got)
	}
}
