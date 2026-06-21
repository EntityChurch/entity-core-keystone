package cbor

import (
	"bytes"
	"errors"
	"math"
	"sort"
)

// Major types (RFC 8949 §3.1).
const (
	mtUint  = 0 << 5 // 0x00
	mtNint  = 1 << 5 // 0x20
	mtBytes = 2 << 5 // 0x40
	mtText  = 3 << 5 // 0x60
	mtArray = 4 << 5 // 0x80
	mtMap   = 5 << 5 // 0xa0
	mtTag   = 6 << 5 // 0xc0
	mtSimp  = 7 << 5 // 0xe0
)

// Encode errors.
var (
	// ErrDuplicateKey signals a map with two equal canonical keys (Rule 5).
	ErrDuplicateKey = errors.New("cbor: duplicate map key")
	// ErrUnencodableFloat signals a non-finite float that is not one of the
	// canonical specials (cannot happen with IEEE-754, but guards the path).
	ErrUnencodableFloat = errors.New("cbor: unencodable float")
)

// Encode returns the canonical ECF encoding of v.
//
// Canonicalisation per ENTITY-CBOR-ENCODING §4.1:
//   - Rule 1: minimal integer encoding (head writes the shortest argument).
//   - Rule 2: map keys sorted by encoded length, then byte-wise lexicographic.
//   - Rule 3: definite lengths only.
//   - Rule 4/4a: shortest float preserving value; exact special bytes.
//   - Rule 5: duplicate map keys rejected.
//   - Rule 6: every present field is encoded (no omission); callers control
//     field presence by what they put in the Value.
func Encode(v Value) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeValue(buf *bytes.Buffer, v Value) error {
	switch v.Kind {
	case KindUint:
		writeHead(buf, mtUint, v.Uint)
	case KindNint:
		writeHead(buf, mtNint, v.Nint)
	case KindFloat:
		return encodeFloat(buf, v.Float)
	case KindBool:
		if v.Bool {
			buf.WriteByte(mtSimp | 21) // 0xf5
		} else {
			buf.WriteByte(mtSimp | 20) // 0xf4
		}
	case KindNull:
		buf.WriteByte(mtSimp | 22) // 0xf6
	case KindText:
		writeHead(buf, mtText, uint64(len(v.Text)))
		buf.WriteString(v.Text)
	case KindBytes:
		writeHead(buf, mtBytes, uint64(len(v.Bytes)))
		buf.Write(v.Bytes)
	case KindArray:
		writeHead(buf, mtArray, uint64(len(v.Array)))
		for i := range v.Array {
			if err := encodeValue(buf, v.Array[i]); err != nil {
				return err
			}
		}
	case KindMap:
		return encodeMap(buf, v.Map)
	case KindTag:
		// A Tag value is never produced for a data field by the decoder
		// (it is rejected first per §6.3). Encoding a tag is therefore an
		// internal invariant violation, but if a caller constructs one we
		// refuse rather than emit a forbidden major-type-6 item.
		return ErrTagRejected
	default:
		return errors.New("cbor: unknown value kind")
	}
	return nil
}

// writeHead writes the major-type byte and its minimal argument (Rule 1).
func writeHead(buf *bytes.Buffer, mt byte, arg uint64) {
	switch {
	case arg < 24:
		buf.WriteByte(mt | byte(arg))
	case arg <= 0xff:
		buf.WriteByte(mt | 24)
		buf.WriteByte(byte(arg))
	case arg <= 0xffff:
		buf.WriteByte(mt | 25)
		buf.WriteByte(byte(arg >> 8))
		buf.WriteByte(byte(arg))
	case arg <= 0xffffffff:
		buf.WriteByte(mt | 26)
		buf.WriteByte(byte(arg >> 24))
		buf.WriteByte(byte(arg >> 16))
		buf.WriteByte(byte(arg >> 8))
		buf.WriteByte(byte(arg))
	default:
		buf.WriteByte(mt | 27)
		for s := 56; s >= 0; s -= 8 {
			buf.WriteByte(byte(arg >> uint(s)))
		}
	}
}

// encodeMap sorts the entries per Rule 2, rejects duplicate keys (Rule 5), and
// writes a definite-length map (Rule 3).
func encodeMap(buf *bytes.Buffer, pairs []Pair) error {
	type encoded struct {
		key []byte
		val []byte
	}
	items := make([]encoded, len(pairs))
	for i := range pairs {
		k, err := Encode(pairs[i].Key)
		if err != nil {
			return err
		}
		v, err := Encode(pairs[i].Val)
		if err != nil {
			return err
		}
		items[i] = encoded{key: k, val: v}
	}

	// Rule 2: sort by encoded-key length first, then byte-wise lexicographic.
	sort.SliceStable(items, func(i, j int) bool {
		return canonicalLess(items[i].key, items[j].key)
	})

	// Rule 5: reject duplicate keys (now adjacent after the sort).
	for i := 1; i < len(items); i++ {
		if bytes.Equal(items[i-1].key, items[i].key) {
			return ErrDuplicateKey
		}
	}

	writeHead(buf, mtMap, uint64(len(items)))
	for i := range items {
		buf.Write(items[i].key)
		buf.Write(items[i].val)
	}
	return nil
}

// canonicalLess implements RFC 8949 §4.2.1 / Rule 2 key ordering: shorter
// encoded key first, then byte-wise lexicographic among equal lengths.
func canonicalLess(a, b []byte) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return bytes.Compare(a, b) < 0
}

// encodeFloat writes the shortest IEEE-754 form preserving value (Rule 4) and
// the exact canonical bytes for special values (Rule 4a).
func encodeFloat(buf *bytes.Buffer, f float64) error {
	// Rule 4a: NaN -> F9 7E00 (canonical quiet NaN). All NaN payloads
	// collapse to the canonical one.
	if math.IsNaN(f) {
		buf.Write([]byte{mtSimp | 25, 0x7e, 0x00})
		return nil
	}
	if math.IsInf(f, 1) {
		buf.Write([]byte{mtSimp | 25, 0x7c, 0x00})
		return nil
	}
	if math.IsInf(f, -1) {
		buf.Write([]byte{mtSimp | 25, 0xfc, 0x00})
		return nil
	}
	// -0.0 -> F9 8000. (math.Signbit distinguishes -0.0 from +0.0.)
	if f == 0 {
		if math.Signbit(f) {
			buf.Write([]byte{mtSimp | 25, 0x80, 0x00})
		} else {
			buf.Write([]byte{mtSimp | 25, 0x00, 0x00})
		}
		return nil
	}

	// Rule 4: try float16, then float32, then float64 — the shortest that
	// round-trips to the exact same float64 value wins.
	if h, ok := float64ToHalf(f); ok {
		buf.WriteByte(mtSimp | 25)
		buf.WriteByte(byte(h >> 8))
		buf.WriteByte(byte(h))
		return nil
	}
	f32 := float32(f)
	if float64(f32) == f {
		bits := math.Float32bits(f32)
		buf.WriteByte(mtSimp | 26)
		buf.WriteByte(byte(bits >> 24))
		buf.WriteByte(byte(bits >> 16))
		buf.WriteByte(byte(bits >> 8))
		buf.WriteByte(byte(bits))
		return nil
	}
	bits := math.Float64bits(f)
	buf.WriteByte(mtSimp | 27)
	for s := 56; s >= 0; s -= 8 {
		buf.WriteByte(byte(bits >> uint(s)))
	}
	return nil
}

// float64ToHalf converts f to an IEEE-754 half-precision (float16) value,
// returning (bits, true) only if the half-precision value is an exact
// representation of f. Non-finite and signed-zero cases are handled by the
// caller (encodeFloat), so f here is finite and non-zero.
func float64ToHalf(f float64) (uint16, bool) {
	f32 := float32(f)
	if float64(f32) != f {
		return 0, false // not even float32-exact -> not float16-exact
	}
	b := math.Float32bits(f32)
	sign := uint16((b >> 16) & 0x8000)
	exp := int32((b>>23)&0xff) - 127 // unbiased float32 exponent
	mant := b & 0x7fffff

	// Normal half range: unbiased exponent in [-14, 15], and the float32
	// mantissa must fit in 10 bits (low 13 bits zero).
	if exp >= -14 && exp <= 15 {
		if mant&0x1fff != 0 {
			return 0, false // low mantissa bits lost in 10-bit mantissa
		}
		h := sign | uint16((exp+15)<<10) | uint16(mant>>13)
		return h, true
	}
	// Subnormal half range: unbiased exponent in [-24, -15]. The value is
	// mant-with-implicit-1 shifted; require exact representability.
	if exp >= -24 && exp < -14 {
		// Reconstruct full significand (1.mant) then shift into the
		// subnormal half mantissa, checking no bits are lost.
		full := mant | 0x800000 // implicit leading 1, 24-bit significand
		// Subnormal half: value = significand >> (13 + (-14 - exp)).
		rshift := uint(13 + (-14 - exp))
		if rshift >= 32 {
			return 0, false
		}
		if full&((1<<rshift)-1) != 0 {
			return 0, false // bits lost
		}
		hm := uint16(full >> rshift)
		return sign | hm, true
	}
	return 0, false
}
