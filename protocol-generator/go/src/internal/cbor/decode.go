package cbor

import (
	"errors"
	"math"
	"unicode/utf8"
)

// Decode errors.
var (
	// ErrTruncated signals input that ends mid-item.
	ErrTruncated = errors.New("cbor: truncated input")
	// ErrTagRejected signals a CBOR major-type-6 (tag) item appearing in a
	// data position; rejected per §6.3 (maps to 400 non_canonical_ecf).
	ErrTagRejected = errors.New("cbor: tag rejected (non_canonical_ecf)")
	// ErrIndefinite signals an indefinite-length item; canonical ECF is
	// definite-length only (Rule 3).
	ErrIndefinite = errors.New("cbor: indefinite length not permitted")
	// ErrInvalidUTF8 signals a malformed text string (§9.2 rule 5).
	ErrInvalidUTF8 = errors.New("cbor: invalid utf-8 in text string")
	// ErrTrailing signals bytes left over after a complete top-level item.
	ErrTrailing = errors.New("cbor: trailing bytes after item")
	// ErrReserved signals a reserved/unsupported simple value.
	ErrReserved = errors.New("cbor: reserved or unsupported simple value")
)

// decoder walks a byte slice producing Values. It tracks whether it is inside
// a data-bearing position so it can reject tags per §6.3.
type decoder struct {
	b   []byte
	pos int
}

// Decode parses exactly one canonical-ECF data item from b, rejecting any CBOR
// tag (major type 6) at any depth (§6.3 / N2) and any indefinite-length item
// (Rule 3). Trailing bytes after the item are an error.
func Decode(b []byte) (Value, error) {
	d := &decoder{b: b}
	v, err := d.decodeItem()
	if err != nil {
		return Value{}, err
	}
	if d.pos != len(b) {
		return Value{}, ErrTrailing
	}
	return v, nil
}

// DecodeFirst parses one item and returns the number of bytes consumed, leaving
// trailing bytes to the caller (used for decoding a CBOR array of vectors).
func DecodeFirst(b []byte) (Value, int, error) {
	d := &decoder{b: b}
	v, err := d.decodeItem()
	if err != nil {
		return Value{}, 0, err
	}
	return v, d.pos, nil
}

func (d *decoder) decodeItem() (Value, error) {
	if d.pos >= len(d.b) {
		return Value{}, ErrTruncated
	}
	ib := d.b[d.pos]
	mt := ib & 0xe0
	ai := ib & 0x1f
	d.pos++

	switch mt {
	case mtUint:
		arg, err := d.readArg(ai)
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: KindUint, Uint: arg}, nil
	case mtNint:
		arg, err := d.readArg(ai)
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: KindNint, Nint: arg}, nil
	case mtBytes:
		n, err := d.readLen(ai)
		if err != nil {
			return Value{}, err
		}
		raw, err := d.readN(n)
		if err != nil {
			return Value{}, err
		}
		bs := make([]byte, len(raw))
		copy(bs, raw)
		return Value{Kind: KindBytes, Bytes: bs}, nil
	case mtText:
		n, err := d.readLen(ai)
		if err != nil {
			return Value{}, err
		}
		raw, err := d.readN(n)
		if err != nil {
			return Value{}, err
		}
		if !utf8.Valid(raw) {
			return Value{}, ErrInvalidUTF8
		}
		return Value{Kind: KindText, Text: string(raw)}, nil
	case mtArray:
		n, err := d.readLen(ai)
		if err != nil {
			return Value{}, err
		}
		arr := make([]Value, 0, n)
		for i := uint64(0); i < n; i++ {
			el, err := d.decodeItem()
			if err != nil {
				return Value{}, err
			}
			arr = append(arr, el)
		}
		return Value{Kind: KindArray, Array: arr}, nil
	case mtMap:
		n, err := d.readLen(ai)
		if err != nil {
			return Value{}, err
		}
		pairs := make([]Pair, 0, n)
		seen := make(map[string]struct{}, n)
		for i := uint64(0); i < n; i++ {
			k, err := d.decodeItem()
			if err != nil {
				return Value{}, err
			}
			// Rule 5: reject duplicate keys (compare on canonical key
			// encoding so equal keys of any string type collide).
			ke, err := Encode(k)
			if err != nil {
				return Value{}, err
			}
			if _, dup := seen[string(ke)]; dup {
				return Value{}, ErrDuplicateKey
			}
			seen[string(ke)] = struct{}{}
			v, err := d.decodeItem()
			if err != nil {
				return Value{}, err
			}
			pairs = append(pairs, Pair{Key: k, Val: v})
		}
		return Value{Kind: KindMap, Map: pairs}, nil
	case mtTag:
		// §6.3 / N2: any major-type-6 item in a data position is rejected.
		// We do not interpret, strip, or preserve. (The tag argument is
		// still consumed only to report a clean error, not to accept it.)
		return Value{}, ErrTagRejected
	case mtSimp:
		return d.decodeSimple(ai)
	}
	return Value{}, errors.New("cbor: unreachable major type")
}

// readArg reads the argument for a value-bearing head (mt 0/1), rejecting
// non-minimal and indefinite encodings (Rule 1 / Rule 3 on the decode side).
func (d *decoder) readArg(ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		raw, err := d.readN(1)
		if err != nil {
			return 0, err
		}
		v := uint64(raw[0])
		if v < 24 {
			return 0, errNonMinimal
		}
		return v, nil
	case ai == 25:
		raw, err := d.readN(2)
		if err != nil {
			return 0, err
		}
		v := uint64(raw[0])<<8 | uint64(raw[1])
		if v <= 0xff {
			return 0, errNonMinimal
		}
		return v, nil
	case ai == 26:
		raw, err := d.readN(4)
		if err != nil {
			return 0, err
		}
		v := uint64(raw[0])<<24 | uint64(raw[1])<<16 | uint64(raw[2])<<8 | uint64(raw[3])
		if v <= 0xffff {
			return 0, errNonMinimal
		}
		return v, nil
	case ai == 27:
		raw, err := d.readN(8)
		if err != nil {
			return 0, err
		}
		var v uint64
		for i := 0; i < 8; i++ {
			v = v<<8 | uint64(raw[i])
		}
		if v <= 0xffffffff {
			return 0, errNonMinimal
		}
		return v, nil
	case ai == 31:
		return 0, ErrIndefinite
	}
	return 0, errReservedAI
}

var (
	errNonMinimal = errors.New("cbor: non-minimal integer encoding")
	errReservedAI = errors.New("cbor: reserved additional-info value")
)

// readLen reads a length argument for strings/arrays/maps, rejecting
// indefinite lengths (Rule 3).
func (d *decoder) readLen(ai byte) (uint64, error) {
	if ai == 31 {
		return 0, ErrIndefinite
	}
	return d.readArg(ai)
}

func (d *decoder) readN(n uint64) ([]byte, error) {
	if uint64(len(d.b)-d.pos) < n {
		return nil, ErrTruncated
	}
	raw := d.b[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return raw, nil
}

func (d *decoder) decodeSimple(ai byte) (Value, error) {
	switch ai {
	case 20:
		return Value{Kind: KindBool, Bool: false}, nil
	case 21:
		return Value{Kind: KindBool, Bool: true}, nil
	case 22:
		return Value{Kind: KindNull}, nil
	case 23:
		// undefined — SHOULD NOT appear in ECF (§3.5).
		return Value{}, ErrReserved
	case 25:
		raw, err := d.readN(2)
		if err != nil {
			return Value{}, err
		}
		h := uint16(raw[0])<<8 | uint16(raw[1])
		return Value{Kind: KindFloat, Float: halfToFloat64(h)}, nil
	case 26:
		raw, err := d.readN(4)
		if err != nil {
			return Value{}, err
		}
		bits := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		return Value{Kind: KindFloat, Float: float64(math.Float32frombits(bits))}, nil
	case 27:
		raw, err := d.readN(8)
		if err != nil {
			return Value{}, err
		}
		var bits uint64
		for i := 0; i < 8; i++ {
			bits = bits<<8 | uint64(raw[i])
		}
		return Value{Kind: KindFloat, Float: math.Float64frombits(bits)}, nil
	case 24:
		// simple value in next byte (values 32..255); not used in ECF.
		return Value{}, ErrReserved
	}
	// Simple values 0..19 in the additional info (ai < 20) are unassigned in
	// ECF; reject.
	return Value{}, ErrReserved
}

// halfToFloat64 decodes an IEEE-754 half-precision (float16) bit pattern.
func halfToFloat64(h uint16) float64 {
	sign := uint64(h&0x8000) << 48
	exp := int(h>>10) & 0x1f
	mant := uint64(h & 0x3ff)

	switch exp {
	case 0:
		if mant == 0 {
			return math.Float64frombits(sign) // +/- 0
		}
		// Subnormal: value = mant * 2^-24 (with sign).
		f := float64(mant) * math.Pow(2, -24)
		if sign != 0 {
			f = -f
		}
		return f
	case 0x1f:
		if mant == 0 {
			if sign != 0 {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		return math.NaN()
	default:
		// Normal: rebias exponent (15 -> 1023) and widen mantissa.
		bits := sign | (uint64(exp-15+1023) << 52) | (mant << 42)
		return math.Float64frombits(bits)
	}
}
