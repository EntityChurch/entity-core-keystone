// Package base58 implements Base58 encoding/decoding with the Bitcoin alphabet,
// as used for Entity Core peer identifiers (V7 §1.2 / §7.3). Not in the Go
// standard library; hand-rolled to keep the core peer dependency-free.
package base58

import "errors"

// alphabet is the Bitcoin Base58 alphabet (no 0, O, I, l).
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ErrBadChar is returned when decoding input contains a non-alphabet rune.
var ErrBadChar = errors.New("base58: invalid character")

var decodeMap [256]int8

func init() {
	for i := range decodeMap {
		decodeMap[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		decodeMap[alphabet[i]] = int8(i)
	}
}

// Encode returns the Base58 (Bitcoin-alphabet) encoding of input. Leading zero
// bytes are preserved as leading '1' characters.
func Encode(input []byte) string {
	// Count leading zero bytes.
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	// Big-endian base-256 -> base-58 via repeated division. Work on a copy.
	b := make([]byte, len(input))
	copy(b, input)

	// Upper bound on output length: log(256)/log(58) ~ 1.365.
	out := make([]byte, 0, len(input)*138/100+1)
	start := zeros
	for start < len(b) {
		remainder := 0
		for i := start; i < len(b); i++ {
			acc := remainder*256 + int(b[i])
			b[i] = byte(acc / 58)
			remainder = acc % 58
		}
		out = append(out, alphabet[remainder])
		// Advance past any new leading zero bytes produced by the division.
		for start < len(b) && b[start] == 0 {
			start++
		}
	}

	// out currently holds the base-58 digits least-significant first; the
	// leading-zero bytes map to '1' prefixes. Build the final string reversed.
	res := make([]byte, 0, zeros+len(out))
	for i := 0; i < zeros; i++ {
		res = append(res, '1')
	}
	for i := len(out) - 1; i >= 0; i-- {
		res = append(res, out[i])
	}
	return string(res)
}

// Decode returns the bytes encoded by the Base58 (Bitcoin-alphabet) string s.
func Decode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}

	b := make([]byte, 0, len(s)*733/1000+1) // log(58)/log(256) ~ 0.733
	for i := zeros; i < len(s); i++ {
		d := decodeMap[s[i]]
		if d < 0 {
			return nil, ErrBadChar
		}
		carry := int(d)
		for j := 0; j < len(b); j++ {
			carry += int(b[j]) * 58
			b[j] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			b = append(b, byte(carry&0xff))
			carry >>= 8
		}
	}

	// b is little-endian; prepend leading zeros and reverse.
	res := make([]byte, 0, zeros+len(b))
	for i := 0; i < zeros; i++ {
		res = append(res, 0)
	}
	for i := len(b) - 1; i >= 0; i-- {
		res = append(res, b[i])
	}
	return res, nil
}
