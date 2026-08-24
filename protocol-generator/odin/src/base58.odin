package entity_core

// Base58 (Bitcoin alphabet) encode/decode, hand-rolled (no core package for it —
// profile [codec].base58_library = "hand-rolled"). Used for peer-id formatting
// (§1.5). Each leading zero byte maps to a leading "1" (the standard
// convention). Big-integer division is done byte-wise (no core:math/big needed
// on the conformance path — digests are 33 bytes, small).

BASE58_ALPHABET :: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58_encode encodes raw bytes to a Base58 string (owned by the caller).
base58_encode :: proc(input: []u8, allocator := context.allocator) -> string {
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros += 1
	}

	// Byte-wise base-256 → base-58 long division, into a temporary digit buffer.
	// Worst-case output length ≈ len*138/100 + 1 (log(256)/log(58)).
	size := len(input) * 138 / 100 + 1
	b58 := make([]u8, size, context.temp_allocator)
	defer delete(b58, context.temp_allocator)
	high := size - 1

	for i in zeros ..< len(input) {
		carry := int(input[i])
		j := size - 1
		for j > high - 1 || carry != 0 {
			if j < 0 {
				break
			}
			carry += 256 * int(b58[j])
			b58[j] = u8(carry % 58)
			carry /= 58
			if j == 0 {
				break
			}
			j -= 1
		}
		high = j
	}

	// Skip leading zero digits in the result buffer.
	it := 0
	for it < size && b58[it] == 0 {
		it += 1
	}

	out := make([]u8, zeros + (size - it), allocator)
	for i in 0 ..< zeros {
		out[i] = '1'
	}
	oi := zeros
	alphabet := BASE58_ALPHABET
	for k in it ..< size {
		out[oi] = alphabet[b58[k]]
		oi += 1
	}
	return string(out)
}

// base58_decode decodes a Base58 string to raw bytes (owned). Returns
// Codec_Error.Bad_Base58 on a non-alphabet character.
base58_decode :: proc(s: string, allocator := context.allocator) -> ([]u8, Codec_Error) {
	ones := 0
	for ones < len(s) && s[ones] == '1' {
		ones += 1
	}

	size := len(s) * 733 / 1000 + 1 // log(58)/log(256)
	b256 := make([]u8, size, context.temp_allocator)
	defer delete(b256, context.temp_allocator)
	high := size - 1

	for i in 0 ..< len(s) {
		c := s[i]
		digit := alphabet_index(c)
		if digit < 0 {
			return nil, .Bad_Base58
		}
		carry := digit
		j := size - 1
		for j > high - 1 || carry != 0 {
			if j < 0 {
				break
			}
			carry += 58 * int(b256[j])
			b256[j] = u8(carry % 256)
			carry /= 256
			if j == 0 {
				break
			}
			j -= 1
		}
		high = j
	}

	it := 0
	for it < size && b256[it] == 0 {
		it += 1
	}

	out := make([]u8, ones + (size - it), allocator)
	// leading zero bytes already zero from make
	oi := ones
	for k in it ..< size {
		out[oi] = b256[k]
		oi += 1
	}
	return out, .None
}

alphabet_index :: proc(c: u8) -> int {
	alphabet := BASE58_ALPHABET
	for i in 0 ..< len(alphabet) {
		if alphabet[i] == c {
			return i
		}
	}
	return -1
}
