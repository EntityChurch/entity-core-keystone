// Command oracle is the keystone-local INTERIM dev encoder oracle.
//
// It wraps the real entity-core-go reference encoder (core/ecf.Encode =
// fxamacker/cbor CoreDetEncOptions, RFC 8949 §4.2) and prints canonical ECF
// hex for a curated set of basic-ECF inputs, so the codec C-ABI impls
// (entity-core-codec-ffi-{rust,c}) and native codecs can diff against the
// reference DURING DEVELOPMENT.
//
// This is NOT the authoritative conformance generator and produces nothing
// canonical-of-record. The authoritative, cross-blessed, versioned fixture is
// architecture's to produce per PROPOSAL-WIRE-ENCODING-CONFORMANCE-VECTORS.md
// (Appendix E); see research/stewardship/REQUEST-TO-ARCH-F1-ECF-FIXTURE-2026-06-06.md.
// When that fixture lands, this oracle becomes the CI hash-check, not the source.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"

	"entity-core-go/core/ecf"
)

type vec struct {
	id   string
	desc string
	val  interface{}
}

func main() {
	// Curated basic-ECF inputs expressible as Go values. (Byte-string map keys
	// and other diag-only shapes are deferred to arch's .diag-driven generator.)
	vecs := []vec{
		// int — major-type 0/1 minimization at boundaries
		{"int.0", "zero", 0},
		{"int.23", "max 1-byte inline", 23},
		{"int.24", "min needing 1-byte arg", 24},
		{"int.255", "max uint8 arg", 255},
		{"int.256", "min uint16 arg", 256},
		{"int.1e6", "uint32 range", 1000000},
		{"int.u64max", "2^64-1", uint64(math.MaxUint64)},
		{"int.-1", "neg one", -1},
		{"int.-24", "max 1-byte neg inline", -24},
		{"int.-25", "min neg needing arg", -25},
		// float — Rule 4 shortest + Rule 4a specials
		{"float.+0", "positive zero", 0.0},
		{"float.-0", "negative zero", math.Copysign(0, -1)},
		{"float.1.0", "one (f16)", 1.0},
		{"float.1.5", "exact f16", 1.5},
		{"float.65504", "max finite f16", 65504.0},
		{"float.100000", "not f16 -> f32", 100000.0},
		{"float.1.1", "f64-only", 1.1},
		{"float.nan", "canonical NaN", math.NaN()},
		{"float.+inf", "positive infinity", math.Inf(1)},
		{"float.-inf", "negative infinity", math.Inf(-1)},
		// primitive
		{"prim.true", "bool true", true},
		{"prim.false", "bool false", false},
		{"prim.null", "null", nil},
		// strings / bytes
		{"str.empty", "empty text", ""},
		{"str.a", "one char", "a"},
		{"str.data", "the 'data' key string", "data"},
		{"bytes.empty", "empty byte string", []byte{}},
		{"bytes.0102", "two bytes", []byte{0x01, 0x02}},
		// containers
		{"arr.empty", "empty array", []interface{}{}},
		{"arr.123", "int array", []interface{}{1, 2, 3}},
		{"map.empty", "empty map (N3 shape)", map[string]interface{}{}},
		{"map.ab", "two text keys, same len", map[string]interface{}{"a": 1, "b": 2}},
		{"map.len_order", "key sort by length then bytes", map[string]interface{}{"z": 1, "aa": 2}},
	}

	fmt.Println("# keystone interim dev oracle — core/ecf.Encode (fxamacker CoreDet)")
	fmt.Println("# id\tcanonical_hex\tdescription")
	for _, v := range vecs {
		b, err := ecf.Encode(v.val)
		if err != nil {
			fmt.Printf("%s\tERROR: %v\t%s\n", v.id, err, v.desc)
			continue
		}
		fmt.Printf("%s\t%s\t%s\n", v.id, hex.EncodeToString(b), v.desc)
	}

	// Self-check: ECF(empty map) MUST be the single byte 0xA0 (N3), and
	// sha256(0xA0) is c19a797f... — verified independently via coreutils
	// sha256sum. This is the correct hash of the canonical empty map.
	emptyMap, _ := ecf.Encode(map[string]interface{}{})
	sum := sha256.Sum256(emptyMap)
	gotECF := hex.EncodeToString(emptyMap)
	gotHash := hex.EncodeToString(sum[:])
	const wantECF = "a0"
	const wantHash = "c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0"
	ok := gotECF == wantECF && gotHash == wantHash
	fmt.Printf("\n# self-check: ECF(empty map)=%s  sha256=%s  -> %s\n", gotECF, gotHash,
		map[bool]string{true: "PASS", false: "FAIL"}[ok])
	// FINDING F5: ENTITY-CBOR-ENCODING Appendix A.1 pins this hash as
	// 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a, which is
	// NOT sha256(0xA0). No impl computes it. Escalated to arch (SPEC-FINDINGS-LOG F5).
	fmt.Println("# NOTE: spec Appendix A.1 pins 44136fa3... for this case — disputed (F5), != sha256(0xA0).")
}
