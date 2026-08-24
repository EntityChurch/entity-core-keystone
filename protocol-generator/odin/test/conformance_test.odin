package entity_core_test

import ec "../src"
import "core:crypto/ed25519"
import "core:fmt"
import "core:mem"
import "core:slice"
import "core:testing"

// The 71-vector wire-conformance corpus is compiled IN (offline, hermetic — no
// runtime file IO, no network). Path is relative to THIS source file:
// test/ → ../shared/test-vectors/v0.8.0/…
CORPUS := #load(
	"../../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor",
)

// ── the full 71-vector gate, leak-checked ────────────────────────────────────

@(test)
conformance_71_of_71 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	context.allocator = mem.tracking_allocator(&track)

	summary, err := ec.run_conformance(CORPUS)

	testing.expectf(t, err == .None, "corpus decode failed: %v", err)

	// Dump every non-pass with got/want hex for diagnosis.
	for r in summary.results {
		if r.status != .Pass {
			fmt.printf("  [%s] %v %s\n", r.id, r.status, r.detail)
		}
	}

	testing.expectf(
		t,
		summary.total == 71,
		"expected 71 conformance vectors, saw %d",
		summary.total,
	)
	testing.expectf(
		t,
		summary.passed == 71 && summary.failed == 0 && summary.skipped == 0,
		"conformance: %d/%d PASS (%d fail, %d skip)",
		summary.passed,
		summary.total,
		summary.failed,
		summary.skipped,
	)

	// Free everything explicitly BEFORE the leak check (no `defer` for the
	// codec allocations — the whole point is to prove the run frees clean).
	ec.summary_destroy(&summary)
	free_all(context.temp_allocator)
	for _, entry in track.allocation_map {
		fmt.printf("  LEAK %d bytes @ %v\n", entry.size, entry.location)
	}
	testing.expectf(
		t,
		len(track.allocation_map) == 0,
		"leak: %d un-freed allocation(s)",
		len(track.allocation_map),
	)
	testing.expectf(
		t,
		len(track.bad_free_array) == 0,
		"bad frees: %d",
		len(track.bad_free_array),
	)
}

// ── per-category breakdown (readable when the aggregate fails) ────────────────

@(test)
conformance_by_category :: proc(t: ^testing.T) {
	summary, err := ec.run_conformance(CORPUS)
	defer ec.summary_destroy(&summary)
	testing.expect(t, err == .None)

	// Every id up to first "." should be one of the known categories, and all pass.
	for r in summary.results {
		testing.expectf(t, r.status == .Pass, "vector %s did not pass: %s", r.id, r.detail)
	}
}

// ── fixed-width u64 head-form self-test: [2^63, 2^64-1] ───────────────────────
//
// The band a signed i64 cannot hold. Odin u64 carries it natively; the encoder
// emits the minor-27 (8-byte-argument) head. This is the fixed-width-int-class
// obligation (profile [idiom].native_fixed_width_int, like Zig/Forth/Fortran) —
// a bignum peer gets the range free; a fixed-width peer must PROVE it.

@(test)
head_form_u64_high_band :: proc(t: ^testing.T) {
	Case :: struct {
		v:    u64,
		want: []u8,
	}
	cases := []Case{
		// 2^63 = 9223372036854775808 → 1b 8000000000000000
		{0x8000_0000_0000_0000, {0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		// 2^63-1 (corpus int.10, boundary below the band) → 1b 7fffffffffffffff
		{0x7fff_ffff_ffff_ffff, {0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		// 2^64-1 = 18446744073709551615 → 1b ffffffffffffffff
		{0xffff_ffff_ffff_ffff, {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		// first value requiring the 8-byte arg: 2^32 → 1b 0000000100000000
		{0x1_0000_0000, {0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
	}

	for c in cases {
		got, err := ec.cbor_encode(ec.Ec_Uint(c.v))
		defer delete(got)
		testing.expectf(t, err == .None, "encode u64 %d: %v", c.v, err)
		testing.expectf(
			t,
			slice.equal(got, c.want),
			"u64 %d head-form: got % x want % x",
			c.v,
			got,
			c.want,
		)

		// Round-trip: decode back, confirm the value survives the high band.
		back, derr := ec.cbor_decode(c.want)
		defer ec.value_destroy(back)
		testing.expect(t, derr == .None)
		u, is_u := back.(ec.Ec_Uint)
		testing.expectf(t, is_u && u64(u) == c.v, "round-trip u64 %d -> %v", c.v, back)
	}
}

// ── negative-int high band: nint stores n, wire value = -1 - n ────────────────

@(test)
head_form_nint_full_range :: proc(t: ^testing.T) {
	// Ec_Nint(0xffffffffffffffff) encodes -2^64 → 3b ffffffffffffffff.
	got, err := ec.cbor_encode(ec.Ec_Nint(0xffff_ffff_ffff_ffff))
	defer delete(got)
	testing.expect(t, err == .None)
	want := []u8{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	testing.expectf(t, slice.equal(got, want), "nint(-2^64): got % x want % x", got, want)
}

// ── native pure-Odin Ed25519 KAT accept-path (RFC 8032) ───────────────────────
//
// The oracle categories are rejection-only for many primitives; the corpus
// signature vectors pin the PRODUCED signature (an accept path), but this unit
// additionally exercises the sign→verify round-trip AND asserts a byte-pinned
// signature from the corpus's own deterministic seed so a broken pure-Odin
// RFC-8032 impl fails LOUDLY (A-ODIN-004: unaudited native crypto, oracle-gated).

@(test)
ed25519_kat_accept_path :: proc(t: ^testing.T) {
	// signature.1: seed = all-zero; entity {type:"test/v1", data:{x:1}};
	// the corpus pins the exact 64-byte signature.
	seed := make([]u8, 32)
	defer delete(seed) // all-zero

	entity := ec.Ec_Map(
		[]ec.Ec_Pair{
			{ec.Ec_Text("type"), ec.Ec_Text("test/v1")},
			{
				ec.Ec_Text("data"),
				ec.Ec_Map([]ec.Ec_Pair{{ec.Ec_Text("x"), ec.Ec_Uint(1)}}),
			},
		},
	)

	sig, err := ec.signature_sign(seed, entity)
	defer delete(sig)
	testing.expectf(t, err == .None, "sign: %v", err)

	want_sig := []u8{
		0x3f, 0x0b, 0x5d, 0x06, 0x63, 0x6e, 0xa2, 0x67, 0x19, 0x9d, 0xc2, 0x7e,
		0xb2, 0x0d, 0x8c, 0x9b, 0x37, 0x68, 0x4d, 0x68, 0x1a, 0xdc, 0x5b, 0xe4,
		0x3b, 0xe4, 0x65, 0x81, 0x9a, 0xd6, 0x43, 0xe3, 0xb1, 0x52, 0xe5, 0xc0,
		0x24, 0xbf, 0x67, 0xce, 0x86, 0x26, 0x99, 0xfe, 0x43, 0x94, 0x62, 0xd7,
		0x85, 0x2b, 0x02, 0x9c, 0xb1, 0x25, 0xcd, 0x91, 0x7d, 0x12, 0xa3, 0x15,
		0x15, 0x29, 0x23, 0x0c,
	}
	testing.expectf(
		t,
		slice.equal(sig, want_sig),
		"pinned Ed25519 sig mismatch:\n got % x\nwant % x",
		sig,
		want_sig,
	)

	// Accept path: derive the public key and verify our own signature over the
	// same canonical message (the direction the rejection-only oracle can't cover).
	pub, perr := ec.signature_public_key(seed)
	defer delete(pub)
	testing.expect(t, perr == .None)

	msg, merr := ec.cbor_encode(entity)
	defer delete(msg)
	testing.expect(t, merr == .None)

	testing.expect(t, ec.signature_verify_raw(pub, msg, sig), "verify accept-path failed")

	// Negative control: a flipped signature byte MUST NOT verify.
	bad := slice.clone(sig)
	defer delete(bad)
	bad[0] ~= 0xFF
	testing.expect(t, !ec.signature_verify_raw(pub, msg, bad), "tampered sig verified")
}

// ── raw RFC-8032 KAT (test vector 1 from RFC 8032 §7.1) ──────────────────────
//
// A crypto-only KAT independent of the ECF layer: seed
// 9d61b19d…, empty message → the RFC's pinned signature. Proves the native
// core:crypto/ed25519 matches RFC 8032 at the primitive level.

@(test)
ed25519_rfc8032_vector1 :: proc(t: ^testing.T) {
	seed := []u8{
		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
		0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
		0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	}
	want_pub := []u8{
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3,
		0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
	}
	want_sig := []u8{
		0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc,
		0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
		0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15,
		0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
		0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
		0x8e, 0x7a, 0x10, 0x0b,
	}

	priv: ed25519.Private_Key
	defer ed25519.private_key_clear(&priv)
	testing.expect(t, ed25519.private_key_set_bytes(&priv, seed))

	pub_bytes: [32]u8
	ed25519.private_key_public_bytes(&priv, pub_bytes[:])
	testing.expectf(
		t,
		slice.equal(pub_bytes[:], want_pub),
		"RFC8032 v1 pubkey: got % x",
		pub_bytes[:],
	)

	sig: [64]u8
	ed25519.sign(&priv, []u8{}, sig[:]) // empty message
	testing.expectf(t, slice.equal(sig[:], want_sig), "RFC8032 v1 sig: got % x", sig[:])
}
