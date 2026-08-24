package entity_core

import "core:mem"
import "core:slice"
import "core:strings"

// ECF conformance runner. Pure (no file IO): it takes the corpus bytes, decodes
// them with THIS peer's OWN decoder (a decoder bug here is itself a conformance
// failure — §E.3), and runs every vector. Mirrors the Ruby reference
// (lib/entity_core/conformance.rb).
//
// Dispatch by category (the id prefix before the first "."):
//   * content_hash — varint(format_code) ‖ SHA-256(ECF({type, data}))
//   * peer_id      — cbor_encode(peer_id_format(key_type, hash_type, digest))
//   * signature    — signature_sign(seed, entity)
//   * everything else (float/int/map_keys/length/primitive/nested/envelope)
//                  — cbor_encode(input)
//   * decode_reject — the decoder MUST reject the `canonical` wire bytes.

Vector_Status :: enum {
	Pass,
	Fail,
	Skipped,
}

Vector_Result :: struct {
	id:     string,
	status: Vector_Status,
	detail: string, // owned when non-empty (got/want hex or error)
}

Conformance_Summary :: struct {
	total:   int,
	passed:  int,
	failed:  int,
	skipped: int,
	results: [dynamic]Vector_Result,
}

CONFORMANCE_KINDS :: []string{"encode_equal", "decode_reject"}

// run_conformance decodes the corpus and runs every encode_equal / decode_reject
// vector. The summary owns its result strings; call summary_destroy to free.
run_conformance :: proc(
	corpus_bytes: []u8,
	allocator := context.allocator,
) -> (Conformance_Summary, Codec_Error) {
	summary := Conformance_Summary {
		results = make([dynamic]Vector_Result, allocator),
	}

	corpus, err := cbor_decode(corpus_bytes, allocator)
	if err != .None {
		return summary, err // a decode failure of the fixture itself IS a conformance failure
	}
	defer value_destroy(corpus, allocator)

	arr, is_arr := corpus.(Ec_Array)
	if !is_arr {
		return summary, .Bad_Entity
	}

	for vec in ([]Ec_Value)(arr) {
		kind_v, has_kind := map_get(vec, "kind")
		if !has_kind {
			continue
		}
		kind_t, is_text := kind_v.(Ec_Text)
		if !is_text {
			continue
		}
		kind := string(kind_t)
		if !slice.contains(CONFORMANCE_KINDS, kind) {
			continue // meta / other rows
		}

		result := run_vector(vec, kind, allocator)
		summary.total += 1
		switch result.status {
		case .Pass:
			summary.passed += 1
		case .Fail:
			summary.failed += 1
		case .Skipped:
			summary.skipped += 1
		}
		append(&summary.results, result)
	}

	return summary, .None
}

run_vector :: proc(vec: Ec_Value, kind: string, allocator: mem.Allocator) -> Vector_Result {
	id_v, _ := map_get(vec, "id")
	id_t, _ := id_v.(Ec_Text)
	id := string(id_t)

	if kind == "decode_reject" {
		return run_reject(id, vec, allocator)
	}
	return run_encode(id, vec, allocator)
}

run_reject :: proc(id: string, vec: Ec_Value, allocator: mem.Allocator) -> Vector_Result {
	wire_v, has := map_get(vec, "canonical")
	wire_b, is_bytes := wire_v.(Ec_Bytes)
	if !has || !is_bytes {
		return Vector_Result{id, .Fail, clone_str("missing/non-bytes canonical", allocator)}
	}
	value, err := cbor_decode(([]u8)(wire_b), allocator)
	if err == .None {
		// Decoded successfully — the reject vector FAILED to reject.
		value_destroy(value, allocator)
		return Vector_Result{id, .Fail, clone_str("expected reject but decoded ok", allocator)}
	}
	return Vector_Result{id, .Pass, ""}
}

run_encode :: proc(id: string, vec: Ec_Value, allocator: mem.Allocator) -> Vector_Result {
	want_v, has_want := map_get(vec, "canonical")
	want_b, is_bytes := want_v.(Ec_Bytes)
	if !has_want || !is_bytes {
		return Vector_Result{id, .Fail, clone_str("missing/non-bytes canonical", allocator)}
	}
	want := ([]u8)(want_b)

	got, err := produce(id, vec, allocator)
	if err != .None {
		return Vector_Result{id, .Fail, produce_error_detail(err, allocator)}
	}
	defer delete(got, allocator)

	if slice.equal(got, want) {
		return Vector_Result{id, .Pass, ""}
	}
	detail := strings.concatenate(
		[]string{"got=", hexify(got, allocator), " want=", hexify(want, allocator)},
		allocator,
	)
	return Vector_Result{id, .Fail, detail}
}

// produce runs the category-specific construction, returning the produced wire
// bytes (owned).
produce :: proc(id: string, vec: Ec_Value, allocator: mem.Allocator) -> ([]u8, Codec_Error) {
	cat := category(id)
	input, _ := map_get(vec, "input")

	switch cat {
	case "content_hash":
		fc: u64 = 0
		if fc_v, has := map_get(input, "format_code"); has {
			fc, _ = as_uint(fc_v)
		}
		return content_hash(input, fc, allocator)
	case "peer_id":
		kt_v, _ := map_get(input, "key_type")
		ht_v, _ := map_get(input, "hash_type")
		dg_v, _ := map_get(input, "digest")
		kt, _ := as_uint(kt_v)
		ht, _ := as_uint(ht_v)
		digest, _ := as_bytes(dg_v)
		pid := peer_id_format(kt, ht, digest, context.temp_allocator)
		defer delete(pid, context.temp_allocator)
		return cbor_encode(Ec_Text(pid), allocator)
	case "signature":
		seed_v, _ := map_get(input, "seed")
		entity, _ := map_get(input, "entity")
		seed, _ := as_bytes(seed_v)
		return signature_sign(seed, entity, allocator)
	case:
		return cbor_encode(input, allocator)
	}
}

// category returns the id prefix up to the first ".".
category :: proc(id: string) -> string {
	if i := strings.index_byte(id, '.'); i >= 0 {
		return id[:i]
	}
	return id
}

// ── result helpers ───────────────────────────────────────────────────────────

summary_destroy :: proc(summary: ^Conformance_Summary, allocator := context.allocator) {
	for r in summary.results {
		if len(r.detail) > 0 {
			delete(r.detail, allocator)
		}
	}
	delete(summary.results)
}

hexify :: proc(bytes: []u8, allocator: mem.Allocator) -> string {
	digits := "0123456789abcdef"
	out := make([]u8, len(bytes) * 2, allocator)
	for b, i in bytes {
		out[i * 2] = digits[b >> 4]
		out[i * 2 + 1] = digits[b & 0xF]
	}
	return string(out)
}

clone_str :: proc(s: string, allocator: mem.Allocator) -> string {
	return strings.clone(s, allocator)
}

produce_error_detail :: proc(err: Codec_Error, allocator: mem.Allocator) -> string {
	switch err {
	case .None:
		return ""
	case .Truncated:
		return clone_str("raised Truncated", allocator)
	case .Non_Canonical_Ecf:
		return clone_str("raised Non_Canonical_Ecf", allocator)
	case .Tag_Rejected:
		return clone_str("raised Tag_Rejected", allocator)
	case .Duplicate_Key:
		return clone_str("raised Duplicate_Key", allocator)
	case .Depth_Exceeded:
		return clone_str("raised Depth_Exceeded", allocator)
	case .Unsupported_Value:
		return clone_str("raised Unsupported_Value", allocator)
	case .Unsupported_Key_Type:
		return clone_str("raised Unsupported_Key_Type", allocator)
	case .Unsupported_Hash_Format:
		return clone_str("raised Unsupported_Hash_Format", allocator)
	case .Bad_Seed:
		return clone_str("raised Bad_Seed", allocator)
	case .Bad_Base58:
		return clone_str("raised Bad_Base58", allocator)
	case .Bad_Entity:
		return clone_str("raised Bad_Entity", allocator)
	case .Content_Hash_Mismatch:
		return clone_str("raised Content_Hash_Mismatch", allocator)
	case .Included_Key_Mismatch:
		return clone_str("raised Included_Key_Mismatch", allocator)
	}
	return clone_str("raised unknown", allocator)
}
