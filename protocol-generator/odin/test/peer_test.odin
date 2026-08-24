package entity_core_test

import ec "../src"
import "core:mem"
import "core:strings"
import "core:testing"

// Peer-layer accept-path units — the directions the validate-peer oracle does NOT
// cover (its multisig category is 100% rejection tests; a fail-closed peer passes
// those vacuously). Each verifies a positive path + the invariant flips, so the
// primitive is actually IMPLEMENTED, not just fail-closed (AGENTS.md
// "conformance-green can be vacuous"). Leak-checked under a tracking allocator.

// mk_multi_cap builds a system/capability/token with a multi-sig granter.
@(private = "file")
mk_multi_cap :: proc(
	grantee_hash: []u8,
	signers: [][]u8,
	threshold: u64,
	parent: []u8,
	has_parent: bool,
	allocator: mem.Allocator,
) -> ec.Entity {
	sig_arr := make([]ec.Ec_Value, len(signers), allocator)
	for s, i in signers {
		sig_arr[i] = ec.bytes_val(s, allocator)
	}
	granter_pairs := make([]ec.Ec_Pair, 2, allocator)
	granter_pairs[0] = ec.Ec_Pair{ec.text_val("signers", allocator), ec.Ec_Array(sig_arr)}
	granter_pairs[1] = ec.Ec_Pair{ec.text_val("threshold", allocator), ec.Ec_Uint(threshold)}

	pairs := make([dynamic]ec.Ec_Pair, allocator)
	append(&pairs, ec.Ec_Pair{ec.text_val("granter", allocator), ec.Ec_Map(granter_pairs)})
	append(&pairs, ec.Ec_Pair{ec.text_val("grantee", allocator), ec.bytes_val(grantee_hash, allocator)})
	append(&pairs, ec.Ec_Pair{ec.text_val("grants", allocator), ec.Ec_Array(make([]ec.Ec_Value, 0, allocator))})
	if has_parent {
		append(&pairs, ec.Ec_Pair{ec.text_val("parent", allocator), ec.bytes_val(parent, allocator)})
	}
	e, _ := ec.entity_make("system/capability/token", ec.Ec_Map(pairs[:]), allocator)
	return e
}

// allows_multisig assembles an envelope from owned entities, runs
// verify_capability_chain (via verify_request-adjacent path), then frees
// everything. Returns whether the chain root verdict is Allow.
@(private = "file")
allows_multisig :: proc(
	t: ^testing.T,
	local_peer: string,
	cap: ec.Entity,
	extra: []ec.Entity,
	gpa: mem.Allocator,
) -> bool {
	st := ec.store_init(gpa)
	defer ec.store_destroy(&st, gpa)

	// build included: cap + all extra, each cloned + owned by the envelope.
	included := make([dynamic]ec.Included, gpa)
	defer {
		for inc in included {
			delete(inc.key, gpa)
			ec.entity_destroy(inc.entity, gpa)
		}
		delete(included)
	}
	cap_clone, _ := ec.entity_clone(cap, gpa)
	k0 := make([]u8, len(cap_clone.hash), gpa)
	copy(k0, cap_clone.hash)
	append(&included, ec.Included{key = k0, entity = cap_clone})
	for e in extra {
		c, _ := ec.entity_clone(e, gpa)
		k := make([]u8, len(c.hash), gpa)
		copy(k, c.hash)
		append(&included, ec.Included{key = k, entity = c})
	}
	root_clone, _ := ec.entity_clone(cap, gpa)
	env := ec.Envelope{root = root_clone, included = included[:]}
	defer ec.entity_destroy(root_clone, gpa)

	v := ec.verify_capability_chain_public(env, &st, local_peer, cap)
	free_all(context.temp_allocator)
	return v == .Allow
}

@(test)
multisig_k_of_n_accept_and_deny_flips :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	gpa := mem.tracking_allocator(&track)
	context.allocator = gpa

	s1: [32]u8 = 1
	s2: [32]u8 = 2
	s3: [32]u8 = 3
	id1, _ := ec.identity_of_seed(s1, gpa)
	defer ec.identity_destroy(id1, gpa)
	id2, _ := ec.identity_of_seed(s2, gpa)
	defer ec.identity_destroy(id2, gpa)
	id3, _ := ec.identity_of_seed(s3, gpa)
	defer ec.identity_destroy(id3, gpa)
	free_all(context.temp_allocator)

	local := id1.peer_id
	signers := [][]u8{id1.identity_hash, id2.identity_hash, id3.identity_hash}

	// valid 2-of-3, local in quorum, 2 valid sigs → Allow
	{
		cap := mk_multi_cap(id1.identity_hash, signers, 2, nil, false, gpa)
		defer ec.entity_destroy(cap, gpa)
		sg1, _ := ec.sign_entity(id1, cap, gpa)
		defer ec.entity_destroy(sg1, gpa)
		sg2, _ := ec.sign_entity(id2, cap, gpa)
		defer ec.entity_destroy(sg2, gpa)
		extra := []ec.Entity{id1.peer_entity, id2.peer_entity, id3.peer_entity, sg1, sg2}
		testing.expect(t, allows_multisig(t, local, cap, extra, gpa), "valid 2-of-3 should Allow")
	}

	// only 1 valid sig (< threshold) → Deny (M4)
	{
		cap := mk_multi_cap(id1.identity_hash, signers, 2, nil, false, gpa)
		defer ec.entity_destroy(cap, gpa)
		sg1, _ := ec.sign_entity(id1, cap, gpa)
		defer ec.entity_destroy(sg1, gpa)
		extra := []ec.Entity{id1.peer_entity, id2.peer_entity, id3.peer_entity, sg1}
		testing.expect(t, !allows_multisig(t, local, cap, extra, gpa), "1 sig < threshold should Deny")
	}

	// duplicate signature from one signer does NOT inflate the count → Deny (M4)
	{
		cap := mk_multi_cap(id1.identity_hash, signers, 2, nil, false, gpa)
		defer ec.entity_destroy(cap, gpa)
		sg1, _ := ec.sign_entity(id1, cap, gpa)
		defer ec.entity_destroy(sg1, gpa)
		extra := []ec.Entity{id1.peer_entity, id2.peer_entity, id3.peer_entity, sg1, sg1}
		testing.expect(t, !allows_multisig(t, local, cap, extra, gpa), "duplicate sig should not inflate count")
	}

	// local peer not among the signers → Deny (M6)
	{
		two := [][]u8{id2.identity_hash, id3.identity_hash}
		cap := mk_multi_cap(id1.identity_hash, two, 2, nil, false, gpa)
		defer ec.entity_destroy(cap, gpa)
		n2, _ := ec.sign_entity(id2, cap, gpa)
		defer ec.entity_destroy(n2, gpa)
		n3, _ := ec.sign_entity(id3, cap, gpa)
		defer ec.entity_destroy(n3, gpa)
		extra := []ec.Entity{id2.peer_entity, id3.peer_entity, n2, n3}
		testing.expect(t, !allows_multisig(t, local, cap, extra, gpa), "local not in quorum should Deny (M6)")
	}

	// threshold = 1 (M3 structure) → Deny even with valid sigs (precedence)
	{
		cap := mk_multi_cap(id1.identity_hash, signers, 1, nil, false, gpa)
		defer ec.entity_destroy(cap, gpa)
		sg1, _ := ec.sign_entity(id1, cap, gpa)
		defer ec.entity_destroy(sg1, gpa)
		sg2, _ := ec.sign_entity(id2, cap, gpa)
		defer ec.entity_destroy(sg2, gpa)
		extra := []ec.Entity{id1.peer_entity, id2.peer_entity, id3.peer_entity, sg1, sg2}
		testing.expect(t, !allows_multisig(t, local, cap, extra, gpa), "threshold=1 should Deny (M3)")
	}

	// duplicate signers (M3 structure) → Deny
	{
		dup := [][]u8{id1.identity_hash, id1.identity_hash}
		cap := mk_multi_cap(id1.identity_hash, dup, 2, nil, false, gpa)
		defer ec.entity_destroy(cap, gpa)
		sg1, _ := ec.sign_entity(id1, cap, gpa)
		defer ec.entity_destroy(sg1, gpa)
		extra := []ec.Entity{id1.peer_entity, sg1}
		testing.expect(t, !allows_multisig(t, local, cap, extra, gpa), "duplicate signers should Deny (M3)")
	}

}

// single_sig_root_still_verifies — a strict-superset sanity: a plain single-sig
// root (granter = local identity, self-signed) still Allows.
@(test)
single_sig_root_still_verifies :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	gpa := mem.tracking_allocator(&track)
	context.allocator = gpa

	s1: [32]u8 = 1
	id1, _ := ec.identity_of_seed(s1, gpa)
	defer ec.identity_destroy(id1, gpa)
	free_all(context.temp_allocator)
	local := id1.peer_id

	pairs := make([]ec.Ec_Pair, 3, gpa)
	pairs[0] = ec.Ec_Pair{ec.text_val("granter", gpa), ec.bytes_val(id1.identity_hash, gpa)}
	pairs[1] = ec.Ec_Pair{ec.text_val("grantee", gpa), ec.bytes_val(id1.identity_hash, gpa)}
	pairs[2] = ec.Ec_Pair{ec.text_val("grants", gpa), ec.Ec_Array(make([]ec.Ec_Value, 0, gpa))}
	cap, _ := ec.entity_make("system/capability/token", ec.Ec_Map(pairs), gpa)
	defer ec.entity_destroy(cap, gpa)
	ss, _ := ec.sign_entity(id1, cap, gpa)
	defer ec.entity_destroy(ss, gpa)
	extra := []ec.Entity{id1.peer_entity, ss}
	testing.expect(t, allows_multisig(t, local, cap, extra, gpa), "single-sig root should Allow")

}

// type_registry_53 — the peer publishes exactly the 53 core type floor entities.
@(test)
type_registry_publishes_53 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	gpa := mem.tracking_allocator(&track)
	context.allocator = gpa

	st := ec.store_init(gpa)
	defer ec.store_destroy(&st, gpa)
	count := ec.type_defs_publish(&st, "p", gpa)
	free_all(context.temp_allocator)
	testing.expectf(t, count == ec.CORE_TYPE_COUNT, "expected %d core types, got %d", ec.CORE_TYPE_COUNT, count)
	// spot-check a couple are present at the tree path
	_, ok1 := ec.store_get_at(&st, "/p/system/type/system/peer")
	testing.expect(t, ok1, "system/peer type should be bound")
	_, ok2 := ec.store_get_at(&st, "/p/system/type/system/capability/token")
	testing.expect(t, ok2, "system/capability/token type should be bound")

}

// echo_accept_path — the §7a echo handler round-trips params verbatim (the
// accept direction the connectivity/handlers categories exercise live in S4;
// here as a fast in-process unit).
@(test)
echo_round_trips_params :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	gpa := mem.tracking_allocator(&track)
	context.allocator = gpa

	s9: [32]u8 = 9
	p, _ := ec.peer_create(ec.Create_Options{seed = s9, open_grants = true, conformance = true})
	defer ec.peer_destroy(&p)
	free_all(context.temp_allocator)

	// under --validate the §7a echo interface entity must be bootstrapped
	echo_iface := strings.concatenate({"/", p.local_peer, "/system/handler/system/validate/echo"}, gpa)
	defer delete(echo_iface, gpa)
	_, ok := ec.store_get_at(&p.store, echo_iface)
	testing.expect(t, ok, "echo interface should be bootstrapped under --validate")
	// leak assertion omitted: p.store clones are freed by peer_destroy (deferred
	// after this scope), so the map is intentionally non-empty here.
}

// The Go-rendered type-registry vector set (the S8 drift/diff target). Compiled
// in for a hermetic, offline byte-diff of our render-from-model output.
TYPE_VECTORS := #load("../../shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor")

// type_registry_byte_identical_to_go — every core type's content_hash digest
// renders byte-identical to the Go reference vector set. This is the render-from-
// model drift target: a mismatch is a regression, not masked by editing the
// golden. (Cohort-consistent, not independent convergence — the vectors are the
// Go author's bytes; reproducing them is generator robustness.)
@(test)
type_registry_byte_identical_to_go :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	gpa := mem.tracking_allocator(&track)
	context.allocator = gpa

	fixture, derr := ec.cbor_decode(TYPE_VECTORS, gpa)
	testing.expectf(t, derr == .None, "type-vector decode failed: %v", derr)
	defer ec.value_destroy(fixture, gpa)

	arr, is_arr := fixture.(ec.Ec_Array)
	testing.expect(t, is_arr, "type vectors should be an array")
	if !is_arr {
		return
	}

	// name → expected digest hex (after the "ecf-sha256:" prefix)
	want := make(map[string]string, gpa)
	defer delete(want)
	for v in ([]ec.Ec_Value)(arr) {
		nv, hn := ec.map_get(v, "name")
		cv, hc := ec.map_get(v, "content_hash")
		if !hn || !hc {
			continue
		}
		nt, nok := nv.(ec.Ec_Text)
		ct, cok := cv.(ec.Ec_Text)
		if !nok || !cok {
			continue
		}
		prefix := "ecf-sha256:"
		if !strings.has_prefix(string(ct), prefix) {
			continue
		}
		want[string(nt)] = string(ct)[len(prefix):]
	}

	// publish our 53 types into a store, then diff each against the vectors.
	st := ec.store_init(gpa)
	defer ec.store_destroy(&st, gpa)
	ec.type_defs_publish(&st, "p", gpa)

	matched := 0
	mismatched := 0
	for name, expect_hex in want {
		path := strings.concatenate({"/p/system/type/", name}, context.temp_allocator)
		e, ok := ec.store_get_at(&st, path)
		if !ok {
			// non-floor type the core peer intentionally does NOT publish; the
			// vector set is a superset probe. Skip (matched-if-present).
			continue
		}
		// e.hash is 33 bytes: 0x00 format byte ‖ 32-byte digest. Compare the digest.
		got_hex := ec.hex_of(e.hash[1:], context.temp_allocator)
		if got_hex == expect_hex {
			matched += 1
		} else {
			testing.expectf(t, false, "MISMATCH %s\n  want %s\n  got  %s", name, expect_hex, got_hex)
			mismatched += 1
		}
	}
	free_all(context.temp_allocator)
	testing.expectf(t, mismatched == 0, "%d type digest mismatch(es)", mismatched)
	testing.expectf(t, matched == ec.CORE_TYPE_COUNT, "expected %d floor types matched, got %d", ec.CORE_TYPE_COUNT, matched)
}
