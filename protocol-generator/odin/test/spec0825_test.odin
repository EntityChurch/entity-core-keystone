package entity_core_test

import ec "../src"
import "core:mem"
import "core:testing"

// The 0.8.2.20 -> 0.8.2.25 scope-algebra units: §3.3's effective-target projection,
// §6.3's handler-level path check, §5.2's PATH-SCOPED sentinel guard, §5.5a's
// scope-kind-typed subset check, and §4.11's code-by-cause table.
//
// WHAT IS HERE AND WHAT IS NOT, deliberately. These are the pure functions; the §3.3
// LADDER (which arm answers which code) and the RULE-G operation-before-resource
// ordering are driven over a real socket in `smoke/`, because both are properties of the
// handler's control flow rather than of any one predicate, and because §4.11's frame
// obligation is a RUNTIME property that only a socket can measure. The mapping below is
// the half a unit CAN pin.
//
// Every test is leak-checked under mem.Tracking_Allocator, like the rest of this suite:
// these functions run on the per-dispatch arena in production, so a unit that forgot to
// reset it would report a false leak and a unit that leaked a gpa allocation would be
// caught.

// ── fixtures ─────────────────────────────────────────────────────────────────

@(private = "file")
str_arr :: proc(items: []string, a: mem.Allocator) -> ec.Ec_Value {
	out := make([]ec.Ec_Value, len(items), a)
	for s, i in items {
		out[i] = ec.text_val(s, a)
	}
	return ec.Ec_Array(out)
}

// A `resource` map: {targets: [...]} plus {exclude: [...]} when `excl` is non-empty.
// Canonical key order is irrelevant here -- this value is read, never encoded.
@(private = "file")
resource_v :: proc(targets: []string, excl: []string, a: mem.Allocator) -> ec.Ec_Value {
	pairs := make([dynamic]ec.Ec_Pair, a)
	append(&pairs, ec.Ec_Pair{ec.text_val("targets", a), str_arr(targets, a)})
	if len(excl) > 0 {
		append(&pairs, ec.Ec_Pair{ec.text_val("exclude", a), str_arr(excl, a)})
	}
	return ec.Ec_Map(pairs[:])
}

// An EXECUTE entity carrying `operation`, `uri` and optionally a `resource`.
@(private = "file")
exec_with :: proc(
	operation: string,
	uri: string,
	resource: ec.Ec_Value,
	has_resource: bool,
	a: mem.Allocator,
) -> ec.Entity {
	pairs := make([dynamic]ec.Ec_Pair, a)
	append(&pairs, ec.Ec_Pair{ec.text_val("operation", a), ec.text_val(operation, a)})
	append(&pairs, ec.Ec_Pair{ec.text_val("uri", a), ec.text_val(uri, a)})
	if has_resource {
		append(&pairs, ec.Ec_Pair{ec.text_val("resource", a), resource})
	}
	e, _ := ec.entity_make("system/protocol/execute", ec.Ec_Map(pairs[:]), a)
	return e
}

// A scope map. `include`/`exclude` are both emitted so an empty include is
// DISTINGUISHABLE from an absent one -- §5.2 makes an empty include a legal grant shape
// that denies everything, and a fixture that dropped the key would test the wrong thing.
@(private = "file")
scope_v :: proc(incl: []string, excl: []string, a: mem.Allocator) -> ec.Ec_Value {
	pairs := make([]ec.Ec_Pair, 2, a)
	pairs[0] = ec.Ec_Pair{ec.text_val("include", a), str_arr(incl, a)}
	pairs[1] = ec.Ec_Pair{ec.text_val("exclude", a), str_arr(excl, a)}
	return ec.Ec_Map(pairs)
}

@(private = "file")
grant_v :: proc(
	handlers_i, handlers_x: []string,
	operations_i, operations_x: []string,
	resources_i, resources_x: []string,
	a: mem.Allocator,
) -> ec.Ec_Value {
	pairs := make([]ec.Ec_Pair, 3, a)
	pairs[0] = ec.Ec_Pair{ec.text_val("handlers", a), scope_v(handlers_i, handlers_x, a)}
	pairs[1] = ec.Ec_Pair{ec.text_val("operations", a), scope_v(operations_i, operations_x, a)}
	pairs[2] = ec.Ec_Pair{ec.text_val("resources", a), scope_v(resources_i, resources_x, a)}
	return ec.Ec_Map(pairs)
}

// A system/capability/token carrying exactly the supplied grants.
@(private = "file")
token_of :: proc(grants: []ec.Ec_Value, a: mem.Allocator) -> ec.Entity {
	arr := make([]ec.Ec_Value, len(grants), a)
	copy(arr, grants)
	pairs := make([]ec.Ec_Pair, 1, a)
	pairs[0] = ec.Ec_Pair{ec.text_val("grants", a), ec.Ec_Array(arr)}
	e, _ := ec.entity_make("system/capability/token", ec.Ec_Map(pairs), a)
	return e
}

LOCAL :: "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg"

// ── §3.3 effective targets (0.8.2.20/.21, N11) ───────────────────────────────

@(test)
effective_targets_projection :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	gpa := mem.tracking_allocator(&track)
	context.allocator = gpa
	defer free_all(context.temp_allocator)
	a := context.temp_allocator

	// ABSENT resource -- the two empties must be TELLABLE APART (N11). A projection
	// that answered `[]` here would delete the discriminator before any handler could
	// read it, and `get`'s absent arm (a root listing) and its self-excluded arm (400
	// path_required) would collapse into one.
	{
		e := exec_with("get", "system/tree", nil, false, a)
		defer ec.entity_destroy(e, a)
		eff, had := ec.effective_targets(LOCAL, e)
		testing.expect(t, !had, "an absent resource must report had_resource=false")
		testing.expect(t, len(eff) == 0, "an absent resource has no survivors")
	}

	// PRESENT, every target carved out by the caller's own exclude: had_resource is
	// TRUE and the survivor list is empty. This is the other half of the discriminator.
	{
		e := exec_with("get", "system/tree", resource_v({"a/b"}, {"a/*"}, a), true, a)
		defer ec.entity_destroy(e, a)
		eff, had := ec.effective_targets(LOCAL, e)
		testing.expect(t, had, "a present resource must report had_resource=true")
		testing.expect(t, len(eff) == 0, "every target excluded -> empty survivor list")
	}

	// SURVIVORS COME BACK IN THE CALLER'S OWN SPELLING, not canonicalized (0.8.2.21).
	// The value flows on to the store lookup, which canonicalizes for itself; handing
	// back a canonical form here would double-canonicalize a relative target.
	{
		e := exec_with("get", "system/tree", resource_v({"x/one", "x/two"}, {"x/two"}, a), true, a)
		defer ec.entity_destroy(e, a)
		eff, had := ec.effective_targets(LOCAL, e)
		testing.expect(t, had && len(eff) == 1, "one of two targets survives")
		testing.expect(t, eff[0] == "x/one", "the survivor keeps the caller's own spelling")
	}

	// THE SELECTION MUST (F84): the survivor is the one the exclude LEFT, never
	// targets[0]. This is the whole point -- a handler that counts the effective list
	// and then indexes the raw targets has the arithmetic right and reads a path no
	// authorization covered.
	{
		e := exec_with("get", "system/tree", resource_v({"x/one", "x/two"}, {"x/one"}, a), true, a)
		defer ec.entity_destroy(e, a)
		eff, _ := ec.effective_targets(LOCAL, e)
		testing.expect(t, len(eff) == 1 && eff[0] == "x/two", "the survivor is x/two, not targets[0]")
	}

	// THE CALLER-EXCLUDE ARM IS FAIL-OPEN ON AN UNMATCHABLE PATTERN. §5.4 rules it
	// separately from the grant arm: canonicalize answers the sentinel, matches_pattern
	// then answers false, and the target simply SURVIVES. Inherited, not restated --
	// this test exists so the inheritance is asserted rather than assumed.
	{
		e := exec_with("get", "system/tree", resource_v({"x/one"}, {"../nope"}, a), true, a)
		defer ec.entity_destroy(e, a)
		eff, _ := ec.effective_targets(LOCAL, e)
		testing.expect(t, len(eff) == 1, "an unmatchable CALLER exclude carves out nothing")
	}

	// A PRESENT-BUT-ILL-TYPED `targets` IS PRESENT, with an empty survivor list.
	// Reporting it absent would serve the WIDER absent-case answer to a request that
	// named a resource -- N11's own defect one field over.
	{
		pairs := make([]ec.Ec_Pair, 1, a)
		pairs[0] = ec.Ec_Pair{ec.text_val("targets", a), ec.Ec_Uint(7)}
		e := exec_with("get", "system/tree", ec.Ec_Map(pairs), true, a)
		defer ec.entity_destroy(e, a)
		eff, had := ec.effective_targets(LOCAL, e)
		testing.expect(t, had, "an ill-typed targets is still a PRESENT resource")
		testing.expect(t, len(eff) == 0, "an ill-typed targets yields no survivors")
	}
}

// ── §6.3 check_path_permission (0.8.2.20/.22/.23) ────────────────────────────

@(test)
check_path_permission_three_dimensions :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	gpa := mem.tracking_allocator(&track)
	context.allocator = gpa
	defer free_all(context.temp_allocator)
	a := context.temp_allocator

	pattern := "/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/system/tree"
	covered := "/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/system/type/qA"
	outside := "/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/secrets/qB"

	// The ACCEPT case first, and it is the one that validates the FIXTURE: a suite
	// built only from deny cases is indistinguishable from one asserting False == False,
	// which a mis-built grant fixture guarantees for free.
	{
		g := grant_v({"system/tree"}, {}, {"get"}, {}, {"system/type/*"}, {}, a)
		tok := token_of({g}, a)
		defer ec.entity_destroy(tok, a)
		testing.expect(t, ec.check_path_permission(LOCAL, "get", covered, tok, pattern),
			"a grant covering handler+operation+resource must ALLOW")
		// One deny per DIMENSION -- a single deny cannot distinguish "the predicate
		// checks the dimension I care about" from "the predicate denies".
		testing.expect(t, !ec.check_path_permission(LOCAL, "get", outside, tok, pattern),
			"RESOURCES: a path outside resources.include must DENY")
		testing.expect(t, !ec.check_path_permission(LOCAL, "put", covered, tok, pattern),
			"OPERATIONS: an operation outside operations.include must DENY")
		testing.expect(t, !ec.check_path_permission(LOCAL, "get", covered, tok, "/x/system/other"),
			"HANDLERS: a handler pattern outside handlers.include must DENY")
	}

	// AN EMPTY `resources.include` IS A LEGAL GRANT SHAPE and denies EVERY path
	// (§5.2: handlers that touch no tree paths). `covered` over an empty include list
	// is false, which is what that note says it should be.
	{
		g := grant_v({"system/tree"}, {}, {"get"}, {}, {}, {}, a)
		tok := token_of({g}, a)
		defer ec.entity_destroy(tok, a)
		testing.expect(t, !ec.check_path_permission(LOCAL, "get", covered, tok, pattern),
			"an empty resources.include denies every path")
	}

	// A GRANT EXCLUDE COVERING THE SUBJECT DENIES, even though the include covers it.
	{
		g := grant_v({"system/tree"}, {}, {"get"}, {}, {"system/type/*"}, {"system/type/qA"}, a)
		tok := token_of({g}, a)
		defer ec.entity_destroy(tok, a)
		testing.expect(t, !ec.check_path_permission(LOCAL, "get", covered, tok, pattern),
			"a grant exclude covering the subject denies")
	}

	// A MALFORMED PATH canonicalizes to the §5.4 sentinel, which matches no grant, so
	// it falls through to DENY rather than being matched against anything -- including
	// against a grant whose include is a bare star.
	{
		g := grant_v({"system/tree"}, {}, {"get"}, {}, {"*"}, {}, a)
		tok := token_of({g}, a)
		defer ec.entity_destroy(tok, a)
		testing.expect(t, ec.check_path_permission(LOCAL, "get", covered, tok, pattern),
			"control: the bare-star grant does allow an ordinary path")
		testing.expect(t, !ec.check_path_permission(LOCAL, "get", "../nope", tok, pattern),
			"a path that canonicalizes to NEVER_MATCH denies")
	}

	// THE OPERATIONS DIMENSION IS ID-SCOPE, NOT PATH-SCOPE (F40). A path-form pattern
	// in `operations` is matched as a LITERAL string: a non-match, never a fault, and
	// never a canonicalizing match against an unrelated operation name.
	{
		g := grant_v({"system/tree"}, {}, {"/*/get"}, {}, {"*"}, {}, a)
		tok := token_of({g}, a)
		defer ec.entity_destroy(tok, a)
		testing.expect(t, !ec.check_path_permission(LOCAL, "get", covered, tok, pattern),
			"operations is id-scope: a path-form pattern is a literal and does not match 'get'")
	}
}

// ── §5.2 the sentinel is scoped to PATH-SCOPE (0.8.2.24, N2/N3) ──────────────

@(test)
sentinel_guard_is_path_scope_only :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	gpa := mem.tracking_allocator(&track)
	context.allocator = gpa
	defer free_all(context.temp_allocator)
	a := context.temp_allocator

	uri := "/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/system/tree"
	pattern := uri

	// AN ID-SCOPE EXCLUDE THAT PATH-CANONICALIZES TO THE SENTINEL MUST NOT DENY THE
	// WHOLE DIMENSION. `*/apply` -- an ordinary namespaced operation name -- is a
	// literal under the id-scope grammar and matches nothing; putting it
	// through the §5.4 transforms purely to classify it produced the sentinel and denied
	// EVERY operation. Over-denial, and invisible on any well-formed grant -- which is
	// why this needs a test rather than a reading.
	{
		g := grant_v({"*"}, {}, {"*"}, {"*/apply"}, {"*"}, {}, a)
		tok := token_of({g}, a)
		defer ec.entity_destroy(tok, a)
		e := exec_with("get", uri, nil, false, a)
		defer ec.entity_destroy(e, a)
		v := ec.check_permission(LOCAL, LOCAL, e, tok, pattern)
		testing.expect(t, v == .Allow,
			"an id-scope exclude that path-canonicalizes to the sentinel must not deny the dimension")
	}

	// THE PATH-SCOPE ARM STILL DENIES -- the control that says the guard was SCOPED
	// rather than DELETED. An unmatchable exclude on `resources` excludes everything
	// (0.8.2.21), because there the sentinel means the author wrote a carve-out that
	// carves nothing and the grant is silently wider than written.
	{
		g := grant_v({"*"}, {}, {"*"}, {}, {"*"}, {"../nope"}, a)
		tok := token_of({g}, a)
		defer ec.entity_destroy(tok, a)
		e := exec_with("get", uri, resource_v({"system/type/qA"}, {}, a), true, a)
		defer ec.entity_destroy(e, a)
		v := ec.check_permission(LOCAL, LOCAL, e, tok, pattern)
		testing.expect(t, v == .Deny,
			"an unmatchable PATH-SCOPE exclude still denies (0.8.2.21)")
	}

	// And the same guard on the HANDLERS dimension, which is the other path-scope one.
	{
		g := grant_v({"*"}, {"../nope"}, {"*"}, {}, {"*"}, {}, a)
		tok := token_of({g}, a)
		defer ec.entity_destroy(tok, a)
		e := exec_with("get", uri, nil, false, a)
		defer ec.entity_destroy(e, a)
		v := ec.check_permission(LOCAL, LOCAL, e, tok, pattern)
		testing.expect(t, v == .Deny,
			"an unmatchable handlers exclude still denies (handlers is path-scope)")
	}
}

// ── §5.5a scope_subset is typed by scope kind (F50 / 0.8.2.16, K-7) ──────────

@(test)
scope_subset_is_typed_by_scope_kind :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	gpa := mem.tracking_allocator(&track)
	context.allocator = gpa
	defer free_all(context.temp_allocator)
	a := context.temp_allocator

	sub :: proc(child, parent: ec.Ec_Value) -> bool {
		return ec.grant_subset_local(LOCAL, ec.parse_grant_public(child), ec.parse_grant_public(parent))
	}

	// THE DIFFERENTIAL. `entity-core-formalization` measured 2 of 64 include pairs
	// disagreeing between the two readings, FAIL-CLOSED, with a 16-pair control alphabet
	// reporting 0 -- which is why every hand-tried example missed it. Both witnesses are
	// OPERATIONS patterns (`*/apply`, `/tree/get`), which §3.6 types as id-scope: under
	// the literal matcher a bare
	// star parent covers any child pattern, and under the canonicalizing matcher the
	// child canonicalizes to the sentinel (or to an absolute path the parent's
	// peer-framed star cannot cover) and the subset is wrongly REFUSED.
	{
		child := grant_v({"*"}, {}, {"*/apply"}, {}, {"*"}, {}, a)
		parent := grant_v({"*"}, {}, {"*"}, {}, {"*"}, {}, a)
		testing.expect(t, sub(child, parent),
			"id-scope: a namespaced operation child is covered by a bare-star parent")
	}
	{
		child := grant_v({"*"}, {}, {"/tree/get"}, {}, {"*"}, {}, a)
		parent := grant_v({"*"}, {}, {"*"}, {}, {"*"}, {}, a)
		testing.expect(t, sub(child, parent),
			"id-scope: a path-form operation child is covered by a bare-star parent")
	}

	// THE CONTROL ALPHABET -- the pairs that agree under both readings. Without these
	// the two assertions above are equally explained by a subset check that has stopped
	// checking anything.
	{
		child := grant_v({"*"}, {}, {"get"}, {}, {"*"}, {}, a)
		parent := grant_v({"*"}, {}, {"*"}, {}, {"*"}, {}, a)
		testing.expect(t, sub(child, parent), "control: get is covered by a bare-star parent")
	}
	{
		child := grant_v({"*"}, {}, {"put"}, {}, {"*"}, {}, a)
		parent := grant_v({"*"}, {}, {"get"}, {}, {"*"}, {}, a)
		testing.expect(t, !sub(child, parent), "control: put is NOT covered by a get-only parent")
	}
	// A WIDENING ON THE PATH-SCOPE DIMENSION IS STILL REFUSED -- the kind parameter
	// selected the matcher, it did not disable the check.
	{
		child := grant_v({"*"}, {}, {"get"}, {}, {"*"}, {}, a)
		parent := grant_v({"*"}, {}, {"get"}, {}, {"system/type/*"}, {}, a)
		testing.expect(t, !sub(child, parent),
			"path-scope: a bare-star child is NOT covered by a narrower parent")
	}
	// A PARENT EXCLUDE MUST BE INHERITED BY THE CHILD, on the id arm too.
	{
		child := grant_v({"*"}, {}, {"get"}, {}, {"*"}, {}, a)
		parent := grant_v({"*"}, {}, {"*"}, {"put"}, {"*"}, {}, a)
		testing.expect(t, !sub(child, parent),
			"id-scope: a child that does not inherit the parent's exclude is refused")
	}
}

// ── §4.11 the code belongs to the cause (0.8.2.24 N4/N5, 0.8.2.25) ───────────

@(test)
pre_admission_code_belongs_to_the_cause :: proc(t: ^testing.T) {
	// §5.2a: "A peer that refuses at the decode boundary MUST answer 400 hash_mismatch
	// [MUST] ... 400 non_canonical_ecf is NOT conformant here [MUST]." A mis-keyed
	// `included` entry carries no tag; its encoding is canonical, and what is false is
	// the claim the KEY makes. This peer answered non_canonical_ecf for every
	// decode-boundary refusal until 0.8.2.24/.25 pinned them apart.
	s, c, _ := ec.pre_admission_refusal(.Included_Key_Mismatch)
	testing.expect(t, s == 400 && c == "hash_mismatch", "a mis-keyed included entry is hash_mismatch")
	s, c, _ = ec.pre_admission_refusal(.Content_Hash_Mismatch)
	testing.expect(t, s == 400 && c == "hash_mismatch", "a carried-hash mismatch is hash_mismatch")

	// THE TAG ARM KEEPS non_canonical_ecf, and that is the differential rather than an
	// exception: ENTITY-CBOR-ENCODING defines that code for CBOR tag-policy violations
	// specifically, which §6.3 still MUSTs. If this answered the same code as the arm
	// below, the peer would not be classifying, it would just be refusing.
	s, c, _ = ec.pre_admission_refusal(.Tag_Rejected)
	testing.expect(t, s == 400 && c == "non_canonical_ecf", "a CBOR tag keeps non_canonical_ecf")

	// Everything else that never becomes an Envelope is the framing arm, where §4.11
	// rules non_canonical_ecf NOT conformant.
	for e in ([]ec.Codec_Error{.Truncated, .Non_Canonical_Ecf, .Duplicate_Key, .Depth_Exceeded, .Bad_Entity}) {
		st, code, _ := ec.pre_admission_refusal(e)
		testing.expect(t, st == 400 && code == "invalid_request",
			"a framing failure is 400 invalid_request, never non_canonical_ecf")
	}

	// Every message is wire-visible and therefore ASCII-only: two peers in this cohort
	// have been killed at runtime by a non-ASCII byte in an encoded string, on two
	// unrelated compilers.
	for e in ([]ec.Codec_Error{.Included_Key_Mismatch, .Tag_Rejected, .Truncated, .Bad_Entity}) {
		_, code, msg := ec.pre_admission_refusal(e)
		mb := transmute([]u8)msg
		cb := transmute([]u8)code
		for b in mb {
			testing.expect(t, b < 0x80, "a wire-visible message must be ASCII-only")
		}
		for b in cb {
			testing.expect(t, b < 0x80, "a wire-visible code must be ASCII-only")
		}
	}
}
