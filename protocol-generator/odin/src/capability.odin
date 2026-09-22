package entity_core

import "core:mem"
import "core:slice"
import "core:strings"
import "core:time"

// Capability system (L3) — the §5 verification core: pattern matching (§5.4),
// request verification (§5.2 verify_request / check_permission), delegation-chain
// verification (§5.5), attenuation (§5.6), delegation caveats (§5.7), revocation
// (§5.1), and the §3.6 M3 multi-signature root. Derived from the §5 spec text.
//
// Verdict is the §5.10 Layer-1 deterministic ALLOW/DENY; the dispatcher maps
// DENY→403, with the §5.5 unresolvable-grantee carve-out surfaced as a distinct
// verdict mapping to 401, and the §4.6 authn(401)/authz(403) split surfaced as a
// 3-way request verdict.
//
// No-GC idiom: the verification path runs on `context.temp_allocator` — the whole
// chain walk allocates freely and is freed in one shot when the dispatch arena is
// reset (the clean answer to a recursive borrow graph). All scope/grant parsing
// borrows into the entity's Ec_Value tree.

Verdict :: enum {
	Allow,
	Deny,
}

// 3-way request verdict (§5.2 / §4.6): authn-class failure → 401, authz-class
// deny → 403, allow → dispatch, chain-too-deep → 400.
Req_Verdict :: enum {
	Allow,
	Authn_Fail,
	Authz_Deny,
	Chain_Too_Deep,
	Unresolvable_Grantee,
}

MAX_CHAIN_DEPTH :: 64 // §4.10(b)

// ── parse helpers (borrow into the entity's Ec_Value tree; temp-alloc slices) ──

Scope :: struct {
	incl: []string,
	excl: []string,
}

Grant :: struct {
	handlers:  Scope,
	resources: Scope,
	operations: Scope,
	peers:     Scope,
	has_peers: bool,
}

@(private = "file")
text_list :: proc(v: Ec_Value, has: bool) -> []string {
	if !has {
		return {}
	}
	arr, is_arr := v.(Ec_Array)
	if !is_arr {
		return {}
	}
	out := make([dynamic]string, context.temp_allocator)
	for it in ([]Ec_Value)(arr) {
		if t, ok := it.(Ec_Text); ok {
			append(&out, string(t))
		}
	}
	return out[:]
}

@(private = "file")
bytes_list :: proc(v: Ec_Value, has: bool) -> [][]u8 {
	if !has {
		return {}
	}
	arr, is_arr := v.(Ec_Array)
	if !is_arr {
		return {}
	}
	out := make([dynamic][]u8, context.temp_allocator)
	for it in ([]Ec_Value)(arr) {
		if b, ok := it.(Ec_Bytes); ok {
			append(&out, ([]u8)(b))
		}
	}
	return out[:]
}

@(private = "file")
parse_scope :: proc(c: Ec_Value) -> Scope {
	iv, ih := map_get(c, "include")
	ev, eh := map_get(c, "exclude")
	return Scope{incl = text_list(iv, ih), excl = text_list(ev, eh)}
}

@(private = "file")
scope_field :: proc(c: Ec_Value, key: string) -> Scope {
	v, has := map_get(c, key)
	if has {
		return parse_scope(v)
	}
	return Scope{}
}

@(private = "file")
parse_grant :: proc(c: Ec_Value) -> Grant {
	g := Grant {
		handlers = scope_field(c, "handlers"),
		resources = scope_field(c, "resources"),
		operations = scope_field(c, "operations"),
	}
	if pv, ph := map_get(c, "peers"); ph {
		g.peers = parse_scope(pv)
		g.has_peers = true
	}
	return g
}

grants_of_token :: proc(token: Entity) -> []Grant {
	v, has := entity_field(token, "grants")
	if !has {
		return {}
	}
	arr, is_arr := v.(Ec_Array)
	if !is_arr {
		return {}
	}
	out := make([dynamic]Grant, context.temp_allocator)
	for g in ([]Ec_Value)(arr) {
		append(&out, parse_grant(g))
	}
	return out[:]
}

// ── §5.4 pattern matching ─────────────────────────────────────────────────────

is_peer_id :: proc(seg: string) -> bool {
	if len(seg) < 46 {
		return false
	}
	for i in 0 ..< len(seg) {
		if alphabet_index(seg[i]) < 0 {
			return false
		}
	}
	return true
}

// normalize_uri (§1.4): strip entity:// scheme; peer-relative paths pass through.
// Returns a temp-allocated / borrowed slice.
normalize_uri :: proc(uri: string) -> string {
	if strings.has_prefix(uri, "entity://") {
		rest := uri[len("entity://"):]
		return strings.concatenate({"/", rest}, context.temp_allocator)
	}
	return uri
}

// canonicalize resolves peer-relative paths to absolute "/{local}/..." form.
// NEVER_MATCH — the unmatchable value (0.8.2.20). Unreachable as a canonical path by
// CONSTRUCTION: its first segment cannot be a peer_id, since is_peer_id requires >= 46
// Base58 characters and "-" is outside the Base58 alphabet.
NEVER_MATCH :: "/never-match"

// TOTAL (0.8.2.20): the return domain is "a canonical path OR NEVER_MATCH". The two
// reserved arms were ABSENT here -- "../x" came back as "/{local}/../x", which matched
// nothing, so a grant exclude carrying it carved out nothing and the grant was silently
// wider than its author wrote (measured on the wire 2026-09-14). A non-match is the
// desired outcome in an INCLUDE and the opposite of it in an EXCLUDE.
canonicalize :: proc(local_peer: string, path: string) -> string {
	if strings.has_prefix(path, "./") || strings.has_prefix(path, "../") {
		return NEVER_MATCH
	}
	if strings.has_prefix(path, "*/") {
		return NEVER_MATCH
	}
	if strings.has_prefix(path, "/") {
		return path
	}
	return strings.concatenate({"/", local_peer, "/", path}, context.temp_allocator)
}

// AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED in
// an include (covers nothing -> the grant grants nothing) and fail-OPEN in an exclude
// (carves out nothing), so the reading is chosen where the POSITION is known and
// matches_pattern stays uniform over its operands.
//
// ASK THIS ONLY OF A PATH-SCOPE DIMENSION (0.8.2.24, N2/N3). NEVER_MATCH is a §5.4
// PATH-canonicalization sentinel; an id-scope pattern is a literal identifier that
// §5.2's own id-scope arm forbids putting through the §5.4 transforms. This guard used
// to sit OUTSIDE the type dispatch, transcribing §5.2's loop as it read before that loop
// grew one -- which ran an id pattern through those transforms purely to classify it and
// then DENIED THE WHOLE DIMENSION on a property unrelated to whether the exclude carves
// anything out. An `operations` exclude of a namespaced operation name such as the
// wildcard-slash-apply form -- an ordinary literal that matches nothing under the
// id-scope grammar -- canonicalized to the sentinel and denied every operation.
// Over-denial, and invisible on any well-formed grant.
//
// §5.4 says outright that the rule "does NOT reach `operations` or `peers` [MUST]", and
// it does NOT leave the id-scope dimensions unprotected by oversight: under the id-scope
// grammar every non-star pattern is a literal and a literal is never structurally
// unmatchable, so there is nothing here for this sentinel to detect. A scope boundary,
// not an omission.
exclude_unmatchable :: proc(frame: string, excl: []string) -> bool {
	for p in excl {
		if canonicalize(frame, p) == NEVER_MATCH {
			return true
		}
	}
	return false
}

// matches_pattern — both path and pattern MUST already be canonical (absolute).
matches_pattern :: proc(path, pattern: string) -> bool {
	// NEVER_MATCH never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
	// rule rather than a property of the string: the arm below returns true for a bare
	// "*", so safety must not rest on a value merely looking unmatchable.
	if path == NEVER_MATCH || pattern == NEVER_MATCH {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.has_prefix(pattern, "/*/") {
		remainder := pattern[3:]
		if len(path) < 1 {
			return false
		}
		i := strings.index_byte(path[1:], '/')
		if i < 0 {
			return false
		}
		return matches_pattern(path[1 + i + 1:], remainder)
	}
	if len(pattern) >= 2 && pattern[len(pattern) - 2:] == "/*" {
		prefix := pattern[:len(pattern) - 1] // keep trailing /
		return strings.has_prefix(path, prefix)
	}
	return path == pattern
}

@(private = "file")
covered :: proc(lp: string, v: string, pats: []string) -> bool {
	for p in pats {
		if matches_pattern(v, canonicalize(lp, p)) {
			return true
		}
	}
	return false
}

// Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every
// call site — no default — so a new one cannot inherit the wrong matcher silently,
// which is exactly the F40 defect.
Scope_Kind :: enum {
	Id,   // operations, peers   — system/capability/id-scope
	Path, // handlers, resources — system/capability/path-scope
}

// §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard forms
// — bare "*" and a trailing slash-star segment-prefix. None of the §5.4 path transforms
// apply, so a pattern carrying path syntax is matched as a literal string: a non-match,
// never a fault.
matches_id_pattern :: proc(value: string, pattern: string) -> bool {
	if pattern == "*" {
		return true
	}
	if len(pattern) >= 2 && pattern[len(pattern) - 2:] == "/*" {
		prefix := pattern[:len(pattern) - 1]
		return len(value) >= len(prefix) && value[:len(prefix)] == prefix
	}
	return value == pattern
}

@(private = "file")
covered_id :: proc(value: string, pats: []string) -> bool {
	for p in pats {
		if matches_id_pattern(value, p) {
			return true
		}
	}
	return false
}

@(private = "file")
matches_scope :: proc(local_peer: string, value: string, s: Scope, kind: Scope_Kind) -> bool {
	// SCOPED TO PATH-SCOPE (0.8.2.24). §5.2's exclude loop tests the sentinel INSIDE
	// `if dimension_type == "system/capability/path-scope"`, and §5.4 scopes its own
	// invalid-capability rule the same way. `kind` already names the dimension here, so
	// the scoping costs one term and cannot be got wrong by a new call site.
	if kind == .Path && exclude_unmatchable(local_peer, s.excl) {
		return false // 0.8.2.21 -- deny, do not carve out nothing
	}
	if kind == .Id {
		return covered_id(value, s.incl) && !covered_id(value, s.excl)
	}
	cv := canonicalize(local_peer, value)
	if !covered(local_peer, cv, s.incl) {
		return false
	}
	return !covered(local_peer, cv, s.excl)
}

// ── §5.2 check_permission ─────────────────────────────────────────────────────

@(private = "file")
first_segment :: proc(uri: string) -> string {
	u := uri
	if strings.has_prefix(u, "/") {
		u = u[1:]
	}
	i := strings.index_byte(u, '/')
	if i < 0 {
		return u
	}
	return u[:i]
}

extract_peer :: proc(local_peer: string, uri: string) -> string {
	first := first_segment(normalize_uri(uri))
	if is_peer_id(first) {
		return first
	}
	return local_peer
}

@(private = "file")
check_resource_scope :: proc(
	local_peer: string,
	granter_peer: string,
	resource: Ec_Value,
	s: Scope,
) -> bool {
	tv, th := map_get(resource, "targets")
	ev, eh := map_get(resource, "exclude")
	targets := text_list(tv, th)
	caller_excl := text_list(ev, eh)
	if len(targets) == 0 {
		return false
	}
	// An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
	// target: the coverage test below is correct in isolation and is simply never
	// reached on a sentinel, because matches_pattern answers false.
	//
	// UNGUARDED ON PURPOSE, unlike matches_scope's (0.8.2.24): `s` here is ALWAYS the
	// RESOURCES dimension, which §5.2 fixes as path-scope, so the type test that call
	// site performs would be a constant here. The single-dimension signature is what
	// makes that checkable -- a granter frame reaching an id-scope call site is the
	// defect, and this procedure cannot be one.
	if exclude_unmatchable(granter_peer, s.excl) {
		return false
	}
	for tgt in targets {
		ct := canonicalize(local_peer, tgt)
		if covered(local_peer, ct, caller_excl) {
			continue // caller excluded (local frame)
		}
		if !covered(granter_peer, ct, s.incl) {
			return false // not in grant include (granter frame)
		}
		if covered(granter_peer, ct, s.excl) {
			return false // in grant exclude → deny
		}
	}
	return true
}

// check_permission gates the wire request at the dispatch authorization boundary
// (§5.2 / §3.2.3). `granter_peer` is the canonicalization frame for the cap's
// grant resource patterns; every other dimension stays on the local frame.
check_permission :: proc(
	local_peer: string,
	granter_peer: string,
	exec: Entity,
	token: Entity,
	handler_pattern: string,
) -> Verdict {
	operation, _ := entity_text(exec, "operation")
	uri, _ := entity_text(exec, "uri")
	target_peer := extract_peer(local_peer, uri)
	resource, has_resource := entity_field(exec, "resource")
	grants := grants_of_token(token)
	for g in grants {
		if !matches_scope(local_peer, operation, g.operations, .Id) {
			continue
		}
		if !matches_scope(local_peer, handler_pattern, g.handlers, .Path) {
			continue
		}
		peers := g.peers
		if !g.has_peers {
			peers = Scope{incl = {local_peer}, excl = {}}
		}
		if !matches_scope(local_peer, target_peer, peers, .Id) {
			continue
		}
		r_ok := true
		if has_resource {
			r_ok = check_resource_scope(local_peer, granter_peer, resource, g.resources)
		}
		if r_ok {
			return .Allow
		}
	}
	return .Deny
}

// ── §3.3 effective targets + §6.3 check_path_permission ───────────────────────

// §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude` removes
// entries from `resource.targets` BEFORE anything else looks at the request.
//
// The survivors come back in the caller's OWN SPELLING, not canonicalized -- 0.8.2.21
// is explicit that effective_targets yields raw survivors, and the distinction is
// load-bearing because the value flows on to the store lookup, which canonicalizes for
// itself.
//
// THE SECOND RETURN IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11):
// "where an implementation projects resource.targets onto the effective set ahead of the
// handler, that projection MUST NOT be lossy about its own emptiness -- narrow when
// narrowing leaves something, and retain the raw pair when narrowing would empty it."
// A procedure returning only a list cannot satisfy that: collapsing `[qA] exclude [qA]`
// to `[]` deletes the two-empties discriminator before any handler can read it, and the
// handler's refusal arm becomes dead code that only a WIRE drive can detect. An ABSENT
// `resource` and a resource whose every target was excluded are DIFFERENT REQUESTS for
// a resource-OPTIONAL operation (0.8.2.24, N7), not merely different inputs to one
// disposition.
//
// "Every seam that narrows is exempted alike, inbound-wire and in-process sub-dispatch,
// or one request receives two different answers according to which door it arrived
// through." This peer has exactly ONE narrowing seam -- this procedure, called by the
// tree handler -- and §6.5's dispatch chain does not project: dispatch_outcome passes
// `exec` through untouched and check_permission reads `resource` for itself. So there is
// no second door to keep in step, and adding a projection at dispatch would create one.
//
// A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list.
// Reporting it absent would serve the WIDER absent-case answer to a request that named a
// resource, which is N11's own defect one field over.
//
// The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules it
// separately from the grant arm) and that is INHERITED here rather than restated:
// canonicalize answers the sentinel, matches_pattern then answers false, and the target
// simply survives.
//
// Allocated on context.temp_allocator, like every other per-dispatch value in this peer:
// the caller resets the arena after the response is sent, so there is nothing to free
// and no ownership to transfer.
effective_targets :: proc(local_peer: string, exec: Entity) -> (survivors: []string, had_resource: bool) {
	r, has_r := entity_field(exec, "resource")
	if !has_r {
		return {}, false
	}
	tv, has_t := map_get(r, "targets")
	if !has_t {
		return {}, false
	}
	ev, has_e := map_get(r, "exclude")
	targets := text_list(tv, has_t)
	caller_excl := text_list(ev, has_e)
	out := make([dynamic]string, context.temp_allocator)
	for t in targets {
		ct := canonicalize(local_peer, t)
		dropped := false
		for x in caller_excl {
			if matches_pattern(ct, canonicalize(local_peer, x)) {
				dropped = true
				break
			}
		}
		if !dropped {
			append(&out, t)
		}
	}
	return out[:], true
}

// §6.3's handler-level path check: may the caller access `path` AS A TREE PATH, under
// `handler_pattern`, with `token`?
//
// IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
// subject is derived after dispatch, and the dispatch-level check can be made VACUOUS by
// caller-controlled input: a caller who excludes the one target its capability does not
// cover removes that target from check_permission's view entirely, and a handler that
// then acts on it has authorized nothing.
//
// THREE DIMENSIONS, NOT FOUR. `peers` is not consulted -- the path is local by
// construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
// step 3, before any handler runs), and §6.3's signature names only handlers, operations
// and resources.
//
// THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
// rather than a choice: §6.3's block reads
// `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)` -- there
// is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the subject is
// a pattern compared against a parent's pattern; this call site compares a CONCRETE local
// path the handler is about to touch.
//
// Scope types: handlers -> path-scope, operations -> id-scope, resources -> path-scope.
// An empty `resources.include` is a legal grant shape (§5.2: handlers that touch no tree
// paths) and DENIES every path here, which is what that note says it should -- `covered`
// over an empty include list is false. A malformed path canonicalizes to NEVER_MATCH,
// which matches no grant, so it falls through to DENY rather than being matched against
// anything.
check_path_permission :: proc(
	local_peer: string,
	operation: string,
	path: string,
	token: Entity,
	handler_pattern: string,
) -> bool {
	for g in grants_of_token(token) {
		if !matches_scope(local_peer, handler_pattern, g.handlers, .Path) {
			continue
		}
		if !matches_scope(local_peer, operation, g.operations, .Id) {
			continue
		}
		if !matches_scope(local_peer, path, g.resources, .Path) {
			continue
		}
		return true
	}
	return false
}

// ── §5.5 / §5.6 chain verification + attenuation ──────────────────────────────

// temporal_fields_representable reports whether every CAP-6a temporal field on a
// RECEIVED token is either absent (legal) or representable as a u64.
//
// This is the reader-side half of CAP-6 and it is where a peer fails OPEN.
// entity_uint returns (0, false) BOTH when a field is ABSENT and when it is PRESENT
// but not an Ec_Uint -- a negative integer or a bignum -- so a token carrying
// expires_at:-1 silently skipped the expiry check and was honored with 200. §6.2
// CAP-6a is explicit: such a token "is malformed. A verifier MUST refuse it and MUST
// NOT treat the unrepresentable field as absent." An absent expires_at stays legal
// and is deliberately NOT rejected here.
//
// Refusal must be the §5.2 capability_denied disposition (a status-bearing response),
// never a decode-layer silent drop or a transport close.
temporal_fields_representable :: proc(tok: Entity) -> bool {
	for key in ([]string{"expires_at", "not_before", "created_at"}) {
		v, present := map_get(tok.data, key)
		if !present {
			continue // absent is legal
		}
		if _, is_uint := v.(Ec_Uint); !is_uint {
			return false // present but not a u64 => malformed
		}
	}
	return true
}

// add_ttl converts a DURATION term to an absolute timestamp, reporting whether it
// contributes a ceiling at all.
//
// §5.6 rule 3: a term whose conversion created_at+ttl is not representable is treated
// as ABSENT, exactly as a null term is. It MUST NOT wrap and MUST NOT saturate to a
// representable maximum -- saturation encodes differently from absence and
// manufactures expires_at == 2^64-1, a finite bound no reader can distinguish from a
// deliberate one.
//
// ttl == 0 is NOT a special case here and deliberately so: §5.6 rule 2 makes 0 a
// DEFINED value yielding created_at (expire immediately). The absent field is the only
// "no bound" spelling, and falling out of the arithmetic is what keeps the two from
// ever collapsing into each other.
add_ttl :: proc(created_at, ttl: u64) -> (u64, bool) {
	sum := created_at + ttl
	if sum < created_at {
		return 0, false // u64 wrap => not representable => drop the term
	}
	return sum, true
}

resolve :: proc(env: Envelope, st: ^Store, h: []u8) -> (Entity, bool) {
	if e, ok := envelope_get(env, h); ok {
		return e, true
	}
	return store_get_by_hash(st, h)
}

find_signature :: proc(env: Envelope, target: []u8) -> (Entity, bool) {
	for inc in env.included {
		e := inc.entity
		if e.typ == "system/signature" {
			if t, ok := entity_bytes(e, "target"); ok {
				if slice.equal(t, target) {
					return e, true
				}
			}
		}
	}
	return Entity{}, false
}

@(private = "file")
link_granter_peer :: proc(
	env: Envelope,
	st: ^Store,
	local_peer: string,
	cap: Entity,
) -> (string, bool) {
	gh, has_g := entity_bytes(cap, "granter")
	if !has_g {
		return local_peer, true // multi-sig root → local frame
	}
	g, ok := resolve(env, st, gh)
	if !ok {
		return "", false
	}
	pk, has_pk := entity_bytes(g, "public_key")
	if !has_pk {
		return "", false
	}
	return peer_id_of_pubkey(pk, context.temp_allocator), true
}

// §5.5a/§5.6 subset check: every child include must be covered by some parent include,
// and every parent exclude must be inherited by some child exclude.
//
// TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; entity-core-formalization K-7).
// §3.6's id-scope grammar binds the scope TYPE, not one function -- "An implementation
// on the canonicalizing reading is non-conformant and MUST adopt the literal matcher" --
// so the rule F40 landed on matches_scope reaches here too, with delegation-chain
// WIDENING named as the reason: on the canonicalizing reading a bare id include reads as
// covered by a path-form parent pattern it does not literally match, and a child grant
// comes out wider than its parent. `lean`'s differential put it at 2 of 64 include pairs
// and 2 of 64 exclude pairs, fail-closed, with a 16-pair control alphabet reporting 0 --
// which is why every hand-tried example missed it.
//
// `kind` has NO DEFAULT and is named at every call site, because a default is how the
// next dimension inherits the wrong matcher silently -- the original F40 defect. The
// per-link granter frames are meaningless on the id arm (an id pattern is never
// canonicalized) and are simply unread there.
@(private = "file")
scope_subset :: proc(child_peer, parent_peer: string, child, parent: Scope, kind: Scope_Kind) -> bool {
	frame :: proc(kind: Scope_Kind, pattern, peer: string) -> string {
		return kind == .Path ? canonicalize(peer, pattern) : pattern
	}
	covers :: proc(kind: Scope_Kind, pattern, value: string) -> bool {
		return kind == .Path ? matches_pattern(value, pattern) : matches_id_pattern(value, pattern)
	}
	for cp in child.incl {
		cc := frame(kind, cp, child_peer)
		found := false
		for pp in parent.incl {
			if covers(kind, frame(kind, pp, parent_peer), cc) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for pe in parent.excl {
		cpe := frame(kind, pe, parent_peer)
		found := false
		for ce in child.excl {
			if covers(kind, frame(kind, ce, child_peer), cpe) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

@(private = "file")
grant_subset :: proc(local_peer, child_peer, parent_peer: string, child, parent: Grant) -> bool {
	// §5.5a: only the RESOURCE dimension uses the per-link granter frames; the other
	// dimensions stay on the local frame. The scope KIND is a property of the DIMENSION
	// and is named at every call site, never defaulted (F50 / 0.8.2.16).
	if !scope_subset(local_peer, local_peer, child.handlers, parent.handlers, .Path) {
		return false
	}
	if !scope_subset(local_peer, local_peer, child.operations, parent.operations, .Id) {
		return false
	}
	if !scope_subset(child_peer, parent_peer, child.resources, parent.resources, .Path) {
		return false
	}
	cp := child.peers
	if !child.has_peers {
		cp = Scope{incl = {local_peer}, excl = {}}
	}
	pp := parent.peers
	if !parent.has_peers {
		pp = Scope{incl = {local_peer}, excl = {}}
	}
	return scope_subset(local_peer, local_peer, cp, pp, .Id)
}

@(private = "file")
is_attenuated :: proc(local_peer, child_peer, parent_peer: string, child, parent: Entity) -> bool {
	cg := grants_of_token(child)
	pg := grants_of_token(parent)
	for c in cg {
		ok := false
		for p in pg {
			if grant_subset(local_peer, child_peer, parent_peer, c, p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	pe, has_pe := entity_uint(parent, "expires_at")
	ce, has_ce := entity_uint(child, "expires_at")
	if has_pe && !has_ce {
		return false // child infinite, parent finite
	}
	if has_pe && has_ce && ce > pe {
		return false
	}
	return true
}

@(private = "file")
check_delegation_caveats :: proc(parent, child: Entity, depth: u64) -> bool {
	caveats, has := entity_field(parent, "delegation_caveats")
	if !has {
		return true
	}
	if v, ok := map_get(caveats, "no_delegation"); ok {
		if b, is_b := v.(Ec_Bool); is_b && bool(b) {
			return false
		}
	}
	if v, ok := map_get(caveats, "max_delegation_depth"); ok {
		if m, is_u := v.(Ec_Uint); is_u && depth >= u64(m) {
			return false
		}
	}
	if v, ok := map_get(caveats, "max_delegation_ttl"); ok {
		if maxttl, is_u := v.(Ec_Uint); is_u {
			ex, has_ex := entity_uint(child, "expires_at")
			cr, has_cr := entity_uint(child, "created_at")
			if has_ex {
				if has_cr && ex - cr > u64(maxttl) {
					return false
				}
			} else {
				return false // infinite child lifetime exceeds any finite limit
			}
		}
	}
	return true
}

now_ms :: proc() -> u64 {
	return u64(time.to_unix_nanoseconds(time.now()) / 1_000_000)
}

// collect_chain walks parent pointers. Returns (chain, too_deep, unreachable).
@(private = "file")
collect_chain :: proc(env: Envelope, st: ^Store, cap: Entity) -> ([]Entity, bool, bool) {
	chain := make([dynamic]Entity, context.temp_allocator)
	current := cap
	depth := 0
	for {
		if depth > MAX_CHAIN_DEPTH {
			return nil, true, false
		}
		append(&chain, current)
		ph, has_p := entity_bytes(current, "parent")
		if !has_p {
			return chain[:], false, false
		}
		next, ok := resolve(env, st, ph)
		if !ok {
			return nil, false, true
		}
		current = next
		depth += 1
	}
}

// chain_exceeds_depth (§4.10(b)) — structural pre-check: true if the authority
// chain rooted at `cap` exceeds MAX_CHAIN_DEPTH. Walks parent pointers WITHOUT
// verifying signatures — depth is a purely structural property, gated BEFORE the
// per-link authz walk so an over-deep chain reports 400 chain_depth_exceeded
// (distinct from 403). An UNREACHABLE parent is NOT a depth problem — returns
// false here, left for verify_capability_chain to deny (403).
chain_exceeds_depth :: proc(env: Envelope, st: ^Store, cap: Entity) -> bool {
	current := cap
	depth := 0
	for {
		if depth > MAX_CHAIN_DEPTH {
			return true
		}
		ph, has_p := entity_bytes(current, "parent")
		if !has_p {
			return false // root within bound
		}
		next, ok := resolve(env, st, ph)
		if !ok {
			return false // unreachable — not a depth problem
		}
		current = next
		depth += 1
	}
}

// ── §3.6 M3 multi-signature granter ───────────────────────────────────────────

Multi_Granter :: struct {
	signers:   [][]u8,
	threshold: u64,
}

@(private = "file")
multi_granter_of :: proc(cap: Entity) -> (Multi_Granter, bool) {
	g, has := entity_field(cap, "granter")
	if !has {
		return Multi_Granter{}, false
	}
	m, is_map := g.(Ec_Map)
	if !is_map {
		return Multi_Granter{}, false // bytes (single-sig) or other
	}
	_ = m
	sv, sh := map_get(g, "signers")
	signers := bytes_list(sv, sh)
	threshold: u64 = 0
	if tv, th := map_get(g, "threshold"); th {
		if t, ok := tv.(Ec_Uint); ok {
			threshold = u64(t)
		}
	}
	return Multi_Granter{signers = signers, threshold = threshold}, true
}

@(private = "file")
has_duplicate_signers :: proc(signers: [][]u8) -> bool {
	for i in 0 ..< len(signers) {
		for j in i + 1 ..< len(signers) {
			if slice.equal(signers[i], signers[j]) {
				return true
			}
		}
	}
	return false
}

@(private = "file")
signer_peer_id :: proc(env: Envelope, st: ^Store, h: []u8) -> (string, bool) {
	p, ok := resolve(env, st, h)
	if !ok {
		return "", false
	}
	pk, has_pk := entity_bytes(p, "public_key")
	if !has_pk {
		return "", false
	}
	return peer_id_of_pubkey(pk, context.temp_allocator), true
}

// verify_multisig_root (§3.6 M3 / §5.5 M4·M6). ALLOW only if the quorum is
// well-formed AND a threshold of DISTINCT signers signed the cap's content hash.
// Structural validation (M3) precedes signature counting: a malformed quorum is
// denied on its structure. Every path returns deny → dispatcher maps to 403.
@(private = "file")
verify_multisig_root :: proc(
	env: Envelope,
	st: ^Store,
	local_peer: string,
	cap: Entity,
	mg: Multi_Granter,
) -> Verdict {
	n := len(mg.signers)
	// §3.6 M3 structure (BEFORE signatures) — root-only; real quorum (n >= 2);
	// usable threshold (2 <= threshold <= n); distinct signers.
	if _, has_parent := entity_bytes(cap, "parent"); has_parent {
		return .Deny // multi-sig is root-only
	}
	if n < 2 {
		return .Deny
	}
	if mg.threshold < 2 || mg.threshold > u64(n) {
		return .Deny
	}
	if has_duplicate_signers(mg.signers) {
		return .Deny
	}

	// §5.5 M6 root-at-local — the local peer MUST be a quorum member.
	local_in_quorum := false
	for s in mg.signers {
		if pid, ok := signer_peer_id(env, st, s); ok {
			if pid == local_peer {
				local_in_quorum = true
				break
			}
		}
	}
	if !local_in_quorum {
		return .Deny
	}

	// temporal validity + grantee resolution.
	t := now_ms()
	if nb, ok := entity_uint(cap, "not_before"); ok && t < nb {
		return .Deny
	}
	if ex, ok := entity_uint(cap, "expires_at"); ok && ex < t {
		return .Deny
	}
	grantee, has_grantee := entity_bytes(cap, "grantee")
	if !has_grantee {
		return .Deny
	}
	if _, ok := resolve(env, st, grantee); !ok {
		return .Deny
	}

	// §5.5 M4 k-of-n — count DISTINCT signers with a valid signature over the
	// cap's content hash; >= threshold ⇒ quorum. A duplicate signature from one
	// signer does NOT inflate the count.
	valid := make([dynamic][]u8, context.temp_allocator)
	for s in mg.signers {
		already := false
		for v in valid {
			if slice.equal(v, s) {
				already = true
				break
			}
		}
		if already {
			continue
		}
		signer_peer, sok := resolve(env, st, s)
		if !sok {
			continue
		}
		for inc in env.included {
			sgn := inc.entity
			if sgn.typ != "system/signature" {
				continue
			}
			tgt, ht := entity_bytes(sgn, "target")
			if !ht || !slice.equal(tgt, cap.hash) {
				continue
			}
			sg, hsg := entity_bytes(sgn, "signer")
			if !hsg || !slice.equal(sg, s) {
				continue
			}
			if verify_signature(sgn, signer_peer) {
				append(&valid, s)
				break
			}
		}
	}
	if u64(len(valid)) >= mg.threshold {
		return .Allow
	}
	return .Deny
}

// verify_capability_chain (§5.5). A single-sig root roots at the local peer; a
// §3.6 M3 multi-sig root (root-only) passes k-of-n quorum. Returns
// allow/deny/unresolvable — the third surfaces the §5.5 401 carve-out.
@(private = "file")
verify_capability_chain :: proc(
	env: Envelope,
	st: ^Store,
	local_peer: string,
	capability: Entity,
) -> Req_Verdict {
	return verify_capability_chain_rooted_at(env, st, local_peer, local_peer, capability)
}

// `verify_capability_chain` with the expected ROOT granter named separately from the
// verifying peer.
//
// §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is minted by
// the TARGET peer, so root-trust is relaxed away from the local peer — and every other
// clause (per-link signatures, grantee resolution, temporal validity, attenuation,
// caveats) is unchanged. Parameterized rather than forked because a second copy of a chain
// walk is a second copy that drifts.
//
// A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When `root_peer`
// differs from `local_peer` the quorum arm is REFUSED outright rather than verified:
// *minted by the target* means the target SOLELY minted it, and a K-of-N root is a GROUP's
// authority — its co-signers authorized it too. Accepting it would let any one signer's
// target confer the whole group's grant, which is E3/F66's over-acceptance. §5.5's M6 also
// requires the LOCAL peer in the signer set, so the quorum arm has no meaning in a foreign
// frame even on its own terms.
verify_capability_chain_rooted_at :: proc(
	env: Envelope,
	st: ^Store,
	local_peer: string,
	root_peer: string,
	capability: Entity,
) -> Req_Verdict {
	chain, too_deep, unreachable := collect_chain(env, st, capability)
	if too_deep || unreachable {
		return .Authz_Deny
	}
	root := chain[len(chain) - 1]
	// Root authority.
	root_ok := false
	if mg, is_multi := multi_granter_of(root); is_multi {
		root_ok = root_peer == local_peer &&
			verify_multisig_root(env, st, local_peer, root, mg) == .Allow
	} else if gh, has_g := entity_bytes(root, "granter"); has_g {
		if g, ok := resolve(env, st, gh); ok {
			if pk, has_pk := entity_bytes(g, "public_key"); has_pk {
				pid := peer_id_of_pubkey(pk, context.temp_allocator)
				root_ok = pid == root_peer
			}
		}
	}
	if !root_ok {
		return .Authz_Deny
	}

	n := len(chain)
	t := now_ms()
	for current, i in chain {
		// §3.6 M3 multi-sig is root-only and fully verified above. A multi-sig
		// token anywhere but the root is rejected.
		if _, is_multi := multi_granter_of(current); is_multi {
			if i != n - 1 {
				return .Authz_Deny
			}
			continue
		}
		// signature: signer == granter, verify against granter identity
		gh, has_gh := entity_bytes(current, "granter")
		if !has_gh {
			return .Authz_Deny
		}
		sgn, has_sgn := find_signature(env, current.hash)
		if !has_sgn {
			return .Authz_Deny
		}
		granter, has_granter := resolve(env, st, gh)
		if !has_granter {
			return .Authz_Deny
		}
		signer_ok := false
		if s, hs := entity_bytes(sgn, "signer"); hs {
			signer_ok = slice.equal(s, gh)
		}
		if !(signer_ok && verify_signature(sgn, granter)) {
			return .Authz_Deny
		}
		// grantee resolution → 401 carve-out
		grantee, has_grantee := entity_bytes(current, "grantee")
		if !has_grantee {
			return .Unresolvable_Grantee
		}
		if _, ok := resolve(env, st, grantee); !ok {
			return .Unresolvable_Grantee
		}
		// temporal validity.
		//
		// CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
		// created_at is MALFORMED and must be refused outright. This has to run
		// BEFORE the two range checks below, because those use entity_uint, which
		// cannot tell "absent" from "present but not an Ec_Uint" -- so on its own it
		// would skip the check and honor the token (fail-open).
		if !temporal_fields_representable(current) {
			return .Authz_Deny
		}
		if nb, ok := entity_uint(current, "not_before"); ok && t < nb {
			return .Authz_Deny
		}
		if ex, ok := entity_uint(current, "expires_at"); ok && ex < t {
			return .Authz_Deny
		}
		// delegation link
		if i < n - 1 {
			parent := chain[i + 1]
			child_peer, cok := link_granter_peer(env, st, local_peer, current)
			if !cok {
				return .Authz_Deny
			}
			parent_peer, pok := link_granter_peer(env, st, local_peer, parent)
			if !pok {
				return .Authz_Deny
			}
			pg, has_pg := entity_bytes(parent, "grantee")
			cg, has_cg := entity_bytes(current, "granter")
			if !has_pg || !has_cg || !slice.equal(pg, cg) {
				return .Authz_Deny
			}
			if !is_attenuated(local_peer, child_peer, parent_peer, current, parent) {
				return .Authz_Deny
			}
			if !check_delegation_caveats(parent, current, u64(i)) {
				return .Authz_Deny
			}
		}
	}
	return .Allow
}

// is_revoked (§5.1) — marker check at the revocations path; covers leaf + root.
@(private = "file")
is_revoked :: proc(env: Envelope, st: ^Store, local_peer: string, capability: Entity) -> bool {
	root_hash := capability.hash
	if chain, too_deep, unreachable := collect_chain(env, st, capability);
	   !too_deep && !unreachable && len(chain) > 0 {
		root_hash = chain[len(chain) - 1].hash
	}
	check :: proc(st: ^Store, lp: string, h: []u8) -> bool {
		hex := hex_of(h, context.temp_allocator)
		path := strings.concatenate(
			{"/", lp, "/system/capability/revocations/", hex},
			context.temp_allocator,
		)
		_, ok := store_get_at(st, path)
		return ok
	}
	return check(st, local_peer, capability.hash) || check(st, local_peer, root_hash)
}

// verify_request (§5.2) — 3-way authn/authz verdict (§4.6). Runs on
// context.temp_allocator; caller resets it after dispatch.
verify_request :: proc(env: Envelope, st: ^Store, local_peer: string) -> Req_Verdict {
	exec := env.root
	// 1. content hash validated on parse (entity_of_cbor).
	// 2. signature / author — authentication class (§4.6 → 401).
	sgn, has_sgn := find_signature(env, exec.hash)
	if !has_sgn {
		return .Authn_Fail
	}
	author_h, has_author := entity_bytes(exec, "author")
	signer_ok := false
	if s, hs := entity_bytes(sgn, "signer"); hs && has_author {
		signer_ok = slice.equal(s, author_h)
	}
	if !signer_ok {
		return .Authn_Fail
	}
	author, has_a := envelope_get(env, author_h)
	if !has_a {
		return .Authn_Fail
	}
	if !verify_signature(sgn, author) {
		return .Authn_Fail
	}
	// 3. capability / chain — authorization class (→ 403).
	cap_h, has_cap := entity_bytes(exec, "capability")
	if !has_cap {
		return .Authz_Deny
	}
	capability, has_cap_e := envelope_get(env, cap_h)
	if !has_cap_e {
		return .Authz_Deny
	}
	// §4.10(b): a chain exceeding max depth → 400 chain_depth_exceeded (structural
	// excess) BEFORE the per-link authz walk.
	if chain_exceeds_depth(env, st, capability) {
		return .Chain_Too_Deep
	}
	chain_verdict := verify_capability_chain(env, st, local_peer, capability)
	if chain_verdict == .Unresolvable_Grantee {
		return .Unresolvable_Grantee
	}
	if chain_verdict != .Allow {
		return .Authz_Deny
	}
	// §5.2 grantee == author.
	grantee_ok := false
	if g, hg := entity_bytes(capability, "grantee"); hg && has_author {
		grantee_ok = slice.equal(g, author_h)
	}
	if !grantee_ok {
		return .Authz_Deny
	}
	if is_revoked(env, st, local_peer, capability) {
		return .Authz_Deny
	}
	return .Allow
}

// granter_frame resolves the granter frame for a leaf cap at the dispatch site;
// falls back to the local peer for an unresolvable/multisig granter.
granter_frame :: proc(env: Envelope, st: ^Store, local_peer: string, cap: Entity) -> string {
	gh, has_g := entity_bytes(cap, "granter")
	if !has_g {
		return local_peer
	}
	g, ok := resolve(env, st, gh)
	if !ok {
		return local_peer
	}
	pk, has_pk := entity_bytes(g, "public_key")
	if !has_pk {
		return local_peer
	}
	return peer_id_of_pubkey(pk, context.temp_allocator)
}

// ── §6.2 mint-time local-frame subset (child=parent=local) ────────────────────

grant_subset_local :: proc(local_peer: string, child, parent: Grant) -> bool {
	return grant_subset(local_peer, local_peer, local_peer, child, parent)
}

// parse_grant_public exposes the (file-private) grant parser to the peer layer's
// mint-time subset check (§6.2). Borrows into the Ec_Value tree.
parse_grant_public :: proc(v: Ec_Value) -> Grant {
	return parse_grant(v)
}

// verify_capability_chain_public exposes the chain verifier to the accept-path
// unit tests (the multisig K-of-N direction the oracle can't cover). Returns the
// 3-way verdict; a caller maps .Allow → allow, else deny.
verify_capability_chain_public :: proc(
	env: Envelope,
	st: ^Store,
	local_peer: string,
	capability: Entity,
) -> Req_Verdict {
	return verify_capability_chain(env, st, local_peer, capability)
}


// ── §1.4 PD-2: outbound sub-dispatch authorization ───────────────────────────

// Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
//
// §1.4 admits three spellings of one address — `system/tree`, `/{peer}/system/tree` and
// `entity://{peer}/system/tree` — and §1.4's PD-2 block requires Dimension 1's handler
// pattern to be the target uri's peer-relative path, because a grant names HANDLERS and a
// handler pattern never carries a peer segment. Matching a grant against the absolute or
// schemed form matches nothing, silently, which reads at the wire as an authority refusal.
//
// The first segment is dropped ONLY when it is a peer_id. A peer-relative
// `system/protocol/connect` must not lose `system` — the standing defect on `smalltalk`
// and `forth`, where an unconditional strip made every self-minted grant unusable while
// the handshake stayed green.
peer_relative_of :: proc(uri: string) -> string {
	p := normalize_uri(uri)
	if len(p) == 0 || p[0] != '/' {
		return p
	}
	body := p[1:]
	slash := strings.index_byte(body, '/')
	first := slash < 0 ? body : body[:slash]
	if !is_peer_id(first) {
		return body
	}
	return slash < 0 ? "" : body[slash + 1:]
}

// Store key of a handler's OWN grant (§6.8: `system/capability/grants/{pattern}`),
// tolerant of the pattern arriving absolute or peer-relative.
//
// §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while the
// grant path is built from the PEER-RELATIVE one. The two are one segment apart and
// concatenating the wrong one yields a doubled peer segment whose lookup misses — which
// fails closed as "no handler grant" and is indistinguishable, at the wire, from a genuine
// authority refusal.
grant_path_for :: proc(local_peer, pattern: string, a: mem.Allocator) -> string {
	prefix := strings.concatenate({"/", local_peer, "/"}, a)
	rel := strings.has_prefix(pattern, prefix) ? pattern[len(prefix):] : pattern
	return strings.concatenate({"/", local_peer, "/system/capability/grants/", rel}, a)
}

// Verify a presented reentry credential against §1.4's clauses. Answers
// `(verified, scope, has_scope)`: `verified` is "did every clause hold"; `has_scope` false
// with `verified` true means "the target itself" (an absent `peers` dimension is the
// ordinary reentry shape: "you may dispatch back to me").
//
// THE TRIPLE IS THE POINT. A missing scope is a legitimate RESULT, so a lone Scope return
// would collapse it into "relaxes nothing" — the absent-vs-present conflation §6.2's
// CAP-6a records for temporal accessors, one layer up and in the direction that REFUSES a
// valid reentry.
//
// Every clause is required: the chain ROOT granter resolves to the TARGET peer and is NOT
// a multi-signature root; the LEAF grantee is the local peer; the chain is valid and not
// revoked.
target_minted_peers_relaxation :: proc(
	env: Envelope,
	st: ^Store,
	local_peer, target_peer: string,
	cred: Entity,
) -> (verified: bool, scope: Scope, has_scope: bool) {
	// Nothing to relax — the default already covers this peer.
	if target_peer == local_peer {
		return false, Scope{}, false
	}
	if verify_capability_chain_rooted_at(env, st, local_peer, target_peer, cred) != .Allow {
		return false, Scope{}, false
	}
	if is_revoked(env, st, local_peer, cred) {
		return false, Scope{}, false
	}
	gh, has_gh := entity_bytes(cred, "grantee")
	if !has_gh {
		return false, Scope{}, false
	}
	ge, ok := resolve(env, st, gh)
	if !ok {
		return false, Scope{}, false
	}
	pk, has_pk := entity_bytes(ge, "public_key")
	if !has_pk || peer_id_of_pubkey(pk, context.temp_allocator) != local_peer {
		return false, Scope{}, false
	}
	gs := grants_of_token(cred)
	if len(gs) == 0 {
		return false, Scope{}, false
	}
	return true, gs[0].peers, gs[0].has_peers
}

// §1.4's PD-2 gate: `check_permission` run before a locally-originated sub-dispatch LEAVES
// the peer, with all four dimensions applied.
//
// ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT decides
// all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's pattern the
// target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE TARGET PEER naming
// this peer as `grantee` relaxes Dimension 4 (`peers`) AND ONLY DIMENSION 4.
//
// *"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT a
// grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
// sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
// BYPASS it is distinguished from is a peer that treats the credential as a standalone
// authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
// obvious vectors agree under either reading, so the only input that separates them is a
// VALID credential presented to a handler whose own grant does NOT cover the request.
//
// `have_relax` false is the ambient arm: Dimension 4 is decided by the grant alone.
check_outbound_sub_dispatch :: proc(
	local_peer, target_peer, handler_pattern, operation: string,
	handler_grant: Entity,
	resource: Ec_Value,
	have_relax: bool,
	relax_scope: Scope,
	relax_has_scope: bool,
) -> bool {
	for g in grants_of_token(handler_grant) {
		if !matches_scope(local_peer, handler_pattern, g.handlers, .Path) {
			continue
		}
		if !matches_scope(local_peer, operation, g.operations, .Id) {
			continue
		}
		if !check_resource_scope(local_peer, local_peer, resource, g.resources) {
			continue
		}
		// Dimension 4. §5.2's default for an absent `peers` scope is
		// {include: [local_peer_id]}, so a foreign target fails unless this grant names it
		// or a target-minted credential relaxes it.
		peers := g.peers
		if !g.has_peers {
			one := make([]string, 1, context.temp_allocator)
			one[0] = local_peer
			peers = Scope{incl = one, excl = {}}
		}
		if matches_scope(local_peer, target_peer, peers, .Id) {
			return true
		}
		if have_relax {
			if !relax_has_scope {
				return true // absent `peers` on the credential relaxes to the granter
			}
			if matches_scope(local_peer, target_peer, relax_scope, .Id) {
				return true
			}
		}
	}
	return false
}
