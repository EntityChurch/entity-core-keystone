package entity_core

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
canonicalize :: proc(local_peer: string, path: string) -> string {
	if strings.has_prefix(path, "/") {
		return path
	}
	return strings.concatenate({"/", local_peer, "/", path}, context.temp_allocator)
}

// matches_pattern — both path and pattern MUST already be canonical (absolute).
matches_pattern :: proc(path, pattern: string) -> bool {
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

// ── §5.5 / §5.6 chain verification + attenuation ──────────────────────────────

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

@(private = "file")
scope_subset :: proc(child_peer, parent_peer: string, child, parent: Scope) -> bool {
	for cp in child.incl {
		cc := canonicalize(child_peer, cp)
		found := false
		for pp in parent.incl {
			if matches_pattern(cc, canonicalize(parent_peer, pp)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for pe in parent.excl {
		cpe := canonicalize(parent_peer, pe)
		found := false
		for ce in child.excl {
			if matches_pattern(cpe, canonicalize(child_peer, ce)) {
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
	if !scope_subset(local_peer, local_peer, child.handlers, parent.handlers) {
		return false
	}
	if !scope_subset(local_peer, local_peer, child.operations, parent.operations) {
		return false
	}
	if !scope_subset(child_peer, parent_peer, child.resources, parent.resources) {
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
	return scope_subset(local_peer, local_peer, cp, pp)
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
	chain, too_deep, unreachable := collect_chain(env, st, capability)
	if too_deep || unreachable {
		return .Authz_Deny
	}
	root := chain[len(chain) - 1]
	// Root authority.
	root_ok := false
	if mg, is_multi := multi_granter_of(root); is_multi {
		root_ok = verify_multisig_root(env, st, local_peer, root, mg) == .Allow
	} else if gh, has_g := entity_bytes(root, "granter"); has_g {
		if g, ok := resolve(env, st, gh); ok {
			if pk, has_pk := entity_bytes(g, "public_key"); has_pk {
				pid := peer_id_of_pubkey(pk, context.temp_allocator)
				root_ok = pid == local_peer
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
		// temporal validity
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
