package entity_core

import "core:crypto"
import "core:mem"
import "core:slice"
import "core:strings"

// Peer assembly (L1–L4 + foundation) — bootstrap, the MUST system handlers (§6.2:
// tree, handler, capability, type, connect), the dispatch chain (§6.5), per-
// connection state, and the §6.9a peer-authority seed bootstrap.
//
// The handshake (§4.1/§4.6 three-check proof-of-possession), dispatch-chain order
// (verify → resolve → check_permission → handler), §4.4 initial-grant delivery,
// and §6.9a seed-policy authority are derived from the spec. Transport lives in
// transport.odin; this module is the pure protocol brain — a function from an
// inbound envelope to an outbound response envelope plus per-connection state.
//
// No-GC idiom: every dispatch runs against context.temp_allocator (the per-
// request arena — handlers allocate freely; the chain walk's scratch is arena-
// scoped). The final response envelope is deep-cloned into the long-lived
// context.allocator so it outlives the arena reset. The store owns persistent
// entities (it clones on bind). Outcomes carry entities that live in the arena
// until materialized.

Peer :: struct {
	identity:    Identity,
	store:       Store,
	local_peer:  string, // == identity.peer_id (borrowed)
	open_grants: bool,
	conformance: bool,
	// §6.13(b) reentry seam — bound per-connection by the transport reader thread.
	outbound_ctx: rawptr,
	outbound_fn:  Outbound_Fn,
}

Outbound_Fn :: proc(ctx: rawptr, req: Envelope, allocator: mem.Allocator) -> (Envelope, bool)

// Per-connection state (§4.2). One Conn per connection; the reader thread owns it.
Conn :: struct {
	established:   bool,
	issued_nonce:  [32]u8,
	has_nonce:     bool,
	hello_peer_id: string, // owned dup of the initiator's claimed peer_id ("" = none)
	// §6.13(b) reentry seam bound live by the transport reader thread.
	outbound_ctx:  rawptr,
	outbound_fn:   Outbound_Fn,
	out_counter:   u32,
}

conn_destroy :: proc(c: ^Conn, allocator := context.allocator) {
	if c.hello_peer_id != "" {
		delete(c.hello_peer_id, allocator)
	}
}

// An included entity bundle carried in a response (arena-owned during dispatch).
Inc_Item :: struct {
	key:    []u8,
	entity: Entity,
}

// A handler outcome: status, the result entity, and protocol entities to bundle.
// All allocated from the per-request arena (context.temp_allocator).
Outcome :: struct {
	status:   u64,
	result:   Entity,
	included: []Inc_Item,
}

@(private = "file")
ok_out :: proc(result: Entity) -> Outcome {
	return Outcome{status = 200, result = result, included = {}}
}

@(private = "file")
ok_inc :: proc(result: Entity, included: []Inc_Item) -> Outcome {
	return Outcome{status = 200, result = result, included = included}
}

@(private = "file")
err_out :: proc(status: u64, code: string, message: string) -> Outcome {
	e, _ := error_result(code, message, context.temp_allocator)
	return Outcome{status = status, result = e, included = {}}
}

// ── randomness (§4.6 SHOULD >= 32-byte CSPRNG) ────────────────────────────────

@(private = "file")
random_nonce :: proc() -> [32]u8 {
	buf: [32]u8
	crypto.rand_bytes(buf[:])
	return buf
}

// ── grant construction (§4.4 / §5.4) ──────────────────────────────────────────

@(private = "file")
scope_val :: proc(incl: []string, allocator := context.temp_allocator) -> Ec_Value {
	items := make([]Ec_Value, len(incl), allocator)
	for s, i in incl {
		items[i] = text_val(s, allocator)
	}
	pairs := make([]Ec_Pair, 1, allocator)
	pairs[0] = Ec_Pair{text_val("include", allocator), Ec_Array(items)}
	return Ec_Map(pairs)
}

@(private = "file")
grant_val :: proc(
	handlers, resources, operations: []string,
	peers: []string,
	has_peers: bool,
	allocator := context.temp_allocator,
) -> Ec_Value {
	list := make([dynamic]Ec_Pair, allocator)
	append(&list, Ec_Pair{text_val("handlers", allocator), scope_val(handlers, allocator)})
	append(&list, Ec_Pair{text_val("resources", allocator), scope_val(resources, allocator)})
	append(&list, Ec_Pair{text_val("operations", allocator), scope_val(operations, allocator)})
	if has_peers {
		append(&list, Ec_Pair{text_val("peers", allocator), scope_val(peers, allocator)})
	}
	return Ec_Map(list[:])
}

// §4.4 discovery floor: every authenticated identity gets at least this.
@(private = "file")
discovery_floor :: proc(allocator := context.temp_allocator) -> []Ec_Value {
	out := make([]Ec_Value, 2, allocator)
	out[0] = grant_val({"system/tree"}, {"system/type/*", "system/handler/*"}, {"get"}, {}, false, allocator)
	out[1] = grant_val({"system/capability"}, {}, {"request"}, {}, false, allocator)
	return out
}

// The degenerate `default → *` (= --debug-open-grants).
@(private = "file")
open_grants_scope :: proc(allocator := context.temp_allocator) -> []Ec_Value {
	out := make([]Ec_Value, 1, allocator)
	out[0] = grant_val({"*"}, {"*", "/*/*"}, {"*"}, {"*"}, true, allocator)
	return out
}

// Full owner authority over the local namespace (§6.9a).
@(private = "file")
owner_grants :: proc(local_peer: string, allocator := context.temp_allocator) -> []Ec_Value {
	out := make([]Ec_Value, 1, allocator)
	out[0] = grant_val({"*"}, {"*"}, {"*"}, {local_peer}, true, allocator)
	return out
}

// ── token minting (§4.4 / §5.4) ───────────────────────────────────────────────

Minted :: struct {
	token:     Entity,
	signature: Entity,
}

// mint_token mints a capability token granted by us to `grantee_hash`; signs it.
// Both entities allocated from `allocator` (the per-request arena or gpa).
@(private = "file")
mint_token :: proc(
	p: ^Peer,
	grantee_hash: []u8,
	parent: []u8,
	has_parent: bool,
	grants: []Ec_Value,
	allocator := context.temp_allocator,
) -> (Minted, Codec_Error) {
	list := make([dynamic]Ec_Pair, allocator)
	append(&list, Ec_Pair{text_val("granter", allocator), bytes_val(p.identity.identity_hash, allocator)})
	append(&list, Ec_Pair{text_val("grantee", allocator), bytes_val(grantee_hash, allocator)})
	grants_copy := make([]Ec_Value, len(grants), allocator)
	copy(grants_copy, grants)
	append(&list, Ec_Pair{text_val("grants", allocator), Ec_Array(grants_copy)})
	append(&list, Ec_Pair{text_val("created_at", allocator), Ec_Uint(now_ms())})
	if has_parent {
		append(&list, Ec_Pair{text_val("parent", allocator), bytes_val(parent, allocator)})
	}
	token, terr := entity_make("system/capability/token", Ec_Map(list[:]), allocator)
	if terr != .None {
		return Minted{}, terr
	}
	sig, serr := sign_entity(p.identity, token, allocator)
	if serr != .None {
		return Minted{}, serr
	}
	return Minted{token = token, signature = sig}, .None
}

// ── §6.9a seed-policy derivation ──────────────────────────────────────────────

@(private = "file")
derive_seed_grants :: proc(
	p: ^Peer,
	remote_peer: Entity,
	remote_peer_id: string,
	allocator := context.temp_allocator,
) -> []Ec_Value {
	base := strings.concatenate({"/", p.local_peer, "/system/capability/policy/"}, allocator)
	hex := hex_of(remote_peer.hash, allocator)
	entry: Entity
	have_entry := false
	if e, ok := store_get_at(&p.store, strings.concatenate({base, hex}, allocator)); ok {
		entry = e
		have_entry = true
	} else if e, ok := store_get_at(&p.store, strings.concatenate({base, remote_peer_id}, allocator)); ok {
		entry = e
		have_entry = true
	} else if e, ok := store_get_at(&p.store, strings.concatenate({base, "default"}, allocator)); ok {
		entry = e
		have_entry = true
	}
	floor := discovery_floor(allocator)
	policy_grants: []Ec_Value = {}
	if have_entry {
		policy_grants = seed_entry_grants(p, entry, allocator)
	}
	if len(policy_grants) == 0 {
		return floor
	}
	out := make([]Ec_Value, len(floor) + len(policy_grants), allocator)
	copy(out[:len(floor)], floor)
	copy(out[len(floor):], policy_grants)
	return out
}

@(private = "file")
grants_array_of :: proc(ent: Entity, allocator := context.temp_allocator) -> []Ec_Value {
	v, has := entity_field(ent, "grants")
	if !has {
		return {}
	}
	arr, is_arr := v.(Ec_Array)
	if !is_arr {
		return {}
	}
	out := make([]Ec_Value, len(([]Ec_Value)(arr)), allocator)
	copy(out, ([]Ec_Value)(arr))
	return out
}

@(private = "file")
seed_entry_grants :: proc(p: ^Peer, e: Entity, allocator := context.temp_allocator) -> []Ec_Value {
	if e.typ == "system/capability/token" {
		hex := hex_of(e.hash, allocator)
		sig_path := strings.concatenate({"/", p.local_peer, "/system/signature/", hex}, allocator)
		if sgn, ok := store_get_at(&p.store, sig_path); ok {
			if verify_signature(sgn, p.identity.peer_entity) {
				return grants_array_of(e, allocator)
			}
		}
		return {} // unverifiable seed cap → no authority
	} else if e.typ == "system/capability/policy-entry" {
		return grants_array_of(e, allocator)
	}
	return {}
}

// ── connect handler (§4.1, §4.6) ──────────────────────────────────────────────

@(private = "file")
negotiation_reject :: proc(params: Entity, key: string, required: string) -> bool {
	v, has := entity_field(params, key)
	if !has {
		return false
	}
	arr, is_arr := v.(Ec_Array)
	if !is_arr {
		return false
	}
	for it in ([]Ec_Value)(arr) {
		if s, ok := it.(Ec_Text); ok && string(s) == required {
			return false
		}
	}
	return true // present but disjoint
}

@(private = "file")
connect_handler :: proc(p: ^Peer, conn: ^Conn, exec: Entity, env: Envelope) -> Outcome {
	op, _ := entity_text(exec, "operation")
	a := context.temp_allocator
	if op == "hello" {
		if conn.established {
			return err_out(409, "connection_already_established", "")
		}
		if pe, has_pe, _ := entity_field_entity(exec, "params", a); has_pe {
			if negotiation_reject(pe, "hash_formats", "ecfv1-sha256") {
				return err_out(400, "incompatible_hash_format", "")
			}
			if negotiation_reject(pe, "key_types", "ed25519") {
				return err_out(400, "unsupported_key_type", "")
			}
			if pid, ok := entity_text(pe, "peer_id"); ok {
				if conn.hello_peer_id != "" {
					delete(conn.hello_peer_id, context.allocator)
				}
				conn.hello_peer_id = strings.clone(pid, context.allocator)
			}
		}
		nonce := random_nonce()
		conn.issued_nonce = nonce
		conn.has_nonce = true
		list := make([dynamic]Ec_Pair, a)
		append(&list, Ec_Pair{text_val("peer_id", a), text_val(p.local_peer, a)})
		append(&list, Ec_Pair{text_val("nonce", a), bytes_val(nonce[:], a)})
		protos := make([]Ec_Value, 1, a)
		protos[0] = text_val("entity-core/1.0", a)
		append(&list, Ec_Pair{text_val("protocols", a), Ec_Array(protos)})
		append(&list, Ec_Pair{text_val("timestamp", a), Ec_Uint(now_ms())})
		hf := make([]Ec_Value, 1, a)
		hf[0] = text_val("ecfv1-sha256", a)
		append(&list, Ec_Pair{text_val("hash_formats", a), Ec_Array(hf)})
		kt := make([]Ec_Value, 1, a)
		kt[0] = text_val("ed25519", a)
		append(&list, Ec_Pair{text_val("key_types", a), Ec_Array(kt)})
		hello, _ := entity_make("system/protocol/connect/hello", Ec_Map(list[:]), a)
		return ok_out(hello)
	} else if op == "authenticate" {
		if conn.established {
			return err_out(409, "connection_already_established", "")
		}
		if !conn.has_nonce {
			return err_out(401, "invalid_nonce", "")
		}
		auth, has_auth, _ := entity_field_entity(exec, "params", a)
		if !has_auth {
			return err_out(401, "authentication_failed", "")
		}
		// §4.6 hardening: reject an unsupported key_type.
		if kt, ok := entity_text(auth, "key_type"); ok && kt != "ed25519" {
			return err_out(400, "unsupported_key_type", "")
		}
		if pk, ok := entity_bytes(auth, "public_key"); ok && len(pk) != 32 {
			return err_out(400, "unsupported_key_type", "")
		}
		if pid, ok := entity_text(auth, "peer_id"); ok {
			if kt, _, _, perr := peer_id_parse(pid, a); perr == .None {
				if kt != 0x01 {
					return err_out(400, "unsupported_key_type", "")
				}
			}
		}
		echoed, has_echoed := entity_bytes(auth, "nonce")
		if !has_echoed || !slice.equal(echoed, conn.issued_nonce[:]) {
			return err_out(401, "invalid_nonce", "")
		}
		public_key, has_pk := entity_bytes(auth, "public_key")
		if !has_pk {
			return err_out(401, "authentication_failed", "")
		}
		// step 2: proof of possession — find the auth signature in included.
		sig_ok := false
		if sgn, ok := find_signature(env, auth.hash); ok {
			if sb, hsb := entity_bytes(sgn, "signature"); hsb {
				if len(sb) == 64 && len(public_key) == 32 {
					sig_ok = signature_verify_raw(public_key, auth.hash, sb)
				}
			}
		}
		if !sig_ok {
			return err_out(401, "authentication_failed", "")
		}
		// step 3: identity binding.
		claimed, has_claimed := entity_text(auth, "peer_id")
		derived := peer_id_of_pubkey(public_key, a)
		if !has_claimed || claimed != derived {
			return err_out(401, "identity_mismatch", "")
		}
		if conn.hello_peer_id != "" && conn.hello_peer_id != claimed {
			return err_out(401, "identity_mismatch", "")
		}
		// success: mint the initial capability (§4.4 / §6.9a).
		remote_peer, _ := peer_entity_of_pubkey(public_key, a)
		grants := derive_seed_grants(p, remote_peer, claimed, a)
		minted, merr := mint_token(p, remote_peer.hash, nil, false, grants, a)
		if merr != .None {
			return err_out(500, "internal_error", "")
		}
		conn.established = true
		gpairs := make([]Ec_Pair, 1, a)
		gpairs[0] = Ec_Pair{text_val("token", a), bytes_val(minted.token.hash, a)}
		grant_result, _ := entity_make("system/capability/grant", Ec_Map(gpairs), a)
		inc := make([]Inc_Item, 3, a)
		inc[0] = Inc_Item{key = minted.token.hash, entity = minted.token}
		inc[1] = Inc_Item{key = p.identity.identity_hash, entity = p.identity.peer_entity}
		inc[2] = Inc_Item{key = minted.signature.hash, entity = minted.signature}
		return ok_inc(grant_result, inc)
	}
	return err_out(501, "unsupported_operation", op)
}

// ── tree handler (§6.3) ───────────────────────────────────────────────────────

@(private = "file")
resource_target :: proc(exec: Entity) -> (string, bool) {
	r, has_r := entity_field(exec, "resource")
	if !has_r {
		return "", false
	}
	targets, has_t := map_get(r, "targets")
	if !has_t {
		return "", false
	}
	arr, is_arr := targets.(Ec_Array)
	if !is_arr || len(([]Ec_Value)(arr)) == 0 {
		return "", false
	}
	if s, ok := (([]Ec_Value)(arr))[0].(Ec_Text); ok {
		return string(s), true
	}
	return "", false
}

// path_flex_ok (§1.4 / §5.4): reject null byte, non-peer-id leading slash, ./ ../
// and interior empty segments. A single trailing "/" is the listing marker.
@(private = "file")
path_flex_ok :: proc(target: string) -> bool {
	if strings.index_byte(target, 0) >= 0 {
		return false
	}
	body := target
	if strings.has_prefix(target, "/") {
		rest := target[1:]
		i := strings.index_byte(rest, '/')
		if i < 0 {
			return is_peer_id(rest)
		}
		if !is_peer_id(rest[:i]) {
			return false
		}
		body = rest[i + 1:]
	}
	if len(body) > 0 && body[len(body) - 1] == '/' {
		body = body[:len(body) - 1]
	}
	if len(body) == 0 {
		return true
	}
	segs := strings.split(body, "/", context.temp_allocator)
	for seg in segs {
		if len(seg) == 0 || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

@(private = "file")
build_listing :: proc(p: ^Peer, path: string) -> Outcome {
	a := context.temp_allocator
	entries := store_listing(&p.store, path, a)
	entry_pairs := make([dynamic]Ec_Pair, a)
	emitted: u64 = 0
	for le in entries {
		// §6.3: a leaf bound to a system/deletion-marker is a tombstone — omit it.
		if le.hash != nil {
			if bound, ok := store_get_by_hash(&p.store, le.hash); ok {
				if bound.typ == "system/deletion-marker" {
					continue
				}
			}
		}
		fields := make([dynamic]Ec_Pair, a)
		append(&fields, Ec_Pair{text_val("has_children", a), Ec_Bool(le.has_children)})
		if le.hash != nil {
			append(&fields, Ec_Pair{text_val("hash", a), bytes_val(le.hash, a)})
		}
		le_entity, _ := entity_make("system/tree/listing-entry", Ec_Map(fields[:]), a)
		append(&entry_pairs, Ec_Pair{text_val(le.seg, a), entity_to_cbor(le_entity, a)})
		entity_destroy(le_entity, a)
		emitted += 1
	}
	top := make([dynamic]Ec_Pair, a)
	append(&top, Ec_Pair{text_val("path", a), text_val(path, a)})
	append(&top, Ec_Pair{text_val("entries", a), Ec_Map(entry_pairs[:])})
	append(&top, Ec_Pair{text_val("count", a), Ec_Uint(emitted)})
	append(&top, Ec_Pair{text_val("offset", a), Ec_Uint(0)})
	listing, _ := entity_make("system/tree/listing", Ec_Map(top[:]), a)
	return ok_out(listing)
}

@(private = "file")
tree_handler :: proc(p: ^Peer, exec: Entity) -> Outcome {
	a := context.temp_allocator
	op, _ := entity_text(exec, "operation")
	target, has_target := resource_target(exec)
	if (op == "get" || op == "put") && has_target && !path_flex_ok(target) {
		return err_out(400, "invalid_path", target)
	}

	if op == "get" {
		if !has_target {
			root_path := strings.concatenate({"/", p.local_peer, "/"}, a)
			return build_listing(p, root_path)
		}
		if len(target) == 0 || target[len(target) - 1] == '/' {
			return build_listing(p, canonicalize(p.local_peer, target))
		}
		path := canonicalize(p.local_peer, target)
		e, ok := store_get_at(&p.store, path)
		if !ok {
			return err_out(404, "not_found", path)
		}
		// mode=hash → return system/hash
		if pe, has_pe, _ := entity_field_entity(exec, "params", a); has_pe {
			if m, mok := entity_text(pe, "mode"); mok && m == "hash" {
				he, _ := entity_make("system/hash", bytes_val(e.hash, a), a)
				return ok_out(he)
			}
		}
		clone, _ := entity_clone(e, a)
		return ok_out(clone)
	} else if op == "put" {
		if !has_target {
			return err_out(400, "ambiguous_resource", "tree: missing resource target")
		}
		path := canonicalize(p.local_peer, target)
		params, has_params, _ := entity_field_entity(exec, "params", a)
		entity: Entity
		has_entity := false
		expected: []u8 = nil
		if has_params {
			if inner, hi, _ := entity_field_entity(params, "entity", a); hi {
				entity = inner
				has_entity = true
			}
			if ex, he := entity_bytes(params, "expected_hash"); he {
				expected = ex
			}
		}
		// §3.9 CAS
		current, has_current := store_hash_at(&p.store, path)
		cas_ok := true
		if expected != nil {
			zero33: [33]u8
			if slice.equal(expected, zero33[:]) {
				cas_ok = !has_current
			} else {
				cas_ok = has_current && slice.equal(current, expected)
			}
		}
		if !cas_ok {
			return err_out(409, "hash_mismatch", path)
		}
		if has_entity {
			store_bind(&p.store, path, entity, context.allocator)
			he, _ := entity_make("system/hash", bytes_val(entity.hash, a), a)
			return ok_out(he)
		}
		return err_out(400, "unexpected_params", "put: missing entity")
	}
	return err_out(501, "unsupported_operation", op)
}

// ── capability handler (§6.2) ─────────────────────────────────────────────────

@(private = "file")
is_zero_hash :: proc(h: []u8) -> bool {
	for c in h {
		if c != 0 {
			return false
		}
	}
	return true
}

@(private = "file")
req_grants :: proc(params: Entity, has_params: bool, allocator := context.temp_allocator) -> []Ec_Value {
	if !has_params {
		return {}
	}
	v, has := entity_field(params, "grants")
	if !has {
		return {}
	}
	arr, is_arr := v.(Ec_Array)
	if !is_arr {
		return {}
	}
	out := make([]Ec_Value, len(([]Ec_Value)(arr)), allocator)
	copy(out, ([]Ec_Value)(arr))
	return out
}

// mint_bounded mints a token for `grantee_hash`, bounded as a subset of the
// caller's cap (§6.2 subset-validation).
@(private = "file")
mint_bounded :: proc(
	p: ^Peer,
	caller_cap: Entity,
	has_caller_cap: bool,
	rg: []Ec_Value,
	grantee_hash: []u8,
	parent: []u8,
	has_parent: bool,
) -> Outcome {
	a := context.temp_allocator
	bounded := false
	if has_caller_cap {
		bounded = true
		parent_grants := grants_of_token(caller_cap)
		for cg in rg {
			c := parse_grant_public(cg)
			matched := false
			for pg in parent_grants {
				if grant_subset_local(p.local_peer, c, pg) {
					matched = true
					break
				}
			}
			if !matched {
				bounded = false
				break
			}
		}
	}
	if !bounded {
		return err_out(403, "scope_exceeds_authority", "")
	}
	minted, merr := mint_token(p, grantee_hash, parent, has_parent, rg, a)
	if merr != .None {
		return err_out(500, "internal_error", "")
	}
	gpairs := make([]Ec_Pair, 1, a)
	gpairs[0] = Ec_Pair{text_val("token", a), bytes_val(minted.token.hash, a)}
	grant_result, _ := entity_make("system/capability/grant", Ec_Map(gpairs), a)
	inc := make([]Inc_Item, 3, a)
	inc[0] = Inc_Item{key = minted.token.hash, entity = minted.token}
	inc[1] = Inc_Item{key = p.identity.identity_hash, entity = p.identity.peer_entity}
	inc[2] = Inc_Item{key = minted.signature.hash, entity = minted.signature}
	return ok_inc(grant_result, inc)
}

@(private = "file")
capability_handler :: proc(p: ^Peer, exec: Entity, caller_cap: Entity, has_caller_cap: bool) -> Outcome {
	a := context.temp_allocator
	op, _ := entity_text(exec, "operation")
	params, has_params, _ := entity_field_entity(exec, "params", a)
	author, has_author := entity_bytes(exec, "author")
	rg := req_grants(params, has_params, a)
	if op == "request" {
		if !has_author {
			return err_out(403, "capability_denied", "")
		}
		return mint_bounded(p, caller_cap, has_caller_cap, rg, author, nil, false)
	} else if op == "delegate" {
		parent: []u8 = nil
		has_parent := false
		if has_params {
			if pv, pok := entity_bytes(params, "parent"); pok {
				parent = pv
				has_parent = true
			}
		}
		if !has_parent {
			return err_out(400, "unexpected_params", "delegate: parent required")
		}
		if is_zero_hash(parent) {
			return err_out(400, "unexpected_params", "delegate: zero parent")
		}
		// delegate is same-peer-only in v1
		if !has_author || !slice.equal(author, p.identity.identity_hash) {
			return err_out(501, "unsupported_operation", "delegate: same-peer-only in v1")
		}
		return mint_bounded(p, caller_cap, has_caller_cap, rg, author, parent, true)
	} else if op == "revoke" {
		token_h: []u8 = nil
		has_token := false
		if has_params {
			if tv, tok := entity_bytes(params, "token"); tok {
				token_h = tv
				has_token = true
			}
		}
		if !has_token {
			return err_out(400, "unexpected_params", "revoke: missing token")
		}
		if is_zero_hash(token_h) {
			return err_out(400, "unexpected_params", "revoke: zero token")
		}
		mpairs := make([dynamic]Ec_Pair, a)
		append(&mpairs, Ec_Pair{text_val("token", a), bytes_val(token_h, a)})
		append(&mpairs, Ec_Pair{text_val("revoked_at", a), Ec_Uint(now_ms())})
		marker, _ := entity_make("system/capability/revocation", Ec_Map(mpairs[:]), a)
		defer entity_destroy(marker, a)
		hex := hex_of(token_h, a)
		path := strings.concatenate({"/", p.local_peer, "/system/capability/revocations/", hex}, a)
		store_bind(&p.store, path, marker, context.allocator)
		ep, _ := empty_params(a)
		return ok_out(ep)
	} else if op == "configure" {
		pp: string
		has_pp := false
		if has_params {
			if v, vok := entity_text(params, "peer_pattern"); vok {
				pp = v
				has_pp = true
			}
		}
		if !has_pp {
			return err_out(400, "unexpected_params", "configure: missing peer_pattern")
		}
		is_hex := len(pp) == 66
		if is_hex {
			for i in 0 ..< len(pp) {
				c := pp[i]
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					is_hex = false
					break
				}
			}
		}
		if !(pp == "default" || is_hex || is_peer_id(pp)) {
			return err_out(400, "invalid_peer_pattern", pp)
		}
		path := strings.concatenate({"/", p.local_peer, "/system/capability/policy/", pp}, a)
		store_bind(&p.store, path, params, context.allocator)
		ep, _ := empty_params(a)
		return ok_out(ep)
	}
	return err_out(501, "unsupported_operation", op)
}

// ── handlers handler (§6.2 / §6.13(a)) — register/unregister ──────────────────

@(private = "file")
register_pattern :: proc(exec: Entity) -> (pattern: string, err: Outcome, has_err: bool) {
	target, has_target := resource_target(exec)
	if !has_target {
		return "", err_out(400, "ambiguous_resource", "register/unregister require exactly one resource target"), true
	}
	prefix := "system/handler/"
	if !strings.has_prefix(target, prefix) || len(target) == len(prefix) {
		return "", err_out(400, "invalid_resource", "resource target MUST be system/handler/{pattern}"), true
	}
	return target[len(prefix):], Outcome{}, false
}

@(private = "file")
register_handler :: proc(p: ^Peer, exec: Entity) -> Outcome {
	a := context.temp_allocator
	pattern, perr, has_perr := register_pattern(exec)
	if has_perr {
		return perr
	}
	req, has_req, _ := entity_field_entity(exec, "params", a)
	if !has_req {
		return err_out(400, "unexpected_params", "register: missing params")
	}
	if req.typ != "system/handler/register-request" {
		return err_out(400, "unexpected_params", "register expects register-request")
	}
	manifest, has_manifest := entity_field(req, "manifest")
	if !has_manifest {
		manifest = Ec_Map(make([]Ec_Pair, 0, a))
	}
	name := pattern
	if v, ok := map_get(manifest, "name"); ok {
		if s, sok := v.(Ec_Text); sok {
			name = string(s)
		}
	}
	operations, has_ops := map_get(manifest, "operations")
	if !has_ops {
		operations = Ec_Map(make([]Ec_Pair, 0, a))
	}
	expr_path := ""
	has_expr := false
	if v, ok := map_get(manifest, "expression_path"); ok {
		if s, sok := v.(Ec_Text); sok {
			expr_path = string(s)
			has_expr = true
		}
	}
	internal_scope, has_internal := map_get(manifest, "internal_scope")

	// grant scope = requested_scope ?? internal_scope ?? []
	grant_scope := make([dynamic]Ec_Value, a)
	if v, ok := entity_field(req, "requested_scope"); ok {
		if arr, aok := v.(Ec_Array); aok {
			for it in ([]Ec_Value)(arr) {
				append(&grant_scope, it)
			}
		}
	} else if has_internal {
		if arr, aok := internal_scope.(Ec_Array); aok {
			for it in ([]Ec_Value)(arr) {
				append(&grant_scope, it)
			}
		}
	}

	interface_rel := strings.concatenate({"system/handler/", pattern}, a)
	// (1) handler manifest at the pattern path
	hpairs := make([dynamic]Ec_Pair, a)
	append(&hpairs, Ec_Pair{text_val("interface", a), text_val(interface_rel, a)})
	if has_expr {
		append(&hpairs, Ec_Pair{text_val("expression_path", a), text_val(expr_path, a)})
	}
	if has_internal {
		append(&hpairs, Ec_Pair{text_val("internal_scope", a), value_clone(internal_scope, a)})
	}
	handler_e, _ := entity_make("system/handler", Ec_Map(hpairs[:]), a)
	store_bind(&p.store, strings.concatenate({"/", p.local_peer, "/", pattern}, a), handler_e, context.allocator)
	entity_destroy(handler_e, a)

	// (2) associated types
	if v, ok := entity_field(req, "types"); ok {
		if kvs, mok := v.(Ec_Map); mok {
			for kv in ([]Ec_Pair)(kvs) {
				if tn, tok := kv.key.(Ec_Text); tok {
					te, _ := entity_make("system/type", value_clone(kv.value, a), a)
					store_bind(&p.store, strings.concatenate({"/", p.local_peer, "/system/type/", string(tn)}, a), te, context.allocator)
					entity_destroy(te, a)
				}
			}
		}
	}

	// (3)+(4) self-issued signed handler grant + grant-signature
	minted, merr := mint_token(p, p.identity.identity_hash, nil, false, grant_scope[:], a)
	if merr != .None {
		return err_out(500, "internal_error", "")
	}
	store_bind(&p.store, strings.concatenate({"/", p.local_peer, "/system/capability/grants/", pattern}, a), minted.token, context.allocator)
	thex := hex_of(minted.token.hash, a)
	store_bind(&p.store, strings.concatenate({"/", p.local_peer, "/system/signature/", thex}, a), minted.signature, context.allocator)

	// (5) handler interface entity (discovery index)
	ipairs := make([dynamic]Ec_Pair, a)
	append(&ipairs, Ec_Pair{text_val("pattern", a), text_val(pattern, a)})
	append(&ipairs, Ec_Pair{text_val("name", a), text_val(name, a)})
	append(&ipairs, Ec_Pair{text_val("operations", a), value_clone(operations, a)})
	iface_e, _ := entity_make("system/handler/interface", Ec_Map(ipairs[:]), a)
	store_bind(&p.store, strings.concatenate({"/", p.local_peer, "/", interface_rel}, a), iface_e, context.allocator)
	entity_destroy(iface_e, a)

	rpairs := make([dynamic]Ec_Pair, a)
	append(&rpairs, Ec_Pair{text_val("pattern", a), text_val(pattern, a)})
	append(&rpairs, Ec_Pair{text_val("grant", a), value_clone(minted.token.data, a)})
	result, _ := entity_make("system/handler/register-result", Ec_Map(rpairs[:]), a)
	return ok_out(result)
}

@(private = "file")
unregister_handler :: proc(p: ^Peer, exec: Entity) -> Outcome {
	a := context.temp_allocator
	pattern, perr, has_perr := register_pattern(exec)
	if has_perr {
		return perr
	}
	grant_path := strings.concatenate({"/", p.local_peer, "/system/capability/grants/", pattern}, a)
	if g, ok := store_get_at(&p.store, grant_path); ok {
		ghex := hex_of(g.hash, a)
		store_unbind(&p.store, strings.concatenate({"/", p.local_peer, "/system/signature/", ghex}, a), context.allocator)
		store_unbind(&p.store, grant_path, context.allocator)
	}
	store_unbind(&p.store, strings.concatenate({"/", p.local_peer, "/", pattern}, a), context.allocator)
	store_unbind(&p.store, strings.concatenate({"/", p.local_peer, "/system/handler/", pattern}, a), context.allocator)
	ep, _ := empty_params(a)
	return ok_out(ep)
}

@(private = "file")
handlers_handler :: proc(p: ^Peer, exec: Entity) -> Outcome {
	op, _ := entity_text(exec, "operation")
	if op == "register" {
		return register_handler(p, exec)
	}
	if op == "unregister" {
		return unregister_handler(p, exec)
	}
	return err_out(501, "unsupported_operation", op)
}

@(private = "file")
types_handler :: proc(exec: Entity) -> Outcome {
	op, _ := entity_text(exec, "operation")
	return err_out(501, "unsupported_operation", op)
}

// ── entity-native handler dispatch (§6.13(a)) — the register round-trip body ───

@(private = "file")
entity_native_dispatch :: proc(p: ^Peer, handler_entity: Entity) -> Outcome {
	a := context.temp_allocator
	expr_path_rel, has_expr := entity_text(handler_entity, "expression_path")
	if !has_expr {
		return err_out(501, "no_handler_body", "registered handler has no expression_path")
	}
	expr_path := canonicalize(p.local_peer, expr_path_rel)
	expr, ok := store_get_at(&p.store, expr_path)
	if !ok {
		return err_out(404, "expression_not_found", expr_path)
	}
	if expr.typ == "compute/literal" {
		value, has_value := entity_field(expr, "value")
		if !has_value {
			value = Ec_Null{}
		}
		pairs := make([dynamic]Ec_Pair, a)
		append(&pairs, Ec_Pair{text_val("value", a), value_clone(value, a)})
		append(&pairs, Ec_Pair{text_val("expression", a), bytes_val(expr.hash, a)})
		result, _ := entity_make("compute/result", Ec_Map(pairs[:]), a)
		return ok_out(result)
	}
	return err_out(501, "unsupported_expression", expr.typ)
}

// ── §7a conformance handlers ──────────────────────────────────────────────────

// echo (§7a.1): returns the params entity verbatim. Native body, no compute.
@(private = "file")
echo_handler :: proc(exec: Entity) -> Outcome {
	a := context.temp_allocator
	params, has_params, _ := entity_field_entity(exec, "params", a)
	if !has_params {
		ep, _ := empty_params(a)
		return ok_out(ep)
	}
	return ok_out(params)
}

// dispatch-outbound (§7a): originate one outbound EXECUTE via the §6.11 reentry
// seam back to the caller, invoking `operation` on `target` with `value`, and
// return the downstream response. Proves the target can ORIGINATE.
@(private = "file")
dispatch_outbound_handler :: proc(p: ^Peer, conn: ^Conn, exec: Entity) -> Outcome {
	a := context.temp_allocator
	if conn.outbound_fn == nil {
		return err_out(503, "no_outbound_seam", "dispatch-outbound requires a live §6.11 reentry connection")
	}
	params, has_params, _ := entity_field_entity(exec, "params", a)
	if !has_params {
		return err_out(400, "unexpected_params", "dispatch-outbound: missing params")
	}
	target, ht := entity_text(params, "target")
	operation, ho := entity_text(params, "operation")
	value, hv := entity_field(params, "value")
	if !ht {
		return err_out(400, "unexpected_params", "missing target")
	}
	if !ho {
		return err_out(400, "unexpected_params", "missing operation")
	}
	if !hv {
		return err_out(400, "unexpected_params", "missing value")
	}
	cap_e, hc, _ := entity_field_entity(params, "reentry_capability", a)
	granter_e, hg, _ := entity_field_entity(params, "reentry_granter", a)
	capsig_e, hcs, _ := entity_field_entity(params, "reentry_cap_signature", a)
	if !hc {
		return err_out(400, "unexpected_params", "missing reentry_capability")
	}
	if !hg {
		return err_out(400, "unexpected_params", "missing reentry_granter")
	}
	if !hcs {
		return err_out(400, "unexpected_params", "missing reentry_cap_signature")
	}

	// §7a.1: the `value` field IS the outbound params entity data — pass it
	// through (re-wrapping as {value} double-wraps).
	inner, _ := entity_make("primitive/any", value_clone(value, a), a)

	req, rerr := build_reentry_execute(p, conn, target, operation, inner, cap_e, granter_e, capsig_e)
	if rerr != .None {
		return err_out(500, "internal_error", "")
	}
	resp, got := conn.outbound_fn(conn.outbound_ctx, req, a)
	// build_reentry_execute's req is arena-owned; transport must not free it.
	if !got {
		return err_out(504, "outbound_timeout", "downstream did not reply")
	}
	defer envelope_destroy(resp, a)

	status, _ := entity_uint(resp.root, "status")
	result, has_result := entity_field(resp.root, "result")
	if !has_result {
		result = Ec_Null{}
	}
	rpairs := make([]Ec_Pair, 2, a)
	rpairs[0] = Ec_Pair{text_val("status", a), Ec_Uint(status)}
	rpairs[1] = Ec_Pair{text_val("result", a), value_clone(result, a)}
	out, _ := entity_make("primitive/any", Ec_Map(rpairs), a)
	return ok_out(out)
}

@(private = "file")
build_reentry_execute :: proc(
	p: ^Peer,
	conn: ^Conn,
	target, operation: string,
	inner, cap_e, granter_e, capsig_e: Entity,
) -> (Envelope, Codec_Error) {
	a := context.temp_allocator
	conn.out_counter += 1
	rid := fmt_ro(conn.out_counter, a)
	t_arr := make([]Ec_Value, 1, a)
	t_arr[0] = text_val(strings.concatenate({"system/handler/", target}, a), a)
	rpairs := make([]Ec_Pair, 1, a)
	rpairs[0] = Ec_Pair{text_val("targets", a), Ec_Array(t_arr)}
	resource := Ec_Map(rpairs)
	exec, eerr := make_execute(Execute_Fields{
		request_id = rid,
		uri = target,
		operation = operation,
		params = inner,
		resource = resource,
		has_resource = true,
		author = p.identity.identity_hash,
		capability = cap_e.hash,
	}, a)
	if eerr != .None {
		return Envelope{}, eerr
	}
	exec_sig, serr := sign_entity(p.identity, exec, a)
	if serr != .None {
		return Envelope{}, serr
	}
	included := make([]Included, 4, a)
	included[0] = Included{key = cap_e.hash, entity = cap_e}
	included[1] = Included{key = granter_e.hash, entity = granter_e}
	included[2] = Included{key = capsig_e.hash, entity = capsig_e}
	included[3] = Included{key = exec_sig.hash, entity = exec_sig}
	return Envelope{root = exec, included = included}, .None
}

@(private = "file")
conformance_handler :: proc(p: ^Peer, conn: ^Conn, exec: Entity, stripped: string) -> Outcome {
	if stripped == "system/validate/echo" {
		return echo_handler(exec)
	}
	if stripped == "system/validate/dispatch-outbound" {
		return dispatch_outbound_handler(p, conn, exec)
	}
	return err_out(501, "no_handler_body", stripped)
}

// ── dispatcher-level signature ingestion (§6.5) ───────────────────────────────

@(private = "file")
ingest_signatures :: proc(p: ^Peer, env: Envelope) {
	a := context.temp_allocator
	for inc in env.included {
		e := inc.entity
		if e.typ != "system/signature" {
			continue
		}
		store_put(&p.store, e, context.allocator)
		signer_h, hs := entity_bytes(e, "signer")
		if !hs {
			continue
		}
		signer_peer, hsp := envelope_get(env, signer_h)
		if !hsp {
			continue
		}
		store_put(&p.store, signer_peer, context.allocator)
		target, ht := entity_bytes(e, "target")
		if !ht {
			continue
		}
		pk, hpk := entity_bytes(signer_peer, "public_key")
		if !hpk {
			continue
		}
		pid := peer_id_of_pubkey(pk, a)
		hex := hex_of(target, a)
		path := strings.concatenate({"/", pid, "/system/signature/", hex}, a)
		store_bind(&p.store, path, e, context.allocator)
	}
}

// ── handler resolution (§6.6) — backward tree-walk ────────────────────────────

@(private = "file")
resolve_handler :: proc(p: ^Peer, path: string) -> (string, bool) {
	end := len(path)
	for end > 0 {
		prefix := path[:end]
		if e, ok := store_get_at(&p.store, prefix); ok {
			if e.typ == "system/handler" {
				return prefix, true
			}
		}
		idx := strings.last_index_byte(path[:end], '/')
		if idx < 0 {
			break
		}
		end = idx
	}
	return "", false
}

@(private = "file")
strip_local :: proc(p: ^Peer, pattern: string) -> string {
	prefix_len := 1 + len(p.local_peer) + 1 // "/{local}/"
	if len(pattern) > prefix_len &&
	   strings.has_prefix(pattern, "/") &&
	   pattern[1:1 + len(p.local_peer)] == p.local_peer &&
	   pattern[1 + len(p.local_peer)] == '/' {
		return pattern[prefix_len:]
	}
	return pattern
}

// ── dispatch chain (§6.5) ─────────────────────────────────────────────────────

@(private = "file")
dispatch_outcome :: proc(p: ^Peer, conn: ^Conn, env: Envelope) -> Outcome {
	a := context.temp_allocator
	exec := env.root
	uri, _ := entity_text(exec, "uri")
	if uri == "system/protocol/connect" {
		return connect_handler(p, conn, exec, env)
	}

	ingest_signatures(p, env)
	rv := verify_request(env, &p.store, p.local_peer)
	switch rv {
	case .Authn_Fail:
		return err_out(401, "authentication_failed", "")
	case .Authz_Deny:
		return err_out(403, "capability_denied", "")
	case .Chain_Too_Deep:
		return err_out(400, "chain_depth_exceeded", "")
	case .Unresolvable_Grantee:
		return err_out(401, "unresolvable_grantee", "")
	case .Allow:
	// fall through
	}

	norm := normalize_uri(uri)
	path := canonicalize(p.local_peer, norm)
	// §1.4: inbound dispatch must target the local peer.
	tp := extract_peer(p.local_peer, path)
	if tp != p.local_peer {
		return err_out(404, "handler_not_found", "not local peer")
	}
	pattern, has_pattern := resolve_handler(p, path)
	if !has_pattern {
		return err_out(404, "handler_not_found", path)
	}

	caller_cap: Entity
	has_caller_cap := false
	if ch, hc := entity_bytes(exec, "capability"); hc {
		if cc, ok := envelope_get(env, ch); ok {
			caller_cap = cc
			has_caller_cap = true
		}
	}
	if !has_caller_cap {
		return err_out(403, "capability_denied", "")
	}
	granter_peer := granter_frame(env, &p.store, p.local_peer, caller_cap)
	verdict := check_permission(p.local_peer, granter_peer, exec, caller_cap, pattern)
	if verdict == .Deny {
		return err_out(403, "capability_denied", "")
	}

	stripped := strip_local(p, pattern)
	switch {
	case stripped == "system/tree":
		return tree_handler(p, exec)
	case stripped == "system/capability":
		return capability_handler(p, exec, caller_cap, has_caller_cap)
	case stripped == "system/handler":
		return handlers_handler(p, exec)
	case stripped == "system/type":
		return types_handler(exec)
	case p.conformance && strings.has_prefix(stripped, "system/validate/"):
		return conformance_handler(p, conn, exec, stripped)
	}
	// a dynamically-registered handler: dispatch its entity-native body.
	if handler_entity, ok := store_get_at(&p.store, pattern); ok {
		if handler_entity.typ == "system/handler" {
			return entity_native_dispatch(p, handler_entity)
		}
	}
	_ = a
	return err_out(501, "no_handler_body", stripped)
}

// dispatch materializes the arena Outcome into a gpa-owned response Envelope.
// Returns (envelope, true) for an EXECUTE root; (_, false) for a non-EXECUTE root
// (§3.3 — server ignores non-EXECUTE). Runs dispatch on context.temp_allocator;
// clones survivors into context.allocator; the caller resets temp after sending.
dispatch :: proc(p: ^Peer, conn: ^Conn, env: Envelope) -> (Envelope, bool) {
	exec := env.root
	if exec.typ != "system/protocol/execute" {
		return Envelope{}, false // §3.3 server ignores non-EXECUTE
	}
	request_id, _ := entity_text(exec, "request_id")

	outcome := dispatch_outcome(p, conn, env)

	// Build the response in gpa (so it outlives the arena reset).
	gpa := context.allocator
	result_clone, _ := entity_clone(outcome.result, gpa)
	response_root, _ := make_response(request_id, outcome.status, result_clone, gpa)
	inc_list := make([]Included, len(outcome.included), gpa)
	for src, i in outcome.included {
		e, _ := entity_clone(src.entity, gpa)
		key := make([]u8, len(src.key), gpa)
		copy(key, src.key)
		inc_list[i] = Included{key = key, entity = e}
	}
	return Envelope{root = response_root, included = inc_list}, true
}

// internal_error_response builds a gpa-owned 500 for an envelope that raised.
internal_error_response :: proc(p: ^Peer, env: Envelope) -> Envelope {
	gpa := context.allocator
	request_id, _ := entity_text(env.root, "request_id")
	er, _ := error_result("internal_error", "", gpa)
	root, _ := make_response(request_id, 500, er, gpa)
	return Envelope{root = root, included = make([]Included, 0, gpa)}
}

// ── bootstrap (§6.9) ──────────────────────────────────────────────────────────

Boot_Handler :: struct {
	pattern:    string,
	name:       string,
	operations: []string,
}

// The four MUST handlers' interface operation sets (§6.2). The oracle requires
// these op keys present in the published interface's `operations` map. Package-
// level statics (a slice compound literal cannot be returned from a proc — it
// would dangle on the stack frame).
@(private = "file")
BOOTSTRAP_HANDLERS := [5]Boot_Handler{
	{pattern = "system/tree", name = "Tree", operations = {"get", "put"}},
	{pattern = "system/handler", name = "Handlers", operations = {"register", "unregister"}},
	{pattern = "system/type", name = "Types", operations = {}},
	{pattern = "system/capability", name = "Capability", operations = {"request", "delegate", "revoke"}},
	{pattern = "system/protocol/connect", name = "Connect", operations = {"hello", "authenticate"}},
}

@(private = "file")
CONFORMANCE_HANDLERS := [2]Boot_Handler{
	{pattern = "system/validate/echo", name = "validate-echo", operations = {"echo"}},
	{pattern = "system/validate/dispatch-outbound", name = "validate-dispatch-outbound", operations = {"dispatch"}},
}

@(private = "file")
operations_map :: proc(ops: []string, allocator := context.temp_allocator) -> Ec_Value {
	pairs := make([]Ec_Pair, len(ops), allocator)
	for op, i in ops {
		pairs[i] = Ec_Pair{text_val(op, allocator), Ec_Map(make([]Ec_Pair, 0, allocator))}
	}
	return Ec_Map(pairs)
}

@(private = "file")
bootstrap_handler :: proc(p: ^Peer, bh: Boot_Handler, allocator := context.temp_allocator) {
	a := allocator
	hpairs := make([]Ec_Pair, 1, a)
	hpairs[0] = Ec_Pair{text_val("interface", a), text_val(strings.concatenate({"system/handler/", bh.pattern}, a), a)}
	handler_e, _ := entity_make("system/handler", Ec_Map(hpairs), a)
	store_bind(&p.store, strings.concatenate({"/", p.local_peer, "/", bh.pattern}, a), handler_e, context.allocator)

	ipairs := make([]Ec_Pair, 3, a)
	ipairs[0] = Ec_Pair{text_val("pattern", a), text_val(bh.pattern, a)}
	ipairs[1] = Ec_Pair{text_val("name", a), text_val(bh.name, a)}
	ipairs[2] = Ec_Pair{text_val("operations", a), operations_map(bh.operations, a)}
	iface_e, _ := entity_make("system/handler/interface", Ec_Map(ipairs), a)
	store_bind(&p.store, strings.concatenate({"/", p.local_peer, "/system/handler/", bh.pattern}, a), iface_e, context.allocator)

	minted, _ := mint_token(p, p.identity.identity_hash, nil, false, {}, a)
	store_bind(&p.store, strings.concatenate({"/", p.local_peer, "/system/capability/grants/", bh.pattern}, a), minted.token, context.allocator)
}

Create_Options :: struct {
	seed:        [32]u8,
	open_grants: bool,
	conformance: bool,
}

// peer_create builds and bootstraps a peer (§6.9 + §6.9a). The peer owns its
// store + identity. Bootstrap scratch uses context.temp_allocator (reset by the
// caller after create returns).
peer_create :: proc(opts: Create_Options, allocator := context.allocator) -> (Peer, Codec_Error) {
	identity, ierr := identity_of_seed(opts.seed, allocator)
	if ierr != .None {
		return Peer{}, ierr
	}
	st := store_init(allocator)
	local_peer := identity.peer_id

	p := Peer {
		identity = identity,
		store = st,
		local_peer = local_peer,
		open_grants = opts.open_grants,
		conformance = opts.conformance,
	}

	a := context.temp_allocator

	// local identity entity in the store (root-granter resolution + §3.13 self)
	store_put(&p.store, p.identity.peer_entity, allocator)
	store_bind(&p.store, strings.concatenate({"/", local_peer, "/system/peer/self"}, a), p.identity.peer_entity, allocator)

	// §9.5 core types
	type_defs_publish(&p.store, local_peer, allocator)

	// bootstrap the MUST handlers (§6.2) + §7a scaffolding when conformance.
	for bh in BOOTSTRAP_HANDLERS {
		bootstrap_handler(&p, bh, a)
	}
	if opts.conformance {
		for bh in CONFORMANCE_HANDLERS {
			bootstrap_handler(&p, bh, a)
		}
	}

	// §6.9a peer-authority bootstrap: self-owner cap + default entry.
	policy_base := strings.concatenate({"/", local_peer, "/system/capability/policy/"}, a)
	owner, _ := mint_token(&p, p.identity.identity_hash, nil, false, owner_grants(local_peer, a), a)
	ohex := hex_of(p.identity.identity_hash, a)
	store_bind(&p.store, strings.concatenate({policy_base, ohex}, a), owner.token, allocator)
	othex := hex_of(owner.token.hash, a)
	store_bind(&p.store, strings.concatenate({"/", local_peer, "/system/signature/", othex}, a), owner.signature, allocator)

	default_grants: []Ec_Value
	if opts.open_grants {
		default_grants = open_grants_scope(a)
	} else {
		default_grants = discovery_floor(a)
	}
	dpairs := make([]Ec_Pair, 2, a)
	dpairs[0] = Ec_Pair{text_val("peer_pattern", a), text_val("default", a)}
	dg := make([]Ec_Value, len(default_grants), a)
	copy(dg, default_grants)
	dpairs[1] = Ec_Pair{text_val("grants", a), Ec_Array(dg)}
	default_entry, _ := entity_make("system/capability/policy-entry", Ec_Map(dpairs), a)
	store_bind(&p.store, strings.concatenate({policy_base, "default"}, a), default_entry, allocator)

	return p, .None
}

peer_destroy :: proc(p: ^Peer, allocator := context.allocator) {
	store_destroy(&p.store, allocator)
	identity_destroy(p.identity, allocator)
}

// fmt_ro formats "ro-N" without pulling core:fmt into the hot path.
@(private = "file")
fmt_ro :: proc(n: u32, allocator := context.temp_allocator) -> string {
	digits: [16]u8
	i := len(digits)
	v := n
	if v == 0 {
		i -= 1
		digits[i] = '0'
	}
	for v > 0 {
		i -= 1
		digits[i] = u8('0' + v % 10)
		v /= 10
	}
	num := string(digits[i:])
	return strings.concatenate({"ro-", num}, allocator)
}
