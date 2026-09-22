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
	// No §5.6 ceiling: the self-issued paths (bootstrap, handler registration, the
	// §4.4 handshake) mint from local authority, where no MIN_DEFINED term applies.
	return mint_token_at(p, now_ms(), grantee_hash, parent, has_parent, grants, 0, false, allocator)
}

// mint_token_at mints at a caller-supplied instant, carrying §5.6's MIN_DEFINED
// ceiling.
//
// has_expires false means no term was defined and the token genuinely has no expiry
// (the ONLY "no bound" spelling). A supplied expires_at is emitted verbatim --
// including a value equal to created_at, which §5.6 rule 2 requires for ttl_ms == 0
// and which means "already expired at every observable instant", not "unbounded".
//
// created_at is supplied rather than sampled here so a computed expiry is guaranteed
// to be relative to the SAME instant that lands in the token; sampling the clock twice
// skews the two.
@(private = "file")
mint_token_at :: proc(
	p: ^Peer,
	created_at: u64,
	grantee_hash: []u8,
	parent: []u8,
	has_parent: bool,
	grants: []Ec_Value,
	expires_at: u64,
	has_expires: bool,
	allocator := context.temp_allocator,
) -> (Minted, Codec_Error) {
	list := make([dynamic]Ec_Pair, allocator)
	append(&list, Ec_Pair{text_val("granter", allocator), bytes_val(p.identity.identity_hash, allocator)})
	append(&list, Ec_Pair{text_val("grantee", allocator), bytes_val(grantee_hash, allocator)})
	grants_copy := make([]Ec_Value, len(grants), allocator)
	copy(grants_copy, grants)
	append(&list, Ec_Pair{text_val("grants", allocator), Ec_Array(grants_copy)})
	append(&list, Ec_Pair{text_val("created_at", allocator), Ec_Uint(created_at)})
	if has_expires {
		append(&list, Ec_Pair{text_val("expires_at", allocator), Ec_Uint(expires_at)})
	}
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
		// §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
		// HALF-OPEN connection (hello done, authenticate not yet) is an operation we
		// implement arriving in a state that forbids it — the same class as
		// connection_already_established above, taking the same 409. A half-open
		// connection is NOT established, so the guard above cannot reach it; §4.7
		// names this gap explicitly because two adjacent rules each look like they
		// cover it and neither does.
		if conn.has_nonce {
			return err_out(409, "connection_sequence_error", "")
		}
		protos_present := false
		protos_ok := false
		if pe, has_pe, _ := entity_field_entity(exec, "params", a); has_pe {
			if negotiation_reject(pe, "hash_formats", "ecfv1-sha256") {
				return err_out(400, "incompatible_hash_format", "")
			}
			if negotiation_reject(pe, "key_types", "ed25519") {
				return err_out(400, "unsupported_key_type", "")
			}
			// §4.5 mutual verifiability, the direction that is NOT the array.
			// `key_types` is an ACCEPT-SET; the initiator's OWN key_type is not in
			// it — it rides in its `peer_id` — so a hello may advertise a perfectly
			// good accept-set and still name an identity we cannot verify. Checking
			// only the array leaves that MUST unenforced at hello, which is where
			// §4.5 wants it; authenticate catches it one leg later, which is
			// conformant but non-canonical.
			//
			// An UNPARSEABLE peer_id is deliberately left alone: that is a malformed
			// field, not a key_type we lack, and authenticate already refuses it.
			if pid, ok := entity_text(pe, "peer_id"); ok {
				if kt, _, _, perr := peer_id_parse(pid, a); perr == .None && kt != 0x01 {
					return err_out(400, "unsupported_key_type", "")
				}
			}
			// §4.5 `protocols` — the one negotiated field Required with NO default,
			// so there is no floor to fall back to, and its two failure modes carry
			// different codes on purpose (§4.5 table row / §4.7 row 1):
			//
			//   absent or empty     -> 400 invalid_request       (a malformed hello)
			//   non-empty, disjoint -> 400 incompatible_protocol (we compared)
			//
			// "a caller that named no version cannot be told the comparison failed"
			// — the remedies differ (send the field vs change the version) and §4.7
			// exists so the code selects the remedy. The vocabulary is §8.4's
			// protocol version identifiers, today the single entity-core/1.0.
			if pv, has_pv := entity_field(pe, "protocols"); has_pv {
				if arr, is_arr := pv.(Ec_Array); is_arr {
					for it in ([]Ec_Value)(arr) {
						if s, is_text := it.(Ec_Text); is_text {
							protos_present = true
							if string(s) == "entity-core/1.0" {
								protos_ok = true
							}
						}
					}
				}
			}
		}
		// ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
		// precedence between the three, so a hello disjoint in more than one
		// dimension may be refused on any of them — but the choice is OBSERVABLE,
		// and the reference peer refuses key_types first. Checking protocols first
		// is equally spec-legal and makes AGILITY-UNKNOWN-1 answer
		// incompatible_protocol, because that probe's own hello carries protocols
		// ["entity-core/v7"] — a spec-line name, not a §8.4 identifier (F56).
		if !protos_present {
			return err_out(400, "invalid_request", "hello: protocols absent or empty")
		}
		if !protos_ok {
			return err_out(400, "incompatible_protocol", "")
		}
		// The hello is accepted from here on, so the initiator's peer_id is recorded
		// only now — a refused hello must not leave state on the connection.
		if pe, has_pe, _ := entity_field_entity(exec, "params", a); has_pe {
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
			// RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
			// single-use nonce — pinned to 401 invalid_nonce, not a 409 state-conflict
			// which under-signals the replay.
			return err_out(401, "invalid_nonce", "")
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
	// §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
	// 400 invalid_request, not the 501 every other handler answers. The table
	// separates a STATE conflict from an UNKNOWN operation because they select
	// different remedies — "an unknown connect operation is not out of order at all;
	// it exists in no state", so connection_sequence_error would point the caller at
	// its ORDERING when the defect is its OPERATION NAME. Row 10 is scoped "in any
	// state", so this arm covers pre-handshake AND established; the genuine sequence
	// cases are refused in the two branches above, with 409.
	//
	// SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
	// (§3.3's 501 row, §6.2) is a different contract and is separately gated; moving
	// the other handlers' 501 would trade one green check for another.
	return err_out(400, "invalid_request", "connect: unknown operation")
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

// A §5.4 PATTERN rather than a concrete path. A resource-requiring operation takes a
// concrete path (0.8.2.20); a trailing "/" is a LISTING request, not a pattern -- only a
// star makes it one.
@(private = "file")
pattern_path :: proc(target: string) -> bool {
	return strings.index_byte(target, '*') >= 0
}

// The §6.3 authorization subject a handler carries for the duration of one dispatch:
// the CALLER's capability and the OWNING handler's pattern.
//
// CARRIED, NEVER RECOMPUTED. §6.3's path check needs both, and the dispatch-level check
// already computed both -- recomputing invites the two to drift, and §6.8 is explicit
// that the authority is selected by who named the path. `pattern` is the OWNING
// handler's pattern (§6.3, 0.8.2.23): for the tree handler owner and runner coincide, so
// the distinction is not observable here, but the field is named for the owner.
//
// `has_cap` is false only on the unauthenticated bootstrap path, which has no resolved
// handler entity and therefore no caller to narrow.
Dispatch_Auth :: struct {
	caller_cap: Entity,
	has_cap:    bool,
	pattern:    string,
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

// §6.3's per-entry listing check for one child segment (0.8.2.21/.22).
//
// An unauthenticated context is the bootstrap/internal path and is NOT filtered: the
// filter's subject is "the caller's verified capability", and where there is none there
// is no caller to narrow.
@(private = "file")
entry_visible :: proc(p: ^Peer, auth: Dispatch_Auth, dir: string, segment: string) -> bool {
	if !auth.has_cap {
		return true
	}
	a := context.temp_allocator
	child :=
		strings.has_suffix(dir, "/") \
		? strings.concatenate({dir, segment}, a) \
		: strings.concatenate({dir, "/", segment}, a)
	return check_path_permission(p.local_peer, "get", child, auth.caller_cap, auth.pattern)
}

// Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).
//
// "When any handler returns a multi-entry result whose entries are tree paths, each
// entry MUST be individually checked using check_path_permission. Entries for which
// check_path_permission returns DENY MUST be omitted. The result's `count` field MUST
// reflect the filtered entry count, not the source tree's total count."
//
// This is the read path at its highest volume and it is the reason 0.8.2.21 refused to
// carve reads out of the caller-specified-path rule: an unfiltered listing discloses the
// EXISTENCE of every binding under a prefix to a caller whose capability covers none of
// them. A `count` following the SOURCE total is that disclosure by itself, which is why
// it is computed from the emitted entries -- this peer already counted `emitted` for the
// tombstone filter, so the per-entry check simply joins it.
//
// The DIRECTORY itself is deliberately NOT checked -- §6.3 makes each ENTRY the subject,
// and testing the prefix would deny a listing to a caller whose grant covers children
// but not the node above them, which is the ordinary shape of a narrowed grant.
@(private = "file")
build_listing :: proc(p: ^Peer, path: string, auth: Dispatch_Auth) -> Outcome {
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
		if !entry_visible(p, auth, path, le.seg) {
			continue
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

// RULE: RESOLVE THE OPERATION FIRST, ONLY THEN RUN THE §3.3 RESOURCE LADDER.
//
// An unknown operation is an OPERATION fault and answers 501; a resource fault answers
// 400. A handler that validates the resource first answers a RESOURCE error for every
// unknown operation -- measured across the cohort as `system/tree:bogusop` WITHOUT a
// resource answering `ambiguous_resource` while the same call WITH one correctly
// answered 501, i.e. the fault the caller is told about depends on a field that has
// nothing to do with it. This handler already dispatched on `op` before touching the
// resource; the structure below keeps it that way by construction, with the whole ladder
// living INSIDE the `get` and `put` arms.
@(private = "file")
tree_handler :: proc(p: ^Peer, exec: Entity, auth: Dispatch_Auth) -> Outcome {
	a := context.temp_allocator
	op, _ := entity_text(exec, "operation")

	if op == "get" {
		// §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
		// resource.targets: a handler that counts the effective list and then indexes
		// targets[0] has implemented the arithmetic completely and is still reading a
		// path no authorization covered.
		eff, has_resource := effective_targets(p.local_peer, exec)
		if !has_resource {
			// THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION
			// IS WHAT SAYS SO. §3.3's "an empty effective list IS the absent case" is
			// scoped "for an operation that REQUIRES a resource" (0.8.2.24, N7); `get`
			// does not. For a resource-OPTIONAL operation 0.8.2.25 (N10) decides the
			// present-but-empty case by whether the absent case is WIDER than the
			// request -- BROAD-RESULT refuses it, OPTIONAL-FILTER answers it empty --
			// and requires the operation to declare which it is.
			//
			// EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
			// resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
			// listing", self-excluded case "400 path_required". So both arms here are
			// pinned by text and neither is this peer's choice.
			root_path := strings.concatenate({"/", p.local_peer, "/"}, a)
			return build_listing(p, root_path, auth)
		}
		if len(eff) == 0 {
			// `resource` PRESENT, every target carved out by the caller's own exclude.
			// Serving it the absent case "answers a request for one excluded path with
			// a listing of the tree" (EXTENSION-TREE §2.2a) -- the root listing is
			// wider than what was asked for, which is what BROAD-RESULT means.
			return err_out(400, "path_required", "tree: effective target list is empty")
		}
		if len(eff) > 1 {
			return err_out(400, "ambiguous_resource", "tree: more than one effective target")
		}
		target := eff[0]
		if !path_flex_ok(target) {
			return err_out(400, "invalid_path", target)
		}
		if len(target) == 0 || target[len(target) - 1] == '/' {
			return build_listing(p, canonicalize(p.local_peer, target), auth)
		}
		if pattern_path(target) {
			return err_out(400, "malformed_resource", target)
		}
		path := canonicalize(p.local_peer, target)
		// §6.3: the handler MUST verify the CALLER's capability covers the path it is
		// about to read. Not a secondary check -- the dispatch-level check never saw
		// this path if the caller excluded it.
		if auth.has_cap &&
		   !check_path_permission(p.local_peer, "get", path, auth.caller_cap, auth.pattern) {
			return err_out(403, "capability_denied", path)
		}
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
		// Same ladder as `get`, with the two empties COLLAPSED rather than split:
		// EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's "an
		// empty effective list IS the absent case" applies in its unscoped form and both
		// empties answer `path_required`. That is the same table the `get` arm cites,
		// read one row down -- the field is per-operation and neither answer is
		// derivable from this handler's source.
		//
		// Note the code change 0.8.2.20 forced: this branch answered `ambiguous_resource`
		// for a MISSING target, which 0.8.2.20 names as the exact inversion it forbids
		// ("answering ambiguous_resource for an absent resource inverts them"). The
		// remedies differ -- *supply a resource* is not *disambiguate your request* --
		// and the code selects between them.
		eff, has_resource := effective_targets(p.local_peer, exec)
		if !has_resource || len(eff) == 0 {
			return err_out(400, "path_required", "tree: put requires a resource target")
		}
		if len(eff) > 1 {
			return err_out(400, "ambiguous_resource", "tree: more than one effective target")
		}
		target := eff[0]
		if !path_flex_ok(target) {
			return err_out(400, "invalid_path", target)
		}
		if pattern_path(target) {
			return err_out(400, "malformed_resource", target)
		}
		path := canonicalize(p.local_peer, target)
		// §6.3 (see the `get` arm): the CALLER's capability must cover the path this
		// handler is about to write, because the caller's own exclude can vacate the
		// dispatch-level check.
		if auth.has_cap &&
		   !check_path_permission(p.local_peer, "put", path, auth.caller_cap, auth.pattern) {
			return err_out(403, "capability_denied", path)
		}
		params, has_params, _ := entity_field_entity(exec, "params", a)
		raw_entity: Ec_Value
		has_entity := false
		expected: []u8 = nil
		if has_params {
			if inner, hi := entity_field(params, "entity"); hi {
				raw_entity = inner
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
			entity, refuse_code, refuse_msg, admitted := admit_put(raw_entity, a)
			if !admitted {
				return err_out(400, refuse_code, refuse_msg)
			}
			store_bind(&p.store, path, entity, context.allocator)
			he, _ := entity_make("system/hash", bytes_val(entity.hash, a), a)
			return ok_out(he)
		}
		return err_out(400, "unexpected_params", "put: missing entity")
	}
	return err_out(501, "unsupported_operation", op)
}

// Digest byte length for a `content_hash_format` code per the §1.2 seed table, or 0
// when this peer cannot VERIFY that code. The total wire length is this plus the
// varint prefix, which is not a constant of the code (§7.3): codes >= 0x80 occupy
// more than one byte.
@(private = "file")
hash_digest_len :: proc(format_code: u64) -> int {
	switch format_code {
	case 0x00:
		return 32
	case 0x01:
		return 48
	}
	return 0
}

// §6.3's `put` admission ladder (normative, 0.8.2.11).
//
// `put` is a RECEIPT path: the submitter authors the entity, the peer validates what
// it received (§1.8 item 1) and MUST NOT author a submitted entity's content_hash on
// the submitter's behalf. Two ordered steps:
//
//   1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any CBOR
//      value; null is a legal payload), and a `content_hash` that is a well-formed
//      system/hash whose total byte length matches its format code (§1.2). Any failure
//      -> 400 invalid_request. A well-formed hash naming a format code this peer
//      cannot verify is the separate §1.2 ingest-dispatch case -> 400
//      unsupported_content_hash_format.
//   2. HASH — carried content_hash vs content_hash({type, data}). Disagreement -> 400
//      hash_mismatch.
//
// Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's inputs
// are exactly what step 1 establishes, so a submission that is both malformed and
// mis-hashed is step 1's and answers invalid_request.
//
// Structural admission is not semantic validation: `data` is never checked against the
// type named by `type`.
@(private = "file")
admit_put :: proc(
	v: Ec_Value,
	a := context.allocator,
) -> (entity: Entity, code: string, message: string, admitted: bool) {
	m, is_map := v.(Ec_Map)
	if !is_map {
		return Entity{}, "invalid_request", "put: entity is not a map", false
	}
	_ = m

	tv, has_type := map_get(v, "type")
	typ, is_text := Ec_Text(""), false
	if has_type {
		typ, is_text = tv.(Ec_Text)
	}
	if !is_text || len(string(typ)) == 0 {
		return Entity{}, "invalid_request",
			"put: entity.type absent, empty or not a text string", false
	}
	// Presence, not truthiness: a CBOR null is a legal `data` payload and map_get
	// reports it present, which is exactly the test §6.3 wants.
	data_src, has_data := map_get(v, "data")
	if !has_data {
		return Entity{}, "invalid_request", "put: entity.data absent", false
	}
	chv, has_ch := map_get(v, "content_hash")
	carried, is_bytes := Ec_Bytes(nil), false
	if has_ch {
		carried, is_bytes = chv.(Ec_Bytes)
	}
	if !is_bytes || len(([]u8)(carried)) == 0 {
		return Entity{}, "invalid_request",
			"put: entity.content_hash absent or not a byte string", false
	}
	format_code, consumed, verr := varint_decode(([]u8)(carried))
	if verr != .None {
		return Entity{}, "invalid_request",
			"put: entity.content_hash is not a well-formed system/hash", false
	}
	digest_len := hash_digest_len(format_code)
	if digest_len == 0 {
		// §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
		// invalid_request: the shape is fine, the algorithm is what we lack.
		return Entity{}, "unsupported_content_hash_format",
			"put: unsupported content_hash_format", false
	}
	if len(([]u8)(carried)) != consumed + digest_len {
		return Entity{}, "invalid_request",
			"put: content_hash length does not match its format code", false
	}

	preimage := Ec_Map([]Ec_Pair{{Ec_Text("type"), tv}, {Ec_Text("data"), data_src}})
	computed, herr := content_hash(preimage, format_code, a)
	if herr != .None || !slice.equal(computed, ([]u8)(carried)) {
		return Entity{}, "hash_mismatch",
			"put: content_hash does not match content_hash({type, data})", false
	}

	// The carried hash IS the entity's address; recomputing it into the store would be
	// the authoring arm §6.3 forbids. Built field-by-field rather than through
	// entity_make, which hardcodes format 0x00.
	e := Entity {
		typ  = strings.clone(string(typ), a),
		data = value_clone(data_src, a),
		hash = slice.clone(([]u8)(carried), a),
	}
	return e, "", "", true
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
	env: Envelope,
	caller_cap: Entity,
	has_caller_cap: bool,
	params: Entity,
	has_params: bool,
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
	// §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and
	// convert the duration term against that same instant.
	//
	// Note what this is NOT: an authorization decision. An over-long ttl_ms from a
	// bounded caller MINTS a clamped token and returns 200 -- "rejecting it is
	// non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
	// (parent: null), so §5.6's parent-child attenuation never reaches it; without this
	// clamp, temporal attenuation is the one dimension a requester could escape, and
	// policy withdrawal would have no bounded latency.
	created_at := now_ms()
	ceiling: u64 = 0
	has_ceiling := false
	fold :: proc(term: u64, ok: bool, acc: ^u64, have: ^bool) {
		if ok && (!have^ || term < acc^) {
			acc^ = term
			have^ = true
		}
	}
	if has_parent {                                                    // absolute
		if pt, pok := resolve(env, &p.store, parent); pok {
			pe, has_pe := entity_uint(pt, "expires_at")
			fold(pe, has_pe, &ceiling, &has_ceiling)
		}
	}
	if has_caller_cap {                                                // absolute
		ce, has_ce := entity_uint(caller_cap, "expires_at")
		fold(ce, has_ce, &ceiling, &has_ceiling)
	}
	if has_params {                                                    // duration
		if ttl, tok := entity_uint(params, "ttl_ms"); tok {
			abs, aok := add_ttl(created_at, ttl)
			fold(abs, aok, &ceiling, &has_ceiling)
		}
	}

	minted, merr := mint_token_at(p, created_at, grantee_hash, parent, has_parent, rg, ceiling, has_ceiling, a)
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
capability_handler :: proc(p: ^Peer, env: Envelope, exec: Entity, caller_cap: Entity, has_caller_cap: bool) -> Outcome {
	a := context.temp_allocator
	op, _ := entity_text(exec, "operation")
	params, has_params, _ := entity_field_entity(exec, "params", a)
	author, has_author := entity_bytes(exec, "author")
	rg := req_grants(params, has_params, a)
	if op == "request" {
		if !has_author {
			return err_out(403, "capability_denied", "")
		}
		return mint_bounded(p, env, caller_cap, has_caller_cap, params, has_params, rg, author, nil, false)
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
		return mint_bounded(p, env, caller_cap, has_caller_cap, params, has_params, rg, author, parent, true)
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

// §6.2: user-installed handlers MUST NOT register at system/* paths.
@(private = "file")
is_reserved_system_pattern :: proc(pattern: string) -> bool {
	return pattern == "system" || strings.has_prefix(pattern, "system/")
}

@(private = "file")
register_handler :: proc(p: ^Peer, exec: Entity) -> Outcome {
	a := context.temp_allocator
	pattern, perr, has_perr := register_pattern(exec)
	if has_perr {
		return perr
	}
	if is_reserved_system_pattern(pattern) {
		return err_out(403, "forbidden_pattern", strings.concatenate({"§6.2: user-installed handlers MUST NOT register at system/* paths: ", pattern}, a))
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
	// §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to
	// sit below the verdict, so a pre-establishment EXECUTE naming a FOREIGN namespace took
	// the 401 an unauthenticated request takes. §4.7's own reason: "a 401 directs the caller
	// to authenticate and retry, and for a foreign-namespace address that retry cannot
	// succeed at any authentication state — so the 401 names a remedy that does not exist."
	// §6.5 step 3 calls it "a gate, not an ordering preference" and §1.4 makes the downstream
	// permission check unreachable here.
	norm := normalize_uri(uri)
	path := canonicalize(p.local_peer, norm)
	if extract_peer(p.local_peer, path) != p.local_peer {
		return err_out(400, "invalid_request", "not local peer")
	}

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

	// (The §1.4 address gate that used to sit here has moved ABOVE the verdict — §4.7
	// 0.8.2.6 orders it before authentication. Reaching this line means the path is local.)
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

	// §6.3's authorization subject, CARRIED into the handler rather than recomputed:
	// `pattern` is the resolved OWNING handler pattern and `caller_cap` the capability
	// check_permission just ran against, which is exactly what check_path_permission
	// needs. Recomputing either inside the handler invites the two to drift.
	auth := Dispatch_Auth {
		caller_cap = caller_cap,
		has_cap    = has_caller_cap,
		pattern    = pattern,
	}

	stripped := strip_local(p, pattern)
	switch {
	case stripped == "system/tree":
		return tree_handler(p, exec, auth)
	case stripped == "system/capability":
		return capability_handler(p, env, exec, caller_cap, has_caller_cap)
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
		// §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
		// invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare close
		// -- that is indistinguishable from a network fault."
		//
		// §3.3 read "the connection MUST be closed", assigning no code and requiring no
		// frame, and §9.1's floor row that MANDATED the bare close was REPLACED at the
		// same revision (N18). This peer did something weaker still: it returned false,
		// the transport wrote NOTHING, and the connection stayed open -- which is
		// §4.11's OTHER non-conformant behaviour, the silent drop, "the weaker of the two
		// precisely because nothing surfaces it". This is a PRE-ADMISSION refusal: the
		// root is not an EXECUTE, so nothing was ever admitted and §4.9(c) does not reach
		// it.
		//
		// The request_id is read best-effort -- an arbitrary root type is under no
		// obligation to carry one, and §4.11 licenses the uncorrelated frame exactly
		// there. We do NOT close: on a multiplexed connection that would cost every
		// ADMITTED in-flight request its response, and §4.11 leaves the close to us.
		//
		// EXECUTE_RESPONSE roots never reach here -- read_loop routes them to their
		// awaiting §6.11 caller before dispatch is called.
		gpa := context.allocator
		rid, _ := entity_text(exec, "request_id")
		er, eerr := error_result("invalid_request",
			"root entity is neither EXECUTE nor EXECUTE_RESPONSE", gpa)
		if eerr != .None {
			return Envelope{}, false
		}
		root, rerr := make_response(rid, 400, er, gpa)
		if rerr != .None {
			return Envelope{}, false
		}
		return Envelope{root = root, included = make([]Included, 0, gpa)}, true
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
