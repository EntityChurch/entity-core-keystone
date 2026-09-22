package entity_core

import "core:mem"
import "core:net"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:thread"

// Transport (L4) — TCP listener + dialer + per-connection serve loop, on RAW OS
// THREADS (profile [async]: core:thread + core:sync; no async runtime).
//
// Concurrency model (N6 / N7 / §4.8 / §6.11):
//   - One READER thread per connection demuxes inbound frames (§6.11). An
//     EXECUTE_RESPONSE is routed to the awaiting outbound caller by request_id; an
//     inbound EXECUTE is dispatched on its OWN thread (§4.8) so a handler that
//     originates an outbound EXECUTE (§6.13(b)) and awaits its reply does NOT
//     block the reader — the reader keeps reading and routes the reply back.
//   - Writes (responses + outbound requests share the socket) are serialized by a
//     sync.Mutex.
//   - A pending-request table (request_id → slot) + sync.Cond is the §6.11 demux
//     (the raw-thread correlation-map tax). A never-arriving reply is bounded by
//     connection close (broadcasts all waiters).
//
// No-GC idiom: every inbound frame's decoded envelope is freed after dispatch;
// pending slots own their response envelope until the waiter takes it. Each
// dispatch thread uses its own temp_allocator arena (freed on thread exit).

Pending_Slot :: struct {
	response: Envelope,
	has_resp: bool,
	done:     bool,
}

// Per-connection IO state: the shared socket, write serialization, and the §6.11
// pending-response demux table.
Io :: struct {
	sock:           net.TCP_Socket,
	write_mu:       sync.Mutex,
	pending_mu:     sync.Mutex,
	pending_cond:   sync.Cond,
	pending:        map[string]^Pending_Slot,
	closed:         bool,
	allocator:      mem.Allocator,
}

io_init :: proc(sock: net.TCP_Socket, allocator := context.allocator) -> Io {
	return Io{sock = sock, pending = make(map[string]^Pending_Slot, allocator), allocator = allocator}
}

io_destroy :: proc(io: ^Io) {
	for k, _ in io.pending {
		delete(k, io.allocator)
	}
	delete(io.pending)
}

// io_write_framed serializes a framed write (responses + outbound share the
// socket). Encodes with the io allocator, frees the buffer after.
io_write_framed :: proc(io: ^Io, env: Envelope) -> Wire_Error {
	payload, err := envelope_encode(env, io.allocator)
	if err != .None {
		return .Codec
	}
	defer delete(payload, io.allocator)
	sync.mutex_lock(&io.write_mu)
	defer sync.mutex_unlock(&io.write_mu)
	return write_frame(io.sock, payload)
}

// route_response routes an inbound EXECUTE_RESPONSE to its awaiting outbound
// caller (§6.11). Takes ownership of `env` (stored in the slot or freed).
@(private = "file")
route_response :: proc(io: ^Io, env: Envelope) {
	request_id, _ := entity_text(env.root, "request_id")
	sync.mutex_lock(&io.pending_mu)
	defer sync.mutex_unlock(&io.pending_mu)
	if slot, ok := io.pending[request_id]; ok {
		slot.response = env
		slot.has_resp = true
		slot.done = true
		sync.cond_broadcast(&io.pending_cond)
	} else {
		envelope_destroy(env, io.allocator)
	}
}

// io_outbound (§6.13(b)) sends a request envelope and awaits its correlated
// reply. Returns the owned response Envelope (caller frees) + true, or false on
// close. `request` is owned by the caller (freed by the caller after return).
io_outbound :: proc(io: ^Io, request: Envelope) -> (Envelope, bool) {
	request_id_src, _ := entity_text(request.root, "request_id")
	request_id := strings.clone(request_id_src, io.allocator)
	slot := new(Pending_Slot, io.allocator)
	defer free(slot, io.allocator)

	{
		sync.mutex_lock(&io.pending_mu)
		if io.closed {
			sync.mutex_unlock(&io.pending_mu)
			delete(request_id, io.allocator)
			return Envelope{}, false
		}
		io.pending[request_id] = slot
		sync.mutex_unlock(&io.pending_mu)
	}
	if io_write_framed(io, request) != .None {
		sync.mutex_lock(&io.pending_mu)
		delete_key(&io.pending, request_id)
		sync.mutex_unlock(&io.pending_mu)
		delete(request_id, io.allocator)
		return Envelope{}, false
	}
	sync.mutex_lock(&io.pending_mu)
	for !slot.done && !io.closed {
		sync.cond_wait(&io.pending_cond, &io.pending_mu)
	}
	if _, exists := io.pending[request_id]; exists {
		delete_key(&io.pending, request_id)
	}
	got := slot.has_resp
	resp := slot.response
	sync.mutex_unlock(&io.pending_mu)
	// `request_id` is the map key (same allocation); freed once here.
	delete(request_id, io.allocator)
	return resp, got
}

// io_close wakes every pending outbound waiter on connection close.
io_close :: proc(io: ^Io) {
	sync.mutex_lock(&io.pending_mu)
	io.closed = true
	sync.cond_broadcast(&io.pending_cond)
	sync.mutex_unlock(&io.pending_mu)
}

// ── reader loop (§6.11 demux) ─────────────────────────────────────────────────

Dispatch_Ctx :: struct {
	peer: ^Peer,
	conn: ^Conn,
	io:   ^Io,
	env:  Envelope,
}

// outbound_shim adapts io_outbound to the peer's Outbound_Fn ABI so a §7a
// dispatch-outbound handler can originate back over the inbound connection. The
// reply arrives io.allocator-owned; we deep-clone it into the handler's
// (temp) allocator and free the original, so the returned Envelope is owned by
// the handler's arena.
@(private = "file")
outbound_shim :: proc(ctx: rawptr, req: Envelope, allocator: mem.Allocator) -> (Envelope, bool) {
	io := (^Io)(ctx)
	reply, got := io_outbound(io, req)
	if !got {
		return Envelope{}, false
	}
	defer envelope_destroy(reply, io.allocator)
	root, _ := entity_clone(reply.root, allocator)
	included := make([]Included, len(reply.included), allocator)
	for inc, i in reply.included {
		e, _ := entity_clone(inc.entity, allocator)
		key := make([]u8, len(inc.key), allocator)
		copy(key, inc.key)
		included[i] = Included{key = key, entity = e}
	}
	return Envelope{root = root, included = included}, true
}

// dispatch_execute_thread dispatches one inbound EXECUTE on its own thread
// (§4.8); frees ctx + env + its per-thread arena.
@(private = "file")
dispatch_execute_thread :: proc(ctx: rawptr) {
	dc := (^Dispatch_Ctx)(ctx)
	io := dc.io
	defer {
		envelope_destroy(dc.env, io.allocator)
		free(dc, io.allocator)
		free_all(context.temp_allocator)
	}
	// Bind the §6.11 reentry seam so a §7a dispatch-outbound handler can originate.
	dc.conn.outbound_ctx = io
	dc.conn.outbound_fn = outbound_shim
	resp, ok := dispatch(dc.peer, dc.conn, dc.env)
	if !ok {
		return // non-EXECUTE root ignored (§3.3)
	}
	defer envelope_destroy(resp, io.allocator)
	io_write_framed(io, resp)
}

// The (status, code, message) §4.11 assigns a pre-admission failure's CAUSE.
//
// "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]" --
// a single code for the class would answer an honest caller under the wrong reason and
// send them to the wrong layer.
//
//	connect-auth proof-of-possession       401 authentication_failed  (the connect
//	                                          handler's, not here)
//	envelope over the configured maximum   413 payload_too_large      (§4.10(a), N14)
//	resolution integrity (mis-keyed incl.) 400 hash_mismatch          (§5.2a, §1.8)
//	framing / never becomes an Envelope    400 invalid_request        (§4.7, §4.11)
//	root is neither EXECUTE nor E_R        400 invalid_request        (§3.3, §4.11 --
//	                                          in dispatch, not here)
//
// THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that code
// non-conformant "on the framing arm" and gives its reason in the same sentence:
// ENTITY-CBOR-ENCODING defines it for CBOR tag-policy violations specifically, which that
// document still MUSTs at decode time (§6.3). The two rows are disjoint by CAUSE rather
// than in conflict. Everything else this decoder calls non-canonical -- a non-minimal
// head, an indefinite length, mis-ordered or duplicate keys, over-depth -- is genuinely
// "non-canonical CBOR that never becomes an Envelope" and takes invalid_request.
//
// This peer answered `non_canonical_ecf` for EVERY decode-boundary refusal until
// 0.8.2.24/.25 pinned them apart (measured on the wire, arc-probe B1/B2). A mis-keyed
// `included` entry carries no tag at all: its encoding is canonical, what is false is the
// claim the KEY makes, and the remedy `non_canonical_ecf` selects -- *re-encode* -- sends
// an honest caller to the wrong layer.
//
// The messages are a FIXED TABLE, never an internal diagnostic: a wire-visible string
// stays ASCII (two peers in this cohort have been killed at runtime by a non-ASCII byte
// in an encoded string, on two unrelated compilers) and nothing here echoes
// attacker-supplied bytes back.
// Package-visible (not file-private) so the unit suite can pin the MAPPING directly:
// §4.11's frame obligation is a RUNTIME property only a socket can measure, but the
// code-by-cause table is a pure function and belongs in a test that names each cause.
pre_admission_refusal :: proc(e: Codec_Error) -> (status: u64, code: string, message: string) {
	#partial switch e {
	case .Content_Hash_Mismatch, .Included_Key_Mismatch:
		return 400, "hash_mismatch", "an entity was addressed by a hash that does not bind to it"
	case .Tag_Rejected:
		return 400, "non_canonical_ecf", "CBOR tags are forbidden anywhere in an entity data field"
	}
	return 400, "invalid_request", "frame did not decode into an envelope"
}

// Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
// refused BEFORE it becomes an admitted request.
//
// "A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
// wire [MUST] -- correlated by `request_id` where the id is available, and otherwise as a
// best-effort coded frame carrying no correlation."
//
// §4.9(c)'s deliver-or-signal rule is scoped to "every request the peer ADMITS" and
// therefore reaches none of these, which is why §4.11 exists. Both of the non-conformant
// behaviours it scores separately were present on this peer: DROPPING the frame (the
// unsalvageable-request_id arm, "the weaker of the two precisely because nothing surfaces
// it") and CLOSING with no coded frame (the oversize and truncated arms' bare `break`).
//
// AN EMPTY `request_id` IS THE BEST-EFFORT FORM, not a bug: it is what the section
// prescribes where no id can be recovered, and guessing one would correlate the refusal
// to somebody else's in-flight request. The old code RETURNED here instead, which is the
// silent drop.
@(private = "file")
refuse_pre_admission :: proc(io: ^Io, request_id: string, status: u64, code: string, message: string) {
	errv, eerr := error_result(code, message, io.allocator)
	if eerr != .None {
		return
	}
	// make_response CONSUMES `result` UNCONDITIONALLY -- it encodes and destroys before
	// it can fail -- so `errv` must not be released on either branch here. A
	// conditional ownership contract cannot be reasoned about at the call site at all,
	// which is why the unconditional form is the one to depend on.
	root, rerr := make_response(request_id, status, errv, io.allocator)
	if rerr != .None {
		return
	}
	// io_write_framed does NOT take ownership: it encodes into its own buffer and frees
	// that. The response entity is ours to release and the refusal path that preceded
	// this never did -- a leak of one response entity per rejected frame, on a path any
	// unauthenticated caller can drive as fast as it can open sockets.
	defer entity_destroy(root, io.allocator)
	env := Envelope{root = root, included = nil}
	io_write_framed(io, env)
}

// reject_frame answers a COMPLETE frame the decoder refused, correlated by the
// request_id salvaged from it where one can be recovered and uncorrelated where it
// cannot. Best-effort on the WRITE only -- a dead socket is not a protocol decision.
@(private = "file")
reject_frame :: proc(io: ^Io, payload: []u8, e: Codec_Error) {
	rid, ok := salvage_request_id(payload, io.allocator)
	defer if ok {delete(rid, io.allocator)}
	status, code, message := pre_admission_refusal(e)
	refuse_pre_admission(io, ok ? rid : "", status, code, message)
}

// read_loop: EXECUTE_RESPONSE → route; EXECUTE → dispatch on its own thread.
// Runs until the connection closes / a frame ends it. Uses `context.allocator`
// (the caller sets it) for the read buffer + envelope; a malformed frame is
// dropped and the loop keeps reading (§4.9 deliver-or-signal, never crash).
read_loop :: proc(peer: ^Peer, conn: ^Conn, io: ^Io) {
	for {
		payload, perr := read_frame(io.sock, io.allocator)
		if perr != .None {
			// §4.11: a FRAMING failure is a REFUSAL owed a coded frame, and both of
			// these used to be a bare `break` -- "closing with no coded frame", which is
			// indistinguishable from a network fault and, on a multiplexed connection,
			// destroys unrelated ADMITTED requests. §4.10(a)'s mood was raised SHOULD ->
			// MUST at 0.8.2.25 (N14): the over-size condition is detected at the length
			// prefix with the connection intact and nothing spent, so the permissive
			// mood had nothing to license.
			//
			// The stream is desynchronized on both arms -- an oversize body was never
			// drained, a truncated one never arrived -- so the frame goes out and THEN
			// the connection closes. §4.11 makes the frame mandatory and leaves the
			// close to us; closing is the only sound choice once the framing is lost,
			// and it is a CHOICE rather than an alternative to answering.
			//
			// §4.11's best-effort UNCORRELATED form: no request_id can be recovered from
			// a frame whose body never arrived.
			#partial switch perr {
			case .Frame_Too_Large:
				refuse_pre_admission(io, "", 413, "payload_too_large",
					"inbound frame exceeds the configured maximum size")
			case .Truncated:
				refuse_pre_admission(io, "", 400, "invalid_request",
					"frame did not decode into an envelope")
			}
			break // .Closed is an ordinary hangup at a frame boundary -- owed nothing
		}
		env, eerr := envelope_of_frame(payload, io.allocator)
		if eerr != .None {
			// A COMPLETE frame the decoder refused. The framing is intact, so we answer
			// and KEEP SERVING -- and the refusal MUST be a status rather than silence
			// (§4.11; §4.9(c) says the same from the other direction). This used to
			// `continue`, which rejected the frame (correct) and then dropped it on the
			// floor (wrong): the sender saw no response at all and blocked until its own
			// timeout, so a refusal was indistinguishable from a dead peer.
			//
			// THE CODE IS THE CAUSE'S (§4.11, §5.2a) -- see pre_admission_refusal. And
			// an unrecoverable request_id now takes §4.11's uncorrelated best-effort
			// form rather than the silence it used to take: the salvage recovers only
			// enough to correlate, and failing to correlate is not a reason to say
			// nothing.
			reject_frame(io, payload, eerr)
			delete(payload, io.allocator)
			continue // keep reading (§4.9)
		}
		delete(payload, io.allocator)
		if env.root.typ == "system/protocol/execute/response" {
			route_response(io, env) // takes ownership
		} else {
			// dispatch on its own thread (§4.8). The thread owns `env`.
			dc := new(Dispatch_Ctx, io.allocator)
			dc^ = Dispatch_Ctx{peer = peer, conn = conn, io = io, env = env}
			t := thread.create_and_start_with_poly_data(dc, proc(dc: ^Dispatch_Ctx) {
				dispatch_execute_thread(dc)
			}, context, .Normal, true)
			_ = t
		}
	}
	io_close(io)
}

// ── listener / dialer ─────────────────────────────────────────────────────────

transport_listen :: proc(port: int) -> (net.TCP_Socket, int, bool) {
	ep := net.Endpoint{address = net.IP4_Loopback, port = port}
	sock, err := net.listen_tcp(ep)
	if err != nil {
		return {}, 0, false
	}
	bound, berr := net.bound_endpoint(sock)
	bound_port := port
	if berr == nil {
		bound_port = bound.port
	}
	return sock, bound_port, true
}

transport_dial :: proc(port: int) -> (net.TCP_Socket, bool) {
	ep := net.Endpoint{address = net.IP4_Loopback, port = port}
	sock, err := net.dial_tcp_from_endpoint(ep)
	if err != nil {
		return {}, false
	}
	set_no_delay(sock)
	return sock, true
}

// ── high-level handshake (§4.1) + session ─────────────────────────────────────

// An authenticated session over an established connection (§4.4 / §5.8). Owns the
// capability chain entities it re-presents on every request. All owned via the
// session allocator (the caller's gpa).
Session :: struct {
	io:             ^Io,
	local:          ^Peer,
	remote_peer_id: string, // owned
	capability:     Entity, // owned
	granter_peer:   Entity, // owned
	cap_signature:  Entity, // owned
	req_counter:    u32,
	allocator:      mem.Allocator,
}

session_destroy :: proc(s: ^Session) {
	delete(s.remote_peer_id, s.allocator)
	entity_destroy(s.capability, s.allocator)
	entity_destroy(s.granter_peer, s.allocator)
	entity_destroy(s.cap_signature, s.allocator)
}

// session_execute builds, signs, and sends an authenticated EXECUTE; awaits the
// correlated reply (§5.8 chain inclusion). `resource` (if any) consumed. Returns
// the owned response Envelope + true. Everything allocated via `allocator`.
session_execute :: proc(
	s: ^Session,
	uri, operation: string,
	params: Entity,
	resource: Ec_Value,
	has_resource: bool,
	allocator := context.allocator,
) -> (Envelope, bool) {
	s.req_counter += 1
	rid := fmt_req(s.req_counter, allocator)
	defer delete(rid, allocator)
	exec, eerr := make_execute(Execute_Fields{
		request_id = rid,
		uri = uri,
		operation = operation,
		params = params,
		resource = resource,
		has_resource = has_resource,
		author = s.local.identity.identity_hash,
		capability = s.capability.hash,
	}, allocator)
	if eerr != .None {
		return Envelope{}, false
	}
	exec_sig, serr := sign_entity(s.local.identity, exec, allocator)
	if serr != .None {
		entity_destroy(exec, allocator)
		return Envelope{}, false
	}

	items := [5]Entity{s.capability, s.granter_peer, s.local.identity.peer_entity, s.cap_signature, exec_sig}
	inc := make([]Included, 5, allocator)
	for it, i in items {
		e, _ := entity_clone(it, allocator)
		key := make([]u8, len(it.hash), allocator)
		copy(key, it.hash)
		inc[i] = Included{key = key, entity = e}
	}
	entity_destroy(exec_sig, allocator)
	req := Envelope{root = exec, included = inc}
	defer envelope_destroy(req, allocator)
	resp, got := io_outbound(s.io, req)
	return resp, got
}

// send_connect: a connect-path EXECUTE carries no author/capability (§4.2).
@(private = "file")
send_connect :: proc(
	io: ^Io,
	conn: ^Conn,
	operation: string,
	params: Entity,
	included: []Entity,
	allocator := context.allocator,
) -> (Envelope, bool) {
	conn.out_counter += 1
	rid := fmt_h(conn.out_counter, allocator)
	defer delete(rid, allocator)
	exec, eerr := make_execute(Execute_Fields{
		request_id = rid,
		uri = "system/protocol/connect",
		operation = operation,
		params = params,
	}, allocator)
	if eerr != .None {
		return Envelope{}, false
	}
	inc := make([]Included, len(included), allocator)
	for it, i in included {
		e, _ := entity_clone(it, allocator)
		key := make([]u8, len(it.hash), allocator)
		copy(key, it.hash)
		inc[i] = Included{key = key, entity = e}
	}
	req := Envelope{root = exec, included = inc}
	defer envelope_destroy(req, allocator)
	return io_outbound(io, req)
}

// hello_params_of builds the initiator's §4.5 hello params. `protocols` is the
// load-bearing field: it is Required with no default, so omitting it is a malformed
// hello, not a lenient one.
@(private = "file")
hello_params_of :: proc(local_peer: string, allocator := context.allocator) -> (Entity, Codec_Error) {
	list := make([dynamic]Ec_Pair, allocator)
	append(&list, Ec_Pair{text_val("peer_id", allocator), text_val(local_peer, allocator)})
	protos := make([]Ec_Value, 1, allocator)
	protos[0] = text_val("entity-core/1.0", allocator)
	append(&list, Ec_Pair{text_val("protocols", allocator), Ec_Array(protos)})
	hf := make([]Ec_Value, 1, allocator)
	hf[0] = text_val("ecfv1-sha256", allocator)
	append(&list, Ec_Pair{text_val("hash_formats", allocator), Ec_Array(hf)})
	kt := make([]Ec_Value, 1, allocator)
	kt[0] = text_val("ed25519", allocator)
	append(&list, Ec_Pair{text_val("key_types", allocator), Ec_Array(kt)})
	return entity_make("primitive/any", Ec_Map(list[:]), allocator)
}

// initiate runs the initiator handshake (§4.1): hello → authenticate → Session.
initiate :: proc(local: ^Peer, io: ^Io, conn: ^Conn, allocator := context.allocator) -> (Session, bool) {
	// 1. hello
	// §4.5 makes `protocols` Required with NO default, so a hello that omits it is a
	// MALFORMED hello and a conforming responder answers 400 invalid_request. This
	// dialer used to send empty params and it worked only because no peer enforced
	// the rule — the moment the responder side landed, the peer could not complete a
	// handshake with itself. THE ORACLE CANNOT SEE THIS: its origination check
	// reuses the INBOUND connection and never makes us dial.
	hello_params, _ := hello_params_of(local.local_peer, allocator)
	r1, ok1 := send_connect(io, conn, "hello", hello_params, {}, allocator)
	if !ok1 {
		return Session{}, false
	}
	defer envelope_destroy(r1, allocator)
	if st, _ := entity_uint(r1.root, "status"); st != 200 {
		return Session{}, false
	}
	remote_hello, hh, _ := entity_field_entity(r1.root, "result", allocator)
	if !hh {
		return Session{}, false
	}
	defer entity_destroy(remote_hello, allocator)
	remote_peer_id, hp := entity_text(remote_hello, "peer_id")
	remote_nonce, hn := entity_bytes(remote_hello, "nonce")
	if !hp || !hn {
		return Session{}, false
	}
	return authenticate(local, io, conn, remote_nonce, remote_peer_id, allocator)
}

@(private = "file")
authenticate :: proc(
	local: ^Peer,
	io: ^Io,
	conn: ^Conn,
	remote_nonce: []u8,
	remote_peer_id: string,
	allocator := context.allocator,
) -> (Session, bool) {
	apairs := make([]Ec_Pair, 4, allocator)
	apairs[0] = Ec_Pair{text_val("peer_id", allocator), text_val(local.identity.peer_id, allocator)}
	apairs[1] = Ec_Pair{text_val("public_key", allocator), bytes_val(local.identity.public_key[:], allocator)}
	apairs[2] = Ec_Pair{text_val("key_type", allocator), text_val("ed25519", allocator)}
	apairs[3] = Ec_Pair{text_val("nonce", allocator), bytes_val(remote_nonce, allocator)}
	auth, aerr := entity_make("system/protocol/connect/authenticate", Ec_Map(apairs), allocator)
	if aerr != .None {
		return Session{}, false
	}
	defer entity_destroy(auth, allocator)
	auth_sig, serr := sign_entity(local.identity, auth, allocator)
	if serr != .None {
		return Session{}, false
	}
	defer entity_destroy(auth_sig, allocator)

	auth_clone, _ := entity_clone(auth, allocator)
	included := [2]Entity{local.identity.peer_entity, auth_sig}
	response, ok := send_connect(io, conn, "authenticate", auth_clone, included[:], allocator)
	if !ok {
		return Session{}, false
	}
	defer envelope_destroy(response, allocator)
	if st, _ := entity_uint(response.root, "status"); st != 200 {
		return Session{}, false
	}

	grant, hg, _ := entity_field_entity(response.root, "result", allocator)
	if !hg {
		return Session{}, false
	}
	defer entity_destroy(grant, allocator)
	token_hash, hth := entity_bytes(grant, "token")
	if !hth {
		return Session{}, false
	}
	token, htok := envelope_get(response, token_hash)
	if !htok {
		return Session{}, false
	}
	granter_h, hgr := entity_bytes(token, "granter")
	if !hgr {
		return Session{}, false
	}
	granter_peer, hgp := envelope_get(response, granter_h)
	if !hgp {
		return Session{}, false
	}
	cap_sig, hcs := find_sig_for(response, token.hash)
	if !hcs {
		return Session{}, false
	}

	cap_clone, _ := entity_clone(token, allocator)
	granter_clone, _ := entity_clone(granter_peer, allocator)
	sig_clone, _ := entity_clone(cap_sig, allocator)
	return Session{
		io = io,
		local = local,
		remote_peer_id = strings.clone(remote_peer_id, allocator),
		capability = cap_clone,
		granter_peer = granter_clone,
		cap_signature = sig_clone,
		allocator = allocator,
	}, true
}

@(private = "file")
find_sig_for :: proc(env: Envelope, target: []u8) -> (Entity, bool) {
	for inc in env.included {
		e := inc.entity
		if e.typ == "system/signature" {
			if t, ok := entity_bytes(e, "target"); ok && slice.equal(t, target) {
				return e, true
			}
		}
	}
	return Entity{}, false
}

// ── small itoa helpers (avoid core:fmt in the hot path) ───────────────────────

@(private = "file")
itoa :: proc(prefix: string, n: u32, allocator: mem.Allocator) -> string {
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
	return strings.concatenate({prefix, string(digits[i:])}, allocator)
}

@(private = "file")
fmt_req :: proc(n: u32, allocator: mem.Allocator) -> string {return itoa("req-", n, allocator)}
@(private = "file")
fmt_h :: proc(n: u32, allocator: mem.Allocator) -> string {return itoa("h-", n, allocator)}
