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

// reject_frame answers a rejected frame with `400 non_canonical_ecf` (§6.3),
// correlated by the request_id salvaged from it. Best-effort -- a failure here
// degrades to the silence this exists to remove, which is no worse than the old
// behaviour.
@(private = "file")
reject_frame :: proc(io: ^Io, payload: []u8) {
	rid, ok := salvage_request_id(payload, io.allocator)
	if !ok {
		return
	}
	defer delete(rid, io.allocator)
	errv, eerr := error_result("non_canonical_ecf", "", io.allocator)
	if eerr != .None {
		return
	}
	root, rerr := make_response(rid, 400, errv, io.allocator)
	if rerr != .None {
		return
	}
	env := Envelope{root = root, included = nil}
	io_write_framed(io, env)
}

// read_loop: EXECUTE_RESPONSE → route; EXECUTE → dispatch on its own thread.
// Runs until the connection closes / a frame ends it. Uses `context.allocator`
// (the caller sets it) for the read buffer + envelope; a malformed frame is
// dropped and the loop keeps reading (§4.9 deliver-or-signal, never crash).
read_loop :: proc(peer: ^Peer, conn: ^Conn, io: ^Io) {
	for {
		payload, perr := read_frame(io.sock, io.allocator)
		if perr != .None {
			break
		}
		env, eerr := envelope_of_frame(payload, io.allocator)
		if eerr != .None {
			// §6.3: "Rejection returns 400 non_canonical_ecf" -- a rejected frame is
			// owed a STATUS, not silence. This used to `continue`, which rejected the
			// frame (correct) and then dropped it on the floor (wrong): the sender saw
			// no response at all and blocked until its own timeout, violating §6.3's
			// second sentence and §4.9(c) deliver-or-signal. It also made a refusal
			// indistinguishable from a dead peer, and on a single-connection oracle run
			// it poisons every later request on the same connection.
			//
			// The frame is still REJECTED -- only enough is salvaged to correlate the
			// response. If even the request_id is unrecoverable the frame is
			// unattributable and silence is the only option left.
			reject_frame(io, payload)
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

// initiate runs the initiator handshake (§4.1): hello → authenticate → Session.
initiate :: proc(local: ^Peer, io: ^Io, conn: ^Conn, allocator := context.allocator) -> (Session, bool) {
	// 1. hello
	hello_params, _ := empty_params(allocator)
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
