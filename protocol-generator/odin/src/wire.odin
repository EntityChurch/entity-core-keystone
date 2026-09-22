package entity_core

import "core:net"

// Wire framing (§1.6) and the two L2 message builders (§3.2 EXECUTE, §3.3
// EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR-encoded envelope payload].
// Reads/writes a full frame over a TCP socket; the reader/writer threading lives
// in transport.odin (raw OS threads, profile [async]).
//
// No-GC idiom: builders return owned Entities the caller frees; frame I/O uses a
// caller-provided allocator for the read buffer (caller frees).

MAX_FRAME :: 16 * 1024 * 1024 // §4.10(a) — 16 MiB inbound payload bound

Wire_Error :: enum {
	None = 0,
	Closed,
	// A stream that ended MID-FRAME: a partial length prefix, or a prefix declaring
	// n bytes followed by fewer. §4.11's framing arm names this input outright and
	// makes it a REFUSAL owed a coded frame, where a clean EOF at a FRAME BOUNDARY
	// (.Closed above) is an ordinary hangup and is owed nothing. The two arrive at the
	// socket as the same short read, so the distinction can only be made where the frame
	// boundary is known -- here -- and getting it wrong in the other direction answers
	// 400 to every peer that simply hangs up.
	Truncated,
	Frame_Too_Large,
	Write_Failed,
	Codec,
}

// ── socket read/write of a full frame ─────────────────────────────────────────

// Fill `buf` completely. Reports how many bytes DID arrive, because the caller is the
// only place that knows whether a short read is an ordinary close or a truncation.
read_exact :: proc(sock: net.TCP_Socket, buf: []u8) -> (got: int, err: Wire_Error) {
	off := 0
	for off < len(buf) {
		n, e := net.recv_tcp(sock, buf[off:])
		if e != nil || n == 0 {
			return off, .Closed
		}
		off += n
	}
	return off, .None
}

// read_frame reads one length-prefixed frame; returns the owned payload (caller
// frees). §4.10(a): a length prefix over MAX_FRAME is rejected BEFORE buffering.
read_frame :: proc(
	sock: net.TCP_Socket,
	allocator := context.allocator,
) -> (payload: []u8, err: Wire_Error) {
	hdr: [4]u8
	if got, e := read_exact(sock, hdr[:]); e != .None {
		// ZERO bytes of the prefix is the ordinary close; one to three is a PARTIAL
		// LENGTH PREFIX, which §4.11 owes a coded frame. This arm is the one a naive
		// read-exact collapses into a hangup, and it is invisible to a driver whose
		// "truncated" case sends a COMPLETE prefix -- that truncation is caught in the
		// body read below instead.
		return nil, got == 0 ? .Closed : .Truncated
	}
	length :=
		u32(hdr[0]) << 24 | u32(hdr[1]) << 16 | u32(hdr[2]) << 8 | u32(hdr[3])
	if int(length) > MAX_FRAME {
		return nil, .Frame_Too_Large
	}
	// A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
	// refused there as bytes that never become an Envelope.
	buf := make([]u8, int(length), allocator)
	if _, e := read_exact(sock, buf); e != .None {
		delete(buf, allocator)
		// The prefix arrived and the body did not: a truncation whatever the socket
		// called it.
		return nil, .Truncated
	}
	return buf, .None
}

// write_frame writes a length-prefixed frame. The caller serializes concurrent
// writes (the transport holds a mutex over the shared socket).
write_frame :: proc(sock: net.TCP_Socket, payload: []u8) -> Wire_Error {
	hdr: [4]u8
	l := u32(len(payload))
	hdr[0] = u8(l >> 24)
	hdr[1] = u8(l >> 16)
	hdr[2] = u8(l >> 8)
	hdr[3] = u8(l)
	if !send_all(sock, hdr[:]) {
		return .Write_Failed
	}
	if !send_all(sock, payload) {
		return .Write_Failed
	}
	return .None
}

send_all :: proc(sock: net.TCP_Socket, buf: []u8) -> bool {
	off := 0
	for off < len(buf) {
		n, err := net.send_tcp(sock, buf[off:])
		if err != nil || n == 0 {
			return false
		}
		off += n
	}
	return true
}

// ── EXECUTE_RESPONSE builder (§3.3) ───────────────────────────────────────────

// make_response builds an EXECUTE_RESPONSE entity. Takes ownership of `result`
// (consumed into the response's data tree — freed here). Returns an owned Entity.
make_response :: proc(
	request_id: string,
	status: u64,
	result: Entity,
	allocator := context.allocator,
) -> (Entity, Codec_Error) {
	result_cbor := entity_to_cbor(result, allocator)
	entity_destroy(result, allocator)
	pairs := make([]Ec_Pair, 3, allocator)
	pairs[0] = Ec_Pair{text_val("request_id", allocator), text_val(request_id, allocator)}
	pairs[1] = Ec_Pair{text_val("status", allocator), Ec_Uint(status)}
	pairs[2] = Ec_Pair{text_val("result", allocator), result_cbor}
	return entity_make("system/protocol/execute/response", Ec_Map(pairs), allocator)
}

// ── EXECUTE builder (§3.2) ────────────────────────────────────────────────────

Execute_Fields :: struct {
	request_id:     string,
	uri:            string,
	operation:      string,
	params:         Entity, // consumed
	resource:       Ec_Value, // optional; nil if absent (consumed if present)
	has_resource:   bool,
	author:         []u8, // optional; nil if absent
	capability:     []u8, // optional; nil if absent
}

// make_execute builds an EXECUTE entity. Consumes `params` (and `resource` if
// present). Returns an owned Entity the caller frees.
make_execute :: proc(f: Execute_Fields, allocator := context.allocator) -> (Entity, Codec_Error) {
	params_cbor := entity_to_cbor(f.params, allocator)
	entity_destroy(f.params, allocator)

	list := make([dynamic]Ec_Pair, allocator)
	append(&list, Ec_Pair{text_val("request_id", allocator), text_val(f.request_id, allocator)})
	append(&list, Ec_Pair{text_val("uri", allocator), text_val(f.uri, allocator)})
	append(&list, Ec_Pair{text_val("operation", allocator), text_val(f.operation, allocator)})
	append(&list, Ec_Pair{text_val("params", allocator), params_cbor})
	if f.author != nil {
		append(&list, Ec_Pair{text_val("author", allocator), bytes_val(f.author, allocator)})
	}
	if f.capability != nil {
		append(&list, Ec_Pair{text_val("capability", allocator), bytes_val(f.capability, allocator)})
	}
	if f.has_resource {
		append(&list, Ec_Pair{text_val("resource", allocator), f.resource})
	}
	return entity_make("system/protocol/execute", Ec_Map(list[:]), allocator)
}

// ── small result entities ─────────────────────────────────────────────────────

// error_result builds a system/protocol/error result entity (§3.3). Owned.
error_result :: proc(
	code: string,
	message: string,
	allocator := context.allocator,
) -> (Entity, Codec_Error) {
	list := make([dynamic]Ec_Pair, allocator)
	append(&list, Ec_Pair{text_val("code", allocator), text_val(code, allocator)})
	if message != "" {
		append(&list, Ec_Pair{text_val("message", allocator), text_val(message, allocator)})
	}
	return entity_make("system/protocol/error", Ec_Map(list[:]), allocator)
}

// empty_params builds the empty-params entity (§3.2): primitive/any whose data is
// the canonical empty map (single byte 0xA0 on the wire — N3).
empty_params :: proc(allocator := context.allocator) -> (Entity, Codec_Error) {
	return entity_make("primitive/any", Ec_Map(make([]Ec_Pair, 0, allocator)), allocator)
}

// set_no_delay disables Nagle on a socket (§7b). Best-effort — a failure just
// leaves Nagle on, not fatal. Small request/response frames otherwise pay the
// ~40ms delayed-ACK penalty every round trip.
set_no_delay :: proc(sock: net.TCP_Socket) {
	_ = net.set_option(sock, .TCP_Nodelay, true)
}
