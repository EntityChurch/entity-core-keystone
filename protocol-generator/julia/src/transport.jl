# Transport (L4) — TCP listener + dialer + per-connection reader Task + the §6.11 request_id
# demux, on the SINGLE-THREADED Task scheduler (profile [async]; A-JULIA-005).
#
# CONCURRENCY MODEL (§4.8 / §6.11 / §7b), all on ONE OS thread, Tasks cooperatively scheduled:
#   • One READER Task per connection demuxes inbound frames. An EXECUTE_RESPONSE is routed to the
#     awaiting outbound caller BY request_id via a per-request `Channel`; an inbound EXECUTE is
#     dispatched on its OWN `@async` Task (§4.8) so a handler that originates an outbound EXECUTE
#     (§6.11 reentry) and awaits its reply does NOT block the reader — the reader keeps reading
#     and `put!`s the correlated reply into the waiter's channel. On the cooperative scheduler
#     this reentry is a PLAIN CHANNEL HANDOFF: no cross-thread demux, no correlation-map tax, no
#     deadlock (the actor/CSP/event-loop result — profile [async].request_demux).
#   • WRITES are serialized by a `ReentrantLock` so a frame (4-byte len + body, which yields at
#     the libuv `write`/`flush`) is emitted atomically w.r.t. any other Task sharing the socket.
#     The STORE needs no such lock — it is structurally race-free (see store.jl §7b note).
#   • A never-arriving reply is bounded by connection close, which closes every pending channel
#     → each waiter wakes with `connection_broken` (§6.12 / §3.6 teardown contract).
#   • TCP_NODELAY is set on every accepted + dialed socket (§7b transport menu).
module Transport

using Sockets
using ..Cbor: CborMap
using ..Model: Entity, Envelope, make_entity, textfield, bytesfield, uintfield, entityfield, included_get, envelope_offrame, salvage_request_id
using ..Wire: read_envelope, write_envelope, read_frame, make_execute, make_response, error_result, empty_params, FrameTooLarge
using ..Wire: TruncatedFrame, classify_pre_admission, is_framing_refusal
using ..Identity: PeerIdentity, sign_entity
using ..Peer: Peer_t, Conn, dispatch

export Io, serve_connection, dial, read_loop, outbound, execute_raw
export Session, initiate, session_execute, close_io

# ── per-connection IO: socket + write serialization + §6.11 pending-response demux ────────────
mutable struct Io
    sock::Any
    conn::Conn
    pending::Dict{String,Channel{Envelope}}   # request_id → 1-slot reply channel
    out_counter::Int
    write_lock::ReentrantLock
    closed::Bool
end
function Io(sock, conn::Conn)
    io = Io(sock, conn, Dict{String,Channel{Envelope}}(), 0, ReentrantLock(), false)
    conn.outbound = req -> outbound(io, req)   # bind the §6.11 reentry seam for this connection
    return io
end

set_nodelay(sock) = try; Sockets.nagle(sock, false); catch; end   # §7b transport menu (best-effort)

function send_framed(io::Io, env::Envelope)
    lock(io.write_lock) do
        write_envelope(io.sock, env)
    end
end

# Route an inbound EXECUTE_RESPONSE to its awaiting outbound caller (§6.11).
function route_response(io::Io, env::Envelope)
    rid = textfield(env.root, "request_id"); rid = rid === nothing ? "" : rid
    ch = get(io.pending, rid, nothing)
    ch === nothing && return                    # unmatched (late/duplicate) reply → drop
    isopen(ch) && put!(ch, env)
    return nothing
end

"""§6.11 outbound: send a request, await its correlated reply by request_id. Returns the
reply Envelope, or `nothing` if the connection closed first (connection_broken)."""
function outbound(io::Io, request::Envelope)::Union{Nothing,Envelope}
    io.closed && return nothing
    rid = textfield(request.root, "request_id"); rid = rid === nothing ? "" : rid
    ch = Channel{Envelope}(1)
    io.pending[rid] = ch
    try
        send_framed(io, request)
        return take!(ch)                        # yields THIS Task until the reader put!s the reply
    catch e
        return nothing                          # channel closed on teardown → connection_broken
    finally
        delete!(io.pending, rid)
    end
end

# Build + send an arbitrary EXECUTE and await the reply (used for connect-path + unauthenticated
# probes in the smoke). Authenticated requests go through `session_execute`.
function execute_raw(io::Io, uri, operation, params::Entity; request_id::AbstractString)
    exec = make_execute(request_id=request_id, uri=uri, operation=operation, params=params)
    return outbound(io, Envelope(exec))
end

# Dispatch one inbound EXECUTE on its own Task; write the response (§4.8).
function dispatch_and_reply(peer::Peer_t, io::Io, env::Envelope)
    resp = dispatch(peer, io.conn, env)
    # `dispatch` now answers EVERY inbound root, including the non-EXECUTE one that used
    # to come back `nothing` and be dropped (§4.11, N12/N17). The guard stays because the
    # return type still admits `nothing` and a silent drop is the failure it would be.
    resp === nothing && return
    try
        send_framed(io, resp)
    catch
    end
    return nothing
end

"""
Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame refused
BEFORE it becomes an admitted request.

"A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the wire
[MUST] — correlated by request_id where the id is available, and otherwise as a
best-effort coded frame carrying no correlation."

§4.9(c)'s deliver-or-signal rule is scoped to "every request the peer ADMITS" and therefore
reaches none of these, which is why §4.11 exists. Both of the non-conformant behaviours it
names SEPARATELY were present on this peer: DROPPING the frame (the un-salvageable decode
arm and the non-EXECUTE root, "the weaker of the two precisely because nothing surfaces
it") and CLOSING with no coded frame (the oversize arm's bare `break`).

AN EMPTY `rid` IS THE BEST-EFFORT FORM, not a bug: it is what the section prescribes where
no id can be recovered. This used to return early on a `nothing` salvage, which is exactly
the silence §4.11 forbids.
"""
function refuse_pre_admission(io::Io, rid::AbstractString, refusal)
    io.closed && return nothing           # nobody left to answer
    status, code, message = refusal
    try
        resp = make_response(request_id=String(rid), status=status,
                             result=error_result(code, message))
        # THROUGH `send_framed`, WHICH TAKES THE PER-CONNECTION WRITE LOCK. The previous
        # reject path wrote `write_envelope(io.sock, ...)` directly and so bypassed it —
        # a latent stream-corruption bypass that only became REACHABLE with this change,
        # because it used to fire solely when a request_id could be salvaged and now
        # fires on every pre-admission refusal. A frame is `[4-byte len][body]` and each
        # `write` yields the Task, so an unlocked refusal interleaving with an @async
        # dispatch reply produces a spliced frame the CALLER decodes as "trailing bytes
        # after top-level item" — which reads as a codec bug in the READER. Measured: it
        # showed up on the first four-refusal connection this file drove.
        send_framed(io, Envelope(resp))
    catch
        # A write failure here is a dead socket, not a protocol decision.
    end
    return nothing
end

"""
A COMPLETE frame the decoder refused. The framing is intact, so we answer and KEEP SERVING,
and the refusal MUST be a status rather than silence (§4.11; §4.9(c) says the same from the
other direction).

THE CODE IS THE CAUSE'S (§4.11, §5.2a). This answered `non_canonical_ecf` for every cause
until 0.8.2.24/.25 pinned them apart: a mis-keyed `included` entry is `400 hash_mismatch`
(its encoding is canonical — what is false is the claim the key makes), a tag-policy
violation keeps `non_canonical_ecf`, and everything else that never becomes an Envelope is
`400 invalid_request`.

The frame is still REJECTED — only enough is salvaged to correlate the response, and an
unrecoverable id takes §4.11's uncorrelated best-effort form.
"""
function reject_frame(io::Io, payload::AbstractVector{UInt8}, e)
    rid = salvage_request_id(payload)
    refuse_pre_admission(io, rid === nothing ? "" : rid, classify_pre_admission(e))
    return nothing
end

"""The reader loop (§6.11 demux): EXECUTE_RESPONSE → route; EXECUTE → dispatch on its own Task.
Runs until the connection closes / a frame ends it; closes all pending channels on exit."""
function read_loop(peer::Peer_t, io::Io)
    while true
        payload = try
            read_frame(io.sock)
        catch e
            # §4.11: an OVERSIZE prefix and a TRUNCATED frame are REFUSALS owed a coded
            # frame, and both used to be a bare `break` — "closing with no coded frame",
            # which is indistinguishable from a network fault and, on a multiplexed
            # connection, destroys unrelated ADMITTED requests. §4.10(a)'s mood was raised
            # SHOULD -> MUST at 0.8.2.25 (N14): the over-size condition is detected at the
            # length prefix with the connection intact and nothing spent, so the permissive
            # mood had nothing to license.
            #
            # The stream is desynchronized on both arms — an oversize body was never
            # drained, a truncated one never arrived — so the frame goes out and THEN the
            # reader ends. §4.11 makes the frame mandatory and leaves the close to us.
            #
            # §4.11's best-effort UNCORRELATED form: no request_id can be recovered from a
            # frame whose body never arrived, and guessing one would correlate the refusal
            # to somebody else's in-flight request. Anything `is_framing_refusal` does NOT
            # name — an EOFError at a frame boundary, a reset socket — is not a refusal of
            # anything and there is nobody left to answer.
            is_framing_refusal(e) && refuse_pre_admission(io, "", classify_pre_admission(e))
            break
        end
        env = try
            envelope_offrame(payload)
        catch e
            # §6.3: "Rejection returns 400 non_canonical_ecf" — a rejected frame is
            # owed a STATUS, not silence. This used to `continue`, which rejected the
            # frame (correct) and then dropped it on the floor (wrong): the sender saw
            # no response at all and blocked until its own timeout, violating §6.3's
            # second sentence and §4.9(c) deliver-or-signal. It also made a refusal
            # indistinguishable from a dead peer, and on a single-connection oracle run
            # it poisons every later request on the same connection.
            #
            # The frame is still REJECTED — only enough is salvaged to correlate the
            # response. If even the request_id is unrecoverable the frame is
            # unattributable and silence is the only option left.
            reject_frame(io, payload, e)
            continue                             # frame boundary known → keep reading
        end
        if env.root.typ == "system/protocol/execute/response"
            route_response(io, env)
        else
            @async dispatch_and_reply(peer, io, env)
        end
    end
    close_io(io)
    return nothing
end

function close_io(io::Io)
    io.closed = true
    for ch in values(io.pending)
        isopen(ch) && close(ch)                  # wake every waiter → connection_broken
    end
    try; close(io.sock); catch; end
    return nothing
end

# ── listener / dialer ──────────────────────────────────────────────────────────────────────────
"""Accept the connection, run its reader loop to completion (blocks the calling Task)."""
function serve_connection(peer::Peer_t, sock)
    set_nodelay(sock)
    io = Io(sock, Conn())
    read_loop(peer, io)
    return nothing
end

"""Dial a peer; returns an `Io` with its reader loop already spawned (@async)."""
function dial(host, port)::Io
    sock = Sockets.connect(host, port)
    set_nodelay(sock)
    return Io(sock, Conn())
end

# ── initiator handshake (§4.1) + authenticated session ───────────────────────────────────────
struct Session
    io::Io
    local_id::PeerIdentity
    remote_peer_id::String
    capability::Entity        # the seed token minted for us at authenticate
    granter_peer::Entity      # the responder's system/peer (the granter)
    cap_signature::Entity     # the granter's signature over the token
    req_counter::Base.RefValue{Int}
end

sig_for(env::Envelope, target::AbstractVector{UInt8}) = begin
    r = nothing
    for (_, e) in env.included
        if e.typ == "system/signature"
            t = bytesfield(e, "target")
            t !== nothing && t == target && (r = e)
        end
    end
    r
end

"""Run the §4.1/§4.6 handshake (hello → authenticate) over `io`; returns an authenticated
`Session`. Both request/response legs traverse real frames through the responder's dispatch."""
function initiate(io::Io, local_id::PeerIdentity)::Session
    io.out_counter += 1
    # §4.5 makes `protocols` Required with NO default, so a hello that omits it is a
    # MALFORMED hello and a conforming responder answers 400 invalid_request. This
    # dialer used to send empty params and it worked only because no peer enforced
    # the rule — the moment the responder side landed, the peer could not complete a
    # handshake with itself. THE ORACLE CANNOT SEE THIS: its origination check
    # reuses the INBOUND connection and never makes us dial.
    hello_params = make_entity("primitive/any", CborMap(Pair[
        ("peer_id" => local_id.peer_id),
        ("protocols" => Any["entity-core/1.0"]),
        ("hash_formats" => Any["ecfv1-sha256"]),
        ("key_types" => Any["ed25519"])]))
    r1 = execute_raw(io, "system/protocol/connect", "hello", hello_params;
                     request_id="h-$(io.out_counter)")
    r1 === nothing && error("handshake: no hello response")
    status_of(r1) == 200 || error("handshake: hello status $(status_of(r1))")
    hello = entityfield(r1.root, "result")
    hello === nothing && error("handshake: hello result missing")
    remote_peer_id = textfield(hello, "peer_id")
    remote_nonce = bytesfield(hello, "nonce")
    (remote_peer_id === nothing || remote_nonce === nothing) && error("handshake: malformed hello")

    auth = make_entity("system/protocol/connect/authenticate",
        CborMap(Pair[("peer_id" => local_id.peer_id),
                     ("public_key" => local_id.public_key),
                     ("key_type" => "ed25519"),
                     ("nonce" => remote_nonce)]))
    auth_sig = sign_entity(local_id, auth)
    io.out_counter += 1
    exec = make_execute(request_id="h-$(io.out_counter)", uri="system/protocol/connect",
                        operation="authenticate", params=auth)
    inc = Pair{Vector{UInt8},Entity}[local_id.peer_entity.hash => local_id.peer_entity,
                                     auth_sig.hash => auth_sig]
    r2 = outbound(io, Envelope(exec, inc))
    r2 === nothing && error("handshake: no authenticate response")
    status_of(r2) == 200 || error("handshake: authenticate status $(status_of(r2))")
    grant = entityfield(r2.root, "result")
    grant === nothing && error("handshake: grant result missing")
    token_h = bytesfield(grant, "token")
    token_h === nothing && error("handshake: grant token missing")
    token = included_get(r2, token_h)
    token === nothing && error("handshake: token not in included")
    granter_h = bytesfield(token, "granter")
    granter = included_get(r2, granter_h)
    cap_sig = sig_for(r2, token.hash)
    (granter === nothing || cap_sig === nothing) && error("handshake: granter/cap-sig missing")

    return Session(io, local_id, String(remote_peer_id), token, granter, cap_sig, Ref(0))
end

# The EXECUTE_RESPONSE `status` is a CBOR integer (§3.3).
status_of(env::Envelope) = (v = uintfield(env.root, "status"); v === nothing ? -1 : Int(v))

"""Send an AUTHENTICATED EXECUTE (§5.8 chain inclusion: author peer, exec-sig, cap token,
granter peer, cap-sig) and await the correlated reply."""
function session_execute(s::Session, uri::AbstractString, operation::AbstractString, params::Entity)
    s.req_counter[] += 1
    rid = "req-$(s.req_counter[])"
    exec = make_execute(request_id=rid, uri=uri, operation=operation, params=params,
                        author=s.local_id.peer_entity.hash, capability=s.capability.hash)
    exec_sig = sign_entity(s.local_id, exec)
    inc = Pair{Vector{UInt8},Entity}[
        s.local_id.peer_entity.hash => s.local_id.peer_entity,
        exec_sig.hash => exec_sig,
        s.capability.hash => s.capability,
        s.granter_peer.hash => s.granter_peer,
        s.cap_signature.hash => s.cap_signature]
    return outbound(s.io, Envelope(exec, inc))
end

end # module Transport
