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
    resp === nothing && return
    try
        send_framed(io, resp)
    catch
    end
    return nothing
end

"""§6.3: answer a rejected frame with `400 non_canonical_ecf`, correlated by the
request_id salvaged from it. Best-effort — a failure here degrades to the silence this
exists to remove, which is no worse than the old behaviour."""
function reject_frame(io::Io, payload::AbstractVector{UInt8})
    rid = salvage_request_id(payload)
    rid === nothing && return nothing
    try
        resp = make_response(request_id=rid, status=400,
                             result=error_result("non_canonical_ecf"))
        write_envelope(io.sock, Envelope(resp))
    catch
        # write failure ends this exchange; the reader keeps going
    end
    return nothing
end

"""The reader loop (§6.11 demux): EXECUTE_RESPONSE → route; EXECUTE → dispatch on its own Task.
Runs until the connection closes / a frame ends it; closes all pending channels on exit."""
function read_loop(peer::Peer_t, io::Io)
    while true
        payload = try
            read_frame(io.sock)
        catch e
            e isa EOFError && break              # peer closed → clean teardown
            e isa FrameTooLarge && break         # §4.10: cannot resync a length-prefixed stream
            break
        end
        env = try
            envelope_offrame(payload)
        catch
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
            reject_frame(io, payload)
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
    r1 = execute_raw(io, "system/protocol/connect", "hello", empty_params();
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
