# Wire framing (§1.6) and the two L2 message builders (§3.2 EXECUTE, §3.3 EXECUTE_RESPONSE).
# Frame := [4-byte BE length][CBOR-encoded envelope].  ONLY EXECUTE and EXECUTE_RESPONSE are
# message roots (§3.3); `hello`/`authenticate` are OPERATIONS on system/protocol/connect, not
# message types.
#
# I/O is over the Sockets-stdlib `TCPSocket` under the async Task scheduler: `read!` yields the
# Task (never blocks the one scheduler thread) until the bytes arrive, and EOF on close raises
# `EOFError` — the reader loop's clean teardown signal (profile [async].blocking_discipline).
module Wire

using Sockets
using ..Cbor: CborMap
using ..Model: Entity, Envelope, make_entity, entity_tocbor, frame_ofenvelope, envelope_offrame

export MAX_FRAME, FrameTooLarge
export read_frame, write_frame, read_envelope, write_envelope
export make_execute, make_response, error_result, empty_params

# §4.10 resource bound: finite max inbound payload. The length prefix is checked BEFORE the
# body is buffered → reject over-limit as 413 payload_too_large (informative default 16 MiB).
const MAX_FRAME = 16 * 1024 * 1024

struct FrameTooLarge <: Exception; len::Int; end

# ── frame I/O over a socket ──────────────────────────────────────────────────────────────────
"""Read one length-prefixed frame; the §4.10 length check fires BEFORE buffering the body.
Raises `EOFError` on a closed connection (the reader-loop teardown signal)."""
function read_frame(sock)::Vector{UInt8}
    hdr = read!(sock, Vector{UInt8}(undef, 4))
    len = (UInt32(hdr[1]) << 24) | (UInt32(hdr[2]) << 16) | (UInt32(hdr[3]) << 8) | UInt32(hdr[4])
    len > MAX_FRAME && throw(FrameTooLarge(Int(len)))     # do NOT read the body (§4.10)
    return read!(sock, Vector{UInt8}(undef, Int(len)))
end

function write_frame(sock, payload::AbstractVector{UInt8})
    len = length(payload)
    hdr = UInt8[(len >> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]
    write(sock, hdr)
    write(sock, payload)
    flush(sock)
    return nothing
end

read_envelope(sock)::Envelope = envelope_offrame(read_frame(sock))
write_envelope(sock, env::Envelope) = write_frame(sock, frame_ofenvelope(env))

# ── EXECUTE builder (§3.2) ────────────────────────────────────────────────────────────────────
# `params` is itself an entity (its wire form is nested as the `params` field). An authenticated
# EXECUTE additionally carries `author` (the caller's system/peer content_hash) and `capability`
# (the presented cap's content_hash); a connect-path EXECUTE carries neither (§4.2 pre-auth).
function make_execute(; request_id::AbstractString, uri::AbstractString, operation::AbstractString,
                        params::Entity,
                        author::Union{Nothing,AbstractVector{UInt8}}=nothing,
                        capability::Union{Nothing,AbstractVector{UInt8}}=nothing)::Entity
    ps = Pair[("request_id" => String(request_id)),
              ("uri" => String(uri)),
              ("operation" => String(operation)),
              ("params" => entity_tocbor(params))]
    author === nothing || push!(ps, "author" => Vector{UInt8}(author))
    capability === nothing || push!(ps, "capability" => Vector{UInt8}(capability))
    return make_entity("system/protocol/execute", CborMap(ps))
end

# ── EXECUTE_RESPONSE builder (§3.3) ─────────────────────────────────────────────────────────────
function make_response(; request_id::AbstractString, status::Integer, result::Entity)::Entity
    return make_entity("system/protocol/execute/response",
        CborMap(Pair[("request_id" => String(request_id)),
                     ("status" => Int(status)),
                     ("result" => entity_tocbor(result))]))
end

# system/protocol/error result entity (§3.3).
function error_result(code::AbstractString, message::Union{Nothing,AbstractString}=nothing)::Entity
    ps = Pair[("code" => String(code))]
    message === nothing || push!(ps, "message" => String(message))
    return make_entity("system/protocol/error", CborMap(ps))
end

# Empty-params entity (§3.2): primitive/any whose data is the canonical empty map.
empty_params()::Entity = make_entity("primitive/any", CborMap(Pair[]))

end # module Wire
