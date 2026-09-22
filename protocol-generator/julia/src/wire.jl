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
using ..Cbor: TagRejected
using ..Model: Entity, Envelope, make_entity, entity_tocbor, frame_ofenvelope, envelope_offrame
using ..Model: HashMismatch

export MAX_FRAME, FrameTooLarge
export read_frame, write_frame, read_envelope, write_envelope
export FrameTooLarge, TruncatedFrame, MAX_FRAME
export PreAdmissionRefusal, classify_pre_admission, is_framing_refusal
export make_execute, make_response, error_result, empty_params

# §4.10 resource bound: finite max inbound payload. The length prefix is checked BEFORE the
# body is buffered → reject over-limit as 413 payload_too_large (informative default 16 MiB).
const MAX_FRAME = 16 * 1024 * 1024

struct FrameTooLarge <: Exception; len::Int; end

"""
A frame that never completed: a prefix declaring `n` bytes followed by fewer, or a partial
length prefix. §4.11's framing arm names this input outright — "un-parseable, truncated or
non-canonical CBOR, or a length prefix that never completes" -> `400 invalid_request`.

A SEPARATE TYPE FROM `EOFError`, because the two are different events and `read!` collapses
them: a clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing, while a
stream that ends MID-FRAME is a REFUSAL and is owed a coded frame. Getting it wrong in the
other direction would answer 400 to every peer that simply hangs up. The distinction can
only be made HERE, where the frame boundary is known, which is why `read_frame` counts
bytes with `readbytes!` instead of asking `read!` to raise.
"""
struct TruncatedFrame <: Exception; msg::String; end

# ── frame I/O over a socket ──────────────────────────────────────────────────────────────────
"""Read one length-prefixed frame; the §4.10 length check fires BEFORE buffering the body.
Raises `EOFError` on a closed connection (the reader-loop teardown signal)."""
function read_frame(sock)::Vector{UInt8}
    hdr = Vector{UInt8}(undef, 4)
    got = readbytes!(sock, hdr, 4)
    # ZERO bytes at a FRAME BOUNDARY is an ordinary close and is owed nothing; ONE to
    # THREE is a length prefix that never completed and is a §4.11 framing REFUSAL. This
    # used to be `read!`, which raises the SAME EOFError for both.
    got == 0 && throw(EOFError())
    got < 4 && throw(TruncatedFrame("length prefix: $(got) of 4 bytes"))
    len = (UInt32(hdr[1]) << 24) | (UInt32(hdr[2]) << 16) | (UInt32(hdr[3]) << 8) | UInt32(hdr[4])
    len > MAX_FRAME && throw(FrameTooLarge(Int(len)))     # do NOT read the body (§4.10)
    # A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is refused
    # there as bytes that never become an Envelope.
    len == 0 && return UInt8[]
    body = Vector{UInt8}(undef, Int(len))
    nb = readbytes!(sock, body, Int(len))
    nb < Int(len) && throw(TruncatedFrame("body: $(nb) of $(len) bytes"))
    return body
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

# ── §4.11 pre-admission refusal classification (0.8.2.25) ─────────────────────────────────

"""
The `(status, code, message)` §4.11 assigns a pre-admission failure's CAUSE.

"The frame obligation belongs to the class; the CODE belongs to the cause [MUST]" — a
single code for the class would answer an honest caller under the wrong reason and send
them to the wrong layer.

    connect-auth proof-of-possession      401 authentication_failed  (§4.6/§4.7 — the
                                             connect handler's, not here)
    envelope over the configured maximum  413 payload_too_large      (§4.10(a), N14)
    resolution integrity (mis-keyed inc.) 400 hash_mismatch          (§5.2a, §1.8)
    framing / never becomes an Envelope   400 invalid_request        (§4.7, §4.11)
    root is neither EXECUTE nor E_R       400 invalid_request        (§3.3, §4.11 — in
                                             Peer.dispatch, not here)

THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that code
non-conformant "on the framing arm" and gives its reason in the same sentence:
ENTITY-CBOR-ENCODING defines it for CBOR tag-policy violations specifically, which that
document still MUSTs at decode time (§6.3). The two rows are disjoint by CAUSE rather than
in conflict. Everything else this decoder calls non-canonical (a non-minimal head, an
indefinite length, mis-ordered keys) is genuinely "non-canonical CBOR that never becomes an
Envelope" and takes invalid_request.

ORDER IS NOT LOAD-BEARING HERE AND THAT IS A PROPERTY OF THE SUBSTRATE, not of the rule.
Julia selects the method by the argument's concrete type, and the four exception types are
siblings rather than a hierarchy, so the arms are mutually exclusive by construction. The
trade is that a NEW decode-side exception silently lands on the `::Any` fallback instead of
being an error — which is why every type this classifier is meant to separate has its own
method here explicitly, never by exclusion.

The messages are a FIXED TABLE, never the exception's own text: an exception message is a
developer diagnostic and can name internal state. ASCII by discipline.
"""
const PreAdmissionRefusal = Tuple{Int,String,String}

classify_pre_admission(::FrameTooLarge)::PreAdmissionRefusal =
    (413, "payload_too_large", "frame exceeds the configured maximum")
classify_pre_admission(::HashMismatch)::PreAdmissionRefusal =
    (400, "hash_mismatch", "included entry does not bind to its key")
classify_pre_admission(::TagRejected)::PreAdmissionRefusal =
    (400, "non_canonical_ecf", "CBOR tag in a data-field position")
classify_pre_admission(::Any)::PreAdmissionRefusal =
    (400, "invalid_request", "frame does not decode to an envelope")

"""
Whether a `read_frame` failure is a REFUSAL owed a coded frame at all (§4.11).

A closed or reset socket is not a refusal of anything and there is nobody left to answer;
an `EOFError` here is the ordinary close at a frame boundary, which `read_frame` raises
only when ZERO bytes of a prefix arrived.
"""
is_framing_refusal(::FrameTooLarge)::Bool = true
is_framing_refusal(::TruncatedFrame)::Bool = true
is_framing_refusal(::Any)::Bool = false

end # module Wire
