# Entity Canonical Form (ECF) — hand-rolled canonical CBOR (profile [codec], A-JULIA-002).
#
# Why hand-rolled and not CBOR.jl: ECF (ENTITY-CBOR-ENCODING.md v1.5, RFC 8949 §4.2 with
# Entity clarifications) needs (a) length-then-lex map-key ordering, (b) shortest-float
# minimisation incl. f16, (c) recursive major-type-6 tag rejection on decode (N2),
# (d) full uint64/nint range. No Julia CBOR lib offers these, and a faithful ECF codec must
# OWN the canonical layer regardless (the A-005 pattern) — so a library buys nothing.
#
# THE HEADLINE MECHANISM (profile [idiom].multiple_dispatch_codec): `encode!` is a generic
# function dispatched by MULTIPLE DISPATCH on the Julia value TYPE — the type system makes
# CBOR major-type selection natural (String→mt3, Vector{UInt8}→mt2, Integer→mt0/1,
# AbstractFloat→mt7, Bool→mt7, Nothing→mt7). A-JULIA-006: branch exclusivity is verified —
# `String` is NOT an `AbstractVector`; a `Vector{UInt8}` is NOT a `String`; `Bool <: Integer`
# so the `Bool` method (more specific) wins over `Integer`; arrays are built as `Vector{Any}`
# so they never collide with byte-strings (`Vector{UInt8}`). No value shimmers across two
# branches.
module Cbor

export CborMap, encode, decode, decode_salvage, NonCanonicalECF, TruncatedInput, TagRejected

# ── error model (profile [error_model] = exceptions; custom <: Exception leaves) ──────────
abstract type EntityCoreError <: Exception end
struct NonCanonicalECF <: EntityCoreError; msg::String; end
struct TruncatedInput  <: EntityCoreError; msg::String; end
struct TagRejected     <: EntityCoreError; end
struct DuplicateKey    <: EntityCoreError; end
struct UnsupportedSimple <: EntityCoreError; ai::Int; end

# ── value model ───────────────────────────────────────────────────────────────────────────
# A CBOR map is an ORDERED pair list (NOT a Julia Dict): duplicate keys must be representable
# (to reject them, Rule 5) and byte-string keys must keep their type distinct from text keys.
# encode! sorts by encoded-key bytes, so insertion order is irrelevant to output.
struct CborMap
    pairs::Vector{Pair{Any,Any}}
end
CborMap() = CborMap(Pair{Any,Any}[])
CborMap(ps::AbstractVector) = CborMap(Pair{Any,Any}[Pair{Any,Any}(k, v) for (k, v) in ps])

# ── float16 exact decode (mirror of the encoder's round-trip check) ─────────────────────────
function half_to_double(h::UInt16)::Float64
    # Julia's Float16 is native: reinterpret the bits and widen. Handles ±0, subnormal,
    # inf and NaN exactly per IEEE-754 binary16→binary64.
    return Float64(reinterpret(Float16, h))
end

# ── big-endian argument emit ────────────────────────────────────────────────────────────────
@inline function be!(out::Vector{UInt8}, v::UInt64, nbytes::Int)
    i = nbytes
    while i > 0
        i -= 1
        push!(out, UInt8((v >> (8 * i)) & 0xff))
    end
    return nothing
end

# Emit a CBOR head: major type (0..7) << 5 | minimal-length unsigned argument (RFC 8949 §4.2.1).
@inline function addhead!(out::Vector{UInt8}, major::UInt8, arg::UInt64)
    mt = major << 5
    if arg < 0x18                      # < 24  → immediate
        push!(out, mt | UInt8(arg))
    elseif arg < 0x100                 # 1-byte argument
        push!(out, mt | 0x18); be!(out, arg, 1)
    elseif arg < 0x10000               # 2-byte argument
        push!(out, mt | 0x19); be!(out, arg, 2)
    elseif arg < 0x100000000           # 4-byte argument
        push!(out, mt | 0x1a); be!(out, arg, 4)
    else                               # 8-byte argument
        push!(out, mt | 0x1b); be!(out, arg, 8)
    end
    return nothing
end

# ── canonical map-key ordering: encoded-length ascending, then bytewise-lex ascending ───────
@inline function canon_less(a::Vector{UInt8}, b::Vector{UInt8})::Bool
    la, lb = length(a), length(b)
    la != lb && return la < lb
    return a < b            # Julia's Vector{UInt8} isless is bytewise-lexicographic
end

# ── shortest-float ladder (Rule 4): f16 ← f32 ← f64, native Float16/Float32 ──────────────────
# NaN canonicalises to f9 7e00 (Rule 4a). Otherwise EMIT the narrowest form that round-trips
# BIT-EXACTLY back to the f64 (bit compare via reinterpret so -0.0 ≠ 0.0). Float16 is a native
# Julia type, so the f16 leg needs no hand-rolled half-float packer — but the ladder DECISION
# (does it round-trip?) is hand-made regardless.
function encode_float!(out::Vector{UInt8}, x::Float64)
    if isnan(x)
        push!(out, 0xf9); be!(out, 0x7e00 % UInt64, 2); return nothing
    end
    xb = reinterpret(UInt64, x)
    h = Float16(x)
    if reinterpret(UInt64, Float64(h)) == xb
        push!(out, 0xf9); be!(out, UInt64(reinterpret(UInt16, h)), 2); return nothing
    end
    s = Float32(x)
    if reinterpret(UInt64, Float64(s)) == xb
        push!(out, 0xfa); be!(out, UInt64(reinterpret(UInt32, s)), 4); return nothing
    end
    push!(out, 0xfb); be!(out, xb, 8); return nothing
end

# ── encode! — multiple dispatch on the value type (the headline mechanism) ──────────────────
# Bool BEFORE Integer: `Bool <: Integer`, and the Bool method is more specific, so dispatch
# selects it (A-JULIA-006). Nothing → mt7 null. Wire integer carrier is UInt64 (A-JULIA-008):
# the mt0/mt1 argument is exact over [0, 2^64-1]; negative values fold via -1-n in BigInt space
# then narrow, so no fixed-width overflow at the 2^63/2^64 boundary.
encode!(out::Vector{UInt8}, ::Nothing) = (push!(out, 0xf6); nothing)
encode!(out::Vector{UInt8}, b::Bool)   = (push!(out, b ? 0xf5 : 0xf4); nothing)

function encode!(out::Vector{UInt8}, n::Integer)
    if n < 0
        addhead!(out, 0x01, UInt64(-1 - big(n)))      # mt1: argument = -1 - n
    else
        addhead!(out, 0x00, UInt64(n))                # mt0: argument = n  (exact to 2^64-1)
    end
    return nothing
end

encode!(out::Vector{UInt8}, x::AbstractFloat) = encode_float!(out, Float64(x))

function encode!(out::Vector{UInt8}, b::AbstractVector{UInt8})   # mt2 byte string
    addhead!(out, 0x02, UInt64(length(b)))
    append!(out, b)
    return nothing
end

function encode!(out::Vector{UInt8}, s::AbstractString)          # mt3 text string
    cu = codeunits(s)                                # UTF-8 bytes; length is BYTE length
    addhead!(out, 0x03, UInt64(length(cu)))          # A-JULIA-007: ncodeunits, NEVER length(s)
    append!(out, cu)
    return nothing
end

function encode!(out::Vector{UInt8}, v::AbstractVector)          # mt4 array (Vector{Any} etc.)
    addhead!(out, 0x04, UInt64(length(v)))
    for it in v
        encode!(out, it)
    end
    return nothing
end

function encode!(out::Vector{UInt8}, m::CborMap)                 # mt5 map (length-then-lex)
    keyed = Tuple{Vector{UInt8},Any}[]
    for p in m.pairs
        kb = UInt8[]
        encode!(kb, p.first)
        push!(keyed, (kb, p.second))
    end
    sort!(keyed; lt = (a, b) -> canon_less(a[1], b[1]))
    for i in 2:length(keyed)
        keyed[i-1][1] == keyed[i][1] && throw(DuplicateKey())    # Rule 5
    end
    addhead!(out, 0x05, UInt64(length(m.pairs)))
    for (kb, val) in keyed
        append!(out, kb)
        encode!(out, val)
    end
    return nothing
end

"""Encode `v` to a fresh canonical-ECF byte vector."""
function encode(v)::Vector{UInt8}
    out = UInt8[]
    encode!(out, v)
    return out
end

# ── decode (rejects tags at any depth, indefinite lengths, trailing bytes) ──────────────────
mutable struct Decoder
    s::Vector{UInt8}
    pos::Int          # 1-based
    # keep_tags makes decode_item yield the tag's INNER item instead of throwing
    # TagRejected. It exists for ONE caller — decode_salvage — and is never set on
    # the strict path. See decode_salvage for why this is not a weakening of §6.3.
    keep_tags::Bool
end
Decoder(s::Vector{UInt8}, pos::Int) = Decoder(s, pos, false)

@inline function need(d::Decoder, k::Int)
    d.pos + k - 1 > length(d.s) && throw(TruncatedInput("need $k byte(s) at pos $(d.pos)"))
    return nothing
end
@inline function readbyte(d::Decoder)::UInt8
    need(d, 1); c = d.s[d.pos]; d.pos += 1; return c
end
@inline function take(d::Decoder, k::Int)::Vector{UInt8}
    need(d, k); r = d.s[d.pos:d.pos+k-1]; d.pos += k; return r
end
@inline function be(d::Decoder, k::Int)::UInt64
    need(d, k); v = UInt64(0)
    for _ in 1:k
        v = (v << 8) | UInt64(d.s[d.pos]); d.pos += 1
    end
    return v
end
@inline function read_arg(d::Decoder, ai::UInt8)::UInt64
    ai < 0x18 && return UInt64(ai)
    ai == 0x18 && return be(d, 1)
    ai == 0x19 && return be(d, 2)
    ai == 0x1a && return be(d, 4)
    ai == 0x1b && return be(d, 8)
    throw(NonCanonicalECF("indefinite/reserved length argument (ai=$ai)"))   # 28..31
end

function decode_item(d::Decoder)
    ib = readbyte(d)
    major = ib >> 5
    ai = ib & 0x1f
    if major == 0x00
        arg = read_arg(d, ai)
        return arg <= UInt64(typemax(Int64)) ? Int64(arg) : arg      # widen only above i64-max
    elseif major == 0x01
        n = read_arg(d, ai)                                          # value = -1 - n
        return n < UInt64(typemax(Int64)) ? Int64(-1 - Int64(n)) : (-1 - Int128(n))
    elseif major == 0x02
        return take(d, Int(read_arg(d, ai)))                         # Vector{UInt8}
    elseif major == 0x03
        return String(take(d, Int(read_arg(d, ai))))                # UTF-8 text
    elseif major == 0x04
        len = Int(read_arg(d, ai))
        items = Vector{Any}(undef, len)
        for i in 1:len
            items[i] = decode_item(d)
        end
        return items
    elseif major == 0x05
        len = Int(read_arg(d, ai))
        ps = Vector{Pair{Any,Any}}(undef, len)
        for i in 1:len
            k = decode_item(d)
            v = decode_item(d)
            ps[i] = Pair{Any,Any}(k, v)
        end
        return CborMap(ps)
    elseif major == 0x06
        d.keep_tags || throw(TagRejected())                         # N2: any tag, any depth
        # Salvage path only (decode_salvage): consume the tag head and yield the item
        # it wrapped, so the caller can locate the request_id and SIGNAL the rejection.
        # The frame is still rejected — the tag is never interpreted and the value
        # never reaches an entity.
        read_arg(d, ai)
        return decode_item(d)
    else # major == 0x07
        if ai == 0x14
            return false
        elseif ai == 0x15
            return true
        elseif ai == 0x16
            return nothing
        elseif ai == 0x19
            return half_to_double(UInt16(be(d, 2)))
        elseif ai == 0x1a
            return Float64(reinterpret(Float32, UInt32(be(d, 4))))
        elseif ai == 0x1b
            return reinterpret(Float64, be(d, 8))
        else
            throw(UnsupportedSimple(Int(ai)))
        end
    end
end

"""Decode a single top-level ECF item; rejects trailing bytes."""
function decode(s::AbstractVector{UInt8})
    d = Decoder(Vector{UInt8}(s), 1, false)
    v = decode_item(d)
    d.pos != length(d.s) + 1 && throw(NonCanonicalECF("trailing bytes after top-level item"))
    return v
end

"""
Decode `s` for the sole purpose of REPORTING a rejection, not of accepting one.
Identical to `decode` except that a major-type-6 tag yields the item it wrapped
instead of throwing `TagRejected`.

Why this exists (§6.3, a conformance requirement rather than a convenience): the tag
rule is *"Implementations MUST reject any received protocol frame containing a CBOR
tag on a data field. Rejection returns `400 non_canonical_ecf`."* Rejecting by
dropping the frame on the floor satisfies the first sentence and violates the second
— the peer owes the sender a status, and §4.9(c) deliver-or-signal says the same from
the other direction. But the status must ride a response correlated by `request_id`,
and the strict decoder cannot reach the request_id in a frame it refuses to parse.
This recovers exactly that much and nothing more.

This is NOT a weakening of the tag reject. The frame stays rejected: the value this
returns is never converted to an Entity, never stored, never forwarded and never
interpreted, so §6.3's MUST NOT silently strip / MUST NOT preserve / MUST NOT attempt
to interpret all still hold. The strict `decode` path that every real ingestion route
uses is unchanged, which is what keeps the `tag_reject` wire-conformance vectors
meaningful.
"""
function decode_salvage(s::AbstractVector{UInt8})
    d = Decoder(Vector{UInt8}(s), 1, true)
    v = decode_item(d)
    d.pos != length(d.s) + 1 && throw(NonCanonicalECF("trailing bytes after top-level item"))
    return v
end

end # module Cbor
