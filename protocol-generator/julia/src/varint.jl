# Multicodec-style LEB128 varints (ENTITY-CBOR-ENCODING §1.5 / §7.3 — NORMATIVE).
#
# Invariant N1: format codes, key_type and hash_type are framed as LEB128 varints, NOT fixed
# bytes. Every currently-allocated code is < 0x80 (one byte) so this is byte-identical to a
# fixed field today — the point is that a future code ≥ 0x80 extends to 2+ bytes and a
# fixed-width impl breaks silently. Corpus content_hash.4 (format_code 128) and peer_id.3
# (key_type 128) prove the multi-byte path. Inline bit ops (profile [codec].varint_handling).
module Varint

export encode_varint!, decode_varint

"""Append the LEB128 encoding of `n` (≥ 0) to `out`."""
function encode_varint!(out::Vector{UInt8}, n::Integer)
    v = UInt64(n)
    while true
        byte = UInt8(v & 0x7f)
        v >>= 7
        if v == 0
            push!(out, byte); break
        else
            push!(out, byte | 0x80)
        end
    end
    return nothing
end

"""Decode one varint at 1-based `pos`; returns (value::UInt64, len::Int) bytes consumed."""
function decode_varint(s::AbstractVector{UInt8}, pos::Int)
    acc = UInt64(0); shift = 0; i = pos
    while true
        i > length(s) && error("truncated varint")
        b = s[i]; acc |= UInt64(b & 0x7f) << shift; i += 1
        (b & 0x80) == 0 && return (acc, i - pos)
        shift += 7
    end
end

end # module Varint
