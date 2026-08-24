# content_hash construction (ENTITY-CBOR-ENCODING §4.2 / §9.3):
#
#     content_hash = varint(format_code) || HASH(ECF({type, data}))
#
# format_code 0x00 = ecfv1-sha256 (the required floor); 0x01 = ecfv1-sha384 (agility). The
# varint prefix is LEB128 (N1) — a synthetic code ≥ 0x80 exercises the multi-byte path
# (corpus content_hash.4). SHA from the `SHA` stdlib (profile [codec].sha256_source), native.
module ContentHash

using ..Cbor: CborMap, encode
using ..Varint: encode_varint!
using SHA: sha256, sha2_384

export ecf_of_entity, content_hash

"""ECF bytes of the {type, data} entity. The encoder sorts keys, so "data" precedes "type"
(both 5 encoded bytes; 0x64 0x64… < 0x64 0x74…)."""
function ecf_of_entity(typ::AbstractString, data)::Vector{UInt8}
    return encode(CborMap([("type" => String(typ)), ("data" => data)]))
end

"""content_hash bytes. format_code 0 → SHA-256, 1 → SHA-384; any other code still emits
varint(code) || SHA-256 (construction side — receive-side dispatch of unsupported codes is
the S3 peer surface)."""
function content_hash(format_code::Integer, typ::AbstractString, data)::Vector{UInt8}
    ecf = ecf_of_entity(typ, data)
    out = UInt8[]
    encode_varint!(out, format_code)
    digest = format_code == 1 ? sha2_384(ecf) : sha256(ecf)
    append!(out, digest)
    return out
end

end # module ContentHash
