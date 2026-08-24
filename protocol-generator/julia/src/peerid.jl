# Peer identifier (ENTITY-CBOR-ENCODING §1.2 / §7.3):
#
#     peer_id = Base58(varint(key_type) || varint(hash_type) || digest)
#
# key_type/hash_type are LEB128 varints (N1). For the canonical Ed25519 identity-multihash
# form: key_type 0x01 = ed25519, hash_type 0x00, digest = the RAW 32-byte public key (the §1.5
# canonical-form table — settled, see SPEC-AMBIGUITY-LOG). `format` is construction-agnostic
# over the component values, so the corpus peer_id vectors (which pin hash_type=0x01 over an
# opaque 32-byte digest) are reproduced faithfully. A synthetic key_type ≥ 0x80 exercises the
# multi-byte varint prefix (corpus peer_id.3).
module PeerId

using ..Varint: encode_varint!, decode_varint
using ..Base58: base58encode, base58decode

export peerid_format, peerid_parse

"""Format the peer-id String (Base58) for the given components."""
function peerid_format(key_type::Integer, hash_type::Integer, digest::AbstractVector{UInt8})::String
    raw = UInt8[]
    encode_varint!(raw, key_type)
    encode_varint!(raw, hash_type)
    append!(raw, digest)
    return base58encode(raw)
end

"""Parse a peer-id String back into (key_type, hash_type, digest)."""
function peerid_parse(s::AbstractString)
    raw = base58decode(s)
    kt, klen = decode_varint(raw, 1)
    ht, hlen = decode_varint(raw, 1 + klen)
    digest = raw[1+klen+hlen:end]
    return (key_type = kt, hash_type = ht, digest = digest)
end

end # module PeerId
