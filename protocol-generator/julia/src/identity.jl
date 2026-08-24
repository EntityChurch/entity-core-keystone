# Identity (L1) — a peer's keypair and the entities derived from it (§1.5, §3.5, §7.4).
# A peer identity is a 32-byte Ed25519 seed; everything else derives:
#
#   public_key    = Ed25519 pub of seed                          (32 bytes)
#   peer_id       = Base58(varint(1) ‖ varint(0) ‖ public_key)   (§1.5 canonical
#                   identity-multihash — hash_type 0x00, digest = RAW pubkey, NOT
#                   SHA-256(pubkey); the cohort-settled form baked in the profile)
#   peer entity   = system/peer { public_key, key_type }         (§3.5 — no peer_id in
#                   the hashable basis; peer_id is derivable from public_key)
#   identity_hash = content_hash(peer entity)                    (33 bytes)
#
# Signing is over the full 33-byte content_hash of the target entity (§3.5). Ed25519 via
# system libsodium `ccall` (the S2 native-audited-lib floor; A-JULIA-003).
module Identity

using ..Sign: ed25519_pubkey, ed25519_sign, ed25519_verify
using ..PeerId: peerid_format
using ..Cbor: CborMap
using ..Model: Entity, make_entity, bytesfield

export PeerIdentity, peer_identity, peer_entity_of_pubkey, peerid_of_pubkey
export sign_entity, verify_signature

# The `system/peer` entity for a public key (§3.5; peer_id is NOT in the hashable basis).
peer_entity_of_pubkey(public_key::AbstractVector{UInt8}) =
    make_entity("system/peer", CborMap(Pair[("public_key" => Vector{UInt8}(public_key)),
                                            ("key_type" => "ed25519")]))

# Canonical Ed25519 peer_id (§1.5 identity-multihash: key_type 0x01, hash_type 0x00, raw pubkey).
peerid_of_pubkey(public_key::AbstractVector{UInt8}) = peerid_format(1, 0, public_key)

struct PeerIdentity
    seed::Vector{UInt8}         # 32-byte Ed25519 seed
    public_key::Vector{UInt8}   # 32 bytes
    peer_id::String             # Base58 identity-multihash
    peer_entity::Entity         # system/peer
end

peer_identity_hash(id::PeerIdentity) = id.peer_entity.hash

function peer_identity(seed::AbstractVector{UInt8})::PeerIdentity
    pk = ed25519_pubkey(seed)
    return PeerIdentity(Vector{UInt8}(seed), pk, peerid_of_pubkey(pk), peer_entity_of_pubkey(pk))
end

"""Sign a target entity's 33-byte content_hash → a `system/signature` entity (§3.5)."""
function sign_entity(id::PeerIdentity, target::Entity)::Entity
    length(target.hash) == 33 || error("sign_entity: target hash must be 33 bytes")
    sig = ed25519_sign(id.seed, target.hash)
    return make_entity("system/signature",
        CborMap(Pair[("target" => target.hash),
                     ("signer" => id.peer_entity.hash),
                     ("algorithm" => "ed25519"),
                     ("signature" => sig)]))
end

"""Verify a `system/signature` entity against the signer's `system/peer` entity. The
signer-hash ↔ author binding is the caller's (§5.2) responsibility."""
function verify_signature(signature::Entity, signer_peer::Entity)::Bool
    target = bytesfield(signature, "target")
    sig = bytesfield(signature, "signature")
    pk = bytesfield(signer_peer, "public_key")
    (target === nothing || sig === nothing || pk === nothing) && return false
    (length(sig) == 64 && length(pk) == 32) || return false
    return ed25519_verify(pk, sig, target)
end

end # module Identity
