# entity-core-protocol-tcl — L1 identity (§1.5, §3.5, §7.3).
#
# Everything derived from a 32-byte Ed25519 seed:
#   public_key    = Ed25519 pubkey of seed                       (32 bytes, shim)
#   peer_id       = §1.5 canonical-form identity-multihash        (Base58)
#   peer_entity   = system/peer {public_key, key_type}           (§3.5; v7.65 — NO
#                   peer_id in the hashable basis)
#   id_hash       = content_hash(peer_entity)                    (33 bytes)
#
# peer_id is the §1.5 identity-multihash form (hash_type 0x00, digest = the raw
# ≤32-byte pubkey), which SUPERSEDES the stale §7.4 SHA-256 skeleton — baked in per
# the profile [spec] note to avoid the handshake debug cycle Zig/OCaml burned.
# Signing is over the full 33-byte content_hash (§7.3), binding the sig to the hash
# format. Ed25519 sign/verify cross the C-ABI (crypto shim); SHA is in the hash layer.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] entity.tcl]
source [file join [file dirname [info script]] ecf.tcl]
source [file join [file dirname [info script]] varint.tcl]
source [file join [file dirname [info script]] base58.tcl]

namespace eval ::entity::core::identity {
    namespace export of_seed peer_id_of_pubkey peer_entity_of_pubkey \
        sign verify_signature
    variable KEY_TYPE_ED25519 1
}

# construct an identity dict from a 32-byte Ed25519 seed.
proc ::entity::core::identity::of_seed {seed} {
    set pub [::entity::core::crypto::ed25519_pubkey $seed]
    set peer_entity [peer_entity_of_pubkey $pub]
    return [dict create \
        seed        $seed \
        pub         $pub \
        peer_id     [peer_id_of_pubkey $pub] \
        peer_entity $peer_entity \
        id_hash     [::entity::core::entity::hash $peer_entity]]
}

# §1.5 size-cutoff peer_id from a raw Ed25519 pubkey: ≤32 B → identity-multihash
# (hash_type 0, digest = pubkey). Returns the Base58 string.
proc ::entity::core::identity::peer_id_of_pubkey {pub} {
    variable KEY_TYPE_ED25519
    if {[string length [binary format a* $pub]] <= 32} {
        set hash_type 0
        set digest $pub
    } else {
        set hash_type 1
        set digest [::entity::core::crypto::sha256 $pub]
    }
    set raw [::entity::core::varint::encode $KEY_TYPE_ED25519]
    append raw [::entity::core::varint::encode $hash_type]
    append raw [binary format a* $digest]
    return [::entity::core::base58::encode $raw]
}

# the system/peer entity for a raw pubkey (v7.65: no peer_id field in the basis).
proc ::entity::core::identity::peer_entity_of_pubkey {pub} {
    return [::entity::core::entity::make system/peer [::entity::core::ecf::map \
        public_key [::entity::core::ecf::bstr $pub] \
        key_type   [::entity::core::ecf::tstr ed25519]]]
}

# sign a target entity's content_hash → a system/signature entity (§3.5).
proc ::entity::core::identity::sign {ident target} {
    set th [::entity::core::entity::hash $target]
    set sig [::entity::core::crypto::ed25519_sign [dict get $ident seed] $th]
    return [::entity::core::entity::make system/signature [::entity::core::ecf::map \
        target    [::entity::core::ecf::bstr $th] \
        signer    [::entity::core::ecf::bstr [dict get $ident id_hash]] \
        algorithm [::entity::core::ecf::tstr ed25519] \
        signature [::entity::core::ecf::bstr $sig]]]
}

# verify a system/signature entity against the signer's system/peer entity. The
# §5.2 signer-hash binding is the caller's responsibility.
proc ::entity::core::identity::verify_signature {signature signer_peer} {
    set target [::entity::core::entity::bytes $signature target]
    set sig    [::entity::core::entity::bytes $signature signature]
    set pub    [::entity::core::entity::bytes $signer_peer public_key]
    if {$target eq "" || $sig eq "" || $pub eq ""} { return 0 }
    if {[string length [binary format a* $sig]] != 64} { return 0 }
    if {[string length [binary format a* $pub]] != 32} { return 0 }
    return [::entity::core::crypto::ed25519_verify $pub $target $sig]
}
