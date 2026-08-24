# entity-core-protocol-tcl — peer_id canonical form (§1.5 canonical-form table).
#
# peer_id wire form = Base58( varint(key_type) || varint(hash_type) || digest ),
# and the peer_id VALUE on the wire is a CBOR text string wrapping that base58 string.
# For Ed25519 the §1.5 table sets hash_type = 0x00 identity-multihash with digest =
# the raw 32-byte public key; the conformance vectors also exercise SHA-256 peer-ids
# (hash_type 0x01, digest = SHA-256(pubkey)) and a synthetic multi-byte key_type
# (peer_id.3, key_type 128 -> a two-byte LEB128 prefix, the N1 varint test).

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] varint.tcl]
source [file join [file dirname [info script]] base58.tcl]

namespace eval ::entity::core::peerid {
    namespace export format_id parse
}

# parse a peer_id string back to {key_type hash_type digest} (§1.5). Throws on a
# non-Base58 char or a truncated varint prefix.
proc ::entity::core::peerid::parse {str} {
    set raw [::entity::core::base58::decode $str]
    set pos 0
    set key_type  [::entity::core::varint::decode $raw pos]
    set hash_type [::entity::core::varint::decode $raw pos]
    set digest    [string range $raw $pos end]
    return [list $key_type $hash_type $digest]
}

# format_id key_type hash_type digestBytes -> a tagged {text <base58>} value
# (ready for ::entity::core::cbor::encode to wrap as CBOR mt3).
proc ::entity::core::peerid::format_id {key_type hash_type digest} {
    set prefix [::entity::core::varint::encode $key_type]
    append prefix [::entity::core::varint::encode $hash_type]
    append prefix [binary format a* $digest]
    return [list text [::entity::core::base58::encode $prefix]]
}
