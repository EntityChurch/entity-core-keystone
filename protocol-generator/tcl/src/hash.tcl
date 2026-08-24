# entity-core-protocol-tcl — content-hash construction (ENTITY-CBOR-ENCODING §4.2):
#
#   content_hash = varint(format_code) || hash_alg(ECF({type, data}))
#
# Format code 0x00 = ecfv1-sha256 (the §9.1 floor); 0x01 = ecfv1-sha384 (agility).
# The format_code is NOT part of the hashed basis — only {type, data} is hashed —
# and its prefix is a multicodec-style LEB128 varint (N1: a code ≥ 0x80 widens).
# SHA-256/384 cross the C-ABI (crypto shim); the ECF encoding is the pure-Tcl codec.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] cbor.tcl]
source [file join [file dirname [info script]] varint.tcl]
source [file join [file dirname [info script]] ecf.tcl]

namespace eval ::entity::core::hash {
    namespace export content_hash
}

# content_hash over a type string + an arbitrary ECF `data` tagged value.
# `data` is any ECF node (A-JAVA-010) — a map for protocol entities, a scalar
# otherwise; NEVER assume a map here.
proc ::entity::core::hash::content_hash {type data {format_code 0}} {
    set basis [::entity::core::ecf::map type [::entity::core::ecf::tstr $type] data $data]
    set enc [::entity::core::cbor::encode $basis]
    if {$format_code == 1} {
        set digest [::entity::core::crypto::sha384 $enc]
    } else {
        set digest [::entity::core::crypto::sha256 $enc]
    }
    set out [::entity::core::varint::encode $format_code]
    append out $digest
    return $out
}
