# entity-core-protocol-tcl — per-connection state carried through the §6.5 dispatch
# chain: the §4.1/§4.6 handshake state (issued nonce + hello-declared peer_id), the
# `established` post-authenticate gate, the §6.13(b)/§6.11 reentry OUTBOUND seam (a
# command prefix that originates an EXECUTE back over THIS connection and returns
# the correlated response envelope, or ""), and an outbound request_id counter.
#
# A conn is a handle into the `C` array (the "object as namespaced array" idiom).

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1

namespace eval ::entity::core::conn {
    variable C
    variable counter 0
    namespace export new get set_ next_out_counter
}

proc ::entity::core::conn::new {} {
    variable C
    variable counter
    set h "conn[incr counter]"
    set C($h) [dict create established 0 issued_nonce "" hello_peer_id "" \
        outbound "" out_counter 0]
    return $h
}

proc ::entity::core::conn::get {h key} {
    variable C
    return [dict get $C($h) $key]
}

proc ::entity::core::conn::set_ {h key value} {
    variable C
    dict set C($h) $key $value
}

proc ::entity::core::conn::next_out_counter {h} {
    variable C
    dict incr C($h) out_counter
    return [dict get $C($h) out_counter]
}
