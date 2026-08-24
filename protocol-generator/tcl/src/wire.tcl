# entity-core-protocol-tcl — wire framing (§1.6) + the two message builders (§3.2
# EXECUTE, §3.3 EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR payload]; the
# payload is a canonical-ECF-encoded system/protocol/envelope (§3.1).
#
# Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
# authenticate are OPERATIONS on system/protocol/connect, NOT message types — any
# other root type is ignored on the server side (the dispatcher returns "").

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] cbor.tcl]
source [file join [file dirname [info script]] entity.tcl]
source [file join [file dirname [info script]] envelope.tcl]
source [file join [file dirname [info script]] ecf.tcl]

namespace eval ::entity::core::wire {
    variable MAX_FRAME [expr {16 * 1024 * 1024}]   ;# §1.6 / §4.10(a) — 16 MiB
    namespace export now_ms frame_of_envelope envelope_of_frame frame \
        make_execute make_response error_result empty_params resource_target \
        response_status response_result
}

proc ::entity::core::wire::now_ms {} { return [clock milliseconds] }

# ── envelope <-> frame ──
proc ::entity::core::wire::frame_of_envelope {env} {
    return [::entity::core::cbor::encode [::entity::core::envelope::to_cbor $env]]
}
proc ::entity::core::wire::envelope_of_frame {payload} {
    set v [::entity::core::cbor::decode $payload]
    if {[lindex $v 0] ne "map"} { throw {ENTITY_CORE WIRE not_a_map} "frame: not a map" }
    return [::entity::core::envelope::of_cbor $v]
}

# prefix $payload with its 4-byte big-endian length (§1.6).
proc ::entity::core::wire::frame {payload} {
    set p [binary format a* $payload]
    return [binary format Iu [string length $p]]$p
}

# ── EXECUTE builder (§3.2) ──
# $params is a materialized entity; author/capability are raw hash octets ("" to
# omit); resource is a {map …} tagged value ("" to omit).
proc ::entity::core::wire::make_execute {request_id uri operation params \
        {author ""} {capability ""} {resource ""}} {
    set kv [list \
        request_id [::entity::core::ecf::tstr $request_id] \
        uri        [::entity::core::ecf::tstr $uri] \
        operation  [::entity::core::ecf::tstr $operation] \
        params     [::entity::core::entity::to_cbor $params]]
    if {$author ne ""}     { lappend kv author     [::entity::core::ecf::bstr $author] }
    if {$capability ne ""} { lappend kv capability [::entity::core::ecf::bstr $capability] }
    if {$resource ne ""}   { lappend kv resource   $resource }
    return [::entity::core::entity::make system/protocol/execute \
        [::entity::core::ecf::map {*}$kv]]
}

# ── EXECUTE_RESPONSE builder (§3.3) ──
proc ::entity::core::wire::make_response {request_id status result} {
    return [::entity::core::entity::make system/protocol/execute/response [::entity::core::ecf::map \
        request_id [::entity::core::ecf::tstr $request_id] \
        status     [::entity::core::ecf::tint $status] \
        result     [::entity::core::entity::to_cbor $result]]]
}

proc ::entity::core::wire::error_result {code {message ""}} {
    if {$message ne ""} {
        set data [::entity::core::ecf::map code [::entity::core::ecf::tstr $code] \
            message [::entity::core::ecf::tstr $message]]
    } else {
        set data [::entity::core::ecf::map code [::entity::core::ecf::tstr $code]]
    }
    return [::entity::core::entity::make system/protocol/error $data]
}

# empty-params (§3.2): a primitive/any whose data is the canonical empty map.
proc ::entity::core::wire::empty_params {} {
    return [::entity::core::entity::make primitive/any [::entity::core::ecf::emptymap]]
}

# a resource map {targets: [...]} from a Tcl list of target path strings.
proc ::entity::core::wire::resource_target {args} {
    return [::entity::core::ecf::map targets [::entity::core::ecf::text_array $args]]
}

# ── response decode helpers (initiator side) ──
proc ::entity::core::wire::response_status {env} {
    set s [::entity::core::entity::uint [::entity::core::envelope::root $env] status]
    return [expr {$s eq "" ? 0 : $s}]
}
proc ::entity::core::wire::response_result {env} {
    set m [::entity::core::entity::mapfield [::entity::core::envelope::root $env] result]
    if {$m eq ""} { return "" }
    return [::entity::core::entity::of_cbor $m]
}
