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
        response_status response_result pre_admission_refusal
}

proc ::entity::core::wire::now_ms {} { return [clock milliseconds] }

# ── envelope <-> frame ──
proc ::entity::core::wire::frame_of_envelope {env} {
    return [::entity::core::cbor::encode [::entity::core::envelope::to_cbor $env]]
}
# §6.3 rejection reporting: recover ONLY the request_id from a frame the strict decoder
# rejected, so the rejection can be delivered as a correlated `400 non_canonical_ecf`
# response instead of silence. The frame stays rejected — nothing else is read out of it.
# Returns "" when even the request_id is unrecoverable (an unattributable frame, where
# silence is the only option left).
#
# The envelope and entity-wrapper shapes are fixed maps with no legal tag position (§6.3),
# so a frame whose ONLY defect is a tag inside some entity's `data` still has a
# structurally sound root — which is exactly the case this recovers.
proc ::entity::core::wire::salvage_request_id {payload} {
    if {[catch {::entity::core::cbor::decode_salvage $payload} v]} { return "" }
    set root [::entity::core::ecf::get $v root]
    if {$root eq ""} { return "" }
    set data [::entity::core::ecf::get $root data]
    if {$data eq ""} { return "" }
    set rid [::entity::core::ecf::get $data request_id]
    if {[lindex $rid 0] ne "text"} { return "" }
    return [lindex $rid 1]
}

proc ::entity::core::wire::envelope_of_frame {payload} {
    set v [::entity::core::cbor::decode $payload]
    if {[lindex $v 0] ne "map"} { throw {ENTITY_CORE WIRE not_a_map} "frame: not a map" }
    return [::entity::core::envelope::of_cbor $v]
}

# ── §4.11 pre-admission refusal classification (0.8.2.25) ──
#
# The {status code message} §4.11 assigns a pre-admission failure's CAUSE.
#
# "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]" --
# a single code for the class would answer an honest caller under the wrong reason and
# send them to the wrong layer.
#
#   connect-auth proof-of-possession      401 authentication_failed  (4.6/4.7 -- the
#                                            connect handler's, not here)
#   envelope over the configured maximum  413 payload_too_large      (4.10(a), N14)
#   resolution integrity (mis-keyed inc.) 400 hash_mismatch          (5.2a, 1.8)
#   framing / never becomes an Envelope   400 invalid_request        (4.7, 4.11)
#   root is neither EXECUTE nor E_R       400 invalid_request        (3.3, 4.11 -- in
#                                            peer::dispatch, not here)
#
# THE TAG ARM KEEPS non_canonical_ecf AND THAT IS DELIBERATE. 4.11 rules that code
# non-conformant "on the framing arm" and gives its reason in the same sentence:
# ENTITY-CBOR-ENCODING defines it for CBOR tag-policy violations specifically, which that
# document still MUSTs at decode time (6.3). The two rows are disjoint by CAUSE rather
# than in conflict. Everything else this decoder calls non-canonical (a non-minimal head,
# an indefinite length, mis-ordered keys) is genuinely "non-canonical CBOR that never
# becomes an Envelope".
#
# The classifier reads the STRUCTURED -errorcode, never the message text: a classifier
# that recognises a cause by matching on prose is one string edit away from silently
# re-collapsing the codes. tcl's error model gives {ENTITY_CORE <KIND> <detail>}, so the
# kind IS the cause.
#
# The messages are a FIXED TABLE, never the internal exception text: a wire-visible string
# stays ASCII (two peers in this cohort have been killed at runtime by a non-ASCII byte in
# an encoded string, on two unrelated compilers), the internal texts carry section signs,
# and nothing here echoes attacker-supplied bytes back.
proc ::entity::core::wire::pre_admission_refusal {errorcode} {
    set kind [lindex $errorcode 1]
    set detail [lindex $errorcode 2]
    if {$kind eq "WIRE" && $detail eq "payload_too_large"} {
        return [list 413 payload_too_large "inbound frame exceeds the configured maximum size"]
    }
    if {$kind eq "WIRE" && $detail eq "truncated_frame"} {
        return [list 400 invalid_request "frame did not decode into an envelope"]
    }
    if {$kind eq "PROTOCOL" && $detail in {included_key_mismatch content_hash_mismatch}} {
        # 1.8 item 1 -- RESOLUTION INTEGRITY, not a structural fault. 5.2a pins the
        # decode-boundary code for this cause to `400 hash_mismatch` and rules
        # `400 non_canonical_ecf` non-conformant here (0.8.2.24 N4/N5). A mis-keyed
        # `included` entry carries no tag and its encoding is canonical -- what is false
        # is the claim the KEY makes, and the remedy non_canonical_ecf selects
        # (*re-encode*) sends an honest caller to the wrong layer.
        return [list 400 hash_mismatch "an entity was addressed by a hash that does not bind to it"]
    }
    if {$kind eq "TAG_REJECTED"} {
        return [list 400 non_canonical_ecf "CBOR tags are forbidden anywhere in an entity data field"]
    }
    return [list 400 invalid_request "frame did not decode into an envelope"]
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
