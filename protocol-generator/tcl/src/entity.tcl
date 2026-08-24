# entity-core-protocol-tcl — a materialized entity {type, data, content_hash}
# (§1.1, §3.4) on top of the S2 codec value model.
#
# An entity is a Tcl dict: {type <string> data <tagged value> hash <raw octets>}.
# The content_hash covers ONLY {type, data} (§1.1); the WIRE form (to_cbor) carries
# it as a third field so entities are self-describing across serialization (§3.1) —
# the hash is NEVER recomputed over a map that already contains content_hash.
#
# `data` is an ARBITRARY ECF value (§1.1 / A-JAVA-010): a {map …} for every core
# protocol entity, or a scalar for e.g. primitive/string. The field-read helpers
# take the map VIEW (the empty map for scalar data) so reads never throw.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] hash.tcl]
source [file join [file dirname [info script]] ecf.tcl]

namespace eval ::entity::core::entity {
    namespace export make of_cbor to_cbor type hash data raw_data \
        text bytes uint field mapfield entity_field
}

# construct a materialized entity, computing the §9.1 content_hash (format 0x00)
# over {type, data}. $data is any tagged ECF value.
proc ::entity::core::entity::make {type data} {
    set h [::entity::core::hash::content_hash $type $data]
    return [dict create type $type data $data hash $h]
}

# parse a wire entity map {type, data, content_hash}, recompute the hash from
# {type, data}, and validate it against the carried content_hash (§1.8 fidelity —
# trust the recomputed hash, not the wire bytes). Throws on mismatch / bad shape.
proc ::entity::core::entity::of_cbor {mtv} {
    set type [::entity::core::ecf::text $mtv type]
    if {$type eq "" && ![::entity::core::ecf::has $mtv type]} {
        throw {ENTITY_CORE PROTOCOL missing_type} "entity: missing/invalid type"
    }
    if {![::entity::core::ecf::has $mtv data]} {
        throw {ENTITY_CORE PROTOCOL missing_data} "entity: missing data"
    }
    set data [::entity::core::ecf::get $mtv data]
    set e [make $type $data]
    set carried [::entity::core::ecf::bytes $mtv content_hash]
    if {$carried ne "" && $carried ne [dict get $e hash]} {
        throw {ENTITY_CORE PROTOCOL content_hash_mismatch} "content_hash mismatch (§1.8 fidelity)"
    }
    return $e
}

proc ::entity::core::entity::type {e} { return [dict get $e type] }
proc ::entity::core::entity::hash {e} { return [dict get $e hash] }
proc ::entity::core::entity::raw_data {e} { return [dict get $e data] }

# the `data` as a map VIEW: the map itself when data IS a map, else the empty map.
proc ::entity::core::entity::data {e} {
    set d [dict get $e data]
    return [expr {[lindex $d 0] eq "map" ? $d : [::entity::core::ecf::emptymap]}]
}

# the wire entity map {type, data, content_hash}.
proc ::entity::core::entity::to_cbor {e} {
    return [::entity::core::ecf::map \
        type         [::entity::core::ecf::tstr [dict get $e type]] \
        data         [dict get $e data] \
        content_hash [::entity::core::ecf::bstr [dict get $e hash]]]
}

# ── field reads off the data map view ──
proc ::entity::core::entity::text {e key}   { return [::entity::core::ecf::text [data $e] $key] }
proc ::entity::core::entity::bytes {e key}  { return [::entity::core::ecf::bytes [data $e] $key] }
proc ::entity::core::entity::uint {e key}   { return [::entity::core::ecf::uint [data $e] $key] }
proc ::entity::core::entity::field {e key}  { return [::entity::core::ecf::get [data $e] $key] }
proc ::entity::core::entity::mapfield {e key} { return [::entity::core::ecf::mapfield [data $e] $key] }

# decode a nested entity carried at $key (a wire entity map), or "" if absent.
proc ::entity::core::entity::entity_field {e key} {
    set m [mapfield $e $key]
    if {$m eq ""} { return "" }
    return [of_cbor $m]
}
