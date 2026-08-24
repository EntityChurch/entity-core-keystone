# entity-core-protocol-tcl — the protocol envelope (§3.1): a `root` entity plus an
# `included` list of protocol entities keyed by content_hash. `included` is the
# §5.8 authority carrier (capabilities, peer identities, signatures travel here).
#
# Held as an insertion-ordered Tcl list of {hashOctets entity} pairs so a wire
# round-trip is deterministic; lookup is by content_hash octets. On the wire (§3.1)
# `included` is a content_hash → entity MAP (byte-string keys — the major-2 seam,
# NOT text keys), so duplicate hashes collapse; we dedup preserving first-seen order
# before encoding (the canonical codec rejects a duplicate map key).

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] entity.tcl]
source [file join [file dirname [info script]] ecf.tcl]

namespace eval ::entity::core::envelope {
    namespace export make inc included_get to_cbor of_cbor root included
}

# an envelope dict {root <entity> included <list of {hash entity} pairs>}.
proc ::entity::core::envelope::make {root {included {}}} {
    return [dict create root $root included $included]
}

proc ::entity::core::envelope::root {env} { return [dict get $env root] }
proc ::entity::core::envelope::included {env} { return [dict get $env included] }

# a typed included entry from an entity.
proc ::entity::core::envelope::inc {e} {
    return [list [::entity::core::entity::hash $e] $e]
}

# find an included entity by its content_hash octets, or "".
proc ::entity::core::envelope::included_get {env h} {
    foreach pair [dict get $env included] {
        if {[lindex $pair 0] eq $h} { return [lindex $pair 1] }
    }
    return ""
}

# the wire envelope map {root, included}. Dedup `included` by content_hash,
# first-seen order (§3.1: the same entity listed twice — e.g. granter == local
# identity — would emit a duplicate byte key the codec rejects).
proc ::entity::core::envelope::to_cbor {env} {
    set incl_kv {}
    set seen {}
    foreach pair [dict get $env included] {
        set h [lindex $pair 0]
        set hex [binary encode hex $h]
        if {[dict exists $seen $hex]} { continue }
        dict set seen $hex 1
        lappend incl_kv [::entity::core::ecf::bstr $h] \
            [::entity::core::entity::to_cbor [lindex $pair 1]]
    }
    return [::entity::core::ecf::map \
        root     [::entity::core::entity::to_cbor [dict get $env root]] \
        included [list map $incl_kv]]
}

# parse a wire envelope map. Verifies each included content_hash == its map key
# (§3.1) and dedups first-seen.
proc ::entity::core::envelope::of_cbor {mtv} {
    set rootv [::entity::core::ecf::mapfield $mtv root]
    if {$rootv eq ""} { throw {ENTITY_CORE PROTOCOL missing_root} "envelope: missing root" }
    set root [::entity::core::entity::of_cbor $rootv]
    set included {}
    set incm [::entity::core::ecf::mapfield $mtv included]
    if {$incm ne ""} {
        set seen {}
        foreach {k v} [::entity::core::ecf::entries $incm] {
            if {[lindex $k 0] ne "bytes"} {
                throw {ENTITY_CORE PROTOCOL included_key_not_bytes} "envelope: included key not bytes"
            }
            if {[lindex $v 0] ne "map"} {
                throw {ENTITY_CORE PROTOCOL included_value_not_map} "envelope: included value not a map"
            }
            set kb [lindex $k 1]
            set ent [::entity::core::entity::of_cbor $v]
            if {$kb ne [::entity::core::entity::hash $ent]} {
                throw {ENTITY_CORE PROTOCOL included_key_mismatch} "included key != content_hash"
            }
            set hex [binary encode hex $kb]
            if {[dict exists $seen $hex]} { continue }
            dict set seen $hex 1
            lappend included [list $kb $ent]
        }
    }
    return [make $root $included]
}
