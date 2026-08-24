# entity-core-protocol-tcl — storage (foundation, §1.7): the two layers.
#
#   Content Store: hash → entity   (immutable, content-addressed, dedup)
#   Entity Tree:   path → hash      (mutable location index)
#
# In-memory minimal impl. Paths are the canonical absolute form /{peer_id}/rest
# (§1.4); the peer canonicalizes before calling in. The content store is keyed by
# the LOWERCASE-hex content_hash (A-CL-009: §3.4/§3.5 tree paths are case-sensitive
# and lowercase-hex; `binary encode hex` is lowercase — pinned).
#
# == §4.8 store data-race safety — STRUCTURAL under the Tcl event-loop idiom
# The transport is a SINGLE-THREADED event loop (chan event + vwait): one handler
# runs to completion before the next readable event is serviced, so these dicts are
# never accessed concurrently — the §4.8 MUST holds BY CONSTRUCTION, no lock.
#
# == EMIT PATHWAY (§6.10 / §6.13(c)) — the Core Extensibility Boundary
# Tree/content writes produce events delivered to registered consumers. The hook is
# LIVE even with ZERO consumers (events produced and discarded) so a future
# extension registers a consumer WITHOUT rebuilding the peer (§6.13(c) MUST).
#
# A store instance is a handle into the `S` array (the idiomatic Tcl "object as a
# namespaced array" — a single interp, no lock).

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] entity.tcl]
source [file join [file dirname [info script]] ecf.tcl]

namespace eval ::entity::core::store {
    variable S        ;# array: handle -> dict {content <hex->entity> tree <path->hex>
                       #                         cconsumers <list> tconsumers <list>}
    variable counter 0
    namespace export new register_content_consumer register_tree_consumer \
        put_entity get_by_hash bind unbind hash_at get_at listing
}

proc ::entity::core::store::new {} {
    variable S
    variable counter
    set h "store[incr counter]"
    set S($h) [dict create content {} tree {} cconsumers {} tconsumers {}]
    return $h
}

proc ::entity::core::store::register_content_consumer {h cmd} {
    variable S
    dict lappend S($h) cconsumers $cmd
}
proc ::entity::core::store::register_tree_consumer {h cmd} {
    variable S
    dict lappend S($h) tconsumers $cmd
}

# ── content store (§6.10 Store step: event only when the entity is NEW) ──
proc ::entity::core::store::put_entity {h e} {
    variable S
    set hex [binary encode hex [::entity::core::entity::hash $e]]
    if {![dict exists $S($h) content $hex]} {
        dict set S($h) content $hex $e
        foreach cmd [dict get $S($h) cconsumers] {
            {*}$cmd [dict create hash [::entity::core::entity::hash $e] entity $e]
        }
    }
}

proc ::entity::core::store::get_by_hash {h hbytes} {
    variable S
    set hex [binary encode hex $hbytes]
    if {[dict exists $S($h) content $hex]} { return [dict get $S($h) content $hex] }
    return ""
}

# ── entity tree (§6.10 Bind step: event when the binding at the path changes) ──
proc ::entity::core::store::bind {h path e} {
    variable S
    put_entity $h $e
    set next [binary encode hex [::entity::core::entity::hash $e]]
    set prev [expr {[dict exists $S($h) tree $path] ? [dict get $S($h) tree $path] : ""}]
    dict set S($h) tree $path $next
    if {$next ne $prev} {
        set ev [dict create event_type [_event_type $prev $next] path $path \
            new_hash $next previous_hash $prev]
        foreach cmd [dict get $S($h) tconsumers] { {*}$cmd $ev }
    }
}

proc ::entity::core::store::unbind {h path} {
    variable S
    if {[dict exists $S($h) tree $path]} {
        set prev [dict get $S($h) tree $path]
        dict unset S($h) tree $path
        set ev [dict create event_type deleted path $path new_hash "" previous_hash $prev]
        foreach cmd [dict get $S($h) tconsumers] { {*}$cmd $ev }
    }
}

proc ::entity::core::store::_event_type {prev next} {
    if {$prev eq ""} { return created }
    if {$next eq ""} { return deleted }
    return modified
}

proc ::entity::core::store::hash_at {h path} {
    variable S
    if {[dict exists $S($h) tree $path]} { return [dict get $S($h) tree $path] }
    return ""
}

proc ::entity::core::store::get_at {h path} {
    variable S
    if {![dict exists $S($h) tree $path]} { return "" }
    set hex [dict get $S($h) tree $path]
    if {[dict exists $S($h) content $hex]} { return [dict get $S($h) content $hex] }
    return ""
}

# one-level listing under $prefix (trailing slash added if absent), sorted by
# segment (§3.9). Returns a list of {segment hashHexOrEmpty hasChildren} rows.
proc ::entity::core::store::listing {h prefix} {
    variable S
    set p [expr {[string index $prefix end] eq "/" ? $prefix : "$prefix/"}]
    set plen [string length $p]
    set acc {}   ;# dict: segment -> {hashHex hasChildren}
    dict for {path hash} [dict get $S($h) tree] {
        if {[string length $path] > $plen && [string range $path 0 [expr {$plen-1}]] eq $p} {
            set rest [string range $path $plen end]
            set slash [string first "/" $rest]
            if {$slash >= 0} {
                set seg [string range $rest 0 [expr {$slash-1}]]
                set cur [expr {[dict exists $acc $seg] ? [dict get $acc $seg] : [list "" 0]}]
                dict set acc $seg [list [lindex $cur 0] 1]
            } else {
                set cur [expr {[dict exists $acc $rest] ? [dict get $acc $rest] : [list "" 0]}]
                dict set acc $rest [list $hash [lindex $cur 1]]
            }
        }
    }
    set out {}
    foreach seg [lsort [dict keys $acc]] {
        set cell [dict get $acc $seg]
        lappend out [list $seg [lindex $cell 0] [lindex $cell 1]]
    }
    return $out
}
