# entity-core-protocol-tcl — peer-layer value helpers over the S2 codec value model.
#
# The codec (src/cbor.tcl) speaks an EXPLICIT tagged-value representation (the EIAS
# resolution, A-TCL-001/003) — a value carries its CBOR major type as tag 0:
#   {int N} {bytes B} {text S} {array L} {map KV} {float F} {bool 0|1} {null} …
# This module is the protocol-altitude analogue of the codec: map/list builders +
# typed field reads, so the peer code reads as map builders and field accessors
# instead of restating the tagged rep inline at every call site.
#
# == The absent sentinel (A-TCL-007, resolved at THIS layer)
# The empty string is a legitimate wire value (`{text {}}` / `{bytes {}}`), so it
# cannot double as "absent". But a PRESENT tagged value is ALWAYS a non-empty Tcl
# list (≥1 element: the tag). So the bare empty string "" is a safe absent sentinel
# at this layer — a field read returns "" iff the key is truly absent. Callers that
# must tell present-empty-array from absent (§4.5 hello negotiation) use `has`.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] cbor.tcl]

namespace eval ::entity::core::ecf {
    namespace export tstr bstr tint tbool tnull tarray text_array map emptymap \
        scope get has text bytes uint bool_is asmap mapfield textlist maplist entries
}

# ───────────────────────── constructors ─────────────────────────

proc ::entity::core::ecf::tstr {s}  { return [list text  $s] }   ;# text value  (mt3)
proc ::entity::core::ecf::bstr {b}  { return [list bytes $b] }   ;# byte value  (mt2)
proc ::entity::core::ecf::tint {n}  { return [list int   $n] }   ;# int  value  (mt0/1)
proc ::entity::core::ecf::tbool {b} { return [list bool  [expr {$b ? 1 : 0}]] }
proc ::entity::core::ecf::tnull {}  { return {null} }

# a CBOR array (mt4) from a list of ALREADY-tagged items.
proc ::entity::core::ecf::tarray {items} { return [list array $items] }

# a CBOR array of text strings from a Tcl list of bare strings.
proc ::entity::core::ecf::text_array {strs} {
    set out {}
    foreach s $strs { lappend out [list text $s] }
    return [list array $out]
}

# Build a map (mt5) from alternating key value pairs. A bare-string key becomes a
# TEXT key; an already-tagged key ({text …}/{bytes …}) is kept verbatim (the
# byte-keyed `included` map). VALUES must already be tagged.
proc ::entity::core::ecf::map {args} {
    if {[llength $args] % 2 != 0} {
        throw {ENTITY_CORE UNSUPPORTED_VALUE odd_kv} "ecf::map: odd key/value count"
    }
    set kv {}
    foreach {k v} $args {
        # already-tagged key ({text …}/{bytes …}/{int …}) must be a 2-element list
        # led by a tag word — NOT merely a bare word that happens to equal a tag (a
        # text key literally "int"/"text"/"bytes" is a bare string → wrap it as text).
        if {[llength $k] == 2 && [lindex $k 0] in {text bytes int}} {
            lappend kv $k $v
        } else {
            lappend kv [list text $k] $v
        }
    }
    return [list map $kv]
}

proc ::entity::core::ecf::emptymap {} { return {map {}} }

# a §5.4 scope map {include: <text array>} from a Tcl list of pattern strings.
proc ::entity::core::ecf::scope {patterns} {
    return [::entity::core::ecf::map include [::entity::core::ecf::text_array $patterns]]
}

# ───────────────────────── field reads (null-safe over a map TV) ─────────────────────────

# the raw KV list of a map tagged value (k1 v1 k2 v2 …), or {} if not a map.
proc ::entity::core::ecf::entries {mtv} {
    if {[lindex $mtv 0] ne "map"} { return {} }
    return [lindex $mtv 1]
}

# the value tagged value bound to TEXT key $key, or "" (absent).
proc ::entity::core::ecf::get {mtv key} {
    foreach {k v} [entries $mtv] {
        if {[lindex $k 0] eq "text" && [lindex $k 1] eq $key} { return $v }
    }
    return ""
}

# is TEXT key $key present at all (distinguishes present-empty from absent)?
proc ::entity::core::ecf::has {mtv key} {
    foreach {k v} [entries $mtv] {
        if {[lindex $k 0] eq "text" && [lindex $k 1] eq $key} { return 1 }
    }
    return 0
}

# a TEXT field's string, or "" if absent / not text.
proc ::entity::core::ecf::text {mtv key} {
    set v [get $mtv $key]
    return [expr {[lindex $v 0] eq "text" ? [lindex $v 1] : ""}]
}

# a BYTE field's raw octets, or "" if absent / not bytes.
proc ::entity::core::ecf::bytes {mtv key} {
    set v [get $mtv $key]
    return [expr {[lindex $v 0] eq "bytes" ? [lindex $v 1] : ""}]
}

# an INTEGER field (native Tcl bignum — no fixed-width trap), or "" if absent.
proc ::entity::core::ecf::uint {mtv key} {
    set v [get $mtv $key]
    return [expr {[lindex $v 0] eq "int" ? [lindex $v 1] : ""}]
}

# is tagged value $v the boolean true?
proc ::entity::core::ecf::bool_is {v} { return [expr {$v eq [list bool 1]}] }

# a map view of $v: $v itself if it is a {map …}, else "".
proc ::entity::core::ecf::asmap {v} {
    return [expr {[lindex $v 0] eq "map" ? $v : ""}]
}

# the {map …} value at $key, or "".
proc ::entity::core::ecf::mapfield {mtv key} { return [asmap [get $mtv $key]] }

# the text items of an array field as a Tcl list, or "" if the field is absent /
# not an array (present-empty array returns the empty list {}).
proc ::entity::core::ecf::textlist {mtv key} {
    set v [get $mtv $key]
    if {[lindex $v 0] ne "array"} { return "" }
    set out {}
    foreach it [lindex $v 1] {
        if {[lindex $it 0] eq "text"} { lappend out [lindex $it 1] }
    }
    return $out
}

# the {map …} items of an array field as a Tcl list of tagged maps, or "" if absent.
proc ::entity::core::ecf::maplist {mtv key} {
    set v [get $mtv $key]
    if {[lindex $v 0] ne "array"} { return "" }
    set out {}
    foreach it [lindex $v 1] {
        if {[lindex $it 0] eq "map"} { lappend out $it }
    }
    return $out
}
