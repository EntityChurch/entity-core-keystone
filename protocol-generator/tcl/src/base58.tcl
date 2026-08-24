# entity-core-protocol-tcl — Base58 (Bitcoin alphabet), pure Tcl.
# Uses Tcl's native bignums (libtommath) for the big-endian base-256 -> base-58
# conversion — no fixed-width limit. Leading zero bytes map to leading '1's.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1

namespace eval ::entity::core::base58 {
    variable ALPHA "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    namespace export encode decode
}

# encode bytes -> base58 string
proc ::entity::core::base58::encode {bytes} {
    variable ALPHA
    set bytes [binary format a* $bytes]
    if {[string length $bytes] == 0} { return "" }
    binary scan $bytes cu* vals
    # count leading zero bytes
    set nzeros 0
    foreach v $vals { if {$v == 0} { incr nzeros } else break }
    # big-endian bytes -> bignum
    set num 0
    foreach v $vals { set num [expr {$num * 256 + $v}] }
    # bignum -> base58 (reversed)
    set out ""
    while {$num > 0} {
        set rem [expr {$num % 58}]
        set num [expr {$num / 58}]
        set out [string index $ALPHA $rem]$out
    }
    return [string repeat "1" $nzeros]$out
}

# decode base58 string -> bytes (rejects a non-alphabet char)
proc ::entity::core::base58::decode {s} {
    variable ALPHA
    if {[string length $s] == 0} { return "" }
    set nzeros 0
    foreach c [split $s ""] { if {$c eq "1"} { incr nzeros } else break }
    set num 0
    foreach c [split $s ""] {
        set d [string first $c $ALPHA]
        if {$d < 0} { throw {ENTITY_CORE BAD_BASE58 char} "base58: bad char '$c'" }
        set num [expr {$num * 58 + $d}]
    }
    # bignum -> big-endian bytes
    set body ""
    while {$num > 0} {
        set body [binary format c [expr {$num & 0xff}]]$body
        set num [expr {$num >> 8}]
    }
    return [binary format a* [string repeat "\x00" $nzeros]]$body
}
