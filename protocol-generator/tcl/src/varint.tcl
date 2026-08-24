# entity-core-protocol-tcl — unsigned LEB128 varint (multicodec key/hash-type codes).
# N1: route all format-code / key-type / hash-type framing through a real varint,
# never fixed bytes (a code ≥ 0x80 must widen — peer_id.3 / content_hash.4 test this).

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1

namespace eval ::entity::core::varint {
    namespace export encode decode
}

# unsigned LEB128 encode: integer -> byte string
proc ::entity::core::varint::encode {n} {
    if {$n < 0} { throw {ENTITY_CORE BAD_VARINT negative} "varint: negative value" }
    set out ""
    while {1} {
        set b [expr {$n & 0x7f}]
        set n [expr {$n >> 7}]
        if {$n != 0} {
            append out [binary format c [expr {$b | 0x80}]]
        } else {
            append out [binary format c $b]
            break
        }
    }
    return $out
}

# unsigned LEB128 decode: (bytes, posVar) -> integer, advancing pos. Rejects a
# non-minimal (trailing 0x80 with nothing above) or truncated encoding.
proc ::entity::core::varint::decode {bytes posVar} {
    upvar 1 $posVar pos
    set shift 0
    set result 0
    set nbytes 0
    while {1} {
        if {$pos >= [string length $bytes]} {
            throw {ENTITY_CORE BAD_VARINT truncated} "varint: truncated"
        }
        binary scan [string index $bytes $pos] cu b
        incr pos
        incr nbytes
        set result [expr {$result | (($b & 0x7f) << $shift)}]
        if {($b & 0x80) == 0} {
            # minimal-form check: a multi-byte encoding whose last byte is 0x00 is non-minimal
            if {$nbytes > 1 && $b == 0} {
                throw {ENTITY_CORE BAD_VARINT non_minimal} "varint: non-minimal encoding"
            }
            break
        }
        incr shift 7
    }
    return $result
}
