# entity-core-protocol-tcl — canonical CBOR (ECF) codec, pure Tcl.
#
# THE PARADIGM PROBE (A-TCL-001/003). Tcl is Everything-Is-A-String: a value has
# no intrinsic type. So this codec carries the CBOR major type EXPLICITLY in a
# tagged value representation — the decoder produces it, the encoder dispatches on
# it — rather than inferring type from a value's current string form (which EIAS
# makes impossible: "1" is a valid int, float, AND 1-byte text/bytes).
#
# Tagged value representation (a Tcl list, elem 0 = kind):
#   {int  N}      major 0/1  (sign of N picks the major type; N is a Tcl bignum)
#   {bytes B}     major 2    (B is a Tcl bytearray — raw octets)
#   {text S}      major 3    (S is a Tcl string; wire = UTF-8 of S)
#   {array L}     major 4    (L is a Tcl list of tagged values)
#   {map KV}      major 5    (KV is a flat list: k1 v1 k2 v2 …, each a tagged value)
#   {float F}     major 7    (F is a Tcl double; shortest-float ladder on encode)
#   {bool 0|1} {null} {undef} {simple N}   major 7 simple values
#
# Canonical rules enforced (ENTITY-CBOR-ENCODING v1.5, conformance invariants N1–N3):
#   - minimal integer/length argument (never a wider head than needed)
#   - length-then-lexicographic map-key ordering on ENCODED key bytes (§4.2.1)
#   - shortest-float ladder f16→f32→f64 (Rule 4); canonical NaN 0x7e00
#   - recursive major-type-6 (tag) REJECTION on decode (N2) — never trust defaults
#   - full-consume check on decode (no trailing data; A-CBL-003)
#   - decode re-validates minimality (a non-minimal head is rejected, not accepted)

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1

namespace eval ::entity::core::cbor {
    namespace export encode decode
}

# ───────────────────────── error helper ─────────────────────────
proc ::entity::core::cbor::_reject {kind detail} {
    # N2/N3 hard reject — structured -errorcode (A-TCL error model).
    throw [list ENTITY_CORE $kind $detail] "cbor: $kind: $detail"
}

# ═════════════════════════ ENCODE ═════════════════════════
# encode taggedValue -> byte string (bytearray)
proc ::entity::core::cbor::encode {val} {
    set acc ""
    _enc acc $val
    return $acc
}

proc ::entity::core::cbor::_emit_head {accVar major arg} {
    upvar 1 $accVar acc
    set ib [expr {$major << 5}]
    if {$arg < 0} { _reject NON_CANONICAL_ECF "negative head arg" }
    if {$arg <= 23} {
        append acc [binary format c [expr {$ib | $arg}]]
    } elseif {$arg <= 0xff} {
        append acc [binary format cc [expr {$ib | 24}] [expr {$arg & 0xff}]]
    } elseif {$arg <= 0xffff} {
        append acc [binary format c [expr {$ib | 25}]]
        _emit_be acc $arg 2
    } elseif {$arg <= 0xffffffff} {
        append acc [binary format c [expr {$ib | 26}]]
        _emit_be acc $arg 4
    } else {
        append acc [binary format c [expr {$ib | 27}]]
        _emit_be acc $arg 8
    }
}

# big-endian minimal-safe: split a (possibly bignum) integer into nbytes octets.
proc ::entity::core::cbor::_emit_be {accVar n nbytes} {
    upvar 1 $accVar acc
    for {set i [expr {($nbytes - 1) * 8}]} {$i >= 0} {incr i -8} {
        append acc [binary format c [expr {($n >> $i) & 0xff}]]
    }
}

proc ::entity::core::cbor::_enc {accVar val} {
    upvar 1 $accVar acc
    set kind [lindex $val 0]
    switch -- $kind {
        int {
            set n [lindex $val 1]
            if {$n >= 0} {
                _emit_head acc 0 $n
            } else {
                _emit_head acc 1 [expr {-1 - $n}]
            }
        }
        bytes {
            set b [lindex $val 1]
            # ensure a byte array; length is byte count
            set b [binary format a* $b]
            _emit_head acc 2 [string length $b]
            append acc $b
        }
        text {
            set s [lindex $val 1]
            # A-TCL-002: wire length is the UTF-8 BYTE count, not [string length $s]
            set u [encoding convertto utf-8 $s]
            _emit_head acc 3 [string length $u]
            append acc $u
        }
        array {
            set items [lindex $val 1]
            _emit_head acc 4 [llength $items]
            foreach it $items { _enc acc $it }
        }
        map {
            _enc_map acc [lindex $val 1]
        }
        float {
            _enc_float acc [lindex $val 1]
        }
        bool {
            append acc [binary format c [expr {[lindex $val 1] ? 0xf5 : 0xf4}]]
        }
        null  { append acc [binary format c 0xf6] }
        undef { append acc [binary format c 0xf7] }
        simple {
            set n [lindex $val 1]
            if {$n < 24} {
                append acc [binary format c [expr {0xe0 | $n}]]
            } else {
                append acc [binary format cc 0xf8 [expr {$n & 0xff}]]
            }
        }
        default { _reject NON_CANONICAL_ECF "unknown value kind '$kind'" }
    }
}

# canonical map: sort entries by ENCODED KEY bytes, length-then-lexicographic (§4.2.1)
proc ::entity::core::cbor::_enc_map {accVar kv} {
    upvar 1 $accVar acc
    set n [expr {[llength $kv] / 2}]
    set entries {}
    foreach {k v} $kv {
        set kb [encode $k]
        lappend entries [list $kb $k $v]
    }
    set entries [lsort -command ::entity::core::cbor::_keycmp $entries]
    _emit_head acc 5 $n
    foreach e $entries {
        append acc [lindex $e 0]        ;# already-encoded key bytes
        _enc acc [lindex $e 2]
    }
}

# length-first, then bytewise-lexicographic on the encoded key bytes.
proc ::entity::core::cbor::_keycmp {a b} {
    set ka [lindex $a 0]; set kb [lindex $b 0]
    set la [string length $ka]; set lb [string length $kb]
    if {$la != $lb} { return [expr {$la < $lb ? -1 : 1}] }
    # bytewise unsigned compare
    binary scan $ka cu* av
    binary scan $kb cu* bv
    foreach x $av y $bv {
        if {$x != $y} { return [expr {$x < $y ? -1 : 1}] }
    }
    return 0
}

# ───────── shortest-float ladder: f64 -> try f16, then f32, else f64 ─────────
proc ::entity::core::cbor::_enc_float {accVar f} {
    upvar 1 $accVar acc
    # Special values: canonical half-float forms.
    if {$f != $f} { append acc [binary format cH* 0xf9 7e00]; return }      ;# NaN -> 0x7e00
    if {$f eq "Inf"  || $f == Inf}  { append acc [binary format cH* 0xf9 7c00]; return }
    if {$f eq "-Inf" || $f == -Inf} { append acc [binary format cH* 0xf9 fc00]; return }

    # 64-bit IEEE big-endian reference bytes.
    binary scan [binary format Q $f] W f64bits
    set f64bits [expr {$f64bits & 0xffffffffffffffff}]

    # Try f16: encode->decode->compare exact.
    set h [_f64_to_f16 $f64bits]
    if {$h ne "" && [_f16_to_f64bits $h] == $f64bits} {
        append acc [binary format c 0xf9]
        _emit_be acc $h 2
        return
    }
    # Try f32: encode->decode->compare exact.
    binary scan [binary format R $f] Iu f32bits
    if {[_f32bits_to_f64bits $f32bits] == $f64bits} {
        append acc [binary format c 0xfa]
        _emit_be acc $f32bits 4
        return
    }
    # Fall back to f64.
    append acc [binary format c 0xfb]
    _emit_be acc $f64bits 8
}

# f64 bit pattern -> f16 bit pattern, or "" if not exactly representable.
proc ::entity::core::cbor::_f64_to_f16 {bits} {
    set sign [expr {($bits >> 63) & 0x1}]
    set exp  [expr {($bits >> 52) & 0x7ff}]
    set mant [expr {$bits & 0xfffffffffffff}]
    if {$exp == 0} {
        # zero (subnormal f64 can't be exact f16 unless zero)
        if {$mant == 0} { return [expr {$sign << 15}] }
        return ""
    }
    if {$exp == 0x7ff} { return "" }   ;# inf/nan handled by caller
    set unbiased [expr {$exp - 1023}]
    if {$unbiased > 15}  { return "" } ;# too large for f16 normal
    if {$unbiased >= -14} {
        # normal f16: mantissa must fit in 10 bits exactly (low 42 bits zero)
        if {($mant & 0x3ffffffff) != 0} { return "" }
        set m10 [expr {$mant >> 42}]
        set e5 [expr {$unbiased + 15}]
        return [expr {($sign << 15) | ($e5 << 10) | $m10}]
    }
    # subnormal f16 range: -24..-15
    if {$unbiased >= -24} {
        set full [expr {(1 << 52) | $mant}]      ;# implicit leading 1
        set shift [expr {42 + (-14 - $unbiased)}]
        if {($full & ((1 << $shift) - 1)) != 0} { return "" }
        set m [expr {$full >> $shift}]
        return [expr {($sign << 15) | $m}]
    }
    return ""
}

proc ::entity::core::cbor::_f16_to_f64bits {h} {
    set sign [expr {($h >> 15) & 0x1}]
    set exp  [expr {($h >> 10) & 0x1f}]
    set mant [expr {$h & 0x3ff}]
    if {$exp == 0} {
        if {$mant == 0} { return [expr {$sign << 63}] }
        # subnormal: normalize
        set e -14
        while {($mant & 0x400) == 0} { set mant [expr {$mant << 1}]; incr e -1 }
        set mant [expr {$mant & 0x3ff}]
        set exp64 [expr {($e + 1023) & 0x7ff}]
        return [expr {($sign << 63) | ($exp64 << 52) | ($mant << 42)}]
    } elseif {$exp == 0x1f} {
        return [expr {($sign << 63) | (0x7ff << 52) | ($mant << 42)}]
    }
    set exp64 [expr {($exp - 15 + 1023)}]
    return [expr {($sign << 63) | ($exp64 << 52) | ($mant << 42)}]
}

proc ::entity::core::cbor::_f32bits_to_f64bits {bits} {
    set sign [expr {($bits >> 31) & 0x1}]
    set exp  [expr {($bits >> 23) & 0xff}]
    set mant [expr {$bits & 0x7fffff}]
    if {$exp == 0} {
        if {$mant == 0} { return [expr {$sign << 63}] }
        set e -126
        while {($mant & 0x800000) == 0} { set mant [expr {$mant << 1}]; incr e -1 }
        set mant [expr {$mant & 0x7fffff}]
        set exp64 [expr {($e + 1023) & 0x7ff}]
        return [expr {($sign << 63) | ($exp64 << 52) | ($mant << 29)}]
    } elseif {$exp == 0xff} {
        return [expr {($sign << 63) | (0x7ff << 52) | ($mant << 29)}]
    }
    set exp64 [expr {($exp - 127 + 1023)}]
    return [expr {($sign << 63) | ($exp64 << 52) | ($mant << 29)}]
}

# ═════════════════════════ DECODE ═════════════════════════
# decode bytes -> taggedValue ; rejects non-canonical + trailing data.
proc ::entity::core::cbor::decode {bytes} {
    set b [binary format a* $bytes]
    set pos 0
    set val [_dec $b pos]
    if {$pos != [string length $b]} {
        _reject TRUNCATED_INPUT "trailing data after top-level value ($pos of [string length $b])"
    }
    return $val
}

proc ::entity::core::cbor::_byte {b posVar} {
    upvar 1 $posVar pos
    if {$pos >= [string length $b]} { _reject TRUNCATED_INPUT "read past end" }
    binary scan [string index $b $pos] cu v
    incr pos
    return $v
}

proc ::entity::core::cbor::_take {b posVar n} {
    upvar 1 $posVar pos
    if {$n < 0 || $pos + $n > [string length $b]} { _reject TRUNCATED_INPUT "read past end ($n)" }
    set s [string range $b $pos [expr {$pos + $n - 1}]]
    incr pos $n
    return $s
}

# read a head; return {major arg}; enforce minimal-argument canonicality.
proc ::entity::core::cbor::_head {b posVar} {
    upvar 1 $posVar pos
    set ib [_byte $b pos]
    set major [expr {$ib >> 5}]
    set ai [expr {$ib & 0x1f}]
    if {$ai < 24} {
        return [list $major $ai]
    } elseif {$ai == 24} {
        set v [_byte $b pos]
        if {$v < 24} { _reject NON_CANONICAL_ECF "non-minimal 1-byte arg ($v)" }
        return [list $major $v]
    } elseif {$ai == 25} {
        binary scan [_take $b pos 2] Su v; set v [expr {$v & 0xffff}]
        if {$v <= 0xff} { _reject NON_CANONICAL_ECF "non-minimal 2-byte arg ($v)" }
        return [list $major $v]
    } elseif {$ai == 26} {
        binary scan [_take $b pos 4] Iu v; set v [expr {$v & 0xffffffff}]
        if {$v <= 0xffff} { _reject NON_CANONICAL_ECF "non-minimal 4-byte arg ($v)" }
        return [list $major $v]
    } elseif {$ai == 27} {
        binary scan [_take $b pos 8] Wu v; set v [expr {$v & 0xffffffffffffffff}]
        if {$v <= 0xffffffff} { _reject NON_CANONICAL_ECF "non-minimal 8-byte arg ($v)" }
        return [list $major $v]
    } else {
        _reject NON_CANONICAL_ECF "reserved additional-info $ai (no indefinite lengths in ECF)"
    }
}

proc ::entity::core::cbor::_dec {b posVar} {
    upvar 1 $posVar pos
    # Peek for major type 6 (tags) and 7 specials that need raw handling.
    set start $pos
    binary scan [string index $b $pos] cu ib0
    set major0 [expr {$ib0 >> 5}]
    if {$major0 == 6} {
        _reject TAG_REJECTED "major-type-6 tag not permitted in ECF (§6.3)"
    }
    if {$major0 == 7} {
        return [_dec_simple $b pos]
    }
    lassign [_head $b pos] major arg
    switch -- $major {
        0 { return [list int $arg] }
        1 { return [list int [expr {-1 - $arg}]] }
        2 { return [list bytes [_take $b pos $arg]] }
        3 {
            set u [_take $b pos $arg]
            return [list text [encoding convertfrom utf-8 $u]]
        }
        4 {
            set items {}
            for {set i 0} {$i < $arg} {incr i} { lappend items [_dec $b pos] }
            return [list array $items]
        }
        5 {
            set kv {}
            set prevkb ""
            for {set i 0} {$i < $arg} {incr i} {
                set kstart $pos
                set k [_dec $b pos]
                set kb [string range $b $kstart [expr {$pos - 1}]]
                # enforce canonical key ordering on decode too (strict)
                if {$i > 0 && [_rawkeycmp $prevkb $kb] >= 0} {
                    _reject NON_CANONICAL_ECF "map keys not in canonical order"
                }
                set prevkb $kb
                set v [_dec $b pos]
                lappend kv $k $v
            }
            return [list map $kv]
        }
        default { _reject NON_CANONICAL_ECF "unexpected major $major" }
    }
}

proc ::entity::core::cbor::_rawkeycmp {a b} {
    set la [string length $a]; set lb [string length $b]
    if {$la != $lb} { return [expr {$la < $lb ? -1 : 1}] }
    binary scan $a cu* av; binary scan $b cu* bv
    foreach x $av y $bv { if {$x != $y} { return [expr {$x < $y ? -1 : 1}] } }
    return 0
}

proc ::entity::core::cbor::_dec_simple {b posVar} {
    upvar 1 $posVar pos
    set ib [_byte $b pos]
    set ai [expr {$ib & 0x1f}]
    switch -- $ai {
        20 { return {bool 0} }
        21 { return {bool 1} }
        22 { return {null} }
        23 { return {undef} }
        24 {
            set v [_byte $b pos]
            if {$v < 32} { _reject NON_CANONICAL_ECF "simple value < 32 must be 1-byte form" }
            return [list simple $v]
        }
        25 { return [_dec_f16 $b pos] }
        26 { return [_dec_f32 $b pos] }
        27 { return [_dec_f64 $b pos] }
        default {
            if {$ai < 20} { return [list simple $ai] }
            _reject NON_CANONICAL_ECF "reserved simple/float additional-info $ai"
        }
    }
}

proc ::entity::core::cbor::_dec_f16 {b posVar} {
    upvar 1 $posVar pos
    binary scan [_take $b pos 2] Su h; set h [expr {$h & 0xffff}]
    set bits [_f16_to_f64bits $h]
    return [list float [_f64bits_to_double $bits]]
}
proc ::entity::core::cbor::_dec_f32 {b posVar} {
    upvar 1 $posVar pos
    binary scan [_take $b pos 4] R f
    # strict shortest-float: an f32 that fits f16 exactly is non-canonical
    binary scan [binary format Q $f] W f64bits; set f64bits [expr {$f64bits & 0xffffffffffffffff}]
    if {[_would_be_f16 $f64bits]} { _reject NON_CANONICAL_ECF "float not shortest (f32 fits f16)" }
    return [list float $f]
}
proc ::entity::core::cbor::_dec_f64 {b posVar} {
    upvar 1 $posVar pos
    binary scan [_take $b pos 8] Q f
    binary scan [binary format Q $f] W f64bits; set f64bits [expr {$f64bits & 0xffffffffffffffff}]
    if {[_would_be_f16 $f64bits] || [_would_be_f32 $f64bits]} {
        _reject NON_CANONICAL_ECF "float not shortest (f64 fits narrower)"
    }
    return [list float $f]
}
proc ::entity::core::cbor::_would_be_f16 {bits} {
    set exp [expr {($bits >> 52) & 0x7ff}]
    if {$exp == 0x7ff} { return 1 }  ;# inf/nan -> f16
    set h [_f64_to_f16 $bits]
    return [expr {$h ne "" && [_f16_to_f64bits $h] == $bits}]
}
proc ::entity::core::cbor::_would_be_f32 {bits} {
    set exp [expr {($bits >> 52) & 0x7ff}]
    if {$exp == 0x7ff} { return 1 }
    binary scan [binary format R [_f64bits_to_double $bits]] Iu f32bits
    return [expr {[_f32bits_to_f64bits $f32bits] == $bits}]
}
proc ::entity::core::cbor::_f64bits_to_double {bits} {
    binary scan [binary format Wu $bits] Q d
    return $d
}
