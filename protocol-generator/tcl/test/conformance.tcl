# entity-core-protocol-tcl — S2 codec conformance harness.
#
# Walks the PINNED v0.8.0 corpus (protocol-generator/shared/test-vectors/v0.8.0/
# conformance-vectors-v1.cbor) — decoded with OUR OWN decoder (the corpus is trusted
# canonical ECF) — and asserts, per vector:
#   encode_equal   : encode(reconstructed value) == canonical bytes
#   decode_reject  : decode(canonical bytes) throws
# Class B (content_hash / signature / peer_id) is reconstructed from the vector's
# `input` fields and driven through the pure-Tcl base58/varint + the crypto C-shim.
#
# Usage (in container):
#   LD_LIBRARY_PATH=<codec-build> tclsh test/conformance.tcl <corpus.cbor> <shim.so>

set here [file dirname [file normalize [info script]]]
set root [file dirname $here]
source $root/src/cbor.tcl
source $root/src/peerid.tcl
namespace import ::entity::core::cbor::*

set corpus [lindex $argv 0]
set shim   [lindex $argv 1]
set have_crypto 0
if {$shim ne "" && [file exists $shim]} {
    load $shim Entitycorecrypto
    set have_crypto 1
}

# ── helpers over the decoded tagged representation ──
# a decoded vector is {map {k1 v1 k2 v2 …}} with text keys; pull one field's value.
proc field {vec name} {
    foreach {k v} [lindex $vec 1] {
        if {[lindex $k 0] eq "text" && [lindex $k 1] eq $name} { return $v }
    }
    return ""
}
proc tval {v} { return [lindex $v 1] }   ;# unwrap a scalar tagged value (int/bytes/text)

# ── load + decode the corpus ──
set fh [open $corpus rb]; set data [read $fh]; close $fh
set top [decode $data]
if {[lindex $top 0] ne "array"} { puts "FATAL: corpus top-level is not an array"; exit 2 }
set vecs [lindex $top 1]

set pass 0; set fail 0; set skip 0
set fails {}
proc ok {} { incr ::pass }
proc bad {id why} { incr ::fail; lappend ::fails "$id: $why" }
proc skp {id why} { incr ::skip; puts "SKIP $id — $why" }

foreach vec $vecs {
    set id   [tval [field $vec id]]
    set kind [tval [field $vec kind]]
    set cat  [lindex [split $id .] 0]
    set canon [tval [field $vec canonical]]     ;# byte string
    set input [field $vec input]

    if {$kind eq "decode_reject"} {
        if {[catch {decode $canon}]} { ok } else { bad $id "expected decode reject, but decoded" }
        continue
    }

    # encode_equal — reconstruct the value per category, encode, compare.
    switch -- $cat {
        peer_id {
            set got [encode [::entity::core::peerid::format_id \
                        [tval [field $input key_type]] \
                        [tval [field $input hash_type]] \
                        [tval [field $input digest]]]]
        }
        content_hash {
            if {!$have_crypto} { skp $id "crypto shim not loaded"; continue }
            set entity [list map [list {text type} [field $input type] \
                                       {text data} [field $input data]]]
            set fc [field $input format_code]
            set code [expr {$fc eq "" ? 0 : [tval $fc]}]
            set got [::entity::core::varint::encode $code]
            append got [::entity::core::crypto::sha256 [encode $entity]]
        }
        signature {
            if {!$have_crypto} { skp $id "crypto shim not loaded"; continue }
            set got [::entity::core::crypto::ed25519_sign \
                        [tval [field $input seed]] [encode [field $input entity]]]
        }
        default {
            # Class A + envelope: the input IS the value; re-encode it canonically.
            set got [encode $input]
        }
    }

    if {$got eq $canon} { ok } else {
        bad $id "encode mismatch\n    want [binary encode hex $canon]\n    got  [binary encode hex $got]"
    }
}

puts "\n=== conformance: [llength $vecs] vectors — $pass pass / $fail fail / $skip skip ==="
foreach f $fails { puts "  FAIL $f" }
exit [expr {$fail ? 1 : 0}]
