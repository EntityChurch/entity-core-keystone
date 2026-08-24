# S2 codec spike — the high-risk legs (float ladder, map-key sort, byte-vs-text,
# int minimal, tag reject). Not the full corpus walker (that is conformance.tcl);
# this validates the codec in isolation with hand-picked vectors from the pinned
# v0.8.0 corpus so the shortest-float + canonical-ordering logic is proven first.

lappend auto_path [file dirname [file dirname [file normalize [info script]]]]/src
source [file dirname [file dirname [file normalize [info script]]]]/src/cbor.tcl
namespace import ::entity::core::cbor::*

set ::pass 0; set ::fail 0
proc hx {bytes} { binary scan $bytes H* h; return $h }
proc unhx {h} { return [binary format H* $h] }

# encode(decode(canonical)) == canonical  — universal canonical round-trip stability
proc rt {id hex} {
    set want [unhx $hex]
    if {[catch {decode $want} val]} {
        puts "FAIL $id  decode threw: $val"; incr ::fail; return
    }
    if {[catch {encode $val} got]} {
        puts "FAIL $id  encode threw: $got"; incr ::fail; return
    }
    if {[hx $got] eq $hex} { incr ::pass } else {
        puts "FAIL $id  rt  want=$hex got=[hx $got]  val=$val"; incr ::fail
    }
}
# encode(taggedInput) == canonical  — forward transform (tests sorting/typing)
proc fwd {id val hex} {
    if {[catch {encode $val} got]} { puts "FAIL $id fwd encode threw: $got"; incr ::fail; return }
    if {[hx $got] eq $hex} { incr ::pass } else {
        puts "FAIL $id  fwd want=$hex got=[hx $got]"; incr ::fail
    }
}
# decode(canonical) must throw  — decode_reject
proc rej {id hex} {
    if {[catch {decode [unhx $hex]} e]} { incr ::pass } else {
        puts "FAIL $id  expected reject, decoded: $e"; incr ::fail
    }
}

puts "── float (shortest-float ladder) ──"
rt float.1  f90000
rt float.2  f98000
rt float.3  f93c00
rt float.4  f93e00
rt float.5  f97c00
rt float.6  f9fc00
rt float.7  f97e00
rt float.8  f97800
rt float.9  f97bfe
# f32-only and f64-only values (from the corpus battery)
rt float.f32  fa47c35000     ;# 100000.0 -> f32
rt float.f64  fb3ff199999999999a   ;# 1.1 -> f64

puts "── int (minimal head, boundaries) ──"
rt int.1  00
rt int.2  17
rt int.3  1818
rt int.4  18ff
rt int.5  190100
rt int.6  19ffff
rt int.7  1a00010000
rt int.8  1affffffff
rt int.9  1b0000000100000000
rt int.max  1bffffffffffffffff
fwd int.neg1 {int -1} 20
fwd int.neg500 {int -500} 3901f3

puts "── length boundaries ──"
rt length.1  80
rt length.2  a0
rt length.3  60
rt length.4  40
rt length.5  97000102030405060708090a0b0c0d0e0f10111213141516
rt length.8  78186162636465666768696a6b6c6d6e6f707172737475767778

puts "── map_keys (length-then-lex on encoded key bytes) ──"
rt map_keys.1  a1616101
# forward: give NON-canonical input order; encoder must sort
fwd map_keys.2 {map {{text aa} {int 2} {text z} {int 1}}} a2617a0162616102
fwd map_keys.3 {map {{text b} {int 2} {text a} {int 1}}} a2616101616202
fwd map_keys.6 {map {{text aaa} {int 2} {text aa} {int 1}}} a2626161016361616102
# byte-key vs text-key mixed (A-TCL-001 byte-vs-text under EIAS)
fwd map_keys.5 {map {{bytes key} {int 2} {text text_key} {int 1}}} a2436b65790268746578745f6b657901

puts "── primitive + nested (round-trip) ──"
rt primitive.1 f6
rt primitive.2 f5
rt primitive.3 f4
rt primitive.4 a16576616c7565f6
rt primitive.5 a26161f56162f4
rt primitive.6 a2616240617360
rt nested.1 a1656f75746572a165696e6e657201
rt nested.3 a26464617461a261610161626374776f647479706567746573742f7631

puts "── tag_reject (major-type-6 MUST reject) ──"
rej tag_reject.1 a2647479706567746573742f7631646461746161316274736374323032362d30362d30365431323a30303a30305a
rej tag_reject.4 d9d9f7a0

puts "── non-canonical decode MUST reject ──"
rej noncanon.int24  1817       ;# 24-encoded value 23 (should be single-byte)
rej noncanon.trailing 0000     ;# trailing data after first 00

puts "\n=== spike: $::pass pass / $::fail fail ==="
exit [expr {$::fail ? 1 : 0}]
