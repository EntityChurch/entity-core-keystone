# entity-core-protocol-tcl — S3 foundation self-test (offline, no network).
# Exercises the value model + entity + identity layers against the crypto shim.
# Usage (in container): LD_LIBRARY_PATH=<codec-build> tclsh test/s3_selftest.tcl <shim.so>

set here [file dirname [file normalize [info script]]]
set root [file dirname $here]
set shim [lindex $argv 0]
load $shim Entitycorecrypto

source $root/src/entity_core.tcl
namespace eval t {}
set ::pass 0; set ::fail 0
proc check {name cond} {
    if {[uplevel 1 [list expr $cond]]} { incr ::pass; puts "  \[PASS\] $name" } \
    else       { incr ::fail; puts "  \[FAIL\] $name" }
}

# ── entity hashing determinism + wire round-trip ──
set e1 [::entity::core::entity::make primitive/string [::entity::core::ecf::tstr hello]]
set e2 [::entity::core::entity::make primitive/string [::entity::core::ecf::tstr hello]]
check "entity hash deterministic" {[::entity::core::entity::hash $e1] eq [::entity::core::entity::hash $e2]}
check "content_hash is 33 bytes (fmt byte + sha256)" \
    {[string length [binary format a* [::entity::core::entity::hash $e1]]] == 33}
set wire [::entity::core::entity::to_cbor $e1]
set back [::entity::core::entity::of_cbor $wire]
check "wire round-trip preserves type" {[::entity::core::entity::type $back] eq "primitive/string"}
check "wire round-trip preserves hash" \
    {[::entity::core::entity::hash $back] eq [::entity::core::entity::hash $e1]}

# tamper the content_hash → §1.8 fidelity reject
set bad [::entity::core::ecf::map type [::entity::core::ecf::tstr primitive/string] \
    data [::entity::core::ecf::tstr hello] \
    content_hash [::entity::core::ecf::bstr [string repeat "\x00" 33]]]
check "tampered content_hash rejected (§1.8)" {[catch {::entity::core::entity::of_cbor $bad}]}

# ── identity: seed → pubkey → peer_id → peer entity ──
set seedA [string repeat "\x11" 32]
set seedB [string repeat "\x22" 32]
set idA [::entity::core::identity::of_seed $seedA]
set idB [::entity::core::identity::of_seed $seedB]
check "peer_id is Base58 non-empty" {[string length [dict get $idA peer_id]] >= 32}
check "distinct seeds → distinct peer_ids" {[dict get $idA peer_id] ne [dict get $idB peer_id]}
check "id_hash is 33 bytes" {[string length [binary format a* [dict get $idA id_hash]]] == 33}
check "peer_id derivable from pubkey matches" \
    {[::entity::core::identity::peer_id_of_pubkey [dict get $idA pub]] eq [dict get $idA peer_id]}

# ── sign / verify round-trip ──
set target [::entity::core::entity::make primitive/any [::entity::core::ecf::map ping [::entity::core::ecf::tint 42]]]
set sigA [::entity::core::identity::sign $idA $target]
check "signature entity type" {[::entity::core::entity::type $sigA] eq "system/signature"}
check "signature verifies against signer peer" \
    {[::entity::core::identity::verify_signature $sigA [dict get $idA peer_entity]]}
check "signature FAILS against wrong peer" \
    {![::entity::core::identity::verify_signature $sigA [dict get $idB peer_entity]]}
# signer-hash binding: the sig's signer == A's id_hash
check "signature signer == author id_hash" \
    {[::entity::core::entity::bytes $sigA signer] eq [dict get $idA id_hash]}

# ── wire: EXECUTE + envelope frame round-trip ──
set exec [::entity::core::wire::make_execute req-1 /peer/system/tree get \
    [::entity::core::wire::empty_params] [dict get $idA id_hash] "" \
    [::entity::core::wire::resource_target system/handler/system/tree]]
set envx [::entity::core::envelope::make $exec [list \
    [::entity::core::envelope::inc [dict get $idA peer_entity]] \
    [::entity::core::envelope::inc [::entity::core::identity::sign $idA $exec]]]]
set payload [::entity::core::wire::frame_of_envelope $envx]
set framed [::entity::core::wire::frame $payload]
check "frame prefix is 4-byte BE length" \
    {[binary format Iu [string length [binary format a* $payload]]] eq [string range $framed 0 3]}
set envx2 [::entity::core::wire::envelope_of_frame $payload]
check "envelope frame round-trips root type" \
    {[::entity::core::entity::type [::entity::core::envelope::root $envx2]] eq "system/protocol/execute"}
check "envelope round-trips included count (2)" \
    {[llength [::entity::core::envelope::included $envx2]] == 2}
check "included_get by hash resolves the signer peer" \
    {[::entity::core::envelope::included_get $envx2 [dict get $idA id_hash]] ne ""}

# ── response builder + decode ──
set resp [::entity::core::wire::make_response req-1 404 [::entity::core::wire::error_result not_found here]]
set renv [::entity::core::envelope::make $resp]
set rback [::entity::core::wire::envelope_of_frame [::entity::core::wire::frame_of_envelope $renv]]
check "response status decodes to 404" {[::entity::core::wire::response_status $rback] == 404}
check "response result is system/protocol/error" \
    {[::entity::core::entity::type [::entity::core::wire::response_result $rback]] eq "system/protocol/error"}

# ── store: bind / get / listing + emit seam ──
set sh [::entity::core::store::new]
set ::emit 0
proc noteemit {ev} { incr ::emit }
::entity::core::store::register_tree_consumer $sh noteemit
::entity::core::store::bind $sh /p/system/tree/a $e1
::entity::core::store::bind $sh /p/system/tree/b $e2
check "emit hook fired on each new bind" {$emit == 2}
check "get_at resolves a bound entity" \
    {[::entity::core::entity::hash [::entity::core::store::get_at $sh /p/system/tree/a]] eq [::entity::core::entity::hash $e1]}
check "get_by_hash resolves content" \
    {[::entity::core::store::get_by_hash $sh [::entity::core::entity::hash $e1]] ne ""}
check "listing sees 2 children under /p/system/tree/" \
    {[llength [::entity::core::store::listing $sh /p/system/tree]] == 2}

# ── core types: 53-type floor, deterministic ──
set models [::entity::core::coretypes::models]
check "53-type core floor present" {[dict size $models] == 53}
set sh2 [::entity::core::store::new]
::entity::core::coretypes::publish $sh2 PEERX
check "publish binds system/type/system/peer" \
    {[::entity::core::store::get_at $sh2 /PEERX/system/type/system/peer] ne ""}
# determinism: same model → same content_hash across two builds
set t1 [::entity::core::entity::make system/type [dict get $models system/capability/token]]
set t2 [::entity::core::entity::make system/type [dict get [::entity::core::coretypes::models] system/capability/token]]
check "type-model content_hash deterministic" \
    {[::entity::core::entity::hash $t1] eq [::entity::core::entity::hash $t2]}

# ── §4.5 hello negotiation: present-empty vs absent (review finding #1) ──
# The oracle can't cover present-empty hash_formats/key_types; this locks the fix.
set npeer [::entity::core::peer::create $seedA]
proc hello_status {peer fields} {
    set hello [::entity::core::entity::make system/protocol/connect/hello $fields]
    set exec [::entity::core::wire::make_execute rq system/protocol/connect hello $hello]
    set conn [::entity::core::conn::new]
    set out [::entity::core::handlers::connect $peer hello \
        [dict create exec $exec conn $conn included {} caller_cap "" env ""]]
    return [dict get $out status]
}
# (a) absent hash_formats → accepted (200, nonce issued)
check "hello: absent hash_formats accepted" \
    {[hello_status $npeer [::entity::core::ecf::map peer_id [::entity::core::ecf::tstr [dict get $idA peer_id]]]] == 200}
# (b) present-EMPTY hash_formats → 400 incompatible (the fix: not silently skipped)
check "hello: present-empty hash_formats → 400" \
    {[hello_status $npeer [::entity::core::ecf::map hash_formats [::entity::core::ecf::text_array {}]]] == 400}
# (c) present-empty key_types → 400 unsupported_key_type
check "hello: present-empty key_types → 400" \
    {[hello_status $npeer [::entity::core::ecf::map key_types [::entity::core::ecf::text_array {}]]] == 400}
# (d) present with the supported value → accepted
check "hello: hash_formats with ecfv1-sha256 accepted" \
    {[hello_status $npeer [::entity::core::ecf::map hash_formats [::entity::core::ecf::text_array {ecfv1-sha256}]]] == 200}
# (e) present but DISJOINT (real value, wrong) → 400
check "hello: disjoint hash_formats → 400" \
    {[hello_status $npeer [::entity::core::ecf::map hash_formats [::entity::core::ecf::text_array {sha3-512}]]] == 400}

# ── ecf::map key robustness (review finding #2): a text key literally "int" ──
set km [::entity::core::ecf::map int [::entity::core::ecf::tstr v]]
check "ecf::map: bare key 'int' encodes as a TEXT key, not a mangled tag" \
    {[lindex [::entity::core::ecf::entries $km] 0] eq {text int}}

puts "\n=== S3 foundation: $::pass pass / $::fail fail ==="
exit [expr {$::fail ? 1 : 0}]
