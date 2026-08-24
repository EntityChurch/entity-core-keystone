#!/usr/bin/env tclsh
# entity-core-protocol-tcl — standalone S4-ready host.
#
# Boots a peer on a localhost port, prints a `LISTENING <port>` readiness line so a
# harness can scrape the bound port, then runs the single-threaded chan-event/vwait
# event loop forever (the §4.9 serve loop). Flags:
#
#   --port N               bind port (0 = auto, the default)
#   --seed B               seed byte (repeated 32×) for a deterministic identity
#   --name NAME            load a persistent Ed25519 identity from the standard on-disk
#                          location ~/.entity/peers/NAME/keypair (the entity-core PEM
#                          keypair: base64 of a 32-byte seed between BEGIN/END ENTITY
#                          PRIVATE KEY lines — the Go entity-peer --name / peer-manager
#                          convention). Lets the validator's multisig accept-path probe
#                          co-sign AS the peer (crypto.LookupKeypairByPeerID).
#   --debug-open-grants    degenerate [default → *] admin seed (non-conformant, F27)
#   --validate             bootstrap the §7a system/validate/* conformance handlers
#   --shim PATH            crypto C-extension shim (default src/ffi/libentitycorecrypto.so)
#
# The §7a handlers are OFF by default (a standing dispatch-outbound originator must
# never ship live); --validate opts in (the keystone cohort mechanism).

set here [file dirname [file normalize [info script]]]
set proj [file dirname $here]

# defaults
set port 0
set seed_byte ""
set name ""
set open_grants 0
set conformance 0
set shim [file join $proj src ffi libentitycorecrypto.so]

for {set i 0} {$i < [llength $argv]} {incr i} {
    set a [lindex $argv $i]
    switch -- $a {
        --port  { set port [lindex $argv [incr i]] }
        --seed  { set seed_byte [lindex $argv [incr i]] }
        --name  { set name [lindex $argv [incr i]] }
        --shim  { set shim [lindex $argv [incr i]] }
        --debug-open-grants { set open_grants 1 }
        --validate          { set conformance 1 }
        default { puts stderr "peer: unknown flag '$a'"; exit 2 }
    }
}

# load the crypto shim, then the peer.
if {![file exists $shim]} { puts stderr "peer: crypto shim not found: $shim (run `make shim`)"; exit 2 }
load $shim Entitycorecrypto
source [file join $proj src entity_core.tcl]

# ── resolve the 32-byte seed ──
proc load_seed_from_name {name} {
    set home [expr {[info exists ::env(HOME)] && $::env(HOME) ne "" ? $::env(HOME) : "/root"}]
    set path [file join $home .entity peers $name keypair]
    if {[catch {open $path r} fh]} { puts stderr "error: --name $name: cannot read $path"; exit 2 }
    set raw [read $fh]; close $fh
    set body ""
    foreach line [split $raw "\n"] {
        set line [string trim $line]
        if {$line eq "" || [string index $line 0] eq "-"} { continue }
        append body $line
    }
    if {[catch {binary decode base64 $body} seed] || [string length [binary format a* $seed]] != 32} {
        puts stderr "error: --name $name: expected a 32-byte seed"; exit 2
    }
    return $seed
}

if {$name ne ""} {
    set seed [load_seed_from_name $name]
} elseif {$seed_byte ne ""} {
    set seed [string repeat [binary format c $seed_byte] 32]
} else {
    set seed [string repeat "\x11" 32]
}

# ── boot ──
set peer [::entity::core::peer::create $seed $open_grants $conformance]
lassign [::entity::core::transport::start_listener $peer $port] srv bound
puts "LISTENING $bound"
flush stdout

# serve forever (the event loop; a var that is never set).
vwait ::__peer_forever__
