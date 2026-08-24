# entity-core-protocol-tcl — S3 two-peer loopback smoke test (the phase exit gate).
#
# Two Tcl peers talk over REAL loopback TCP through the full §6.5 dispatch chain,
# multiplexed on ONE single-threaded Tcl event loop (chan event + vwait): a
# RESPONDER listens; an INITIATOR (a second identity) dials it, drives the §4.1
# forward handshake (hello → authenticate), then:
#   - 404 on an unregistered path (no handler resolved);
#   - an authority-gated tree get (200) over the §4.4 discovery floor, returning a
#     system/handler/interface entity;
#   - a capability request (200);
#   - 8-way request_id demux of concurrently-issued replies (N7, §6.11) — 8 requests
#     in flight on the one connection, resolved out of order by the loop.
#
# The full validate-peer --profile core run is S4. This smoke proves the wire-level
# peer surface so S4 can run the oracle.
#
# Usage (in container): LD_LIBRARY_PATH=<codec-build> tclsh test/smoke.tcl <shim.so>

set here [file dirname [file normalize [info script]]]
set root [file dirname $here]
set shim [lindex $argv 0]
load $shim Entitycorecrypto
source $root/src/entity_core.tcl

namespace import ::entity::core::transport::*

set ::pass 0
set ::fail 0
proc check {name cond} {
    if {[uplevel 1 [list expr $cond]]} { incr ::pass; puts "  \[PASS\] $name" } \
    else     { incr ::fail; puts "  \[FAIL\] $name" }
}
proc seed {b} { return [string repeat [binary format c $b] 32] }

# helpers over a response envelope
proc rstatus {env} { return [expr {$env ne "" ? [::entity::core::wire::response_status $env] : -1}] }
proc rtype {env} {
    if {$env eq ""} { return "" }
    set r [::entity::core::wire::response_result $env]
    return [expr {$r ne "" ? [::entity::core::entity::type $r] : ""}]
}

set responder [::entity::core::peer::create [seed 0x11]]
lassign [start_listener $responder 0] srv port
set initiator [::entity::core::peer::create [seed 0x22]]
set s [dial $initiator 127.0.0.1 $port]

set remote [session_get $s remote_peer_id]
check "session established (capability minted)" {[session_get $s capability] ne ""}
check "remote peer_id matches responder" {$remote eq [::entity::core::peer::local_peer $responder]}

# 404 on an unregistered path
set r404 [session_execute $s "/$remote/does/not/exist" noop [::entity::core::wire::empty_params]]
check "unregistered path -> 404" {[rstatus $r404] == 404}

# authority-gated tree get (200) over the discovery floor
set iface_target [::entity::core::wire::resource_target system/handler/system/tree]
set rget [session_execute $s "/$remote/system/tree" get [::entity::core::wire::empty_params] $iface_target]
check "granted tree get -> 200" {[rstatus $rget] == 200}
check "tree get returns a system/handler/interface entity" {[rtype $rget] eq "system/handler/interface"}

# capability request (200)
set req_grant [::entity::core::capability::grant {system/tree} {system/type/*} {get} ""]
set req_params [::entity::core::entity::make system/capability/request \
    [::entity::core::ecf::map grants [::entity::core::ecf::tarray [list $req_grant]]]]
set rcap [session_execute $s "/$remote/system/capability" request $req_params]
check "capability request -> 200" {[rstatus $rcap] == 200}

# 8-way request_id demux (N7, §6.11) — 8 requests in flight at once
set rids {}
for {set i 0} {$i < 8} {incr i} {
    lappend rids [session_execute_async $s "/$remote/system/tree" get \
        [::entity::core::wire::empty_params] [::entity::core::wire::resource_target system/handler/system/tree]]
}
set replies [session_await_all $s $rids]
set correlated 0
foreach rid $rids {
    set r [dict get $replies $rid]
    if {$r eq "" || [rstatus $r] != 200} { continue }
    # the reply's request_id MUST equal the one we sent (demux correctness)
    if {[rtype $r] eq "system/handler/interface"
        && [::entity::core::entity::text [::entity::core::envelope::root $r] request_id] eq $rid} {
        incr correlated
    }
}
check "8 interleaved requests each correlated -> $correlated/8" {$correlated == 8}

session_close $s
stop_listener $srv

# ═════════ Scenario 2: the v7.74 Core Extensibility Boundary over the wire ═════════
# --debug-open-grants + --validate: the register live-hook (§6.13(a)), the emit hook
# firing on register's tree writes (§6.13(c)), the §7a echo handler, AND the §6.11
# dispatch-outbound reentry (B originates an EXECUTE back to A over the inbound conn).
set ::emit 0
proc bump_emit {ev} { incr ::emit }
set responder2 [::entity::core::peer::create [seed 0x33] 1 1]
::entity::core::store::register_tree_consumer [::entity::core::peer::store $responder2] bump_emit
lassign [start_listener $responder2 0] srv2 port2
# the initiator is ALSO --validate so the §6.11 reentry echo round-trips (A serves B's echo).
set initiator2 [::entity::core::peer::create [seed 0x44] 1 1]
set s2 [dial $initiator2 127.0.0.1 $port2]
set remote2 [session_get $s2 remote_peer_id]
set emit_before $::emit

# register live-hook (§6.13(a))
set manifest [::entity::core::ecf::map name [::entity::core::ecf::tstr demo] operations [::entity::core::ecf::emptymap]]
set reg_req [::entity::core::entity::make system/handler/register-request [::entity::core::ecf::map manifest $manifest]]
set rreg [session_execute $s2 "/$remote2/system/handler" register $reg_req [::entity::core::wire::resource_target system/handler/demo]]
check "handler register -> 200 (live, not 501)" {[rstatus $rreg] == 200}
check "emit hook fired on register tree writes (§6.13(c))" {$::emit > $emit_before}

# §7a echo conformance handler (resolve→dispatch)
set payload [::entity::core::entity::make primitive/any [::entity::core::ecf::map ping [::entity::core::ecf::tint 42]]]
set recho [session_execute $s2 "/$remote2/system/validate/echo" echo $payload]
check "§7a echo -> 200" {[rstatus $recho] == 200}
check "§7a echo returns params verbatim" {[rtype $recho] eq "primitive/any"}

# §6.11 dispatch-outbound REENTRY: B originates an EXECUTE back over THIS inbound
# connection to A; A's reader dispatches it. Outer 200 = the reentry round-tripped
# end-to-end (nested vwait); the INNER verdict is A's §5.2 cap check (the cross-peer
# reentry cap that makes it 200 is S4's validator surface).
set reentry_params [::entity::core::entity::make primitive/any [::entity::core::ecf::map \
    target             [::entity::core::ecf::tstr system/validate/echo] \
    operation          [::entity::core::ecf::tstr echo] \
    value              [::entity::core::ecf::map ping [::entity::core::ecf::tint 7]] \
    reentry_capability [::entity::core::entity::to_cbor [session_get $s2 capability]] \
    reentry_granter    [::entity::core::entity::to_cbor [session_get $s2 granter_peer]] \
    reentry_cap_signature [::entity::core::entity::to_cbor [session_get $s2 cap_signature]]]]
set rre [session_execute $s2 "/$remote2/system/validate/dispatch-outbound" dispatch $reentry_params]
check "§6.11 dispatch-outbound reentry round-trips (B->A echo over inbound conn)" {[rstatus $rre] == 200}

session_close $s2
stop_listener $srv2

puts "\nSMOKE: [expr {$::fail ? {FAIL} : {PASS}}] ($::pass/[expr {$::pass + $::fail}])"
exit [expr {$::fail ? 1 : 0}]
