# entity-core-protocol-tcl — transport (L4): TCP listener + dialer over Tcl's
# SINGLE-THREADED event loop (chan event + vwait), the §6.11 request_id demux, the
# §4.8 inbound-concurrent-with-outbound dispatch (cooperative interleaving on one
# thread), and the §6.13(b) reentry seam. Plus the initiator dialer/handshake that
# drives the two-peer loopback.
#
# == Concurrency model (profile [async] = event-loop): the Tcl reactor
# The Tcl notifier multiplexes the listen socket + every connection. An inbound
# EXECUTE is dispatched inline (peer::dispatch); a handler that originates an
# outbound EXECUTE (§6.13(b)) calls the conn `outbound` seam, which PUMPS the same
# loop (a NESTED `vwait` — the natural §6.11 reentry) until the reply correlates by
# request_id — no thread, no condvar. The §4.8 store-safety MUST holds by
# construction (one handler runs to completion before the next readable event).
#
# == §4.10(a) resource bound
# The 4-byte length prefix is checked against wire::MAX_FRAME (16 MiB) BEFORE the
# body is buffered — an over-limit prefix ends the connection (§4.10(a): the body
# boundary is unknowable). The peer keeps serving every other connection.
#
# Io / Session are handles into namespaced arrays (the one-interp "object" idiom).

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] handlers.tcl]
source [file join [file dirname [info script]] wire.tcl]
source [file join [file dirname [info script]] envelope.tcl]
source [file join [file dirname [info script]] conn.tcl]

namespace eval ::entity::core::transport {
    variable IO         ;# array: io-handle -> dict {sock rbuf closed pending peer conn}
    variable DONE       ;# array: "$io,$rid" -> 0|1|timeout (the §6.11 demux rendezvous)
    variable SESSION    ;# array: session-handle -> dict {io peer ident req_counter ...}
    variable counter 0
    namespace export start_listener stop_listener dial \
        session_execute session_execute_async session_await_all session_close session_get
}

# ═════════════════════════ framed Io ═════════════════════════
proc ::entity::core::transport::_io_new {sock peer_h conn_h} {
    variable IO
    variable counter
    set io "io[incr counter]"
    chan configure $sock -translation binary -blocking 0 -buffering none
    catch {chan configure $sock -nodelay 1}   ;# §7b TCP_NODELAY (best-effort)
    set IO($io) [dict create sock $sock rbuf "" closed 0 pending {} peer $peer_h conn $conn_h]
    chan event $sock readable [list ::entity::core::transport::_on_readable $io]
    return $io
}

proc ::entity::core::transport::_on_readable {io} {
    variable IO
    if {[dict get $IO($io) closed]} return
    set sock [dict get $IO($io) sock]
    if {[catch {read $sock} chunk]} { _close $io; return }
    if {$chunk ne ""} { dict append IO($io) rbuf $chunk }
    if {[catch {_drain $io}]} { _close $io; return }   ;# §4.10(a) over-limit / bad frame
    if {[eof $sock]} { _close $io }
}

proc ::entity::core::transport::_drain {io} {
    variable IO
    set max $::entity::core::wire::MAX_FRAME
    while {1} {
        set rbuf [dict get $IO($io) rbuf]
        if {[string length $rbuf] < 4} break
        binary scan $rbuf Iu len
        if {$len < 0 || $len > $max} {
            throw {ENTITY_CORE WIRE payload_too_large} "frame length out of bounds: $len"
        }
        if {[string length $rbuf] < [expr {4 + $len}]} break
        set payload [string range $rbuf 4 [expr {4 + $len - 1}]]
        dict set IO($io) rbuf [string range $rbuf [expr {4 + $len}] end]
        _dispatch_frame $io $payload
    }
}

proc ::entity::core::transport::_dispatch_frame {io payload} {
    variable IO
    variable DONE
    if {[catch {::entity::core::wire::envelope_of_frame $payload} env]} {
        # §6.3: "Rejection returns 400 non_canonical_ecf" — a rejected frame is owed a
        # STATUS, not silence. This used to be a bare `return`, which rejected the frame
        # (correct) and then dropped it on the floor (wrong): the sender saw no response
        # at all and blocked until its own timeout, violating §6.3's second sentence and
        # §4.9(c) deliver-or-signal. It also made a refusal indistinguishable from a dead
        # peer, and on a single-connection oracle run it poisons every later request on
        # the same connection.
        #
        # The frame is still REJECTED — only enough is salvaged to correlate the
        # response. If even the request_id is unrecoverable the frame is unattributable
        # and silence is the only option left.
        set rid [::entity::core::wire::salvage_request_id $payload]
        if {$rid ne ""} {
            catch {
                _write_framed $io [::entity::core::envelope::make \
                    [::entity::core::wire::make_response $rid 400 \
                        [::entity::core::wire::error_result non_canonical_ecf]]]
            }
        }
        return
    }
    set root [::entity::core::envelope::root $env]
    if {[::entity::core::entity::type $root] eq "system/protocol/execute/response"} {
        set rid [::entity::core::entity::text $root request_id]
        if {[dict exists [dict get $IO($io) pending] $rid]} {
            dict set IO($io) pending $rid [dict create env $env done 1]
            set DONE($io,$rid) 1
        }
        return
    }
    # inbound EXECUTE (§6.11 reentry-capable) — dispatch on the SAME loop.
    set peer_h [dict get $IO($io) peer]
    set conn_h [dict get $IO($io) conn]
    if {[catch {::entity::core::peer::dispatch $peer_h $conn_h $env} resp]} {
        set rid [::entity::core::entity::text $root request_id]
        set resp [::entity::core::envelope::make \
            [::entity::core::wire::make_response $rid 500 [::entity::core::wire::error_result internal_error]]]
    }
    if {$resp ne ""} { catch {_write_framed $io $resp} }
}

proc ::entity::core::transport::_write_framed {io env} {
    variable IO
    if {[dict get $IO($io) closed]} { throw {ENTITY_CORE WIRE closed} "write on closed connection" }
    set payload [::entity::core::wire::frame_of_envelope $env]
    set sock [dict get $IO($io) sock]
    puts -nonewline $sock [::entity::core::wire::frame $payload]
    flush $sock
}

# register a waiter, then PUMP the loop (nested vwait) until the correlated
# EXECUTE_RESPONSE arrives (§6.11 reentry) or timeout / close. Returns the response
# envelope, or "".
proc ::entity::core::transport::_io_outbound {io request} {
    variable IO
    variable DONE
    set rid [::entity::core::entity::text [::entity::core::envelope::root $request] request_id]
    dict set IO($io) pending $rid [dict create env "" done 0]
    set DONE($io,$rid) 0
    if {[catch {_write_framed $io $request}]} {
        dict unset IO($io) pending $rid
        catch {unset DONE($io,$rid)}
        return ""
    }
    _wait_done $io $rid 30000
    set env ""
    if {[dict exists [dict get $IO($io) pending] $rid]} {
        set env [dict get [dict get $IO($io) pending] $rid env]
    }
    dict unset IO($io) pending $rid
    catch {unset DONE($io,$rid)}
    return $env
}

# fire WITHOUT awaiting (multiple in-flight → the §6.11 out-of-order demux check).
proc ::entity::core::transport::_io_send_async {io request} {
    variable IO
    variable DONE
    set rid [::entity::core::entity::text [::entity::core::envelope::root $request] request_id]
    dict set IO($io) pending $rid [dict create env "" done 0]
    set DONE($io,$rid) 0
    _write_framed $io $request
    return $rid
}

# pump the loop until DONE($io,$rid) leaves 0 (response, timeout, or close-wake).
proc ::entity::core::transport::_wait_done {io rid timeout} {
    variable IO
    variable DONE
    set tid [after $timeout [list set ::entity::core::transport::DONE($io,$rid) timeout]]
    while {![dict get $IO($io) closed] && [info exists DONE($io,$rid)] && $DONE($io,$rid) == 0} {
        vwait ::entity::core::transport::DONE($io,$rid)
    }
    after cancel $tid
}

proc ::entity::core::transport::_io_take {io rid} {
    variable IO
    variable DONE
    set env ""
    if {[dict exists [dict get $IO($io) pending] $rid]} {
        set env [dict get [dict get $IO($io) pending] $rid env]
    }
    dict unset IO($io) pending $rid
    catch {unset DONE($io,$rid)}
    return $env
}

proc ::entity::core::transport::_close {io} {
    variable IO
    variable DONE
    if {[dict get $IO($io) closed]} return
    dict set IO($io) closed 1
    # wake any parked waiters so a reentrant/awaiting outbound returns "".
    foreach rid [dict keys [dict get $IO($io) pending]] { set DONE($io,$rid) 1 }
    catch {close [dict get $IO($io) sock]}
}

# ═════════════════════════ server: listener ═════════════════════════
proc ::entity::core::transport::start_listener {peer_h port} {
    set srv [socket -server [list ::entity::core::transport::_accept $peer_h] -myaddr 127.0.0.1 $port]
    set bound [lindex [chan configure $srv -sockname] 2]
    return [list $srv $bound]
}

proc ::entity::core::transport::stop_listener {srv} { catch {close $srv} }

proc ::entity::core::transport::_accept {peer_h sock addr port} {
    set conn_h [::entity::core::conn::new]
    set io [_io_new $sock $peer_h $conn_h]
    ::entity::core::conn::set_ $conn_h outbound [list ::entity::core::transport::_io_outbound $io]
}

# ═════════════════════════ client: dialer + §4.1 handshake ═════════════════════════
proc ::entity::core::transport::dial {peer_h host port} {
    set sock [socket $host $port]
    set conn_h [::entity::core::conn::new]
    set io [_io_new $sock $peer_h $conn_h]
    # a core responder sends only EXECUTE_RESPONSEs, but an inbound EXECUTE (§6.11
    # reentry from B) is dispatched on the SAME loop — so wire the outbound seam too.
    ::entity::core::conn::set_ $conn_h outbound [list ::entity::core::transport::_io_outbound $io]
    set sess [_session_new $io $peer_h]
    _handshake $sess
    return $sess
}

# ═════════════════════════ session (§4.4) ═════════════════════════
proc ::entity::core::transport::_session_new {io peer_h} {
    variable SESSION
    variable counter
    set s "sess[incr counter]"
    set SESSION($s) [dict create io $io peer $peer_h ident [::entity::core::peer::identity $peer_h] \
        req_counter 0 remote_peer_id "" capability "" granter_peer "" cap_signature ""]
    return $s
}

proc ::entity::core::transport::_next_request_id {s} {
    variable SESSION
    dict incr SESSION($s) req_counter
    return "req-[dict get $SESSION($s) req_counter]"
}

proc ::entity::core::transport::_send {s request} {
    variable SESSION
    return [_io_outbound [dict get $SESSION($s) io] $request]
}

# build + sign + send an authenticated EXECUTE; await the response.
proc ::entity::core::transport::session_execute {s uri operation params {resource ""}} {
    variable SESSION
    set ident [dict get $SESSION($s) ident]
    set cap [dict get $SESSION($s) capability]
    set exec [::entity::core::wire::make_execute [_next_request_id $s] $uri $operation $params \
        [dict get $ident id_hash] [::entity::core::entity::hash $cap] $resource]
    return [_send $s [::entity::core::envelope::make $exec [_auth_included $s $ident $exec]]]
}

# build + sign + send WITHOUT awaiting; return the request_id.
proc ::entity::core::transport::session_execute_async {s uri operation params {resource ""}} {
    variable SESSION
    set ident [dict get $SESSION($s) ident]
    set cap [dict get $SESSION($s) capability]
    set exec [::entity::core::wire::make_execute [_next_request_id $s] $uri $operation $params \
        [dict get $ident id_hash] [::entity::core::entity::hash $cap] $resource]
    return [_io_send_async [dict get $SESSION($s) io] \
        [::entity::core::envelope::make $exec [_auth_included $s $ident $exec]]]
}

# the §5.8 authority chain that travels with an authenticated EXECUTE.
proc ::entity::core::transport::_auth_included {s ident exec} {
    variable SESSION
    set exec_sig [::entity::core::identity::sign $ident $exec]
    return [list \
        [::entity::core::envelope::inc [dict get $SESSION($s) capability]] \
        [::entity::core::envelope::inc [dict get $SESSION($s) granter_peer]] \
        [::entity::core::envelope::inc [dict get $ident peer_entity]] \
        [::entity::core::envelope::inc [dict get $SESSION($s) cap_signature]] \
        [::entity::core::envelope::inc $exec_sig]]
}

# pump until every rid resolves, then return a {rid env rid env …} dict (§6.11 demux).
proc ::entity::core::transport::session_await_all {s rids {timeout 30000}} {
    variable SESSION
    set io [dict get $SESSION($s) io]
    foreach rid $rids { _wait_done $io $rid $timeout }
    set out {}
    foreach rid $rids { lappend out $rid [_io_take $io $rid] }
    return $out
}

proc ::entity::core::transport::session_close {s} {
    variable SESSION
    _close [dict get $SESSION($s) io]
}

proc ::entity::core::transport::_require_ok {env step} {
    if {$env eq ""} { throw {ENTITY_CORE WIRE handshake} "$step failed: no response" }
    set status [::entity::core::wire::response_status $env]
    if {$status != 200} {
        set r [::entity::core::wire::response_result $env]
        set code [expr {$r ne "" ? [::entity::core::entity::text $r code] : ""}]
        throw {ENTITY_CORE WIRE handshake} "$step failed: $status $code"
    }
}

# drive the §4.1 forward handshake as initiator: hello then authenticate.
proc ::entity::core::transport::_handshake {s} {
    variable SESSION
    set ident [dict get $SESSION($s) ident]
    # ── hello ──
    set hello [::entity::core::entity::make system/protocol/connect/hello [::entity::core::ecf::map \
        peer_id      [::entity::core::ecf::tstr [dict get $ident peer_id]] \
        nonce        [::entity::core::ecf::bstr [::entity::core::peer::random_bytes 32]] \
        protocols    [::entity::core::ecf::text_array {entity-core/1.0}] \
        timestamp    [::entity::core::ecf::tint [::entity::core::capability::now_ms]] \
        hash_formats [::entity::core::ecf::text_array {ecfv1-sha256}] \
        key_types    [::entity::core::ecf::text_array {ed25519}]]]
    set r1 [_send $s [::entity::core::envelope::make \
        [::entity::core::wire::make_execute [_next_request_id $s] system/protocol/connect hello $hello]]]
    _require_ok $r1 hello
    set remote_hello [::entity::core::wire::response_result $r1]
    dict set SESSION($s) remote_peer_id [::entity::core::entity::text $remote_hello peer_id]
    set remote_nonce [::entity::core::entity::bytes $remote_hello nonce]
    if {$remote_nonce eq ""} { throw {ENTITY_CORE WIRE handshake} "hello: missing remote nonce" }

    # ── authenticate ──
    set auth [::entity::core::entity::make system/protocol/connect/authenticate [::entity::core::ecf::map \
        peer_id    [::entity::core::ecf::tstr [dict get $ident peer_id]] \
        public_key [::entity::core::ecf::bstr [dict get $ident pub]] \
        key_type   [::entity::core::ecf::tstr ed25519] \
        nonce      [::entity::core::ecf::bstr $remote_nonce]]]
    set auth_sig [::entity::core::identity::sign $ident $auth]
    set auth_inc [list \
        [::entity::core::envelope::inc [dict get $ident peer_entity]] \
        [::entity::core::envelope::inc $auth_sig]]
    set r2 [_send $s [::entity::core::envelope::make \
        [::entity::core::wire::make_execute [_next_request_id $s] system/protocol/connect authenticate $auth] $auth_inc]]
    _require_ok $r2 authenticate

    # parse the §4.4 initial capability grant
    set grant [::entity::core::wire::response_result $r2]
    set token_h [expr {$grant ne "" ? [::entity::core::entity::bytes $grant token] : ""}]
    set token [expr {$token_h ne "" ? [::entity::core::envelope::included_get $r2 $token_h] : ""}]
    if {$token eq ""} { throw {ENTITY_CORE WIRE handshake} "authenticate grant omits the capability token" }
    set granter_h [::entity::core::entity::bytes $token granter]
    set granter_peer [expr {$granter_h ne "" ? [::entity::core::envelope::included_get $r2 $granter_h] : ""}]
    if {$granter_peer eq ""} { throw {ENTITY_CORE WIRE handshake} "authenticate grant omits the granter identity" }
    set cap_sig [::entity::core::capability::find_signature [::entity::core::entity::hash $token] [::entity::core::envelope::included $r2]]
    if {$cap_sig eq ""} { throw {ENTITY_CORE WIRE handshake} "authenticate grant omits the capability signature" }
    dict set SESSION($s) capability $token
    dict set SESSION($s) granter_peer $granter_peer
    dict set SESSION($s) cap_signature $cap_sig
}

# session field accessors (initiator-side probes).
proc ::entity::core::transport::session_get {s key} {
    variable SESSION
    return [dict get $SESSION($s) $key]
}
