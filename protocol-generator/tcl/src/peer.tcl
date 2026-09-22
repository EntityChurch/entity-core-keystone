# entity-core-protocol-tcl — peer assembly: bootstrap (§6.9 / §6.9a), the MUST
# system handlers (§6.2: connect, tree, handler, capability, type), the §6.5
# dispatch chain, §6.6 resolution, and the §6.9a peer-authority seed policy.
#
# The pure protocol brain — dispatch is a function from an inbound envelope to an
# outbound response envelope; transport lives in src/transport.tcl. Each handler is
# a proc `handle(peer_h, operation, ctx)` returning an OUTCOME dict {status result
# included} — the recoverable seam (a throw is reserved for the unrecoverable
# codec/transport boundary, per profile [error_model]).
#
# A peer is a handle into the `P` array (the "object as namespaced array" idiom);
# the store lives under the same peer via its own handle.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] identity.tcl]
source [file join [file dirname [info script]] store.tcl]
source [file join [file dirname [info script]] wire.tcl]
source [file join [file dirname [info script]] envelope.tcl]
source [file join [file dirname [info script]] capability.tcl]
source [file join [file dirname [info script]] coretypes.tcl]
source [file join [file dirname [info script]] conn.tcl]
source [file join [file dirname [info script]] ecf.tcl]

namespace eval ::entity::core::peer {
    variable P
    variable counter 0
    namespace export create identity store local_peer dispatch getHandler \
        grant mint_token mint_token_at cap_included random_bytes abs
}

# ── outcome helpers (the recoverable handler-result seam) ──
proc ::entity::core::peer::outcome_ok {result {included {}}} {
    return [dict create status 200 result $result included $included]
}
proc ::entity::core::peer::outcome_err {status code {message ""}} {
    return [dict create status $status result [::entity::core::wire::error_result $code $message] included {}]
}

# ── construction + bootstrap ──
proc ::entity::core::peer::create {seed {open_grants 0} {conformance 0}} {
    variable P
    variable counter
    set h "peer[incr counter]"
    set ident [::entity::core::identity::of_seed $seed]
    set P($h) [dict create \
        identity    $ident \
        store       [::entity::core::store::new] \
        local_peer  [dict get $ident peer_id] \
        open_grants $open_grants \
        conformance $conformance \
        handlers    {}]
    _bootstrap $h
    return $h
}

proc ::entity::core::peer::identity {h}   { variable P; return [dict get $P($h) identity] }
proc ::entity::core::peer::store {h}      { variable P; return [dict get $P($h) store] }
proc ::entity::core::peer::local_peer {h} { variable P; return [dict get $P($h) local_peer] }
proc ::entity::core::peer::getHandler {h pattern} {
    variable P
    set hs [dict get $P($h) handlers]
    return [expr {[dict exists $hs $pattern] ? [dict get $hs $pattern] : ""}]
}

# §4.6 nonce randomness (≥32-byte CSPRNG) — /dev/urandom in the sealed container.
proc ::entity::core::peer::random_bytes {n} {
    set fh [open /dev/urandom rb]
    set b [read $fh $n]
    close $fh
    return $b
}

# ── grant construction (§4.4 / §5.4) ──
proc ::entity::core::peer::_discovery_floor {h} {
    return [list \
        [::entity::core::capability::grant {system/tree} {system/type/* system/handler/*} {get} ""] \
        [::entity::core::capability::grant {system/capability} {} {request} ""]]
}
proc ::entity::core::peer::_open_grants_scope {h} {
    return [list [::entity::core::capability::grant {*} {* /*/*} {*} {*}]]
}
proc ::entity::core::peer::_owner_grants {h} {
    return [list [::entity::core::capability::grant {*} {*} {*} [list [local_peer $h]]]]
}

# ── token mint (§4.4 / §6.9a) ──
# Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.
#
# An empty $expires_at means no term was defined and the token genuinely has no expiry
# (the ONLY "no bound" spelling). A present value is emitted verbatim — including one
# equal to $created_at, which §5.6 rule 2 requires for ttl_ms == 0 and which means
# "already expired at every observable instant", not "unbounded".
#
# $created_at is supplied rather than sampled here so a computed expiry is guaranteed to
# be relative to the SAME instant that lands in the token; sampling the clock twice
# skews the two.
proc ::entity::core::peer::mint_token_at {h created_at grantee_hash grants {parent ""} {expires_at ""}} {
    variable P
    set ident [dict get $P($h) identity]
    set kv [list \
        granter    [::entity::core::ecf::bstr [dict get $ident id_hash]] \
        grantee    [::entity::core::ecf::bstr $grantee_hash] \
        grants     [::entity::core::ecf::tarray $grants] \
        created_at [::entity::core::ecf::tint $created_at]]
    if {$expires_at ne ""} { lappend kv expires_at [::entity::core::ecf::tint $expires_at] }
    if {$parent ne ""} { lappend kv parent [::entity::core::ecf::bstr $parent] }
    set token [::entity::core::entity::make system/capability/token [::entity::core::ecf::map {*}$kv]]
    return [dict create token $token signature [::entity::core::identity::sign $ident $token]]
}

# mint_token_at at the current instant with no §5.6 ceiling. Used by the paths that mint
# a self-issued grant from local authority (bootstrap, handler registration, the §4.4
# handshake), where no MIN_DEFINED term is in play.
proc ::entity::core::peer::mint_token {h grantee_hash grants {parent ""}} {
    return [mint_token_at $h [::entity::core::capability::now_ms] $grantee_hash $grants $parent]
}

proc ::entity::core::peer::cap_included {h minted} {
    variable P
    set ident [dict get $P($h) identity]
    return [list \
        [::entity::core::envelope::inc [dict get $minted token]] \
        [::entity::core::envelope::inc [dict get $ident peer_entity]] \
        [::entity::core::envelope::inc [dict get $minted signature]]]
}

# ── §6.9a seed policy (authenticate-time grant derivation) ──
proc ::entity::core::peer::_seed_entry_grants {h e} {
    variable P
    set ident [dict get $P($h) identity]
    set store_h [dict get $P($h) store]
    set type [::entity::core::entity::type $e]
    if {$type eq "system/capability/token"} {
        set sig_path "/[local_peer $h]/system/signature/[binary encode hex [::entity::core::entity::hash $e]]"
        set sgn [::entity::core::store::get_at $store_h $sig_path]
        if {$sgn ne "" && [::entity::core::identity::verify_signature $sgn [dict get $ident peer_entity]]} {
            set gl [::entity::core::ecf::maplist [::entity::core::entity::data $e] grants]
            return [expr {$gl eq "" ? {} : $gl}]
        }
        return {}
    }
    if {$type eq "system/capability/policy-entry"} {
        set gl [::entity::core::ecf::maplist [::entity::core::entity::data $e] grants]
        return [expr {$gl eq "" ? {} : $gl}]
    }
    return {}
}

# §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 → default),
# then UNION the matched scope with the §4.4 discovery floor.
proc ::entity::core::peer::derive_seed_grants {h remote_peer remote_peer_id} {
    variable P
    set store_h [dict get $P($h) store]
    set base "/[local_peer $h]/system/capability/policy/"
    set entry [::entity::core::store::get_at $store_h "$base[binary encode hex [::entity::core::entity::hash $remote_peer]]"]
    if {$entry eq ""} { set entry [::entity::core::store::get_at $store_h "$base$remote_peer_id"] }
    if {$entry eq ""} { set entry [::entity::core::store::get_at $store_h "${base}default"] }
    set floor [_discovery_floor $h]
    if {$entry eq ""} { return $floor }
    set policy [_seed_entry_grants $h $entry]
    if {$policy eq {}} { return $floor }
    return [concat $floor $policy]
}

# ── §6.13(b) handler-facing outbound dispatch (§6.11 reentry) ──
proc ::entity::core::peer::outbound_dispatch {h conn_h uri operation params capability granter_peer cap_sig resource} {
    variable P
    set ident [dict get $P($h) identity]
    set send [::entity::core::conn::get $conn_h outbound]
    if {$send eq ""} { return "" }
    set request_id "out-[::entity::core::conn::next_out_counter $conn_h]"
    set exec [::entity::core::wire::make_execute $request_id $uri $operation $params \
        [dict get $ident id_hash] [::entity::core::entity::hash $capability] $resource]
    set exec_sig [::entity::core::identity::sign $ident $exec]
    set included [list \
        [::entity::core::envelope::inc $capability] \
        [::entity::core::envelope::inc $granter_peer] \
        [::entity::core::envelope::inc [dict get $ident peer_entity]] \
        [::entity::core::envelope::inc $cap_sig] \
        [::entity::core::envelope::inc $exec_sig]]
    return [{*}$send [::entity::core::envelope::make $exec $included]]
}

# ── dispatcher-level signature ingestion (§6.5) ──
proc ::entity::core::peer::_ingest_signatures {h env} {
    variable P
    set store_h [dict get $P($h) store]
    foreach pair [::entity::core::envelope::included $env] {
        set e [lindex $pair 1]
        if {[::entity::core::entity::type $e] ne "system/signature"} { continue }
        ::entity::core::store::put_entity $store_h $e
        set signer_h [::entity::core::entity::bytes $e signer]
        if {$signer_h eq ""} { continue }
        set signer_peer [::entity::core::envelope::included_get $env $signer_h]
        if {$signer_peer eq ""} { continue }
        ::entity::core::store::put_entity $store_h $signer_peer
        set target [::entity::core::entity::bytes $e target]
        set pk [::entity::core::entity::bytes $signer_peer public_key]
        if {$target ne "" && $pk ne ""} {
            set pid [::entity::core::identity::peer_id_of_pubkey $pk]
            ::entity::core::store::bind $store_h "/$pid/system/signature/[binary encode hex $target]" $e
        }
    }
}

# ── handler resolution (§6.6) — backward tree-walk ──
proc ::entity::core::peer::_resolve_handler {h path} {
    variable P
    set store_h [dict get $P($h) store]
    set segs [split $path "/"]
    for {set i [llength $segs]} {$i >= 1} {incr i -1} {
        set prefix [join [lrange $segs 0 [expr {$i-1}]] "/"]
        set e [::entity::core::store::get_at $store_h $prefix]
        if {$e ne "" && [::entity::core::entity::type $e] eq "system/handler"} { return $prefix }
    }
    return ""
}

proc ::entity::core::peer::_strip_local {h pattern} {
    set prefix "/[local_peer $h]/"
    if {[string range $pattern 0 [expr {[string length $prefix]-1}]] eq $prefix} {
        return [string range $pattern [string length $prefix] end]
    }
    return $pattern
}

proc ::entity::core::peer::abs {h rel} { return "/[local_peer $h]/$rel" }

# ── entity-native dispatch (v7.74 §6.13(a)) ──
proc ::entity::core::peer::_entity_native_dispatch {h handler_path} {
    variable P
    set store_h [dict get $P($h) store]
    set he [::entity::core::store::get_at $store_h $handler_path]
    if {$he eq ""} { return [outcome_err 404 handler_not_found $handler_path] }
    set expr_path [::entity::core::entity::text $he expression_path]
    if {$expr_path eq ""} { return [outcome_err 501 no_handler_body $handler_path] }
    set abs_ [::entity::core::capability::canonicalize [local_peer $h] $expr_path]
    set expr [::entity::core::store::get_at $store_h $abs_]
    if {$expr eq ""} { return [outcome_err 404 expression_not_found $abs_] }
    if {[::entity::core::entity::type $expr] eq "compute/literal"} {
        set value [::entity::core::entity::field $expr value]
        if {$value eq ""} { return [outcome_err 400 unexpected_params "compute/literal missing value"] }
        return [outcome_ok [::entity::core::entity::make compute/result [::entity::core::ecf::map \
            value $value expression [::entity::core::ecf::bstr [::entity::core::entity::hash $expr]]]]]
    }
    return [outcome_err 501 unsupported_expression [::entity::core::entity::type $expr]]
}

# ── dispatch chain (§6.5) ──
# returns an EXECUTE_RESPONSE envelope, or "" for a non-EXECUTE root (§3.3).
proc ::entity::core::peer::dispatch {h conn_h env} {
    set exec [::entity::core::envelope::root $env]
    if {[::entity::core::entity::type $exec] ne "system/protocol/execute"} { return "" }
    set request_id [::entity::core::entity::text $exec request_id]
    set outcome ""
    set rc [catch {_dispatch_inner $h $conn_h $env $exec} result opts]
    if {$rc == 0} {
        set outcome $result
    } else {
        set code [lindex [dict get $opts -errorcode] 1]
        if {$code eq "UNRESOLVABLE_GRANTEE"} {
            set outcome [outcome_err 401 unresolvable_grantee]
        } elseif {$code in {NON_CANONICAL_ECF TRUNCATED_INPUT TAG_REJECTED}} {
            set outcome [outcome_err 400 non_canonical_ecf]
        } else {
            if {[info exists ::env(PEER_DEBUG_500)]} { puts stderr "500: $result\n[dict get $opts -errorinfo]" }
            set outcome [outcome_err 500 internal_error]
        }
    }
    return [::entity::core::envelope::make \
        [::entity::core::wire::make_response $request_id [dict get $outcome status] [dict get $outcome result]] \
        [dict get $outcome included]]
}

proc ::entity::core::peer::_dispatch_inner {h conn_h env exec} {
    variable P
    set store_h [dict get $P($h) store]
    set uri [::entity::core::entity::text $exec uri]
    set operation [::entity::core::entity::text $exec operation]
    set included [::entity::core::envelope::included $env]
    if {$uri eq "system/protocol/connect"} {
        set proc [dict get [dict get $P($h) handlers] system/protocol/connect]
        return [$proc $h $operation [dict create exec $exec conn $conn_h included $included caller_cap "" env $env]]
    }
    _ingest_signatures $h $env
    # §5.2 three-way request verdict (+ §4.10(b) chain-depth).
    set rv [::entity::core::capability::verify_request [local_peer $h] $store_h $env]
    switch -- $rv {
        AUTHN_FAIL     { return [outcome_err 401 authentication_failed] }
        AUTHZ_DENY     { return [outcome_err 403 capability_denied] }
        CHAIN_TOO_DEEP { return [outcome_err 400 chain_depth_exceeded] }
    }
    set path [::entity::core::capability::canonicalize [local_peer $h] [::entity::core::capability::normalize_uri $uri]]
    # §1.4: inbound dispatch must target the local peer.
    if {[::entity::core::capability::extract_peer [local_peer $h] $path] ne [local_peer $h]} {
        return [outcome_err 400 invalid_request "not local peer"]
    }
    set pattern [_resolve_handler $h $path]
    if {$pattern eq ""} { return [outcome_err 404 handler_not_found $path] }
    set cap_h [::entity::core::entity::bytes $exec capability]
    set caller_cap [expr {$cap_h ne "" ? [::entity::core::envelope::included_get $env $cap_h] : ""}]
    if {$caller_cap eq ""} { return [outcome_err 403 capability_denied] }
    set granter_peer [::entity::core::capability::resolve_granter_peer_id $included $store_h $caller_cap]
    if {$granter_peer eq ""} { set granter_peer [local_peer $h] }
    if {[::entity::core::capability::check_permission [local_peer $h] $granter_peer $exec $caller_cap $pattern] eq "DENY"} {
        return [outcome_err 403 capability_denied]
    }
    set stripped [_strip_local $h $pattern]
    set hs [dict get $P($h) handlers]
    if {[dict exists $hs $stripped]} {
        set proc [dict get $hs $stripped]
        return [$proc $h $operation [dict create exec $exec conn $conn_h included $included caller_cap $caller_cap env $env]]
    }
    return [_entity_native_dispatch $h $pattern]
}

# ── bootstrap (§6.9) ──
proc ::entity::core::peer::_op_spec {input output} {
    set kv {}
    if {$input ne ""}  { lappend kv input_type  [::entity::core::ecf::tstr $input] }
    if {$output ne ""} { lappend kv output_type [::entity::core::ecf::tstr $output] }
    return [::entity::core::ecf::map {*}$kv]
}

proc ::entity::core::peer::_bootstrap_handler_entities {h pattern name ops} {
    variable P
    set store_h [dict get $P($h) store]
    set ident [dict get $P($h) identity]
    set operations {}
    foreach op $ops {
        lassign $op opname input output
        lappend operations $opname [_op_spec $input $output]
    }
    ::entity::core::store::bind $store_h [abs $h $pattern] [::entity::core::entity::make system/handler \
        [::entity::core::ecf::map interface [::entity::core::ecf::tstr "system/handler/$pattern"]]]
    ::entity::core::store::bind $store_h [abs $h "system/handler/$pattern"] [::entity::core::entity::make system/handler/interface \
        [::entity::core::ecf::map pattern [::entity::core::ecf::tstr $pattern] \
            name [::entity::core::ecf::tstr $name] \
            operations [::entity::core::ecf::map {*}$operations]]]
    set m [mint_token $h [dict get $ident id_hash] {} ""]
    ::entity::core::store::bind $store_h [abs $h "system/capability/grants/$pattern"] [dict get $m token]
}

proc ::entity::core::peer::_bootstrap {h} {
    variable P
    set store_h [dict get $P($h) store]
    set ident [dict get $P($h) identity]
    # local identity entity in the store (root-granter resolution).
    ::entity::core::store::put_entity $store_h [dict get $ident peer_entity]
    # publish the §9.5 core type floor.
    ::entity::core::coretypes::publish $store_h [local_peer $h]

    # instantiate + register the MUST handler instances (§6.6 → instance map).
    set bootstrap {
        {system/tree ::entity::core::handlers::tree Tree
            {{get "" ""} {put "" ""}}}
        {system/handler ::entity::core::handlers::handlers Handlers
            {{register system/handler/register-request system/handler/register-result}
             {unregister system/handler/unregister-request ""}}}
        {system/type ::entity::core::handlers::type Types
            {{validate system/type/validate-request system/type/validate-result}}}
        {system/capability ::entity::core::handlers::capability Capability
            {{request system/capability/request system/capability/grant}
             {revoke system/capability/revoke-request ""}
             {configure system/capability/policy-entry ""}
             {delegate system/capability/delegate-request system/capability/grant}}}
        {system/protocol/connect ::entity::core::handlers::connect Connect
            {{hello "" ""} {authenticate "" ""}}}
    }
    foreach spec $bootstrap {
        lassign $spec pattern proc name ops
        dict set P($h) handlers $pattern $proc
        _bootstrap_handler_entities $h $pattern $name $ops
    }

    # §6.9a Peer Authority Bootstrap: self-owner cap (root, full scope, grantee = own
    # identity) + default scope-template entry. Read back by authenticate (dual-form).
    set policy_base "/[local_peer $h]/system/capability/policy/"
    set owner [mint_token $h [dict get $ident id_hash] [_owner_grants $h] ""]
    ::entity::core::store::bind $store_h "$policy_base[binary encode hex [dict get $ident id_hash]]" [dict get $owner token]
    ::entity::core::store::bind $store_h "/[local_peer $h]/system/signature/[binary encode hex [::entity::core::entity::hash [dict get $owner token]]]" [dict get $owner signature]
    if {[dict get $P($h) open_grants]} {
        set default_grants [_open_grants_scope $h]
    } else {
        set default_grants [_discovery_floor $h]
    }
    ::entity::core::store::bind $store_h "${policy_base}default" [::entity::core::entity::make system/capability/policy-entry \
        [::entity::core::ecf::map peer_pattern [::entity::core::ecf::tstr default] \
            grants [::entity::core::ecf::tarray $default_grants]]]

    # §7a conformance handlers — only under --validate.
    if {[dict get $P($h) conformance]} {
        set conf {
            {system/validate/echo ::entity::core::handlers::echo validate-echo
                {{echo "" ""}}}
            {system/validate/dispatch-outbound ::entity::core::handlers::dispatch_outbound
                validate-dispatch-outbound {{dispatch "" ""}}}
        }
        foreach spec $conf {
            lassign $spec pattern proc name ops
            dict set P($h) handlers $pattern $proc
            _bootstrap_handler_entities $h $pattern $name $ops
        }
    }
}
