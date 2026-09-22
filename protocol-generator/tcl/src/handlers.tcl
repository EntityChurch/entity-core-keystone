# entity-core-protocol-tcl — the MUST system handlers (§6.2) + §7a conformance
# handlers. Each is a proc `handle(peer_h, operation, ctx)` returning an OUTCOME
# dict; the per-operation dispatch is a `switch` ladder with an "unknown operation
# → 501" default. A handler that originates an outbound EXECUTE (§6.13(b)/§6.11
# reentry) calls peer::outbound_dispatch, which PUMPS the single event loop until
# the reply correlates (no thread to block).
#
# ctx is a dict {exec <entity> conn <conn_h> included <list> caller_cap <entity|"">
# env <envelope>}.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] peer.tcl]
source [file join [file dirname [info script]] peerid.tcl]
source [file join [file dirname [info script]] ecf.tcl]

namespace eval ::entity::core::handlers {}

# ── outcome + ctx shorthands ──
proc ::entity::core::handlers::ok {result {included {}}} {
    return [::entity::core::peer::outcome_ok $result $included]
}
proc ::entity::core::handlers::err {status code {message ""}} {
    return [::entity::core::peer::outcome_err $status $code $message]
}
proc ::entity::core::handlers::_exec {ctx} { return [dict get $ctx exec] }
proc ::entity::core::handlers::_params {ctx} { return [::entity::core::entity::entity_field [dict get $ctx exec] params] }

# ── stateless helpers (path/resource parsing + §3.9 zero-hash) ──
proc ::entity::core::handlers::exec_resource_target {exec} {
    set r [::entity::core::entity::mapfield $exec resource]
    if {$r eq ""} { return "" }
    set targets [::entity::core::ecf::textlist $r targets]
    if {$targets eq "" || $targets eq {}} { return "" }
    return [lindex $targets 0]
}

# §1.4 path validity (no NUL, no empty/./.. segments; abs paths peer-rooted).
proc ::entity::core::handlers::path_flex_ok {target} {
    if {[string first "\x00" $target] >= 0} { return 0 }
    set segs0 [split $target "/"]
    if {[string index $target 0] eq "/"} {
        if {[llength $segs0] >= 2 && [lindex $segs0 0] eq ""} {
            set abs_ok [::entity::core::capability::is_peer_id [lindex $segs0 1]]
            set body [lrange $segs0 1 end]
        } else {
            set abs_ok 0
            set body $segs0
        }
    } else {
        set abs_ok 1
        set body $segs0
    }
    if {!$abs_ok} { return 0 }
    if {[llength $body] > 0 && [lindex $body end] eq ""} { set body [lrange $body 0 end-1] }
    foreach seg $body {
        if {$seg eq "" || $seg eq "." || $seg eq ".."} { return 0 }
    }
    return 1
}

proc ::entity::core::handlers::is_zero_hash {h} {
    return [expr {[string trim $h "\x00"] eq ""}]
}

proc ::entity::core::handlers::req_grants {params} {
    if {$params eq ""} { return {} }
    set gl [::entity::core::ecf::maplist [::entity::core::entity::data $params] grants]
    return [expr {$gl eq "" ? {} : $gl}]
}

proc ::entity::core::handlers::register_pattern {exec} {
    set target [exec_resource_target $exec]
    if {$target eq ""} { return "" }
    set prefix "system/handler/"
    if {[string range $target 0 [expr {[string length $prefix]-1}]] ne $prefix
        || [string length $target] == [string length $prefix]} { return "" }
    return [string range $target [string length $prefix] end]
}

proc ::entity::core::handlers::register_pattern_error {exec} {
    if {[exec_resource_target $exec] eq ""} {
        return [err 400 ambiguous_resource "register/unregister require exactly one resource target"]
    }
    return [err 400 invalid_resource "resource target MUST be system/handler/{pattern}"]
}

# §6.2: true iff pattern == "system" or pattern starts with "system/" -- user-installed
# handlers MUST NOT register there.
proc ::entity::core::handlers::is_reserved_pattern {pattern} {
    if {$pattern eq "system"} { return 1 }
    set prefix "system/"
    if {[string length $pattern] < [string length $prefix]} { return 0 }
    return [expr {[string range $pattern 0 [expr {[string length $prefix]-1}]] eq $prefix}]
}

# ═════════════════════════ §4.1 / §4.6 connect handler ═════════════════════════
proc ::entity::core::handlers::connect {peer_h operation ctx} {
    switch -- $operation {
        hello        { return [_connect_hello $peer_h $ctx] }
        authenticate { return [_connect_authenticate $peer_h $ctx] }
        default      { return [err 501 unsupported_operation $operation] }
    }
}

# is a §4.5-declared format list PRESENT and DISJOINT from our single supported value?
# Uses `ecf::has` so a present-but-EMPTY array (client supports zero formats) is a
# genuine mismatch → reject, NOT silently skipped as if absent (A-TCL-007 present-
# empty-vs-absent seam; a bare `ne ""` cannot tell {} from absent in Tcl).
proc ::entity::core::handlers::_negotiation_disjoint {params key supported} {
    if {$params eq "" || ![::entity::core::ecf::has [::entity::core::entity::data $params] $key]} {
        return 0
    }
    set declared [::entity::core::ecf::textlist [::entity::core::entity::data $params] $key]
    return [expr {$supported ni $declared}]
}

proc ::entity::core::handlers::_connect_hello {peer_h ctx} {
    set conn [dict get $ctx conn]
    set exec [dict get $ctx exec]
    if {[::entity::core::conn::get $conn established]} {
        return [err 409 connection_already_established]
    }
    # §4.5 negotiation: reject disjoint hash_formats / key_types up front.
    set params [::entity::core::entity::entity_field $exec params]
    if {[_negotiation_disjoint $params hash_formats ecfv1-sha256]} { return [err 400 incompatible_hash_format] }
    if {[_negotiation_disjoint $params key_types ed25519]} { return [err 400 unsupported_key_type] }
    if {$params ne ""} {
        ::entity::core::conn::set_ $conn hello_peer_id [::entity::core::entity::text $params peer_id]
    }
    set nonce [::entity::core::peer::random_bytes 32]
    ::entity::core::conn::set_ $conn issued_nonce $nonce
    return [ok [::entity::core::entity::make system/protocol/connect/hello [::entity::core::ecf::map \
        peer_id      [::entity::core::ecf::tstr [::entity::core::peer::local_peer $peer_h]] \
        nonce        [::entity::core::ecf::bstr $nonce] \
        protocols    [::entity::core::ecf::text_array {entity-core/1.0}] \
        timestamp    [::entity::core::ecf::tint [::entity::core::capability::now_ms]] \
        hash_formats [::entity::core::ecf::text_array {ecfv1-sha256}] \
        key_types    [::entity::core::ecf::text_array {ed25519}]]]]
}

proc ::entity::core::handlers::_connect_authenticate {peer_h ctx} {
    set conn [dict get $ctx conn]
    set exec [dict get $ctx exec]
    set included [dict get $ctx included]
    # RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
    # single-use nonce. The anti-replay property is the MUST and the mechanism
    # (established-state tracking) is impl-defined, but the STATUS is pinned to
    # 401 invalid_nonce — a 409 state-conflict under-signals the replay.
    if {[::entity::core::conn::get $conn established]} {
        return [err 401 invalid_nonce]
    }
    set issued_nonce [::entity::core::conn::get $conn issued_nonce]
    if {$issued_nonce eq ""} { return [err 401 invalid_nonce] }
    set auth [::entity::core::entity::entity_field $exec params]
    if {$auth eq ""} { return [err 401 authentication_failed] }
    # §4.6 hardening: reject unsupported key_type / non-32-byte pubkey / non-ed25519 peer_id.
    set bad_kt 0
    set kt_field [::entity::core::entity::text $auth key_type]
    if {$kt_field ne "" && $kt_field ne "ed25519"} { set bad_kt 1 }
    set pub [::entity::core::entity::bytes $auth public_key]
    if {!$bad_kt && $pub ne "" && [string length [binary format a* $pub]] != 32} { set bad_kt 1 }
    set claimed [::entity::core::entity::text $auth peer_id]
    if {!$bad_kt && $claimed ne ""} {
        if {![catch {::entity::core::peerid::parse $claimed} parsed]} {
            if {[lindex $parsed 0] != 1} { set bad_kt 1 }
        }
    }
    if {$bad_kt} { return [err 400 unsupported_key_type] }
    # step 1: nonce-echo
    set echoed [::entity::core::entity::bytes $auth nonce]
    if {!($echoed ne "" && $echoed eq $issued_nonce)} { return [err 401 invalid_nonce] }
    if {$pub eq ""} { return [err 401 authentication_failed] }
    # step 2: proof of possession
    set sgn [::entity::core::capability::find_signature [::entity::core::entity::hash $auth] $included]
    set sig_ok 0
    if {$sgn ne ""} {
        set sb [::entity::core::entity::bytes $sgn signature]
        if {$sb ne "" && [string length [binary format a* $sb]] == 64} {
            set sig_ok [::entity::core::crypto::ed25519_verify $pub [::entity::core::entity::hash $auth] $sb]
        }
    }
    if {!$sig_ok} { return [err 401 authentication_failed] }
    # step 3: identity binding
    if {$claimed ne [::entity::core::identity::peer_id_of_pubkey $pub]} { return [err 401 identity_mismatch] }
    set hello_pid [::entity::core::conn::get $conn hello_peer_id]
    if {$hello_pid ne "" && $hello_pid ne $claimed} { return [err 401 identity_mismatch] }
    # success: mint the initial capability for the remote (§4.4 / §6.9a)
    set remote_peer [::entity::core::identity::peer_entity_of_pubkey $pub]
    set grants [::entity::core::peer::derive_seed_grants $peer_h $remote_peer $claimed]
    set m [::entity::core::peer::mint_token $peer_h [::entity::core::entity::hash $remote_peer] $grants ""]
    ::entity::core::conn::set_ $conn established 1
    return [ok [::entity::core::entity::make system/capability/grant [::entity::core::ecf::map \
        token [::entity::core::ecf::bstr [::entity::core::entity::hash [dict get $m token]]]]] \
        [::entity::core::peer::cap_included $peer_h $m]]
}

# ═════════════════════════ §6.3 tree handler ═════════════════════════
proc ::entity::core::handlers::tree {peer_h operation ctx} {
    switch -- $operation {
        get     { return [_tree_get $peer_h $ctx] }
        put     { return [_tree_put $peer_h $ctx] }
        default { return [err 501 unsupported_operation $operation] }
    }
}

proc ::entity::core::handlers::_tree_get {peer_h ctx} {
    set exec [dict get $ctx exec]
    set local [::entity::core::peer::local_peer $peer_h]
    set store_h [::entity::core::peer::store $peer_h]
    set target [exec_resource_target $exec]
    if {$target ne "" && ![path_flex_ok $target]} { return [err 400 invalid_path $target] }
    if {$target eq ""} { return [_tree_listing $peer_h "/$local/"] }
    if {[string index $target end] eq "/"} {
        return [_tree_listing $peer_h [::entity::core::capability::canonicalize $local $target]]
    }
    set path [::entity::core::capability::canonicalize $local $target]
    set e [::entity::core::store::get_at $store_h $path]
    if {$e eq ""} { return [err 404 not_found $path] }
    set params [::entity::core::entity::entity_field $exec params]
    set mode [expr {$params ne "" ? [::entity::core::entity::text $params mode] : ""}]
    if {$mode eq "hash"} {
        return [ok [::entity::core::entity::make system/hash [::entity::core::ecf::map \
            hash [::entity::core::ecf::bstr [::entity::core::entity::hash $e]]]]]
    }
    return [ok $e]
}

proc ::entity::core::handlers::_tree_put {peer_h ctx} {
    set exec [dict get $ctx exec]
    set local [::entity::core::peer::local_peer $peer_h]
    set store_h [::entity::core::peer::store $peer_h]
    set target [exec_resource_target $exec]
    if {$target eq ""} { return [err 400 ambiguous_resource "tree: missing resource target"] }
    if {![path_flex_ok $target]} { return [err 400 invalid_path $target] }
    set path [::entity::core::capability::canonicalize $local $target]
    set params [::entity::core::entity::entity_field $exec params]
    set entity [expr {$params ne "" ? [::entity::core::entity::entity_field $params entity] : ""}]
    set expected [expr {$params ne "" ? [::entity::core::entity::bytes $params expected_hash] : ""}]
    set current [::entity::core::store::hash_at $store_h $path]
    if {$expected eq ""} {
        set cas_ok 1
    } elseif {[is_zero_hash $expected]} {
        set cas_ok [expr {$current eq ""}]
    } else {
        set cas_ok [expr {$current ne "" && $current eq [binary encode hex $expected]}]
    }
    if {!$cas_ok} { return [err 409 hash_mismatch $path] }
    if {$entity eq ""} { return [err 400 unexpected_params "put: missing entity"] }
    ::entity::core::store::bind $store_h $path $entity
    return [ok [::entity::core::entity::make system/hash [::entity::core::ecf::map \
        hash [::entity::core::ecf::bstr [::entity::core::entity::hash $entity]]]]]
}

proc ::entity::core::handlers::_tree_listing {peer_h path} {
    set store_h [::entity::core::peer::store $peer_h]
    set rows {}
    foreach row [::entity::core::store::listing $store_h $path] {
        lassign $row seg hash_hex has_children
        if {$hash_hex ne "" && !$has_children && [_is_deletion_marker $peer_h [binary decode hex $hash_hex]]} { continue }
        lappend rows $row
    }
    set entry_kv {}
    foreach row $rows {
        lassign $row seg hash_hex has_children
        if {$hash_hex ne ""} {
            set data [::entity::core::ecf::map has_children [::entity::core::ecf::tbool $has_children] \
                hash [::entity::core::ecf::bstr [binary decode hex $hash_hex]]]
        } else {
            set data [::entity::core::ecf::map has_children [::entity::core::ecf::tbool $has_children]]
        }
        set le [::entity::core::entity::make system/tree/listing-entry $data]
        lappend entry_kv [::entity::core::ecf::tstr $seg] [::entity::core::entity::to_cbor $le]
    }
    return [ok [::entity::core::entity::make system/tree/listing [::entity::core::ecf::map \
        path    [::entity::core::ecf::tstr $path] \
        entries [list map $entry_kv] \
        count   [::entity::core::ecf::tint [llength $rows]] \
        offset  [::entity::core::ecf::tint 0]]]]
}

proc ::entity::core::handlers::_is_deletion_marker {peer_h h} {
    set e [::entity::core::store::get_by_hash [::entity::core::peer::store $peer_h] $h]
    return [expr {$e ne "" && [::entity::core::entity::type $e] eq "system/deletion-marker"}]
}

# ═════════════════════════ §6.2/§6.13(a) handlers handler ═════════════════════════
proc ::entity::core::handlers::handlers {peer_h operation ctx} {
    switch -- $operation {
        register   { return [_handlers_register $peer_h $ctx] }
        unregister { return [_handlers_unregister $peer_h $ctx] }
        default    { return [err 501 unsupported_operation $operation] }
    }
}

proc ::entity::core::handlers::_handlers_register {peer_h ctx} {
    set exec [dict get $ctx exec]
    set store_h [::entity::core::peer::store $peer_h]
    set ident [::entity::core::peer::identity $peer_h]
    set pattern [register_pattern $exec]
    if {$pattern eq ""} { return [register_pattern_error $exec] }
    if {[is_reserved_pattern $pattern]} {
        return [err 403 forbidden_pattern "§6.2: user-installed handlers MUST NOT register at system/* paths: $pattern"]
    }
    set req [::entity::core::entity::entity_field $exec params]
    if {$req eq ""} { return [err 400 unexpected_params "register: missing params"] }
    if {[::entity::core::entity::type $req] ne "system/handler/register-request"} {
        return [err 400 unexpected_params "register expects register-request, got [::entity::core::entity::type $req]"]
    }
    set manifest [::entity::core::entity::mapfield $req manifest]
    if {$manifest eq ""} { set manifest [::entity::core::ecf::emptymap] }
    set name [::entity::core::ecf::text $manifest name]
    if {$name eq ""} { set name $pattern }
    set operations [::entity::core::ecf::mapfield $manifest operations]
    if {$operations eq ""} { set operations [::entity::core::ecf::emptymap] }
    set expr_path [::entity::core::ecf::text $manifest expression_path]
    set internal_scope [::entity::core::ecf::get $manifest internal_scope]
    set grant_scope [::entity::core::ecf::maplist [::entity::core::entity::data $req] requested_scope]
    if {$grant_scope eq "" && $internal_scope ne ""} {
        set grant_scope [::entity::core::ecf::maplist [::entity::core::entity::data $req] internal_scope]
    }
    if {$grant_scope eq ""} { set grant_scope {} }
    set interface_rel "system/handler/$pattern"
    # (1) handler manifest at the pattern path
    set hp [list interface [::entity::core::ecf::tstr $interface_rel]]
    if {$expr_path ne ""} { lappend hp expression_path [::entity::core::ecf::tstr $expr_path] }
    if {$internal_scope ne ""} { lappend hp internal_scope $internal_scope }
    ::entity::core::store::bind $store_h [::entity::core::peer::abs $peer_h $pattern] \
        [::entity::core::entity::make system/handler [::entity::core::ecf::map {*}$hp]]
    # (2) associated types
    set types [::entity::core::entity::mapfield $req types]
    if {$types ne ""} {
        foreach {tk tv} [::entity::core::ecf::entries $types] {
            if {[lindex $tk 0] ne "text"} { continue }
            set tname [lindex $tk 1]
            set td [expr {[lindex $tv 0] eq "map" ? $tv : [::entity::core::ecf::map def $tv]}]
            ::entity::core::store::bind $store_h [::entity::core::peer::abs $peer_h "system/type/$tname"] \
                [::entity::core::entity::make system/type $td]
        }
    }
    # (3) self-issued signed handler grant + (4) grant-signature at §3.5
    set m [::entity::core::peer::mint_token $peer_h [dict get $ident id_hash] $grant_scope ""]
    ::entity::core::store::bind $store_h [::entity::core::peer::abs $peer_h "system/capability/grants/$pattern"] [dict get $m token]
    ::entity::core::store::bind $store_h [::entity::core::peer::abs $peer_h "system/signature/[binary encode hex [::entity::core::entity::hash [dict get $m token]]]"] [dict get $m signature]
    # (5) handler interface entity (discovery index)
    ::entity::core::store::bind $store_h [::entity::core::peer::abs $peer_h $interface_rel] \
        [::entity::core::entity::make system/handler/interface [::entity::core::ecf::map \
            pattern [::entity::core::ecf::tstr $pattern] name [::entity::core::ecf::tstr $name] \
            operations $operations]]
    return [ok [::entity::core::entity::make system/handler/register-result [::entity::core::ecf::map \
        pattern [::entity::core::ecf::tstr $pattern] grant [::entity::core::entity::data [dict get $m token]]]]]
}

proc ::entity::core::handlers::_handlers_unregister {peer_h ctx} {
    set exec [dict get $ctx exec]
    set store_h [::entity::core::peer::store $peer_h]
    set pattern [register_pattern $exec]
    if {$pattern eq ""} { return [register_pattern_error $exec] }
    set g [::entity::core::store::get_at $store_h [::entity::core::peer::abs $peer_h "system/capability/grants/$pattern"]]
    if {$g ne ""} {
        ::entity::core::store::unbind $store_h [::entity::core::peer::abs $peer_h "system/signature/[binary encode hex [::entity::core::entity::hash $g]]"]
        ::entity::core::store::unbind $store_h [::entity::core::peer::abs $peer_h "system/capability/grants/$pattern"]
    }
    ::entity::core::store::unbind $store_h [::entity::core::peer::abs $peer_h $pattern]
    ::entity::core::store::unbind $store_h [::entity::core::peer::abs $peer_h "system/handler/$pattern"]
    return [ok [::entity::core::wire::empty_params]]
}

# ═════════════════════════ system/type:validate handler (EXTENSION) ═════════════════════════
proc ::entity::core::handlers::type {peer_h operation ctx} {
    if {$operation ne "validate"} { return [err 501 unsupported_operation $operation] }
    set store_h [::entity::core::peer::store $peer_h]
    set req [_params $ctx]
    if {$req eq ""} { return [err 400 invalid_params "validate requires a params entity"] }
    set subject [::entity::core::entity::entity_field $req entity]
    if {$subject eq ""} { return [err 400 unexpected_params "validate-request missing entity"] }
    set type_name [::entity::core::entity::text $req type_path]
    if {$type_name eq ""} { set type_name [::entity::core::entity::type $subject] }
    set type_def [::entity::core::store::get_at $store_h [::entity::core::peer::abs $peer_h "system/type/$type_name"]]
    if {$type_def eq ""} {
        set vs [list [::entity::core::ecf::map kind [::entity::core::ecf::tstr unknown_type] \
            field [::entity::core::ecf::tstr $type_name] \
            message [::entity::core::ecf::tstr "no registered type definition for $type_name"]]]
        return [ok [::entity::core::entity::make system/type/validate-result [::entity::core::ecf::map \
            valid [::entity::core::ecf::tbool 0] violations [::entity::core::ecf::tarray $vs]]]]
    }
    set fields [::entity::core::entity::mapfield $type_def fields]
    set subj_data [::entity::core::ecf::asmap [::entity::core::entity::raw_data $subject]]
    set violations {}
    set unevaluated {}
    set declared {}
    if {$fields ne ""} {
        foreach {fk fv} [::entity::core::ecf::entries $fields] {
            if {[lindex $fk 0] ne "text"} { continue }
            set fname [lindex $fk 1]
            dict set declared $fname 1
            set spec [::entity::core::ecf::asmap $fv]
            set optional [expr {$spec ne "" && [::entity::core::ecf::bool_is [::entity::core::ecf::get $spec optional]]}]
            set present [expr {$subj_data ne "" && [::entity::core::ecf::has $subj_data $fname]}]
            if {!$optional && !$present} {
                lappend violations [::entity::core::ecf::map kind [::entity::core::ecf::tstr missing_required_field] \
                    field [::entity::core::ecf::tstr $fname] message [::entity::core::ecf::tstr "required field absent"]]
            }
        }
    }
    if {$subj_data ne ""} {
        foreach {sk sv} [::entity::core::ecf::entries $subj_data] {
            if {[lindex $sk 0] eq "text" && ![dict exists $declared [lindex $sk 1]]} {
                lappend unevaluated [lindex $sk 1]
            }
        }
    }
    set valid [expr {$violations eq {}}]
    set kv [list valid [::entity::core::ecf::tbool $valid]]
    if {$violations ne {}} { lappend kv violations [::entity::core::ecf::tarray $violations] }
    if {$unevaluated ne {}} { lappend kv unevaluated_fields [::entity::core::ecf::text_array $unevaluated] }
    return [ok [::entity::core::entity::make system/type/validate-result [::entity::core::ecf::map {*}$kv]]]
}

# ═════════════════════════ §6.2 capability handler ═════════════════════════
proc ::entity::core::handlers::capability {peer_h operation ctx} {
    switch -- $operation {
        request   { return [_cap_request $peer_h $ctx] }
        delegate  { return [_cap_delegate $peer_h $ctx] }
        revoke    { return [_cap_revoke $peer_h $ctx] }
        configure { return [_cap_configure $peer_h $ctx] }
        default   { return [err 501 unsupported_operation $operation] }
    }
}

proc ::entity::core::handlers::_cap_request {peer_h ctx} {
    set params [_params $ctx]
    set author [::entity::core::entity::bytes [dict get $ctx exec] author]
    if {$author eq ""} { return [err 403 capability_denied] }
    return [_cap_mint_bounded $peer_h $ctx [dict get $ctx caller_cap] $params [req_grants $params] $author ""]
}

proc ::entity::core::handlers::_cap_delegate {peer_h ctx} {
    set params [_params $ctx]
    set author [::entity::core::entity::bytes [dict get $ctx exec] author]
    set ph [expr {$params ne "" ? [::entity::core::entity::bytes $params parent] : ""}]
    if {$ph eq ""} { return [err 400 unexpected_params "delegate: parent required"] }
    if {[is_zero_hash $ph]} { return [err 400 unexpected_params "delegate: zero parent"] }
    set id_hash [dict get [::entity::core::peer::identity $peer_h] id_hash]
    if {!($author ne "" && $id_hash eq $author)} {
        return [err 501 unsupported_operation "delegate: same-peer-only in v1"]
    }
    return [_cap_mint_bounded $peer_h $ctx [dict get $ctx caller_cap] $params [req_grants $params] $author $ph]
}

proc ::entity::core::handlers::_cap_revoke {peer_h ctx} {
    set params [_params $ctx]
    set store_h [::entity::core::peer::store $peer_h]
    set token_h [expr {$params ne "" ? [::entity::core::entity::bytes $params token] : ""}]
    if {$token_h eq ""} { return [err 400 unexpected_params "revoke: missing token"] }
    if {[is_zero_hash $token_h]} { return [err 400 unexpected_params "revoke: zero token"] }
    set marker [::entity::core::entity::make system/capability/revocation [::entity::core::ecf::map \
        token [::entity::core::ecf::bstr $token_h] revoked_at [::entity::core::ecf::tint [::entity::core::capability::now_ms]]]]
    ::entity::core::store::bind $store_h "/[::entity::core::peer::local_peer $peer_h]/system/capability/revocations/[binary encode hex $token_h]" $marker
    return [ok [::entity::core::wire::empty_params]]
}

proc ::entity::core::handlers::_cap_configure {peer_h ctx} {
    set params [_params $ctx]
    set store_h [::entity::core::peer::store $peer_h]
    set pp [expr {$params ne "" ? [::entity::core::entity::text $params peer_pattern] : ""}]
    if {$pp eq ""} { return [err 400 unexpected_params "configure: missing peer_pattern"] }
    set is_hex [expr {[string length $pp] == 66 && [string is xdigit -strict $pp] && [string tolower $pp] eq $pp}]
    if {!($pp eq "default" || $is_hex || [::entity::core::capability::is_peer_id $pp])} {
        return [err 400 invalid_peer_pattern $pp]
    }
    ::entity::core::store::bind $store_h "/[::entity::core::peer::local_peer $peer_h]/system/capability/policy/$pp" $params
    return [ok [::entity::core::wire::empty_params]]
}

proc ::entity::core::handlers::_cap_mint_bounded {peer_h ctx caller_cap params req_grants grantee_hash parent} {
    set local [::entity::core::peer::local_peer $peer_h]
    set bounded 0
    if {$caller_cap ne ""} {
        set parent_grants [::entity::core::capability::grants_of_token $caller_cap]
        set bounded 1
        foreach cg_raw $req_grants {
            set c [::entity::core::capability::parse_grant $cg_raw]
            set covered 0
            foreach pg $parent_grants {
                if {[::entity::core::capability::grant_subset $local $local $local $c $pg]} { set covered 1; break }
            }
            if {!$covered} { set bounded 0; break }
        }
    }
    if {!$bounded} { return [err 403 scope_exceeds_authority] }

    # §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and
    # convert the duration term against that same instant.
    #
    # Note what this is NOT: an authorization decision. An over-long ttl_ms from a
    # bounded caller MINTS a clamped token and returns 200 — "rejecting it is
    # non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
    # (parent: null), so §5.6's parent-child attenuation never reaches it; without this
    # clamp, temporal attenuation is the one dimension a requester could escape, and
    # policy withdrawal would have no bounded latency.
    set created_at [::entity::core::capability::now_ms]
    set terms {}
    if {$parent ne ""} {
        set pt [::entity::core::capability::cap_resolve \
                    [dict get $ctx included] [::entity::core::peer::store $peer_h] $parent]
        if {$pt ne ""} { lappend terms [::entity::core::entity::uint $pt expires_at] }
    }
    if {$caller_cap ne ""} { lappend terms [::entity::core::entity::uint $caller_cap expires_at] }
    if {$params ne ""} {
        set ttl [::entity::core::entity::uint $params ttl_ms]
        if {$ttl ne ""} { lappend terms [::entity::core::capability::add_ttl $created_at $ttl] }
    }
    set ceiling ""
    foreach t $terms {
        if {$t eq ""} { continue }
        if {$ceiling eq "" || $t < $ceiling} { set ceiling $t }
    }

    set m [::entity::core::peer::mint_token_at $peer_h $created_at $grantee_hash $req_grants $parent $ceiling]
    return [ok [::entity::core::entity::make system/capability/grant [::entity::core::ecf::map \
        token [::entity::core::ecf::bstr [::entity::core::entity::hash [dict get $m token]]]]] \
        [::entity::core::peer::cap_included $peer_h $m]]
}

# ═════════════════════════ §7a conformance handlers (--validate only) ═════════════════════════
proc ::entity::core::handlers::echo {peer_h operation ctx} {
    if {$operation ne "echo"} { return [err 501 unsupported_operation $operation] }
    set p [_params $ctx]
    if {$p eq ""} { return [err 400 invalid_params "echo requires params"] }
    return [ok $p]
}

proc ::entity::core::handlers::dispatch_outbound {peer_h operation ctx} {
    if {$operation ne "dispatch"} { return [err 501 unsupported_operation $operation] }
    set p [_params $ctx]
    if {$p eq ""} { return [err 400 invalid_params "dispatch-outbound requires a params entity"] }
    set target [::entity::core::entity::text $p target]
    set op [::entity::core::entity::text $p operation]
    set value [::entity::core::entity::field $p value]
    set cap [::entity::core::entity::entity_field $p reentry_capability]
    set granter [::entity::core::entity::entity_field $p reentry_granter]
    set cap_sig [::entity::core::entity::entity_field $p reentry_cap_signature]
    if {!($value ne "" && $cap ne "" && $granter ne "" && $cap_sig ne "")} {
        return [err 400 invalid_params "dispatch-outbound requires value + reentry authority"]
    }
    # §7a.1 generic relay: `value` is the downstream's params entity data and MUST be
    # forwarded VERBATIM, never re-wrapped (re-wrapping double-nests — the
    # non-conformant party the keystone matrix caught). uri = the bare target: the
    # receiver canonicalizes it to ITSELF (the §6.11 caller = B-role on the same conn).
    set value_map [::entity::core::ecf::asmap $value]
    set inner_data [expr {$value_map ne "" ? $value_map : [::entity::core::ecf::map value $value]}]
    set inner [::entity::core::entity::make primitive/any $inner_data]
    set resource [::entity::core::wire::resource_target "system/handler/$target"]
    set resp [::entity::core::peer::outbound_dispatch $peer_h [dict get $ctx conn] \
        $target $op $inner $cap $granter $cap_sig $resource]
    if {$resp eq ""} { return [err 503 no_outbound_seam "no live §6.11 reentry connection"] }
    set root [::entity::core::envelope::root $resp]
    set status [::entity::core::entity::uint $root status]
    if {$status eq ""} { set status 0 }
    set result_cbor [::entity::core::entity::field $root result]
    if {$result_cbor eq ""} { set result_cbor [::entity::core::ecf::emptymap] }
    return [ok [::entity::core::entity::make primitive/any [::entity::core::ecf::map \
        status [::entity::core::ecf::tint $status] result $result_cbor]]]
}
