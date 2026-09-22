# entity-core-protocol-tcl — capability system (L3): the §5 verification core.
#
# Pattern matching (§5.4), request verification (§5.2 verify_request /
# check_permission), delegation-chain verification (§5.5), attenuation (§5.6),
# caveats (§5.7), revocation (§5.1), and genuine §3.6 M3 multi-signature K-of-N.
#
# Derived from the §5 pseudocode. Layer-1 verdict is the string ALLOW/DENY (§5.10);
# DENY → 403, the §5.5 unresolvable-grantee carve-out throws → 401. The three-way
# request verdict folds in §4.10(b) CHAIN_TOO_DEEP (→ 400): ALLOW / AUTHN_FAIL /
# AUTHZ_DENY / CHAIN_TOO_DEEP.
#
# §PR-8 / §5.5a granter-frame refinement: the RESOURCE dimension canonicalizes
# against the GRANTER's peer_id; handlers/operations/peers stay on the local frame.
# For the self-issued dominant path (granter = local) this is byte-identical.
#
# Head-form note: thresholds/temporal bounds/depth come off the wire as native Tcl
# bignums (libtommath) — plain integer comparison is exact with NO fixed-width trap
# (the EIAS bignum advantage — contrast the OCaml int63 / C# ulong peers).
#
# `resolve` is done inline via cap_resolve {included store_h h}; procs that walk a
# chain thread (included, store_h) rather than a closure — one interp, no captures.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] entity.tcl]
source [file join [file dirname [info script]] identity.tcl]
source [file join [file dirname [info script]] envelope.tcl]
source [file join [file dirname [info script]] store.tcl]
source [file join [file dirname [info script]] ecf.tcl]

namespace eval ::entity::core::capability {
    variable MAX_CHAIN_DEPTH 64
    variable BASE58 "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    namespace export now_ms verify_request check_permission grant \
        resolve_granter_peer_id cap_resolve find_signature grants_of_token \
        grant_subset parse_grant is_peer_id normalize_uri canonicalize extract_peer \
        effective_targets check_path_permission
}

# §6.2 CAP-6a: 1 iff every temporal field on a RECEIVED token is either absent (legal)
# or representable as a uint64.
#
# This is the reader-side half of CAP-6 and it is where a peer fails OPEN. Tcl's
# fail-open is the ARITHMETIC one, not the null-collapse one, and the distinction matters
# because the grep that catches the other misses this: `ecf::uint` returns the value of
# ANY `int`-tagged item, negative included. The expiry check therefore did NOT skip — it
# RAN and returned the wrong answer. For a negative not_before, `$now < $nb` is simply
# false and the capability passed. No empty string, no skip, nothing an Option-shaped
# audit would find.
#
# Tcl integers are arbitrary-precision, so the >2^64 half is likewise a DELIBERATE range
# check rather than an overflow trap.
#
# An absent field stays legal and is NOT rejected here. Refusal must be the §5.2
# capability_denied disposition, never a decode-layer drop or a transport close.
proc ::entity::core::capability::temporal_fields_representable {tok} {
    foreach key {expires_at not_before created_at} {
        set v [::entity::core::entity::field $tok $key]
        if {$v eq ""} { continue }
        if {[lindex $v 0] ne "int"} { return 0 }
        set n [lindex $v 1]
        if {$n < 0 || $n >= 18446744073709551616} { return 0 }
    }
    return 1
}

# §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp relative to
# $created_at. Rule 3: a conversion that is not representable is treated as ABSENT (the
# empty string) exactly as a null term is — it MUST NOT wrap and MUST NOT saturate to a
# representable maximum, since saturation manufactures expires_at == 2^64-1, a finite
# bound no reader can distinguish from a deliberate one. Tcl does not wrap, so this is a
# deliberate range check.
#
# ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
# yielding $created_at (expire immediately). The absent field is the only "no bound"
# spelling, and falling out of the arithmetic is what keeps the two from collapsing.
proc ::entity::core::capability::add_ttl {created_at ttl} {
    if {$ttl < 0} { return "" }
    set sum [expr {$created_at + $ttl}]
    if {$sum >= 18446744073709551616} { return "" }
    return $sum
}

proc ::entity::core::capability::now_ms {} { return [clock milliseconds] }

# ── small string helpers ──
proc ::entity::core::capability::_sw {s p} {
    return [expr {[string range $s 0 [expr {[string length $p]-1}]] eq $p}]
}
proc ::entity::core::capability::_ew {s p} {
    set n [string length $p]
    return [expr {$n == 0 || [string range $s end-[expr {$n-1}] end] eq $p}]
}

# ── grant / scope parse ──
# a scope is {incl <list> excl <list>} of pattern strings.
proc ::entity::core::capability::parse_scope {mtv} {
    if {$mtv eq ""} { return [dict create incl {} excl {}] }
    set incl [::entity::core::ecf::textlist $mtv include]
    set excl [::entity::core::ecf::textlist $mtv exclude]
    return [dict create incl [expr {$incl eq "" ? {} : $incl}] excl [expr {$excl eq "" ? {} : $excl}]]
}

# a grant is {handlers <scope> resources <scope> operations <scope> peers <scope|"">}.
proc ::entity::core::capability::parse_grant {mtv} {
    set peers ""
    if {$mtv ne "" && [::entity::core::ecf::get $mtv peers] ne ""} {
        set peers [parse_scope [::entity::core::ecf::mapfield $mtv peers]]
    }
    return [dict create \
        handlers   [parse_scope [::entity::core::ecf::mapfield $mtv handlers]] \
        resources  [parse_scope [::entity::core::ecf::mapfield $mtv resources]] \
        operations [parse_scope [::entity::core::ecf::mapfield $mtv operations]] \
        peers      $peers]
}

proc ::entity::core::capability::grants_of_token {token} {
    set list [::entity::core::ecf::maplist [::entity::core::entity::data $token] grants]
    if {$list eq ""} { return {} }
    set out {}
    foreach g $list { lappend out [parse_grant $g] }
    return $out
}

# build a grant map (handlers/resources/operations [+ peers]) — the §4.4 helper.
# $peers "" → OMIT the peers dimension (defaults to local at check time); a
# non-empty list → an explicit peers scope. (All spec callers that set peers pass a
# non-empty list; the peers-omitted grants pass "".)
proc ::entity::core::capability::grant {handlers resources operations {peers ""}} {
    set kv [list \
        handlers   [::entity::core::ecf::scope $handlers] \
        resources  [::entity::core::ecf::scope $resources] \
        operations [::entity::core::ecf::scope $operations]]
    if {$peers ne ""} { lappend kv peers [::entity::core::ecf::scope $peers] }
    return [::entity::core::ecf::map {*}$kv]
}

# ── §5.4 pattern matching ──
proc ::entity::core::capability::normalize_uri {uri} {
    if {[_sw $uri "entity://"]} { return "/[string range $uri 9 end]" }
    return $uri
}

# NEVER_MATCH — the unmatchable value (0.8.2.20). Unreachable as a canonical path by
# CONSTRUCTION: its first segment cannot be a peer_id, since is_peer_id requires >= 46
# Base58 characters and "-" is outside the Base58 alphabet.
set ::entity::core::capability::NEVER_MATCH "/never-match"

# TOTAL (0.8.2.20): the return domain is "a canonical path OR NEVER_MATCH". This used
# to THROW, and the throw was reachable from the wire -- every normative call site is a
# matcher with no error channel to consume one, so the exception escaped the matcher,
# the resilience frame caught it, and "../x" in a resource exclude answered 500
# (measured 2026-09-14). The diagnostic belongs at admission (6.5), which has a caller
# to answer.
proc ::entity::core::capability::canonicalize {local_peer path} {
    variable NEVER_MATCH
    if {[_sw $path "./"] || [_sw $path "../"]} { return $NEVER_MATCH }
    if {[_sw $path "*/"]} { return $NEVER_MATCH }
    if {[_sw $path "/"]} { return $path }
    return "/$local_peer/$path"
}

proc ::entity::core::capability::matches_pattern {path pattern} {
    variable NEVER_MATCH
    # NEVER_MATCH never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
    # rule rather than a property of the string: the arm below returns 1 for a bare
    # "*", so safety must not rest on a value merely looking unmatchable.
    if {$path eq $NEVER_MATCH || $pattern eq $NEVER_MATCH} { return 0 }
    if {$pattern eq "*"} { return 1 }
    if {[_sw $pattern "/*/"]} {
        set remainder [string range $pattern 3 end]
        if {$path eq ""} { return 0 }
        set i [string first "/" $path 1]
        if {$i < 0} { return 0 }
        return [matches_pattern [string range $path [expr {$i+1}] end] $remainder]
    }
    if {[string length $pattern] >= 2 && [_ew $pattern "/*"]} {
        return [_sw $path [string range $pattern 0 end-1]]
    }
    return [expr {$path eq $pattern}]
}

proc ::entity::core::capability::_covered {frame pats cv} {
    foreach p $pats {
        if {[matches_pattern $cv [canonicalize $frame $p]]} { return 1 }
    }
    return 0
}

# §5.2 id-scope match (0.8.1, F40) — operations and peers. Literal comparison with
# exactly two wildcard forms: bare * and a trailing slash-star segment-prefix. None of
# the §5.4 path transforms apply, so a pattern carrying path syntax is matched as a
# literal string: a non-match, never a fault.
proc ::entity::core::capability::matches_id_pattern {value pattern} {
    if {$pattern eq "*"} { return 1 }
    if {[string length $pattern] >= 2 && [string range $pattern end-1 end] eq "/*"} {
        set prefix [string range $pattern 0 end-1]
        return [string equal -length [string length $prefix] $value $prefix]
    }
    return [string equal $value $pattern]
}

proc ::entity::core::capability::_covered_id {pats value} {
    foreach p $pats {
        if {[matches_id_pattern $value $p]} { return 1 }
    }
    return 0
}

# §5.2 typed scope match. `kind` is id (operations, peers) or path (handlers, resources)
# and has no default — every call site names its dimension, so a new one cannot silently
# inherit the wrong matcher, which is exactly the F40 defect.
# AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
# in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an
# exclude (carves out nothing -> the grant is SILENTLY WIDER than its author wrote):
# same value, same matcher, opposite safety direction, so the reading is chosen where
# the POSITION is known and matches_pattern stays uniform over its operands.
#
# ASK THIS ONLY OF A PATH-SCOPE DIMENSION (0.8.2.24, N2/N3). NEVER_MATCH is a 5.4
# PATH-canonicalization sentinel; an id-scope pattern is a literal identifier that
# 5.2's own id-scope arm forbids putting through the 5.4 transforms. This guard used to
# sit OUTSIDE the type dispatch, transcribing 5.2's loop as it read before that loop
# grew one -- which ran an id pattern through those transforms purely to classify it and
# then DENIED THE WHOLE DIMENSION on a property unrelated to whether the exclude carves
# anything out: an `operations` exclude of a namespaced operation name such as the
# apply-under-star form -- an ordinary literal that matches nothing under the id-scope
# grammar -- canonicalized to the sentinel and denied every operation. Over-denial, and
# invisible on any well-formed grant.
#
# 5.4 says outright that the rule "does NOT reach `operations` or `peers` [MUST]", and it
# does not leave the id dimensions unprotected by oversight: under the id-scope grammar
# every non-star pattern is a literal and a literal is never structurally unmatchable, so
# there is nothing here for this sentinel to detect. A scope boundary, not an omission.
proc ::entity::core::capability::_exclude_unmatchable {frame excl} {
    variable NEVER_MATCH
    foreach p $excl {
        if {[canonicalize $frame $p] eq $NEVER_MATCH} { return 1 }
    }
    return 0
}

proc ::entity::core::capability::matches_scope {local_peer value s kind} {
    # SCOPED TO PATH-SCOPE (0.8.2.24). 5.2's exclude loop tests the sentinel INSIDE
    # `if dimension_type == "system/capability/path-scope"`, and 5.4 scopes its own
    # invalid-capability rule the same way. `kind` already names the dimension here, so
    # the scoping costs one term and cannot be got wrong by a new call site.
    if {$kind eq "path" && [_exclude_unmatchable $local_peer [dict get $s excl]]} { return 0 }
    if {$kind eq "id"} {
        return [expr {[_covered_id [dict get $s incl] $value]
            && ![_covered_id [dict get $s excl] $value]}]
    }
    set cv [canonicalize $local_peer $value]
    return [expr {[_covered $local_peer [dict get $s incl] $cv]
        && ![_covered $local_peer [dict get $s excl] $cv]}]
}

# ── §5.2 check-permission ──
proc ::entity::core::capability::first_segment {uri} {
    set u [expr {[_sw $uri "/"] ? [string range $uri 1 end] : $uri}]
    set i [string first "/" $u]
    return [expr {$i >= 0 ? [string range $u 0 [expr {$i-1}]] : $u}]
}

proc ::entity::core::capability::is_peer_id {seg} {
    variable BASE58
    if {[string length $seg] < 46} { return 0 }
    foreach c [split $seg ""] {
        if {[string first $c $BASE58] < 0} { return 0 }
    }
    return 1
}

proc ::entity::core::capability::extract_peer {local_peer uri} {
    set first [first_segment [normalize_uri $uri]]
    return [expr {[is_peer_id $first] ? $first : $local_peer}]
}

proc ::entity::core::capability::check_resource_scope {local_peer granter_peer resource s} {
    set targets [::entity::core::ecf::textlist $resource targets]
    set caller_excl [::entity::core::ecf::textlist $resource exclude]
    if {$targets eq "" || $targets eq {}} { return 0 }
    # An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
    # target: the coverage test below is correct in isolation and is simply never
    # reached on a sentinel, because matches_pattern answers 0.
    #
    # UNGUARDED ON PURPOSE, unlike matches_scope's (0.8.2.24): `s` here is ALWAYS the
    # RESOURCES dimension, which 5.2 fixes as path-scope, so the type test that call site
    # performs would be a constant here. The single-dimension signature is what makes
    # that checkable -- a granter frame reaching an id-scope call site is the defect, and
    # this proc cannot be one.
    if {[_exclude_unmatchable $granter_peer [dict get $s excl]]} { return 0 }
    foreach tgt $targets {
        set ct [canonicalize $local_peer $tgt]
        if {$caller_excl ne "" && [_covered $local_peer $caller_excl $ct]} { continue }
        if {![_covered $granter_peer [dict get $s incl] $ct]} { return 0 }
        if {[_covered $granter_peer [dict get $s excl] $ct]} { return 0 }
    }
    return 1
}

# ── §3.3 effective targets + §6.3 check_path_permission ──

# §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude` removes
# entries from `resource.targets` BEFORE anything else looks at the request.
#
# Returns a TWO-ELEMENT list {had_resource survivors}. The survivors are in the caller's
# OWN SPELLING, not canonicalized -- 0.8.2.21 is explicit that effective_targets yields
# raw survivors, and the distinction is load-bearing because the value flows on to the
# store lookup, which canonicalizes for itself.
#
# THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11): "where an
# implementation projects resource.targets onto the effective set ahead of the handler,
# that projection MUST NOT be lossy about its own emptiness -- narrow when narrowing
# leaves something, and retain the raw pair when narrowing would empty it." A proc
# returning only a list cannot satisfy that in Tcl, where an empty list and an absent
# value are the SAME VALUE (the empty string): collapsing `[qA] exclude [qA]` to {} would
# delete the two-empties discriminator before any handler can read it, and the handler's
# refusal arm becomes dead code that only a WIRE drive can detect. The flag beside the
# survivors keeps the discriminator by construction, and on this substrate it is not
# merely tidier -- it is the only way to have one at all.
#
# "Every seam that narrows is exempted alike, inbound-wire and in-process sub-dispatch,
# or one request receives two different answers according to which door it arrived
# through." This peer has exactly ONE narrowing seam -- this proc, called by the tree
# handler -- and §6.5's dispatch chain does not project: _dispatch_inner passes $exec
# through untouched and check_permission reads `resource` for itself. So there is no
# second door to keep in step, and adding a projection at dispatch would create one.
#
# A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list.
# Reporting it absent would serve the WIDER absent-case answer to a request that named a
# resource, which is N11's own defect one field over.
#
# The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules it separately
# from the grant arm) and that is INHERITED here rather than restated: canonicalize
# answers the sentinel, matches_pattern then answers 0, and the target simply survives.
proc ::entity::core::capability::effective_targets {local_peer exec} {
    set r [::entity::core::entity::mapfield $exec resource]
    if {$r eq ""} { return [list 0 {}] }
    if {![::entity::core::ecf::has $r targets]} { return [list 0 {}] }
    set targets [::entity::core::ecf::textlist $r targets]
    set excl [::entity::core::ecf::textlist $r exclude]
    set out {}
    foreach t $targets {
        set ct [canonicalize $local_peer $t]
        set dropped 0
        foreach x $excl {
            if {[matches_pattern $ct [canonicalize $local_peer $x]]} { set dropped 1; break }
        }
        if {!$dropped} { lappend out $t }
    }
    return [list 1 $out]
}

# §6.3's handler-level path check: may the caller access $path AS A TREE PATH, under
# $handler_pattern, with $token?  -> 1 ALLOW / 0 DENY.
#
# IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
# subject is derived after dispatch, and the dispatch-level check can be made VACUOUS by
# caller-controlled input: a caller who excludes the one target its capability does not
# cover removes that target from check_permission's view entirely, and a handler that
# then acts on it has authorized nothing.
#
# THREE DIMENSIONS, NOT FOUR. `peers` is not consulted -- the path is local by
# construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
# step 3, before any handler runs), and §6.3's signature names only handlers, operations
# and resources.
#
# THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
# rather than a choice: §6.3's block reads
# `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)` -- there
# is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the subject is
# a pattern compared against a parent's pattern; this call site compares a CONCRETE local
# path the handler is about to touch.
#
# Scope types: handlers -> path-scope, operations -> id-scope, resources -> path-scope.
# An empty resources.include is a legal grant shape (§5.2: handlers that touch no tree
# paths) and DENIES every path here, which is what that note says it should -- _covered
# over an empty include list answers 0. A malformed path canonicalizes to NEVER_MATCH,
# which matches no grant, so it falls through to DENY rather than being matched against
# anything.
proc ::entity::core::capability::check_path_permission {local_peer operation path token handler_pattern} {
    foreach g [grants_of_token $token] {
        if {![matches_scope $local_peer $handler_pattern [dict get $g handlers] path]} { continue }
        if {![matches_scope $local_peer $operation [dict get $g operations] id]} { continue }
        if {![matches_scope $local_peer $path [dict get $g resources] path]} { continue }
        return 1
    }
    return 0
}

# §PR-8: the granter's peer_id frames a cap's resource patterns. Single-sig
# granter → derive from public_key; unresolvable → "".
proc ::entity::core::capability::resolve_granter_peer_id {included store_h cap} {
    set gh [::entity::core::entity::bytes $cap granter]
    if {$gh eq ""} { return "" }
    set g [cap_resolve $included $store_h $gh]
    if {$g eq ""} { return "" }
    set pk [::entity::core::entity::bytes $g public_key]
    if {$pk eq ""} { return "" }
    return [::entity::core::identity::peer_id_of_pubkey $pk]
}

# gate the wire request at the dispatch authorization boundary → ALLOW / DENY.
proc ::entity::core::capability::check_permission {local_peer granter_peer exec token handler_pattern} {
    set operation [::entity::core::entity::text $exec operation]
    set uri [::entity::core::entity::text $exec uri]
    set target_peer [extract_peer $local_peer $uri]
    set resource [::entity::core::entity::mapfield $exec resource]
    foreach g [grants_of_token $token] {
        set ok [expr {[matches_scope $local_peer $operation [dict get $g operations] id]
            && [matches_scope $local_peer $handler_pattern [dict get $g handlers] path]}]
        if {$ok} {
            set peers [dict get $g peers]
            if {$peers eq ""} { set peers [dict create incl [list $local_peer] excl {}] }
            set ok [matches_scope $local_peer $target_peer $peers id]
        }
        if {$ok && $resource ne ""} {
            set ok [check_resource_scope $local_peer $granter_peer $resource [dict get $g resources]]
        }
        if {$ok} { return ALLOW }
    }
    return DENY
}

# ── §5.5 chain verification + attenuation ──
proc ::entity::core::capability::find_signature {target included} {
    foreach pair $included {
        set e [lindex $pair 1]
        if {[::entity::core::entity::type $e] eq "system/signature"
            && [::entity::core::entity::bytes $e target] eq $target && $target ne ""} {
            return $e
        }
    }
    return ""
}

proc ::entity::core::capability::_signatures_targeting {target included} {
    set out {}
    foreach pair $included {
        set e [lindex $pair 1]
        if {[::entity::core::entity::type $e] eq "system/signature"
            && [::entity::core::entity::bytes $e target] eq $target && $target ne ""} {
            lappend out $e
        }
    }
    return $out
}

proc ::entity::core::capability::cap_resolve {included store_h h} {
    foreach pair $included {
        if {[lindex $pair 0] eq $h} { return [lindex $pair 1] }
    }
    return [::entity::core::store::get_by_hash $store_h $h]
}

# ── §3.6 M3 multi-signature granter ──
proc ::entity::core::capability::is_multisig {cap} {
    return [expr {[lindex [::entity::core::entity::field $cap granter] 0] eq "map"}]
}

# parse the granter union as {signers <list> threshold <int>}, or "" if single-sig.
proc ::entity::core::capability::multi_granter_of {cap} {
    set m [::entity::core::entity::field $cap granter]
    if {[lindex $m 0] ne "map"} { return "" }
    set signers {}
    set arr [::entity::core::ecf::get $m signers]
    if {[lindex $arr 0] eq "array"} {
        foreach s [lindex $arr 1] {
            if {[lindex $s 0] eq "bytes"} { lappend signers [lindex $s 1] }
        }
    }
    set th [::entity::core::ecf::uint $m threshold]
    return [dict create signers $signers threshold [expr {$th eq "" ? 0 : $th}]]
}

proc ::entity::core::capability::_has_dup_signers {signers} {
    set n [llength $signers]
    for {set i 0} {$i < $n} {incr i} {
        for {set j [expr {$i+1}]} {$j < $n} {incr j} {
            if {[lindex $signers $i] eq [lindex $signers $j]} { return 1 }
        }
    }
    return 0
}

proc ::entity::core::capability::_peer_id_of_signer {included store_h signer_hash} {
    set p [cap_resolve $included $store_h $signer_hash]
    if {$p eq ""} { return "" }
    set pk [::entity::core::entity::bytes $p public_key]
    if {$pk eq ""} { return "" }
    return [::entity::core::identity::peer_id_of_pubkey $pk]
}

# validate a multi-sig root capability (§3.6 M3 / §5.5 M4·M6) → 1 (ALLOW) / 0.
proc ::entity::core::capability::_verify_multisig_root {local_peer included store_h cap mg} {
    set signers [dict get $mg signers]
    set threshold [dict get $mg threshold]
    set n [llength $signers]
    # §3.6 M3 structure (precedence 25) — root-only; n≥2; 2≤threshold≤n; distinct.
    if {[::entity::core::entity::bytes $cap parent] ne ""} { return 0 }
    if {$n < 2} { return 0 }
    if {$threshold < 2 || $threshold > $n} { return 0 }
    if {[_has_dup_signers $signers]} { return 0 }
    # §5.5 M6 root-at-local: the local peer MUST be a quorum signer.
    set local_in 0
    foreach s $signers {
        if {[_peer_id_of_signer $included $store_h $s] eq $local_peer} { set local_in 1; break }
    }
    if {!$local_in} { return 0 }
    # temporal validity + grantee resolution.
    set now [now_ms]
    set nb [::entity::core::entity::uint $cap not_before]
    if {$nb ne "" && $now < $nb} { return 0 }
    set ex [::entity::core::entity::uint $cap expires_at]
    if {$ex ne "" && $ex < $now} { return 0 }
    set grantee [::entity::core::entity::bytes $cap grantee]
    if {$grantee eq "" || [cap_resolve $included $store_h $grantee] eq ""} { return 0 }
    # §5.5 M4 k-of-n: ≥threshold DISTINCT quorum members validly signed the cap hash.
    set sigs [_signatures_targeting [::entity::core::entity::hash $cap] $included]
    set valid {}
    foreach signer_hash $signers {
        if {$signer_hash in $valid} { continue }
        set signer_peer [cap_resolve $included $store_h $signer_hash]
        if {$signer_peer eq ""} { continue }
        foreach sgn $sigs {
            if {[::entity::core::entity::bytes $sgn signer] eq $signer_hash
                && [::entity::core::identity::verify_signature $sgn $signer_peer]} {
                lappend valid $signer_hash; break
            }
        }
    }
    return [expr {[llength $valid] >= $threshold}]
}

# §PR-8 per-link frame = the cap's granter peer_id (root/no-granter → local; single
# sig unresolvable → "").
proc ::entity::core::capability::_link_granter_peer {included store_h local_peer cap} {
    set gh [::entity::core::entity::bytes $cap granter]
    if {$gh eq ""} { return $local_peer }
    set g [cap_resolve $included $store_h $gh]
    if {$g eq ""} { return "" }
    set pk [::entity::core::entity::bytes $g public_key]
    if {$pk eq ""} { return "" }
    return [::entity::core::identity::peer_id_of_pubkey $pk]
}

# 5.5a/5.6 subset check: every child include must be covered by some parent include, and
# every parent exclude must be inherited by some child exclude.
#
# TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; entity-core-formalization K-7). 3.6's
# id-scope grammar binds the scope TYPE, not one function -- "An implementation on the
# canonicalizing reading is non-conformant and MUST adopt the literal matcher" -- so the
# rule F40 landed on matches_scope reaches here too, with delegation-chain WIDENING named
# as the reason: on the canonicalizing reading a bare id include reads as covered by a
# path-form parent pattern it does not literally match, and a child grant comes out wider
# than its parent. `lean`'s differential put it at 2 of 64 include pairs and 2 of 64
# exclude pairs, fail-closed, with a 16-pair control alphabet reporting 0 -- which is why
# every hand-tried example missed it.
#
# `kind` has NO DEFAULT and is named at every call site, because a default is how the next
# dimension inherits the wrong matcher silently -- the original F40 defect. The per-link
# granter frames are meaningless on the id arm (an id pattern is never canonicalized) and
# are simply unread there.
proc ::entity::core::capability::_ss_frame {kind pattern peer} {
    return [expr {$kind eq "path" ? [canonicalize $peer $pattern] : $pattern}]
}
proc ::entity::core::capability::_ss_covers {kind pattern value} {
    return [expr {$kind eq "path" ? [matches_pattern $value $pattern]
                                  : [matches_id_pattern $value $pattern]}]
}

proc ::entity::core::capability::_scope_subset {child_peer parent_peer child parent kind} {
    foreach cp [dict get $child incl] {
        set cc [_ss_frame $kind $cp $child_peer]
        set covered 0
        foreach pp [dict get $parent incl] {
            if {[_ss_covers $kind [_ss_frame $kind $pp $parent_peer] $cc]} { set covered 1; break }
        }
        if {!$covered} { return 0 }
    }
    foreach pe [dict get $parent excl] {
        set cpe [_ss_frame $kind $pe $parent_peer]
        set covered 0
        foreach ce [dict get $child excl] {
            if {[_ss_covers $kind [_ss_frame $kind $ce $child_peer] $cpe]} { set covered 1; break }
        }
        if {!$covered} { return 0 }
    }
    return 1
}

proc ::entity::core::capability::grant_subset {local_peer child_peer parent_peer child parent} {
    # 5.5a: only the RESOURCE dimension uses the per-link granter frames; the other
    # dimensions stay on the local frame. The scope KIND is a property of the DIMENSION
    # and is named at every call site, never defaulted (F50 / 0.8.2.16).
    if {![_scope_subset $local_peer $local_peer [dict get $child handlers] [dict get $parent handlers] path]} { return 0 }
    if {![_scope_subset $local_peer $local_peer [dict get $child operations] [dict get $parent operations] id]} { return 0 }
    if {![_scope_subset $child_peer $parent_peer [dict get $child resources] [dict get $parent resources] path]} { return 0 }
    set cp [dict get $child peers]; if {$cp eq ""} { set cp [dict create incl [list $local_peer] excl {}] }
    set pp [dict get $parent peers]; if {$pp eq ""} { set pp [dict create incl [list $local_peer] excl {}] }
    return [_scope_subset $local_peer $local_peer $cp $pp id]
}

proc ::entity::core::capability::_is_attenuated {local_peer child_peer parent_peer child parent} {
    foreach c [grants_of_token $child] {
        set ok 0
        foreach p [grants_of_token $parent] {
            if {[grant_subset $local_peer $child_peer $parent_peer $c $p]} { set ok 1; break }
        }
        if {!$ok} { return 0 }
    }
    set pe [::entity::core::entity::uint $parent expires_at]
    set ce [::entity::core::entity::uint $child expires_at]
    if {$pe ne "" && $ce eq ""} { return 0 }
    if {$pe ne ""} { return [expr {$ce <= $pe}] }
    return 1
}

proc ::entity::core::capability::_check_delegation_caveats {parent child depth} {
    set caveats [::entity::core::entity::mapfield $parent delegation_caveats]
    if {$caveats eq ""} { return 1 }
    if {[::entity::core::ecf::bool_is [::entity::core::ecf::get $caveats no_delegation]]} { return 0 }
    set depth_ok 1
    set mdd [::entity::core::ecf::uint $caveats max_delegation_depth]
    if {$mdd ne ""} { set depth_ok [expr {$depth < $mdd}] }
    set ttl_ok 1
    set maxttl [::entity::core::ecf::uint $caveats max_delegation_ttl]
    if {$maxttl ne ""} {
        set ex [::entity::core::entity::uint $child expires_at]
        set cr [::entity::core::entity::uint $child created_at]
        if {$ex ne "" && $cr ne ""} {
            set ttl_ok [expr {($ex - $cr) <= $maxttl}]
        } elseif {$ex ne ""} {
            set ttl_ok 1
        } else {
            set ttl_ok 0
        }
    }
    return [expr {$depth_ok && $ttl_ok}]
}

# collect the parent chain → {chain <list|""> ok <0|1>}.
proc ::entity::core::capability::_collect_chain {cap included store_h} {
    variable MAX_CHAIN_DEPTH
    set acc {}; set current $cap; set depth 0
    while {1} {
        if {$depth > $MAX_CHAIN_DEPTH} { return [dict create chain "" ok 0] }
        lappend acc $current
        set ph [::entity::core::entity::bytes $current parent]
        if {$ph eq ""} { return [dict create chain $acc ok 1] }
        set parent [cap_resolve $included $store_h $ph]
        if {$parent eq ""} { return [dict create chain "" ok 0] }
        set current $parent; incr depth
    }
}

# §4.10(b) structural pre-check: true iff the chain exceeds MAX depth. Walks parent
# pointers WITHOUT verifying sigs — an unreachable parent is NOT a depth problem
# (returns 0, left for the authz walk to 403).
proc ::entity::core::capability::chain_exceeds_depth {store_h cap included} {
    variable MAX_CHAIN_DEPTH
    set current $cap; set depth 0
    while {1} {
        if {$depth > $MAX_CHAIN_DEPTH} { return 1 }
        set ph [::entity::core::entity::bytes $current parent]
        if {$ph eq ""} { return 0 }
        set parent [cap_resolve $included $store_h $ph]
        if {$parent eq ""} { return 0 }
        set current $parent; incr depth
    }
}

# §5.5 chain verification → ALLOW / DENY (may throw UNRESOLVABLE_GRANTEE → 401).
proc ::entity::core::capability::verify_capability_chain {local_peer store_h capability included} {
    set c [_collect_chain $capability $included $store_h]
    if {![dict get $c ok]} { return DENY }
    set chain [dict get $c chain]
    set root [lindex $chain end]
    # root authority: single-sig root roots at local; §3.6 multi-sig root passes k-of-n.
    set root_mg [multi_granter_of $root]
    if {$root_mg ne ""} {
        set root_ok [_verify_multisig_root $local_peer $included $store_h $root $root_mg]
    } else {
        set rgh [::entity::core::entity::bytes $root granter]
        set g [expr {$rgh ne "" ? [cap_resolve $included $store_h $rgh] : ""}]
        set pk [expr {$g ne "" ? [::entity::core::entity::bytes $g public_key] : ""}]
        set root_ok [expr {$pk ne "" && [::entity::core::identity::peer_id_of_pubkey $pk] eq $local_peer}]
    }
    if {!$root_ok} { return DENY }

    set good 1
    set n [llength $chain]
    for {set i 0} {$i < $n && $good} {incr i} {
        set current [lindex $chain $i]
        # a §3.6 multi-sig token is root-only + fully verified above; anywhere else → reject.
        if {[is_multisig $current]} {
            if {$i != $n-1} { set good 0 }
            continue
        }
        # signature: signer == granter, verify against granter identity.
        set gh [::entity::core::entity::bytes $current granter]
        if {$gh ne ""} {
            set sgn [find_signature [::entity::core::entity::hash $current] $included]
            set granter [cap_resolve $included $store_h $gh]
            if {$sgn ne "" && $granter ne ""} {
                set signer [::entity::core::entity::bytes $sgn signer]
                if {!($signer ne "" && $signer eq $gh && [::entity::core::identity::verify_signature $sgn $granter])} {
                    set good 0
                }
            } else { set good 0 }
        } else { set good 0 }
        # grantee resolution → 401 carve-out.
        set geh [::entity::core::entity::bytes $current grantee]
        if {$geh ne ""} {
            if {[cap_resolve $included $store_h $geh] eq ""} {
                throw {ENTITY_CORE UNRESOLVABLE_GRANTEE grantee} "capability grantee unresolvable"
            }
        } else {
            throw {ENTITY_CORE UNRESOLVABLE_GRANTEE grantee} "capability grantee absent"
        }
        # temporal validity.
        #
        # CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
        # created_at is MALFORMED and must be refused outright. This has to run BEFORE
        # the two range checks below, because those are what the ambiguity defeats — see
        # temporal_fields_representable for the mechanism, which in Tcl is the ARITHMETIC
        # form rather than the null-collapse one.
        if {![temporal_fields_representable $current]} { set good 0 }
        set now [now_ms]
        set nb [::entity::core::entity::uint $current not_before]
        if {$nb ne "" && $now < $nb} { set good 0 }
        set ex [::entity::core::entity::uint $current expires_at]
        if {$ex ne "" && $ex < $now} { set good 0 }
        # delegation link.
        if {$i < $n-1} {
            set parent [lindex $chain [expr {$i+1}]]
            set child_peer [_link_granter_peer $included $store_h $local_peer $current]
            set parent_peer [_link_granter_peer $included $store_h $local_peer $parent]
            if {$child_peer eq "" || $parent_peer eq ""} {
                set good 0
            } else {
                set pg [::entity::core::entity::bytes $parent grantee]
                set cg [::entity::core::entity::bytes $current granter]
                if {!($pg ne "" && $cg ne "" && $pg eq $cg
                    && [_is_attenuated $local_peer $child_peer $parent_peer $current $parent]
                    && [_check_delegation_caveats $parent $current $i])} {
                    set good 0
                }
            }
        }
    }
    return [expr {$good ? "ALLOW" : "DENY"}]
}

proc ::entity::core::capability::_revoke_marker {local_peer store_h h} {
    return [::entity::core::store::get_at $store_h "/$local_peer/system/capability/revocations/[binary encode hex $h]"]
}

proc ::entity::core::capability::is_revoked {local_peer store_h capability included} {
    set c [_collect_chain $capability $included $store_h]
    if {[dict get $c ok]} {
        set root_hash [::entity::core::entity::hash [lindex [dict get $c chain] end]]
    } else {
        set root_hash [::entity::core::entity::hash $capability]
    }
    return [expr {[_revoke_marker $local_peer $store_h [::entity::core::entity::hash $capability]] ne ""
        || [_revoke_marker $local_peer $store_h $root_hash] ne ""}]
}

# ── §5.2 verify-request (3-way verdict) ──
# → ALLOW / AUTHN_FAIL / AUTHZ_DENY / CHAIN_TOO_DEEP
proc ::entity::core::capability::verify_request {local_peer store_h env} {
    set exec [::entity::core::envelope::root $env]
    set included [::entity::core::envelope::included $env]
    set sgn [find_signature [::entity::core::entity::hash $exec] $included]
    if {$sgn eq ""} { return AUTHN_FAIL }
    set author_h [::entity::core::entity::bytes $exec author]
    set signer [::entity::core::entity::bytes $sgn signer]
    if {!($signer ne "" && $author_h ne "" && $signer eq $author_h)} { return AUTHN_FAIL }
    set author [::entity::core::envelope::included_get $env $author_h]
    if {$author eq ""} { return AUTHN_FAIL }
    if {![::entity::core::identity::verify_signature $sgn $author]} { return AUTHN_FAIL }
    set ch [::entity::core::entity::bytes $exec capability]
    set cap [expr {$ch ne "" ? [::entity::core::envelope::included_get $env $ch] : ""}]
    if {$cap eq ""} { return AUTHZ_DENY }
    # §4.10(b): a chain exceeding max depth → 400 chain_depth_exceeded BEFORE the walk.
    if {[chain_exceeds_depth $store_h $cap $included]} { return CHAIN_TOO_DEEP }
    if {[verify_capability_chain $local_peer $store_h $cap $included] eq "DENY"} { return AUTHZ_DENY }
    set grantee [::entity::core::entity::bytes $cap grantee]
    if {!($grantee ne "" && $grantee eq $author_h)} { return AUTHZ_DENY }
    if {[is_revoked $local_peer $store_h $cap $included]} { return AUTHZ_DENY }
    return ALLOW
}
