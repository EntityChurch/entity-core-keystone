# entity-core-protocol-tcl — 0.8.2.25 sweep unit gate (offline, no network).
#
# Pins the six pieces the 0.8.2.20 -> .25 arc landed on this peer, at the UNIT level.
# The wire-level half -- "a pre-admission refusal reaches the socket" -- cannot be asked
# here and is driven by output/scratch/preadm411.c against the peer's own run-s4.sh
# launch; what this file pins is the MAPPING ("the code belongs to the cause") plus the
# §3.3 ladder, §6.3's path check, the §5.4 sentinel's scoping and §5.5a's scope typing.
#
# EVERY PREDICATE CASE CARRIES AN ACCEPT ASSERTION. A deny-only test of an authorization
# predicate is indistinguishable from one asserting False == False, and the accept case is
# what validates the FIXTURE: a grant fixture built the wrong way parses empty, the
# predicate then denies everything, and every deny case passes for free.
#
# Usage (in container): LD_LIBRARY_PATH=<codec-build> tclsh test/sweep_0_8_2_25.tcl <shim.so>

set here [file dirname [file normalize [info script]]]
set root [file dirname $here]
load [lindex $argv 0] Entitycorecrypto
source $root/src/entity_core.tcl

set ::pass 0; set ::fail 0
proc check {name cond} {
    if {[uplevel 1 [list expr $cond]]} { incr ::pass; puts "  \[PASS\] $name" } \
    else       { incr ::fail; puts "  \[FAIL\] $name  <- $cond" }
}

namespace import ::entity::core::ecf::*
set C ::entity::core::capability
set H ::entity::core::handlers
set LP "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg"   ;# a syntactically valid peer_id

# ── fixtures ──────────────────────────────────────────────────────────────────
# An EXECUTE carrying an explicit `resource` map. $targets/$excl are Tcl lists; passing
# the sentinel string NORESOURCE omits the whole `resource` field, which is the input
# §3.3 makes DIFFERENT from a present resource whose targets all drop out.
proc mkexec {targets {excl ""}} {
    set kv [list request_id [tstr r1] uri [tstr system/tree] operation [tstr get] \
        params [::entity::core::entity::to_cbor [::entity::core::wire::empty_params]]]
    if {$targets ne "NORESOURCE"} {
        set rkv [list targets [text_array $targets]]
        if {$excl ne ""} { lappend rkv exclude [text_array $excl] }
        lappend kv resource [::entity::core::ecf::map {*}$rkv]
    }
    return [::entity::core::entity::make system/protocol/execute [::entity::core::ecf::map {*}$kv]]
}

# A capability token carrying ONE grant. Each dimension is {include-list exclude-list}.
proc mktoken {handlers operations resources} {
    proc _sc {pair} {
        return [::entity::core::ecf::map \
            include [text_array [lindex $pair 0]] exclude [text_array [lindex $pair 1]]]
    }
    set g [::entity::core::ecf::map \
        handlers [_sc $handlers] operations [_sc $operations] resources [_sc $resources]]
    return [::entity::core::entity::make system/capability/token [::entity::core::ecf::map \
        grants [tarray [list $g]]]]
}

# ══════════════════════════════════════════════════════════════════════════════
# §3.3 / §5.2 effective_targets (0.8.2.20/.21, N11)
# ══════════════════════════════════════════════════════════════════════════════
puts "-- effective_targets (3.3/5.2) --"

# THE NON-LOSSY PROJECTION [MUST] (0.8.2.25 N11) — and on THIS substrate the pair is not
# merely tidier, it is the only way to have the discriminator at all: in Tcl an empty list
# and an absent value are THE SAME VALUE (the empty string), so a proc returning only the
# survivors could not tell its caller which empty it meant.
check "absent resource -> had_resource 0" \
    {[lindex [$C\::effective_targets $LP [mkexec NORESOURCE]] 0] == 0}
check "present resource -> had_resource 1 (even when every target drops)" \
    {[lindex [$C\::effective_targets $LP [mkexec {app/a} {app/a}]] 0] == 1}
check "self-excluded request -> empty survivor list" \
    {[llength [lindex [$C\::effective_targets $LP [mkexec {app/a} {app/a}]] 1]] == 0}
check "the two empties are DISTINGUISHABLE" \
    {[lindex [$C\::effective_targets $LP [mkexec NORESOURCE]] 0]
     ne [lindex [$C\::effective_targets $LP [mkexec {app/a} {app/a}]] 0]}

# Survivors in the caller's OWN SPELLING (0.8.2.21), not canonicalized — the value flows
# on to the store lookup, which canonicalizes for itself.
check "survivor keeps the caller's raw spelling" \
    {[lindex [lindex [$C\::effective_targets $LP [mkexec {app/a app/b} {app/b}]] 1] 0] eq "app/a"}
check "the non-excluded target survives, the excluded one does not" \
    {[lindex [$C\::effective_targets $LP [mkexec {app/a app/b} {app/b}]] 1] eq "app/a"}
check "a wildcard caller exclude carves out its whole subtree" \
    {[llength [lindex [$C\::effective_targets $LP [mkexec {app/a app/b} {app/*}]] 1]] == 0}

# THE CALLER-EXCLUDE ARM IS FAIL-OPEN on an unmatchable pattern — §5.4 rules it separately
# from the GRANT arm, which is fail-CLOSED (see the sentinel block below). The asymmetry
# is 0.8.2.21's whole point and it is INHERITED here rather than restated: canonicalize
# answers the sentinel, matches_pattern then answers 0, and the target simply survives.
check "unmatchable caller exclude carves out NOTHING (fail-open)" \
    {[lindex [$C\::effective_targets $LP [mkexec {app/a} {../nope}]] 1] eq "app/a"}

# ══════════════════════════════════════════════════════════════════════════════
# §6.3 check_path_permission (0.8.2.20/.22/.23)
# ══════════════════════════════════════════════════════════════════════════════
puts "-- check_path_permission (6.3) --"
set tok [mktoken {{system/tree} {}} {{get} {}} {{app/*} {}}]
set p_ok   "/$LP/app/a"
set p_deny "/$LP/other/a"

# THE ACCEPT CASE IS THE FIXTURE VALIDATOR. Without it every deny below passes against a
# grant that parsed empty.
check "ACCEPT: all three dimensions match" \
    {[$C\::check_path_permission $LP get $p_ok $tok "system/tree"] == 1}
# One deny per DIMENSION: a single deny cannot distinguish "the predicate checks the
# dimension I care about" from "the predicate denies".
check "DENY on the resources dimension" \
    {[$C\::check_path_permission $LP get $p_deny $tok "system/tree"] == 0}
check "DENY on the operations dimension (id-scope)" \
    {[$C\::check_path_permission $LP put $p_ok $tok "system/tree"] == 0}
check "DENY on the handlers dimension" \
    {[$C\::check_path_permission $LP get $p_ok $tok "system/other"] == 0}

# An empty resources.include is a LEGAL grant shape (§5.2: handlers that touch no tree
# paths) and DENIES every path here.
check "empty resources.include denies every path" \
    {[$C\::check_path_permission $LP get $p_ok [mktoken {{system/tree} {}} {{get} {}} {{} {}}] \
        "system/tree"] == 0}
# A malformed path canonicalizes to NEVER_MATCH, which matches no grant, so it falls
# through to DENY rather than being matched against anything.
check "malformed path falls through to DENY, not to a throw" \
    {[$C\::check_path_permission $LP get "../escape" [mktoken {{system/tree} {}} {{get} {}} {{*} {}}] \
        "system/tree"] == 0}
# THREE DIMENSIONS, NOT FOUR: `peers` is not consulted (the path is local by construction
# here; §6.3's signature names only handlers, operations and resources). A grant whose
# `peers` dimension excludes this very peer still authorizes the path.
check "the `peers` dimension is NOT consulted (three dimensions, not four)" \
    {[$C\::check_path_permission $LP get $p_ok \
        [::entity::core::entity::make system/capability/token [::entity::core::ecf::map \
            grants [tarray [list [$C\::grant {system/tree} {app/*} {get} [list "someotherpeer"]]]]]] \
        "system/tree"] == 1}

# ══════════════════════════════════════════════════════════════════════════════
# §5.4 sentinel scoped to PATH-SCOPE (0.8.2.24, N2/N3) — RULE B
# ══════════════════════════════════════════════════════════════════════════════
puts "-- 5.4 sentinel is path-scope only (0.8.2.24) --"
proc sc {incl excl} { return [dict create incl $incl excl $excl] }

# The symptom of the UN-scoped form: an `operations` exclude that PATH-canonicalizes to
# the sentinel -- an ordinary namespaced operation name -- denied the WHOLE dimension.
# Over-denial, invisible on any well-formed grant.
check "id-scope: a star-slash operations exclude does NOT deny the dimension" \
    {[$C\::matches_scope $LP "get" [sc {*} {*/apply}] id] == 1}
check "id-scope ACCEPT control: no exclude at all" \
    {[$C\::matches_scope $LP "get" [sc {*} {}] id] == 1}
check "id-scope still EXCLUDES a literal that matches" \
    {[$C\::matches_scope $LP "get" [sc {*} {get}] id] == 0}
# path-scope keeps the fail-CLOSED reading: an unmatchable GRANT exclude excludes
# everything (0.8.2.21).
check "path-scope: an unmatchable exclude still denies the dimension" \
    {[$C\::matches_scope $LP "app/a" [sc {*} {../nope}] path] == 0}
check "path-scope ACCEPT control: a matchable exclude that misses" \
    {[$C\::matches_scope $LP "app/a" [sc {*} {other/*}] path] == 1}

# ══════════════════════════════════════════════════════════════════════════════
# §5.5a scope_subset typed by scope kind (F50, 0.8.2.16) — RULE E
# ══════════════════════════════════════════════════════════════════════════════
puts "-- 5.5a scope_subset is typed (F50 / 0.8.2.16) --"
# entity-core-formalization's K-7 differential: 2 of 64 include pairs and 2 of 64 exclude
# pairs disagree between the literal and the canonicalizing readings, fail-closed, with a
# 16-pair control alphabet reporting 0 -- which is why every hand-tried example missed it.
# Both witnesses are reproduced here, on the ID arm where the literal matcher binds.
#
# `/tree/get` under a parent `*`: the id-scope matcher's bare-star arm answers true and so
# does the path arm, so this pair AGREES and is the control that proves the alphabet is
# live rather than that the test is vacuous.
check "id-scope subset: child /tree/get is inside parent *" \
    {[$C\::grant_subset $LP $LP $LP \
        [$C\::parse_grant [$C\::grant {*} {*} {/tree/get}]] \
        [$C\::parse_grant [$C\::grant {*} {*} {*}]]] == 1}
# The divergence: under the CANONICALIZING reading a child operations include of
# `*/apply` canonicalizes to the NEVER_MATCH sentinel, matches_pattern then answers false
# in EITHER operand, and the subset check REFUSES a child that is plainly inside `*`.
# Under the literal matcher the parent's bare `*` covers it, which is what §3.6 requires.
check "id-scope subset: star-slash-apply is inside parent * (the K-7 witness)" \
    {[$C\::grant_subset $LP $LP $LP \
        [$C\::parse_grant [$C\::grant {*} {*} {*/apply}]] \
        [$C\::parse_grant [$C\::grant {*} {*} {*}]]] == 1}
# DENY control on the same arm, so the two above are not "subset always answers yes".
check "id-scope subset DENY: a child operation outside the parent include" \
    {[$C\::grant_subset $LP $LP $LP \
        [$C\::parse_grant [$C\::grant {*} {*} {put}]] \
        [$C\::parse_grant [$C\::grant {*} {*} {get}]]] == 0}
# THE TYPING HAS TWO HALVES AND THE WITNESSES ABOVE ONLY MEASURE ONE. Found by planting:
# forcing the MATCHER to the path flavour while leaving the FRAME on id left every case
# above green, because for `*/apply` vs `*` the two matchers AGREE (both take the bare-star
# arm) and the whole divergence comes from CANONICALIZATION manufacturing the sentinel. So
# a pair is needed whose canonical forms are identical and whose MATCHERS disagree:
# `/*/get` is a §5.4 peer-wildcard PATTERN under the path matcher and an ordinary literal
# under the id matcher, and canonicalize is the identity on both operands (each already
# starts with "/"). §3.6: "An implementation on the canonicalizing reading is
# non-conformant and MUST adopt the literal matcher."
check "id-scope subset MATCHER arm: /a/get is NOT literally inside /*/get" \
    {[$C\::grant_subset $LP $LP $LP \
        [$C\::parse_grant [$C\::grant {*} {*} {/a/get}]] \
        [$C\::parse_grant [$C\::grant {*} {*} {/*/get}]]] == 0}
check "path-scope subset MATCHER arm: /a/get IS inside the pattern /*/get" \
    {[$C\::grant_subset $LP $LP $LP \
        [$C\::parse_grant [$C\::grant {/a/get} {*} {*}]] \
        [$C\::parse_grant [$C\::grant {/*/get} {*} {*}]]] == 1}

# The PATH arm keeps the canonicalizing reading -- handlers and resources are path-scope.
check "path-scope subset: child app/a is inside parent app/*" \
    {[$C\::grant_subset $LP $LP $LP \
        [$C\::parse_grant [$C\::grant {*} {app/a} {*}]] \
        [$C\::parse_grant [$C\::grant {*} {app/*} {*}]]] == 1}
check "path-scope subset DENY: child outside the parent resource include" \
    {[$C\::grant_subset $LP $LP $LP \
        [$C\::parse_grant [$C\::grant {*} {other/a} {*}]] \
        [$C\::parse_grant [$C\::grant {*} {app/*} {*}]]] == 0}

# ══════════════════════════════════════════════════════════════════════════════
# §4.11 / §5.2a — the code belongs to the CAUSE (0.8.2.24 N4/N5, 0.8.2.25) — RULE C/D
# ══════════════════════════════════════════════════════════════════════════════
puts "-- 4.11 pre-admission: the code belongs to the cause --"
proc refusal {ec} { return [::entity::core::wire::pre_admission_refusal $ec] }

check "over-limit prefix -> 413 payload_too_large" \
    {[refusal {ENTITY_CORE WIRE payload_too_large}] eq {413 payload_too_large {inbound frame exceeds the configured maximum size}}}
# A mis-keyed `included` entry carries NO TAG: its encoding is canonical, what is false is
# the claim the KEY makes, and the remedy non_canonical_ecf selects (*re-encode*) sends an
# honest caller to the wrong layer. §5.2a rules that code "NOT conformant here [MUST]".
check "mis-keyed included entry -> 400 hash_mismatch, NOT non_canonical_ecf" \
    {[lrange [refusal {ENTITY_CORE PROTOCOL included_key_mismatch}] 0 1] eq {400 hash_mismatch}}
check "carried content_hash mismatch -> 400 hash_mismatch" \
    {[lrange [refusal {ENTITY_CORE PROTOCOL content_hash_mismatch}] 0 1] eq {400 hash_mismatch}}
# The tag arm KEEPS non_canonical_ecf: ENTITY-CBOR-ENCODING defines that code for CBOR
# tag-policy violations specifically and still MUSTs it at decode time. Disjoint by CAUSE
# rather than in conflict.
check "a CBOR tag in a data field KEEPS 400 non_canonical_ecf" \
    {[lrange [refusal {ENTITY_CORE TAG_REJECTED {major-type-6 tag}}] 0 1] eq {400 non_canonical_ecf}}
# Everything else that never becomes an Envelope is the framing arm, on which
# non_canonical_ecf is explicitly NOT conformant.
check "non-minimal head -> 400 invalid_request (framing arm)" \
    {[lrange [refusal {ENTITY_CORE NON_CANONICAL_ECF {non-minimal head}}] 0 1] eq {400 invalid_request}}
check "truncated frame -> 400 invalid_request" \
    {[lrange [refusal {ENTITY_CORE WIRE truncated_frame}] 0 1] eq {400 invalid_request}}
check "an unrecognised cause falls through to the framing arm" \
    {[lrange [refusal {ENTITY_CORE WIRE not_a_map}] 0 1] eq {400 invalid_request}}
# THE DIFFERENTIAL: the tag arm and the framing arm must answer DIFFERENT codes, or the
# peer is not classifying, it is just refusing.
check "the tag arm and the framing arm are DISTINGUISHED" \
    {[lindex [refusal {ENTITY_CORE TAG_REJECTED x}] 1]
     ne [lindex [refusal {ENTITY_CORE NON_CANONICAL_ECF x}] 1]}
# Every wire-visible message stays ASCII -- two peers in this cohort have been killed at
# runtime by a non-ASCII byte in an encoded string, on two unrelated compilers, and `io`
# is one of them.
foreach ec {{ENTITY_CORE WIRE payload_too_large} {ENTITY_CORE PROTOCOL included_key_mismatch}
            {ENTITY_CORE TAG_REJECTED x} {ENTITY_CORE WIRE truncated_frame}} {
    check "refusal message is ASCII-only ([lindex $ec 2])" \
        {[regexp {^[\x20-\x7e]*$} [lindex [refusal $ec] 2]]}
}

# ══════════════════════════════════════════════════════════════════════════════
# §3.3 ladder + §6.3 in the tree handler, driven through the handler itself
# ══════════════════════════════════════════════════════════════════════════════
puts "-- 3.3 ladder + 6.3 in the tree handler --"
set peer [::entity::core::peer::create [string repeat "\x37" 32]]
set LP2 [::entity::core::peer::local_peer $peer]
proc ctx {exec {cap ""}} {
    return [dict create exec $exec conn [::entity::core::conn::new] included {} \
        caller_cap $cap env "" handler_pattern "/[::entity::core::peer::local_peer $::peer]/system/tree"]
}
proc status {out} { return [dict get $out status] }
proc rcode {out} {
    return [::entity::core::entity::text [dict get $out result] code]
}
proc treeop {op exec {cap ""}} { return [$::H\::tree $::peer $op [ctx $exec $cap]] }

# RULE G — OPERATION RESOLUTION PRECEDES RESOURCE VALIDATION. The defect this pins is an
# op ladder whose *any-operation, no-resource* arm matches BEFORE the unknown-operation
# arm, so `system/tree:bogusop` with no resource answers a RESOURCE error for an OPERATION
# fault. The differential is the point: the SAME unknown operation must answer 501 with a
# resource AND without one, or the resource ladder is reachable for an unknown op.
check "RULE G: unknown op WITHOUT a resource -> 501" \
    {[status [treeop bogusop [mkexec NORESOURCE]]] == 501}
check "RULE G: unknown op WITH a resource -> 501 (the differential)" \
    {[status [treeop bogusop [mkexec {app/a}]]] == 501}
check "RULE G: and it is the OPERATION code, not a resource code" \
    {[rcode [treeop bogusop [mkexec NORESOURCE]]] eq "unsupported_operation"}
# The companion control, so "501 to everything" cannot satisfy the above vacuously: a
# KNOWN op must still route into the ladder.
check "RULE G control: a KNOWN op still routes (not 501)" \
    {[status [treeop get [mkexec NORESOURCE]]] != 501}

# The §3.3 ladder on `get` — resource-OPTIONAL, BROAD-RESULT (EXTENSION-TREE §2.2a v4.11).
check "get, absent resource -> the root listing at 200" \
    {[status [treeop get [mkexec NORESOURCE]]] == 200}
check "get, PRESENT resource whose every target is self-excluded -> 400 path_required" \
    {[rcode [treeop get [mkexec {app/a} {app/a}]]] eq "path_required"}
check "get, two surviving targets -> 400 ambiguous_resource" \
    {[rcode [treeop get [mkexec {app/a app/b}]]] eq "ambiguous_resource"}
# THE SELECTION MUST COME FROM THE EFFECTIVE SET, NOT targets[0] (0.8.2.20). With app/a
# excluded the survivor is app/b, so the handler must look for app/b -- a peer indexing
# targets[0] reports on app/a instead.
check "get selects from the EFFECTIVE set, never targets\[0\]" \
    {[::entity::core::entity::text [dict get [treeop get [mkexec {app/a app/b} {app/a}]] result] message]
     eq "/$LP2/app/b"}
check "get, a PATTERN target -> 400 malformed_resource" \
    {[rcode [treeop get [mkexec {app/*}]]] eq "malformed_resource"}
check "get, a trailing slash is a LISTING request, not a pattern" \
    {[status [treeop get [mkexec {system/}]]] == 200}

# The §3.3 ladder on `put` — resource-REQUIRED, so BOTH empties answer path_required.
# 0.8.2.20 names answering `ambiguous_resource` for an absent resource as the exact
# inversion it forbids: *supply a resource* is not *disambiguate your request*.
check "put, absent resource -> 400 path_required (NOT ambiguous_resource)" \
    {[rcode [treeop put [mkexec NORESOURCE]]] eq "path_required"}
check "put, self-excluded resource -> 400 path_required" \
    {[rcode [treeop put [mkexec {app/a} {app/a}]]] eq "path_required"}
check "put, two surviving targets -> 400 ambiguous_resource" \
    {[rcode [treeop put [mkexec {app/a app/b}]]] eq "ambiguous_resource"}
check "put, a PATTERN target -> 400 malformed_resource" \
    {[rcode [treeop put [mkexec {app/*}]]] eq "malformed_resource"}

# §6.3's path check AT THE HANDLER. The caller's own exclude vacates the dispatch-level
# check, so this is the only thing standing between the caller and the path.
set cap_ok [mktoken {{*} {}} {{*} {}} {{app/*} {}}]
check "6.3 ACCEPT: a covered path is not refused by the path check" \
    {[status [treeop get [mkexec {app/a}] $cap_ok]] != 403}
check "6.3 DENY: an UNCOVERED path -> 403 capability_denied" \
    {[rcode [treeop get [mkexec {other/a}] $cap_ok]] eq "capability_denied"}
check "6.3 DENY on put as well as get" \
    {[rcode [treeop put [mkexec {other/a}] $cap_ok]] eq "capability_denied"}
# An unauthenticated / internal context has no caller to narrow and is NOT filtered.
check "no caller capability -> the path check does not fire" \
    {[status [treeop get [mkexec {other/a}]]] == 404}

# ══════════════════════════════════════════════════════════════════════════════
# §6.3 listing filter (0.8.2.21/.22)
# ══════════════════════════════════════════════════════════════════════════════
puts "-- 6.3 listing filter (0.8.2.21/.22) --"
set store [::entity::core::peer::store $peer]
foreach seg {qA qB qC} {
    ::entity::core::store::bind $store "/$LP2/lst/$seg" \
        [::entity::core::entity::make primitive/string [tstr $seg]]
}
proc listing_of {out} {
    set d [::entity::core::entity::data [dict get $out result]]
    set names {}
    foreach {k v} [entries [::entity::core::ecf::mapfield $d entries]] { lappend names [lindex $k 1] }
    return [list [lsort $names] [::entity::core::ecf::uint $d count]]
}
# THE UNFILTERED CONTROL, and it is what makes the filtered case falsifiable: if the
# directory get does not work at all, "qB absent" is the trivial truth and measures
# nothing.
set all [listing_of [treeop get [mkexec {lst/}]]]
check "listing control: all three entries visible with no caller capability" \
    {[lindex $all 0] eq {qA qB qC} && [lindex $all 1] == 3}

set cap_x [mktoken {{*} {}} {{*} {}} {{lst/*} {lst/qB}}]
set filt [listing_of [treeop get [mkexec {lst/}] $cap_x]]
check "listing filter: an entry the caller's own capability EXCLUDES is omitted" \
    {[lindex $filt 0] eq {qA qC}}
# `count` FOLLOWING THE SOURCE TOTAL IS THE DISCLOSURE BY ITSELF -- it tells the caller how
# many bindings exist under a prefix its capability does not cover.
check "listing filter: `count` reflects the FILTERED total, not the source tree's" \
    {[lindex $filt 1] == 2}
# An include-narrowing filter, not only an exclude: the same rule has to hold when the
# grant simply does not reach the sibling.
set cap_n [mktoken {{*} {}} {{*} {}} {{lst/qA} {}}]
set filt2 [listing_of [treeop get [mkexec {lst/}] $cap_n]]
check "listing filter: narrowing the INCLUDE omits the uncovered entries too" \
    {[lindex $filt2 0] eq {qA} && [lindex $filt2 1] == 1}
#
# NOT DRIVEN, and recorded rather than asserted with a case that would pass either way:
# §6.3's "the DIRECTORY itself is deliberately not checked". Through this handler a grant
# covering only `lst/qA` still yields a listing OF `lst/` (the case directly above proves
# the filter runs, not that the prefix is unchecked), and a grant covering `lst/` cannot
# distinguish a prefix-checking filter from a correct one. Separating the two needs a
# caller whose grant covers children but NOT the node above them AND a dispatch chain that
# lets the request reach the handler -- and §5.2 refuses that request one layer earlier.
# The case above (`lst/qA` only) is the closest observable approximation: it reaches the
# handler because this test drives the handler directly, and a prefix-checking filter
# would answer an EMPTY listing there rather than {qA}. That is evidence, not a proof.

puts "\n=== sweep 0.8.2.25: $::pass pass / $::fail fail ==="
# ASSERT THE COUNT, not merely that the failure list is empty: a gate that examined zero
# things prints the same word as one that examined every case.
if {$::pass + $::fail < 61} {
    puts "FAIL: only [expr {$::pass + $::fail}] cases executed; the suite lost cases"
    exit 1
}
exit [expr {$::fail ? 1 : 0}]
