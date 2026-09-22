# Capability system (L3) — the §5 verification core: pattern matching (§5.4), request
# verification (§5.2 verify_request / check_permission), delegation-chain verification
# (§5.5), attenuation (§5.6), delegation caveats (§5.7), revocation (§5.1), and the §3.6
# M3 K-of-N multi-signature root. A faithful port of Zig capability.zig (derived from the
# §5 pseudocode); independent of peer.jl (depends only on Model/Identity/Store), the same
# layering the Zig original uses.
#
# Verdicts are Julia Symbols (the idiomatic tagged enum): `:allow`/`:deny` for the §5.10
# Layer-1 decision; the request verdict is 4-way — `:authn_fail`→401, `:authz_deny`→403,
# `:chain_too_deep`→400 chain_depth_exceeded, `:allow`→dispatch — plus a distinct
# `:unresolvable` grantee carve-out (§5.5 → 401). This realises the §5.2a verdict-to-status
# enumeration (auth-class 401 vs authz-class 403) the cohort settled.
module Capability

using ..Cbor: CborMap
using ..Model: Entity, Envelope, efield, textfield, bytesfield, uintfield, mapget, included_get
using ..Identity: verify_signature, peerid_of_pubkey
using ..Store: ContentStore, store_get, store_at
using ..Base58: base58decode

export verify_request, check_permission, granter_frame, resolve, find_signature
export matches_pattern, canonicalize, extract_peer, grant_subset_local, grants_of_token
export peer_relative_of, grant_path_for, target_minted_peers_relaxation
export check_outbound_sub_dispatch, verify_capability_chain_rooted_at
export effective_targets, check_path_permission, matches_scope, matches_id_pattern
export scope_subset, grant_subset, ScopeKind, ID_SCOPE, PATH_SCOPE, NEVER_MATCH, Scope, Grant
export temporal_fields_representable, add_ttl

const UINT64_CEILING = big(1) << 64

"""
§6.2 CAP-6a: true when every temporal field on a RECEIVED token is either absent
(legal) or representable as a uint64.

This is the reader-side half of CAP-6 and it is where a peer fails OPEN. Julia's
fail-open is the ARITHMETIC one, not the null-collapse one, and the distinction
matters because the grep that catches the other misses this: `uintfield` is
`v isa Integer ? v : nothing`, so it returns ANY integer, negative included. The
expiry check therefore did NOT skip — it RAN and returned the wrong answer. For a
negative not_before, `t < nb` is simply false and the capability passed. No
`nothing`, no skip, nothing an Option-shaped audit would find.

Julia promotes to BigInt rather than wrapping, so the >2^64 half is likewise a
DELIBERATE range check rather than an overflow trap.

An absent field stays legal and is NOT rejected here. Refusal must be the §5.2
capability_denied disposition, never a decode-layer drop or a transport close.
"""
function temporal_fields_representable(tok::Entity)::Bool
    for key in ("expires_at", "not_before", "created_at")
        v = efield(tok, key)
        v === nothing && continue          # absent is legal
        (v isa Integer) || return false     # present but not an integer => malformed
        (v >= 0 && v < UINT64_CEILING) || return false
    end
    return true
end

"""
§5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp relative to
`created_at`. Rule 3: a conversion that is not representable is treated as ABSENT
(`nothing`) exactly as a null term is — it MUST NOT wrap and MUST NOT saturate to a
representable maximum, since saturation manufactures expires_at == 2^64-1, a finite
bound no reader can distinguish from a deliberate one. Julia promotes rather than
wrapping, so this is a deliberate range check.

`ttl == 0` is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
yielding `created_at` (expire immediately). The absent field is the only "no bound"
spelling, and falling out of the arithmetic is what keeps the two from collapsing.
"""
function add_ttl(created_at::Integer, ttl::Integer)
    ttl < 0 && return nothing
    sum = big(created_at) + big(ttl)
    sum >= UINT64_CEILING ? nothing : sum
end

const MAX_CHAIN_DEPTH = 64

now_ms() = round(Int, time() * 1000)

# ── entity/value resolution ───────────────────────────────────────────────────────────
"""Resolve an entity by content_hash: envelope `included` first, then the store."""
function resolve(env::Envelope, st::ContentStore, h::AbstractVector{UInt8})
    e = included_get(env, h)
    e !== nothing && return e
    return store_get(st, h)
end

"""Find a `system/signature` in `included` targeting `target_hash`."""
function find_signature(env::Envelope, target_hash::AbstractVector{UInt8})
    for (_, e) in env.included
        if e.typ == "system/signature"
            t = bytesfield(e, "target")
            t !== nothing && t == target_hash && return e
        end
    end
    return nothing
end

# ── scope / grant parsing (borrow into the entity's value tree) ───────────────────────
struct Scope
    incl::Vector{String}
    excl::Vector{String}
end
struct Grant
    handlers::Scope
    resources::Scope
    operations::Scope
    peers::Union{Nothing,Scope}
end

function text_list(v)::Vector{String}
    v isa AbstractVector || return String[]
    out = String[]
    for it in v
        it isa AbstractString && push!(out, String(it))
    end
    return out
end

function bytes_list(v)::Vector{Vector{UInt8}}
    v isa AbstractVector || return Vector{UInt8}[]
    out = Vector{UInt8}[]
    for it in v
        it isa AbstractVector{UInt8} && push!(out, Vector{UInt8}(it))
    end
    return out
end

function parse_scope(c)::Scope
    c isa CborMap || return Scope(String[], String[])
    return Scope(text_list(mapget(c, "include")), text_list(mapget(c, "exclude")))
end

function scope_of(grant::CborMap, key::AbstractString)::Scope
    s = mapget(grant, key)
    s === nothing && return Scope(String[], String[])
    return parse_scope(s)
end

function parse_grant(c::CborMap)::Grant
    peers = mapget(c, "peers")
    return Grant(scope_of(c, "handlers"), scope_of(c, "resources"), scope_of(c, "operations"),
                 peers === nothing ? nothing : parse_scope(peers))
end

"""Parse the grant array of a capability token → Vector{Grant}."""
function grants_of_token(token::Entity)::Vector{Grant}
    arr = efield(token, "grants")
    arr isa AbstractVector || return Grant[]
    out = Grant[]
    for g in arr
        g isa CborMap && push!(out, parse_grant(g))
    end
    return out
end

# ── §5.4 pattern matching ─────────────────────────────────────────────────────────────
function is_peer_id(seg::AbstractString)::Bool
    length(seg) < 46 && return false
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    for c in seg
        occursin(c, alpha) || return false
    end
    return true
end

"""URI normalization (§1.4): strip an `entity://` scheme to `/…`."""
function normalize_uri(uri::AbstractString)::String
    startswith(uri, "entity://") && return "/" * uri[length("entity://")+1:end]
    return String(uri)
end

"""The unmatchable value (0.8.2.20). Unreachable as a canonical path by CONSTRUCTION:
its first segment cannot be a peer_id, since `is_peer_id` requires >= 46 Base58
characters and `-` is outside the Base58 alphabet."""
const NEVER_MATCH = "/never-match"

"""Resolve peer-relative paths to absolute `/{local}/…` form.

TOTAL (0.8.2.20): the return domain is "a canonical path OR `NEVER_MATCH`". The two
reserved arms were ABSENT here — `../x` came back as `/{local}/../x`, which matched
nothing, so a grant exclude carrying it carved out nothing and the grant was silently
wider than its author wrote (measured on the wire 2026-09-14). A non-match is the
desired outcome in an INCLUDE and the opposite of it in an EXCLUDE."""
function canonicalize(local_peer::AbstractString, path::AbstractString)::String
    (startswith(path, "./") || startswith(path, "../")) && return NEVER_MATCH
    startswith(path, "*/") && return NEVER_MATCH
    startswith(path, "/") && return String(path)
    return "/$(local_peer)/$(path)"
end

"""AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an exclude
(carves out nothing), so the reading is chosen where the POSITION is known and
`matches_pattern` stays uniform over its operands.

EVERY CALL SITE MUST GUARD IT ON PATH-SCOPE (0.8.2.24, N2/N3). This used to be asked of
every dimension, transcribing §5.2's loop before that loop grew its type dispatch.
`NEVER_MATCH` is a §5.4 PATH-canonicalization sentinel and has no meaning on an id-scope
dimension, whose patterns are literal identifiers that §5.2's own id-scope arm forbids
putting through the §5.4 transforms. Asking it outside the type dispatch ran an id
pattern through those transforms purely to classify it and then DENIED THE WHOLE
DIMENSION on a property unrelated to whether the exclude carves anything out: an
`operations` exclude naming an ordinary namespaced operation with a leading star-slash
canonicalized to the sentinel and denied every operation. Over-denial, and invisible on
any well-formed grant."""
function exclude_unmatchable(frame::AbstractString, excl::Vector{String})::Bool
    for p in excl
        canonicalize(frame, p) == NEVER_MATCH && return true
    end
    return false
end

"""Both `path` and `pattern` MUST already be canonical (absolute)."""
function matches_pattern(path::AbstractString, pattern::AbstractString)::Bool
    # NEVER_MATCH never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
    # rule rather than a property of the string: the line below returns true for a
    # bare "*", so safety must not rest on a value merely looking unmatchable.
    (path == NEVER_MATCH || pattern == NEVER_MATCH) && return false
    pattern == "*" && return true
    if startswith(pattern, "/*/")
        remainder = pattern[4:end]           # after "/*/"
        length(path) < 1 && return false
        i = findnext('/', path, 2)           # first '/' after the leading one
        i === nothing && return false
        return matches_pattern(path[i+1:end], remainder)
    end
    if length(pattern) >= 2 && endswith(pattern, "/*")
        prefix = pattern[1:end-1]            # keep the trailing '/'
        return startswith(path, prefix)
    end
    return path == pattern
end

function covered(frame::AbstractString, pats::Vector{String}, v::AbstractString)::Bool
    for p in pats
        matches_pattern(v, canonicalize(frame, p)) && return true
    end
    return false
end

"""
Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every call
site — no default — so a new one cannot inherit the wrong matcher silently, which is
exactly the F40 defect.
"""
@enum ScopeKind ID_SCOPE PATH_SCOPE

"""
§5.2 id-scope match (0.8.1, F40) — `operations` and `peers`. Literal comparison with
exactly two wildcard forms: bare `*` and a trailing slash-star segment-prefix. None of
the §5.4 path transforms apply, so a pattern carrying path syntax is matched as a literal
string: a non-match, never a fault.
"""
function matches_id_pattern(value::AbstractString, pattern::AbstractString)::Bool
    pattern == "*" && return true
    if length(pattern) >= 2 && endswith(pattern, "/*")
        return startswith(value, pattern[1:end-1])
    end
    return value == pattern
end

function covered_id(pats::Vector{String}, value::AbstractString)::Bool
    for p in pats
        matches_id_pattern(value, p) && return true
    end
    return false
end

function matches_scope(local_peer::AbstractString, value::AbstractString, s::Scope, kind::ScopeKind)::Bool
    if kind == ID_SCOPE
        # No sentinel guard here, and that is 0.8.2.24's ruling rather than an omission:
        # §5.4 says "a capability carrying an unmatchable PATH-SCOPE pattern is INVALID
        # ... It does NOT reach `operations` or `peers` [MUST]". Under the id-scope
        # grammar every non-star pattern is a literal, and a literal is never
        # structurally unmatchable, so there is nothing here for the sentinel to detect.
        return covered_id(s.incl, value) && !covered_id(s.excl, value)
    end
    exclude_unmatchable(local_peer, s.excl) && return false   # 0.8.2.21 — deny
    cv = canonicalize(local_peer, value)
    covered(local_peer, s.incl, cv) || return false
    return !covered(local_peer, s.excl, cv)
end

# ── §5.2 check_permission ─────────────────────────────────────────────────────────────
first_segment(uri::AbstractString) = begin
    u = startswith(uri, "/") ? uri[2:end] : uri
    i = findfirst('/', u)
    i === nothing ? u : u[1:i-1]
end

function extract_peer(local_peer::AbstractString, uri::AbstractString)::String
    first = first_segment(normalize_uri(uri))
    return is_peer_id(first) ? String(first) : String(local_peer)
end

function resolve_granter_peer_id(env::Envelope, st::ContentStore, cap::Entity)
    gh = bytesfield(cap, "granter")
    gh === nothing && return nothing
    g = resolve(env, st, gh)
    g === nothing && return nothing
    pk = bytesfield(g, "public_key")
    pk === nothing && return nothing
    return peerid_of_pubkey(pk)
end

function check_resource_scope(local_peer::AbstractString, granter_peer::AbstractString, resource, s::Scope)::Bool
    resource isa CborMap || return false
    targets = text_list(mapget(resource, "targets"))
    caller_excl = text_list(mapget(resource, "exclude"))
    isempty(targets) && return false
    # An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
    # target: the coverage test below is correct in isolation and is simply never
    # reached on a sentinel, because matches_pattern answers false.
    exclude_unmatchable(granter_peer, s.excl) && return false
    for tgt in targets
        ct = canonicalize(local_peer, tgt)
        covered(local_peer, caller_excl, ct) && continue          # caller excluded (local frame)
        covered(granter_peer, s.incl, ct) || return false          # not in grant include (granter frame)
        covered(granter_peer, s.excl, ct) && return false          # in grant exclude → deny
    end
    return true
end

"""check_permission gates the wire request at the dispatch authorization boundary
(§5.2 / §3.2.3). `granter_peer` is the §PR-8 canonicalization frame for the cap's
grant resource patterns; every other dimension stays on the local frame."""
function check_permission(local_peer::AbstractString, granter_peer::AbstractString,
                          exec::Entity, token::Entity, handler_pattern::AbstractString)::Symbol
    operation = textfield(exec, "operation"); operation = operation === nothing ? "" : operation
    uri = textfield(exec, "uri"); uri = uri === nothing ? "" : uri
    target_peer = extract_peer(local_peer, uri)
    resource = efield(exec, "resource")
    for g in grants_of_token(token)
        matches_scope(local_peer, operation, g.operations, ID_SCOPE) || continue
        matches_scope(local_peer, handler_pattern, g.handlers, PATH_SCOPE) || continue
        peers = g.peers === nothing ? Scope([String(local_peer)], String[]) : g.peers
        matches_scope(local_peer, target_peer, peers, ID_SCOPE) || continue
        r_ok = resource === nothing ? true : check_resource_scope(local_peer, granter_peer, resource, g.resources)
        r_ok && return :allow
    end
    return :deny
end

# ── §5.5 / §5.6 chain verification + attenuation ──────────────────────────────────────
function link_granter_peer(env::Envelope, st::ContentStore, local_peer::AbstractString, cap::Entity)
    gh = bytesfield(cap, "granter")
    gh === nothing && return String(local_peer)   # multi-sig root (M3) → local frame
    g = resolve(env, st, gh)
    g === nothing && return nothing
    pk = bytesfield(g, "public_key")
    pk === nothing && return nothing
    return peerid_of_pubkey(pk)
end

"""
§5.5a/§5.6 attenuation subset, TYPED BY SCOPE KIND (F50, ruled 0.8.2.16).

§3.6's grammar binds the SCOPE TYPE, not one function: "An implementation on the
canonicalizing reading is non-conformant and MUST adopt the literal matcher." F40 typed
`matches_scope` and this sibling was left on the path matcher for all four dimensions, so
`operations` and `peers` — both id-scope — were compared with §5.4 canonicalization and
wildcard semantics they do not have. The divergence is narrow and FAIL-CLOSED (an include
of a namespaced operation is not covered by a parent bare star under the path matcher,
which widens nothing but refuses legitimate delegation), which is exactly why no
hand-tried example found it.

`kind` has NO DEFAULT and is named at every call site, because a default is how the next
dimension inherits the wrong matcher silently — the original F40 defect.

On the ID_SCOPE arm `child_peer`/`parent_peer` are unused BY CONSTRUCTION: no
canonicalization frame applies to an identifier, so both operands are compared as written.
"""
function scope_subset(child_peer::AbstractString, parent_peer::AbstractString,
                      child::Scope, parent::Scope, kind::ScopeKind)::Bool
    if kind == ID_SCOPE
        for cp in child.incl
            any(pp -> matches_id_pattern(cp, pp), parent.incl) || return false
        end
        for pe in parent.excl
            any(ce -> matches_id_pattern(pe, ce), child.excl) || return false
        end
        return true
    end
    for cp in child.incl
        cc = canonicalize(child_peer, cp)
        found = false
        for pp in parent.incl
            if matches_pattern(cc, canonicalize(parent_peer, pp)); found = true; break; end
        end
        found || return false
    end
    for pe in parent.excl
        cpe = canonicalize(parent_peer, pe)
        found = false
        for ce in child.excl
            if matches_pattern(cpe, canonicalize(child_peer, ce)); found = true; break; end
        end
        found || return false
    end
    return true
end

function grant_subset(local_peer::AbstractString, child_peer::AbstractString, parent_peer::AbstractString,
                      child::Grant, parent::Grant)::Bool
    scope_subset(local_peer, local_peer, child.handlers, parent.handlers, PATH_SCOPE) || return false
    scope_subset(local_peer, local_peer, child.operations, parent.operations, ID_SCOPE) || return false
    scope_subset(child_peer, parent_peer, child.resources, parent.resources, PATH_SCOPE) || return false
    cp = child.peers === nothing ? Scope([String(local_peer)], String[]) : child.peers
    pp = parent.peers === nothing ? Scope([String(local_peer)], String[]) : parent.peers
    return scope_subset(local_peer, local_peer, cp, pp, ID_SCOPE)
end

"""§6.2 local-frame subset (child=parent=local) — the mint-time check."""
grant_subset_local(local_peer::AbstractString, child::Grant, parent::Grant)::Bool =
    grant_subset(local_peer, local_peer, local_peer, child, parent)

"""
§5.2's effective target list (0.8.2.20): the caller's OWN `resource.exclude` removes
entries from the request BEFORE anything else looks at it.

Returns `(survivors, had_resource)`. The survivors come back in the caller's OWN
SPELLING, not canonicalized — 0.8.2.21 is explicit that `effective_targets` yields raw
survivors, and the distinction is load-bearing because the value flows on to the store
lookup, which canonicalizes for itself.

`had_resource` says whether a `resource` was present AT ALL. An ABSENT resource and a
resource whose every target was excluded are different inputs to §3.3, and for a
resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT REQUESTS with different
answers.

THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11): "that
projection MUST NOT be lossy about its own emptiness — narrow when narrowing leaves
something, and retain the raw pair when narrowing would empty it." A function returning
only a list cannot satisfy that: collapsing a one-target self-excluded request to `[]`
deletes the two-empties discriminator before any handler can read it, and the handler's
refusal arm becomes dead code only a WIRE drive can detect.

A TUPLE RATHER THAN `Union{Nothing,Vector}`, because the `nothing`/`[]` collapse N11
forbids is exactly what a nullable return invites at the first `something(x, String[])`.
"""
function effective_targets(local_peer::AbstractString, exec::Entity)::Tuple{Vector{String},Bool}
    r = efield(exec, "resource")
    r isa CborMap || return (String[], false)
    targets = mapget(r, "targets")
    # A `resource` MAP carrying no `targets` key reads ABSENT here, which is what every
    # 0.8.2.25 peer answers and is an OPEN question rather than a settled one: §3.2 says
    # `targets` "MUST contain at least one entry", which makes the shape MALFORMED rather
    # than absent. Nothing in the pinned check set drives it and no disposition is pinned,
    # so the shipped behaviour is HELD rather than changed.
    targets isa AbstractVector || return (String[], false)
    caller_excl = let x = mapget(r, "exclude")
        x isa AbstractVector ? String[String(v) for v in x if v isa AbstractString] : String[]
    end
    survivors = String[]
    for t in targets
        t isa AbstractString || continue
        ct = canonicalize(local_peer, t)
        # The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4's table
        # rules it separately from the grant arm): canonicalize answers NEVER_MATCH and
        # matches_pattern then answers false, so the target simply survives. That
        # asymmetry is 0.8.2.21's whole point and it is INHERITED from the primitives
        # here rather than restated.
        any(x -> matches_pattern(ct, canonicalize(local_peer, x)), caller_excl) && continue
        push!(survivors, String(t))   # RAW, not ct
    end
    return (survivors, true)
end

"""
§6.3's handler-level path check.

IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the enforcement wherever the subject
is derived after dispatch, and the dispatch-level check can be made VACUOUS by
caller-controlled input: a caller who excludes the one target its capability does not
cover removes that target from `check_permission`'s view entirely, and a handler that
then acts on it has authorized nothing.

THREE DIMENSIONS, NOT FOUR. `peers` is not consulted here — the path is local by
construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5 step
3, before any handler runs), and §6.3's signature names only handlers, operations and
resources.

THE FRAME IS `local_peer`, NOT THE GRANTER, AND THAT IS THE SPEC'S OWN SIGNATURE RATHER
THAN A CHOICE. §6.3's block reads
`matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)` — there is
no granter parameter to pass. §5.5a governs chain ATTENUATION, where the subject is a
pattern compared against a parent's pattern; this call site compares a CONCRETE local
path the handler is about to touch.

There is no caller-exclude set at this call site: the subject is a single concrete path
and the caller's exclusions have already been applied in deriving it, so every grant
exclude covering the subject denies — which `matches_scope` already implements,
including 0.8.2.21's sentinel rule.

An empty `resources.include` is a legal grant shape (§5.2) and DENIES every path here,
which is what that note says it should.
"""
function check_path_permission(local_peer::AbstractString, operation::AbstractString,
                               path::AbstractString, token::Entity,
                               handler_pattern::AbstractString)::Bool
    # canonicalize is total and may answer NEVER_MATCH, which matches no grant (§5.4) —
    # so a malformed path falls through to DENY rather than being matched against
    # anything.
    cp = canonicalize(local_peer, path)
    for g in grants_of_token(token)
        matches_scope(local_peer, handler_pattern, g.handlers, PATH_SCOPE) || continue
        matches_scope(local_peer, operation, g.operations, ID_SCOPE) || continue
        matches_scope(local_peer, cp, g.resources, PATH_SCOPE) || continue
        return true
    end
    return false
end

function is_attenuated(local_peer, child_peer, parent_peer, child::Entity, parent::Entity)::Bool
    cg = grants_of_token(child)
    pg = grants_of_token(parent)
    for c in cg
        ok = false
        for p in pg
            if grant_subset(local_peer, child_peer, parent_peer, c, p); ok = true; break; end
        end
        ok || return false
    end
    pe = uintfield(parent, "expires_at")
    ce = uintfield(child, "expires_at")
    (pe !== nothing && ce === nothing) && return false   # child infinite, parent finite
    (pe !== nothing && ce !== nothing && ce > pe) && return false
    return true
end

function check_delegation_caveats(parent::Entity, child::Entity, depth::Integer)::Bool
    caveats = efield(parent, "delegation_caveats")
    caveats isa CborMap || return true
    nd = mapget(caveats, "no_delegation")
    (nd isa Bool && nd) && return false
    md = mapget(caveats, "max_delegation_depth")
    (md isa Integer && depth >= md) && return false
    mt = mapget(caveats, "max_delegation_ttl")
    if mt isa Integer
        ex = uintfield(child, "expires_at")
        cr = uintfield(child, "created_at")
        if ex !== nothing
            (cr !== nothing && ex - cr > mt) && return false
        else
            return false   # infinite child lifetime exceeds any finite limit
        end
    end
    return true
end

# Collect the parent-chain; returns (:ok, chain) / (:too_deep, _) / (:unreachable, _).
function collect_chain(env::Envelope, st::ContentStore, cap::Entity)
    chain = Entity[]
    current = cap
    depth = 0
    while true
        depth > MAX_CHAIN_DEPTH && return (:too_deep, chain)
        push!(chain, current)
        ph = bytesfield(current, "parent")
        ph === nothing && return (:ok, chain)
        nxt = resolve(env, st, ph)
        nxt === nothing && return (:unreachable, chain)
        current = nxt
        depth += 1
    end
end

"""§4.10(b) structural pre-check: true if the authority chain rooted at `cap` exceeds
the max depth (64). Walks parent pointers WITHOUT verifying signatures — depth is purely
structural, gated BEFORE the per-link authz walk so an over-deep chain reports 400
chain_depth_exceeded, distinct from a 403 authz failure. An unreachable parent is NOT a
depth problem (false here; left for the chain walk to deny 403)."""
function chain_exceeds_depth(env::Envelope, st::ContentStore, cap::Entity)::Bool
    current = cap
    depth = 0
    while true
        depth > MAX_CHAIN_DEPTH && return true
        ph = bytesfield(current, "parent")
        ph === nothing && return false
        nxt = resolve(env, st, ph)
        nxt === nothing && return false
        current = nxt
        depth += 1
    end
end

# ── §3.6 M3 multi-signature granter ───────────────────────────────────────────────────
struct MultiGranter
    signers::Vector{Vector{UInt8}}
    threshold::Int
end

"""Parse the multi-granter descriptor iff `granter` is a map (not bytes). Single-sig
(bytes) and absent granters return `nothing`."""
function multi_granter_of(cap::Entity)::Union{Nothing,MultiGranter}
    g = efield(cap, "granter")
    g isa CborMap || return nothing
    signers = bytes_list(mapget(g, "signers"))
    t = mapget(g, "threshold")
    threshold = t isa Integer ? Int(t) : 0
    return MultiGranter(signers, threshold)
end

function has_duplicate_signers(signers::Vector{Vector{UInt8}})::Bool
    for i in 1:length(signers), j in i+1:length(signers)
        signers[i] == signers[j] && return true
    end
    return false
end

function signer_peer_id(env::Envelope, st::ContentStore, h::AbstractVector{UInt8})
    p = resolve(env, st, h)
    p === nothing && return nothing
    pk = bytesfield(p, "public_key")
    pk === nothing && return nothing
    return peerid_of_pubkey(pk)
end

"""verify_multisig_root (§3.6 M3 / §5.5 M4·M6). ALLOW only if the quorum is well-formed
AND a threshold of DISTINCT signers signed the cap's content hash. Structural validation
(M3) precedes signature counting (§3.6 precedence): a malformed quorum is denied on its
structure. Every path returns `:deny` → the dispatcher maps it to 403."""
function verify_multisig_root(env::Envelope, st::ContentStore, local_peer::AbstractString,
                              cap::Entity, mg::MultiGranter)::Symbol
    n = length(mg.signers)
    # §3.6 M3 structure (BEFORE signatures) — root-only; real quorum (n≥2);
    # usable threshold (2 ≤ threshold ≤ n); distinct signers.
    bytesfield(cap, "parent") === nothing || return :deny   # multi-sig is root-only
    n < 2 && return :deny
    (mg.threshold < 2 || mg.threshold > n) && return :deny
    has_duplicate_signers(mg.signers) && return :deny

    # §5.5 M6 root-at-local — the local peer MUST be a quorum member.
    local_in_quorum = false
    for s in mg.signers
        pid = signer_peer_id(env, st, s)
        if pid !== nothing && pid == local_peer
            local_in_quorum = true; break
        end
    end
    local_in_quorum || return :deny

    # temporal validity + grantee resolution.
    t = now_ms()
    nb = uintfield(cap, "not_before"); (nb !== nothing && t < nb) && return :deny
    ex = uintfield(cap, "expires_at"); (ex !== nothing && ex < t) && return :deny
    grantee = bytesfield(cap, "grantee"); grantee === nothing && return :deny
    resolve(env, st, grantee) === nothing && return :deny

    # §5.5 M4 k-of-n — count DISTINCT signers with a valid signature over the cap's
    # content hash; ≥ threshold ⇒ quorum. A duplicate signature does NOT inflate.
    valid = Vector{Vector{UInt8}}()
    for s in mg.signers
        any(v -> v == s, valid) && continue          # distinct-signer count
        signer_peer = resolve(env, st, s)
        signer_peer === nothing && continue
        for (_, sgn) in env.included
            sgn.typ == "system/signature" || continue
            tgt = bytesfield(sgn, "target"); (tgt === nothing || tgt != cap.hash) && continue
            sg = bytesfield(sgn, "signer"); (sg === nothing || sg != s) && continue
            if verify_signature(sgn, signer_peer)
                push!(valid, s); break
            end
        end
    end
    return length(valid) >= mg.threshold ? :allow : :deny
end

"""verify_capability_chain (§5.5). A single-sig root roots at the local peer; a §3.6 M3
multi-sig root (root-only) passes k-of-n quorum. Returns `:allow`/`:deny`/`:unresolvable`
(the §5.5 grantee-resolution 401 carve-out)."""
function verify_capability_chain(env::Envelope, st::ContentStore, local_peer::AbstractString,
                                 capability::Entity)::Symbol
    return verify_capability_chain_rooted_at(env, st, local_peer, local_peer, capability)
end

"""`verify_capability_chain` with the expected ROOT granter named separately from the
verifying peer.

§1.4's PD-2 presented-authority arm needs this: the credential it evaluates is minted by
the TARGET peer, so root-trust is relaxed away from the local peer — and every other
clause (per-link signatures, grantee resolution, temporal validity, attenuation, caveats)
is unchanged. Parameterized rather than forked because a second copy of a chain walk is a
second copy that drifts.

A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When `root_peer`
differs from `local_peer` the quorum arm is REFUSED outright rather than verified: *minted
by the target* means the target SOLELY minted it, and a K-of-N root is a GROUP's
authority — its co-signers authorized it too. Accepting it would let any one signer's
target confer the whole group's grant, which is E3/F66's over-acceptance. §5.5's M6 also
requires the LOCAL peer in the signer set, so the quorum arm has no meaning in a foreign
frame even on its own terms."""
function verify_capability_chain_rooted_at(env::Envelope, st::ContentStore,
                                           local_peer::AbstractString, root_peer::AbstractString,
                                           capability::Entity)::Symbol
    status, chain = collect_chain(env, st, capability)
    status == :ok || return :deny   # too_deep / unreachable → deny (depth pre-checked separately)
    root = chain[end]
    root_ok = begin
        mg = multi_granter_of(root)
        if mg !== nothing
            root_peer == local_peer && verify_multisig_root(env, st, local_peer, root, mg) == :allow
        else
            gh = bytesfield(root, "granter")
            if gh === nothing
                false
            else
                g = resolve(env, st, gh)
                if g === nothing
                    false
                else
                    pk = bytesfield(g, "public_key")
                    pk === nothing ? false : peerid_of_pubkey(pk) == root_peer
                end
            end
        end
    end
    root_ok || return :deny

    n = length(chain)
    t = now_ms()
    for (i, current) in enumerate(chain)
        # §3.6 M3 multi-sig is root-only, fully verified above. Off-root → deny; the
        # root's per-link signature/grantee/temporal checks are skipped for the multi-sig
        # root (already done in verify_multisig_root).
        if multi_granter_of(current) !== nothing
            i != n && return :deny     # multi-sig off-root → deny (i is 1-based; root is n)
            continue
        end
        gh = bytesfield(current, "granter"); gh === nothing && return :deny
        sgn = find_signature(env, current.hash); sgn === nothing && return :deny
        granter = resolve(env, st, gh); granter === nothing && return :deny
        signer = bytesfield(sgn, "signer")
        (signer !== nothing && signer == gh) || return :deny
        verify_signature(sgn, granter) || return :deny
        # grantee resolution → 401 carve-out
        grantee = bytesfield(current, "grantee"); grantee === nothing && return :unresolvable
        resolve(env, st, grantee) === nothing && return :unresolvable
        # temporal validity.
        #
        # CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
        # created_at is MALFORMED and must be refused outright. This has to run BEFORE
        # the two range checks below, because those are what the ambiguity defeats —
        # see temporal_fields_representable for the mechanism, which in Julia is the
        # ARITHMETIC form rather than the null-collapse one.
        temporal_fields_representable(current) || return :deny
        nb = uintfield(current, "not_before"); (nb !== nothing && t < nb) && return :deny
        ex = uintfield(current, "expires_at"); (ex !== nothing && ex < t) && return :deny
        # delegation link (child i, parent i+1)
        if i < n
            parent = chain[i+1]
            child_peer = link_granter_peer(env, st, local_peer, current); child_peer === nothing && return :deny
            parent_peer = link_granter_peer(env, st, local_peer, parent); parent_peer === nothing && return :deny
            pg = bytesfield(parent, "grantee")
            cg = bytesfield(current, "granter")
            (pg !== nothing && cg !== nothing && pg == cg) || return :deny
            is_attenuated(local_peer, child_peer, parent_peer, current, parent) || return :deny
            check_delegation_caveats(parent, current, i - 1) || return :deny
        end
    end
    return :allow
end

"""is_revoked (§5.1) — marker check at the revocations path; covers leaf + root."""
function is_revoked(env::Envelope, st::ContentStore, local_peer::AbstractString, capability::Entity)::Bool
    _, chain = collect_chain(env, st, capability)
    root_hash = isempty(chain) ? capability.hash : chain[end].hash
    chk(h) = store_at(st, "/$(local_peer)/system/capability/revocations/$(bytes2hex(h))") !== nothing
    return chk(capability.hash) || chk(root_hash)
end

"""verify_request (§5.2) — 4-way authn/authz verdict (§5.2a / §4.6). Returns
`:authn_fail`→401, `:authz_deny`→403, `:chain_too_deep`→400, `:unresolvable`→401, `:allow`."""
function verify_request(env::Envelope, st::ContentStore, local_peer::AbstractString)::Symbol
    exec = env.root
    # content hash validated on parse (Model.entity_ofcbor).
    # signature / author — authentication class (§4.6 boundary → 401).
    sgn = find_signature(env, exec.hash); sgn === nothing && return :authn_fail
    author_h = bytesfield(exec, "author")
    signer = sgn === nothing ? nothing : bytesfield(sgn, "signer")
    (author_h !== nothing && signer !== nothing && signer == author_h) || return :authn_fail
    author = included_get(env, author_h); author === nothing && return :authn_fail
    verify_signature(sgn, author) || return :authn_fail
    # capability / chain — authorization class (→ 403).
    cap_h = bytesfield(exec, "capability"); cap_h === nothing && return :authz_deny
    capability = included_get(env, cap_h); capability === nothing && return :authz_deny
    # §4.10(b): a chain exceeding max depth → 400 chain_depth_exceeded (structural), BEFORE
    # the per-link authz walk — distinct from 403.
    chain_exceeds_depth(env, st, capability) && return :chain_too_deep
    v = verify_capability_chain(env, st, local_peer, capability)
    v == :unresolvable && return :unresolvable
    v == :deny && return :authz_deny
    grantee = bytesfield(capability, "grantee")
    (grantee !== nothing && author_h !== nothing && grantee == author_h) || return :authz_deny
    is_revoked(env, st, local_peer, capability) && return :authz_deny
    return :allow
end

"""Resolve the §PR-8 granter frame for a leaf cap at the dispatch site; falls back to the
local peer for an unresolvable/multisig granter."""
function granter_frame(env::Envelope, st::ContentStore, local_peer::AbstractString, cap::Entity)::String
    g = resolve_granter_peer_id(env, st, cap)
    return g === nothing ? String(local_peer) : g
end

# ── §1.4 PD-2: outbound sub-dispatch authorization ────────────────────────────

"""Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.

§1.4 admits three spellings of one address — `system/tree`, `/{peer}/system/tree` and
`entity://{peer}/system/tree` — and §1.4's PD-2 block requires Dimension 1's handler
pattern to be the target uri's peer-relative path, because a grant names HANDLERS and a
handler pattern never carries a peer segment. Matching a grant against the absolute or
schemed form matches nothing, silently, which reads at the wire as an authority refusal.

The first segment is dropped ONLY when it is a peer_id. A peer-relative
`system/protocol/connect` must not lose `system` — the standing defect on `smalltalk` and
`forth`, where an unconditional strip made every self-minted grant unusable while the
handshake stayed green."""
function peer_relative_of(uri::AbstractString)::String
    p = normalize_uri(uri)
    startswith(p, "/") || return String(p)
    body = p[2:end]
    slash = findfirst('/', body)
    first_seg = slash === nothing ? body : body[1:slash-1]
    is_peer_id(first_seg) || return String(body)
    return slash === nothing ? "" : String(body[slash+1:end])
end

"""Store key of a handler's OWN grant (§6.8: `system/capability/grants/{pattern}`),
tolerant of the pattern arriving absolute or peer-relative.

§6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while the
grant path is built from the PEER-RELATIVE one. The two are one segment apart and
concatenating the wrong one yields a doubled peer segment whose lookup misses — which
fails closed as "no handler grant" and is indistinguishable, at the wire, from a genuine
authority refusal."""
function grant_path_for(local_peer::AbstractString, pattern::AbstractString)::String
    prefix = "/$(local_peer)/"
    rel = startswith(pattern, prefix) ? pattern[length(prefix)+1:end] : pattern
    return "/$(local_peer)/system/capability/grants/$(rel)"
end

"""Verify a presented reentry credential against §1.4's clauses. Answers
`(verified, scope)`: `verified` is "did every clause hold", `scope` is the `peers` scope
Dimension 4 relaxes to, and `nothing` there means "the target itself".

THE PAIR IS THE POINT. A `nothing` scope is a legitimate RESULT, so a lone scope return
would collapse "relaxes to the target" into "relaxes nothing" — the absent-vs-present
conflation §6.2's CAP-6a records for temporal accessors, one layer up and in the direction
that REFUSES a valid reentry.

Every clause is required: the chain ROOT granter resolves to the TARGET peer and is NOT a
multi-signature root; the LEAF grantee is the local peer; the chain is valid and not
revoked."""
function target_minted_peers_relaxation(env::Envelope, st::ContentStore,
                                        local_peer::AbstractString, target_peer::AbstractString,
                                        cred::Entity)
    # Nothing to relax — the default already covers this peer.
    target_peer == local_peer && return (false, nothing)
    verify_capability_chain_rooted_at(env, st, local_peer, target_peer, cred) == :allow ||
        return (false, nothing)
    is_revoked(env, st, local_peer, cred) && return (false, nothing)
    gh = bytesfield(cred, "grantee")
    gh === nothing && return (false, nothing)
    ge = resolve(env, st, gh)
    ge === nothing && return (false, nothing)
    pk = bytesfield(ge, "public_key")
    (pk === nothing || peerid_of_pubkey(pk) != local_peer) && return (false, nothing)
    gs = grants_of_token(cred)
    isempty(gs) && return (false, nothing)
    return (true, gs[1].peers)
end

"""§1.4's PD-2 gate: `check_permission` run before a locally-originated sub-dispatch
LEAVES the peer, with all four dimensions applied.

ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT decides all
four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's pattern the
target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE TARGET PEER naming
this peer as `grantee` relaxes Dimension 4 (`peers`) AND ONLY DIMENSION 4.

*"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT a
grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
BYPASS it is distinguished from is a peer that treats the credential as a standalone
authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
obvious vectors agree under either reading, so the only input that separates them is a
VALID credential presented to a handler whose own grant does NOT cover the request.

`have_relax == false` is the ambient arm (and equally a credential that failed a clause):
Dimension 4 is decided by the handler's grant alone."""
function check_outbound_sub_dispatch(local_peer::AbstractString, target_peer::AbstractString,
                                     handler_pattern::AbstractString, operation::AbstractString,
                                     handler_grant::Entity, resource, have_relax::Bool,
                                     relax_scope)::Bool
    for g in grants_of_token(handler_grant)
        matches_scope(local_peer, handler_pattern, g.handlers, PATH_SCOPE) || continue
        matches_scope(local_peer, operation, g.operations, ID_SCOPE) || continue
        check_resource_scope(local_peer, local_peer, resource, g.resources) || continue
        # Dimension 4. §5.2's default for an absent `peers` scope is
        # {include: [local_peer_id]}, so a foreign target fails unless this grant names it
        # or a target-minted credential relaxes it.
        peers = g.peers === nothing ? Scope([String(local_peer)], String[]) : g.peers
        matches_scope(local_peer, target_peer, peers, ID_SCOPE) && return true
        if have_relax
            relax_scope === nothing && return true   # absent `peers` relaxes to the granter
            matches_scope(local_peer, target_peer, relax_scope, ID_SCOPE) && return true
        end
    end
    return false
end

end # module Capability
