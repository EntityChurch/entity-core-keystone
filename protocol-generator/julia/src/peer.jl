# Peer machinery (L1–L3 + foundation) — bootstrap (§6.9/§6.9a), the four MUST system
# handlers (§6.2: tree, handler, capability, connect) + the §10.1 type handler, the §6.5
# dispatch chain, per-connection state, and the §7a conformance handlers behind --validate.
# A faithful port of the proven Zig peer.zig onto Julia's single-threaded Task substrate.
#
# THE §6.5 ORDER IS AUTH-BEFORE-RESOLVE (F31). An EXECUTE is authenticated (§5.2) BEFORE
# the handler is resolved: an UNAUTHENTICATED request to an unregistered path is 401, not
# 404 — the 404 is only reachable once authenticated. The §5.2a verdict-to-status tuple:
#   • no/invalid author+signature        → 401 authentication_failed   (auth-class)
#   • authenticated, no valid capability → 403 capability_denied       (authz-class)
#   • chain exceeds §4.10(b) max depth   → 400 chain_depth_exceeded
#   • unresolvable grantee (§5.5)        → 401 unresolvable_grantee
#   • authenticated + valid cap, unknown handler → 404 handler_not_found
#
# Handlers are resolved via STORE-BOUND system/handler entities (§6.6 backward tree-walk):
# the MUST handlers are bootstrapped as store entities; a dynamically-registered handler
# binds its own system/handler entity + expression_path (the §10.1 register round-trip).
module Peer

using ..Cbor: CborMap
using ..Varint: decode_varint
using ..ContentHash: content_hash
using ..Model
using ..Model: Entity, Envelope, make_entity, entity_tocbor, textfield, bytesfield,
               uintfield, entityfield, included_get, efield, mapget
using ..Identity
using ..Identity: PeerIdentity, peer_identity, peer_entity_of_pubkey, peerid_of_pubkey,
                  sign_entity, verify_signature
using ..PeerId: peerid_parse
using ..Store
using ..Store: ContentStore, store_put!, store_get, store_at, store_bind!, store_unbind!,
               store_hash_at, store_listing, ListingEntry
using ..Sign: ed25519_verify
using ..TypeDefs: publish_types!
using ..Capability
using ..Capability: verify_request, check_permission, granter_frame, find_signature,
                    grants_of_token, grant_subset_local, canonicalize, extract_peer,
                    matches_pattern, peer_relative_of, grant_path_for,
                    target_minted_peers_relaxation, check_outbound_sub_dispatch
using ..Handlers: HandlerContext, HandlerResult, NO_INCLUDED
using ..Wire: make_response, make_execute, error_result, empty_params

export Peer_t, Conn, create_peer, dispatch, register_handler!

# ── connection protocol state (per-connection; transport owns the socket + demux) ─────
mutable struct Conn
    issued_nonce::Union{Nothing,Vector{UInt8}}
    established::Bool
    hello_peer_id::Union{Nothing,String}
    outbound::Any                 # set by transport: (Envelope)->Envelope|nothing (§6.11)
    out_counter::Int
end
Conn() = Conn(nothing, false, nothing, nothing, 0)

mutable struct Peer_t
    identity::PeerIdentity
    peer_id::String
    store::ContentStore
    handlers::Dict{String,Function}   # extension seam (community-installed callables)
    validate::Bool                    # --validate: enable system/validate/* (§7a)
    open_grants::Bool                 # --debug-open-grants degenerate seed policy (default→*)
end

const Inc = Pair{Vector{UInt8},Entity}

# ── scope / grant construction (§4.4 / §5.4) ──────────────────────────────────────────
scope_val(incl::Vector{String}) = CborMap(Pair[("include" => Any[String(s) for s in incl])])

function grant_val(; handlers::Vector{String}, resources::Vector{String},
                     operations::Vector{String}, peers::Union{Nothing,Vector{String}}=nothing)
    ps = Pair[("handlers" => scope_val(handlers)),
              ("resources" => scope_val(resources)),
              ("operations" => scope_val(operations))]
    peers === nothing || push!(ps, "peers" => scope_val(peers))
    return CborMap(ps)
end

# §4.4 discovery floor: every authenticated identity gets at least this.
discovery_floor() = Any[
    grant_val(handlers=["system/tree"], resources=["system/type/*", "system/handler/*"], operations=["get"]),
    grant_val(handlers=["system/capability"], resources=String[], operations=["request"])]

# The degenerate default→* (= --debug-open-grants).
open_grants_scope() = Any[grant_val(handlers=["*"], resources=["*", "/*/*"], operations=["*"], peers=["*"])]

# Full owner authority over the local namespace (§6.9a).
owner_grants(local_peer) = Any[grant_val(handlers=["*"], resources=["*"], operations=["*"], peers=[String(local_peer)])]

now_ms() = round(Int, time() * 1000)

# ── token minting (§4.4 / §5.4) ───────────────────────────────────────────────────────
"""Mint a capability token granted by us to `grantee_hash`; sign it. Returns (token, sig)."""
function mint_token(p::Peer_t, grantee_hash::AbstractVector{UInt8},
                    parent::Union{Nothing,AbstractVector{UInt8}}, grants::Vector{Any})
    # No §5.6 ceiling: the self-issued paths (bootstrap, handler registration, the
    # §4.4 handshake) mint from local authority, where no MIN_DEFINED term applies.
    mint_token_at(p, now_ms(), grantee_hash, parent, grants, nothing)
end

"""
Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.

`expires_at === nothing` means no term was defined and the token genuinely has no
expiry (the ONLY "no bound" spelling). A non-nothing value is emitted verbatim —
including one equal to `created_at`, which §5.6 rule 2 requires for `ttl_ms == 0`
and which means "already expired at every observable instant", not "unbounded".

`created_at` is supplied rather than sampled here so a computed expiry is guaranteed
to be relative to the SAME instant that lands in the token; sampling the clock twice
skews the two.
"""
function mint_token_at(p::Peer_t, created_at::Integer, grantee_hash::AbstractVector{UInt8},
                       parent::Union{Nothing,AbstractVector{UInt8}}, grants::Vector{Any},
                       expires_at)
    ps = Pair[("granter" => p.identity.peer_entity.hash),
              ("grantee" => Vector{UInt8}(grantee_hash)),
              ("grants" => grants),
              ("created_at" => created_at)]
    expires_at === nothing || push!(ps, "expires_at" => expires_at)
    parent === nothing || push!(ps, "parent" => Vector{UInt8}(parent))
    token = make_entity("system/capability/token", CborMap(ps))
    store_put!(p.store, token)
    sig = sign_entity(p.identity, token)
    store_put!(p.store, sig)
    return token, sig
end

# ── helpers ───────────────────────────────────────────────────────────────────────────
err(status::Int, code::AbstractString)::HandlerResult = (status, error_result(code), NO_INCLUDED)
err(status::Int, code::AbstractString, message::AbstractString)::HandlerResult =
    (status, error_result(code, message), NO_INCLUDED)
okr(result::Entity)::HandlerResult = (200, result, NO_INCLUDED)
okr(result::Entity, inc::Vector{Inc})::HandlerResult = (200, result, inc)

# ── §6.9a seed-policy derivation ──────────────────────────────────────────────────────
# authenticate-time: look up the seed policy (hex → peer_id → default), UNION the matched
# scope with the §4.4 discovery floor. Returns the grants array for the minted token.
function derive_seed_grants(p::Peer_t, remote_peer::Entity, remote_peer_id::AbstractString)::Vector{Any}
    base = "/$(p.peer_id)/system/capability/policy/"
    hex = bytes2hex(remote_peer.hash)
    entry = store_at(p.store, base * hex)
    entry === nothing && (entry = store_at(p.store, base * remote_peer_id))
    entry === nothing && (entry = store_at(p.store, base * "default"))
    floor = discovery_floor()
    policy_grants = entry === nothing ? Any[] : seed_entry_grants(entry)
    isempty(policy_grants) && return floor
    return vcat(floor, policy_grants)
end

# Extract grants from a seed-policy entry (a policy-entry scope template, or a signed cap).
function seed_entry_grants(e::Entity)::Vector{Any}
    grants_of(ent) = (g = efield(ent, "grants"); g isa AbstractVector ? Any[x for x in g] : Any[])
    if e.typ == "system/capability/policy-entry"
        return grants_of(e)
    elseif e.typ == "system/capability/token"
        return grants_of(e)   # owner-minted, signature stored alongside at bootstrap
    end
    return Any[]
end

# ── connect handler (§4.1 / §4.6) — pre-auth handshake ────────────────────────────────
function connect_handler(p::Peer_t, conn::Conn, exec::Entity, env::Envelope)::HandlerResult
    op = textfield(exec, "operation"); op = op === nothing ? "" : op
    if op == "hello"
        conn.established && return err(409, "connection_already_established")
        # §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
        # HALF-OPEN connection (hello done, authenticate not yet) is an operation we
        # implement arriving in a state that forbids it — the same class as
        # connection_already_established above, taking the same 409. A half-open
        # connection is NOT established, so the guard above cannot reach it; §4.7
        # names this gap explicitly because two adjacent rules each look like they
        # cover it and neither does.
        conn.issued_nonce !== nothing && return err(409, "connection_sequence_error")
        params = entityfield(exec, "params")
        hello_pid = nothing
        if params !== nothing
            negotiation_reject(params, "hash_formats", "ecfv1-sha256") && return err(400, "incompatible_hash_format")
            negotiation_reject(params, "key_types", "ed25519") && return err(400, "unsupported_key_type")
            hello_pid = textfield(params, "peer_id")
            # §4.5 mutual verifiability, the direction that is NOT the array.
            # `key_types` is an ACCEPT-SET; the initiator's OWN key_type is not in it
            # — it rides in its `peer_id` — so a hello may advertise a perfectly good
            # accept-set and still name an identity we cannot verify. Checking only
            # the array leaves that MUST unenforced at hello, which is where §4.5
            # wants it; authenticate catches it one leg later, which is conformant
            # but non-canonical.
            #
            # An UNPARSEABLE peer_id is deliberately left alone: that is a malformed
            # field, not a key_type we lack, and authenticate already refuses it.
            if hello_pid !== nothing
                hp = try; peerid_parse(hello_pid); catch; nothing; end
                (hp !== nothing && hp.key_type != 1) && return err(400, "unsupported_key_type")
            end
        end
        # §4.5 `protocols` — the one negotiated field Required with NO default, so
        # there is no floor to fall back to, and its two failure modes carry
        # different codes on purpose (§4.5 table row / §4.7 row 1):
        #
        #   absent or empty     -> 400 invalid_request       (a malformed hello)
        #   non-empty, disjoint -> 400 incompatible_protocol (we compared)
        #
        # "a caller that named no version cannot be told the comparison failed" —
        # the remedies differ (send the field vs change the version) and §4.7 exists
        # so the code selects the remedy. The vocabulary is §8.4's protocol version
        # identifiers, today the single entity-core/1.0.
        #
        # ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
        # precedence between the three, so a hello disjoint in more than one
        # dimension may be refused on any of them — but the choice is OBSERVABLE, and
        # the reference peer refuses key_types first. Checking protocols first is
        # equally spec-legal and makes AGILITY-UNKNOWN-1 answer incompatible_protocol,
        # because that probe's own hello carries protocols ["entity-core/v7"] — a
        # spec-line name, not a §8.4 identifier (F56).
        protos = params === nothing ? nothing : efield(params, "protocols")
        protol = protos isa AbstractVector ? [x for x in protos if x isa AbstractString] : String[]
        isempty(protol) && return err(400, "invalid_request", "hello: protocols absent or empty")
        ("entity-core/1.0" in protol) || return err(400, "incompatible_protocol")
        hello_pid !== nothing && (conn.hello_peer_id = hello_pid)
        nonce = rand(UInt8, 32)
        conn.issued_nonce = nonce
        hello = make_entity("system/protocol/connect/hello",
            CborMap(Pair[("peer_id" => p.peer_id),
                         ("nonce" => nonce),
                         ("protocols" => Any["entity-core/1.0"]),
                         ("timestamp" => now_ms()),
                         ("hash_formats" => Any["ecfv1-sha256"]),
                         ("key_types" => Any["ed25519"])]))
        return okr(hello)
    elseif op == "authenticate"
        # RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
        # single-use nonce. The anti-replay property is the MUST and the mechanism
        # (established-state tracking) is impl-defined, but the STATUS is pinned to
        # 401 invalid_nonce — a 409 state-conflict under-signals the replay.
        conn.established && return err(401, "invalid_nonce")
        issued = conn.issued_nonce
        issued === nothing && return err(401, "invalid_nonce")
        auth = entityfield(exec, "params")
        auth === nothing && return err(401, "authentication_failed")
        kt = textfield(auth, "key_type")
        (kt !== nothing && kt != "ed25519") && return err(400, "unsupported_key_type")
        public_key = bytesfield(auth, "public_key")
        (public_key === nothing || length(public_key) != 32) && return err(400, "unsupported_key_type")
        # §4.6 / AGILITY-UNKNOWN-1: an unsupported key_type carried in the claimed peer_id
        # prefix (e.g. 0xFD) is a 400 unsupported_key_type, not a 401 identity_mismatch.
        claimed0 = textfield(auth, "peer_id")
        if claimed0 !== nothing
            parsed = try; peerid_parse(claimed0); catch; nothing; end
            (parsed !== nothing && parsed.key_type != 1) && return err(400, "unsupported_key_type")
        end
        echoed = bytesfield(auth, "nonce")
        (echoed === nothing || echoed != issued) && return err(401, "invalid_nonce")
        sgn = find_signature(env, auth.hash)
        sgn === nothing && return err(401, "authentication_failed")
        sig = bytesfield(sgn, "signature")
        (sig === nothing || length(sig) != 64) && return err(401, "authentication_failed")
        ed25519_verify(public_key, sig, auth.hash) || return err(401, "authentication_failed")
        claimed = textfield(auth, "peer_id")
        (claimed === nothing || claimed != peerid_of_pubkey(public_key)) && return err(401, "identity_mismatch")
        (conn.hello_peer_id !== nothing && conn.hello_peer_id != claimed) && return err(401, "identity_mismatch")
        # success (§4.4/§6.9a): mint the seed grant for this identity
        remote_peer = peer_entity_of_pubkey(public_key)
        store_put!(p.store, remote_peer)
        grants = derive_seed_grants(p, remote_peer, claimed)
        token, token_sig = mint_token(p, remote_peer.hash, nothing, grants)
        conn.established = true
        grant = make_entity("system/capability/grant", CborMap(Pair[("token" => token.hash)]))
        inc = Inc[token.hash => token,
                  p.identity.peer_entity.hash => p.identity.peer_entity,
                  token_sig.hash => token_sig]
        return okr(grant, inc)
    end
    # §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
    # 400 invalid_request, not the 501 every other handler answers. The table
    # separates a STATE conflict from an UNKNOWN operation because they select
    # different remedies — "an unknown connect operation is not out of order at all;
    # it exists in no state", so connection_sequence_error would point the caller at
    # its ORDERING when the defect is its OPERATION NAME. Row 10 is scoped "in any
    # state", so this arm covers pre-handshake AND established; the genuine sequence
    # cases are refused in the two branches above, with 409.
    #
    # SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
    # (§3.3's 501 row, §6.2) is a different contract and is separately gated; moving
    # the other handlers' 501 would trade one green check for another.
    return err(400, "invalid_request", "connect: unknown operation " * op)
end

# §4.5 negotiation: present-but-disjoint list → reject.
function negotiation_reject(params::Entity, key::AbstractString, required::AbstractString)::Bool
    arr = efield(params, key)
    arr isa AbstractVector || return false
    for it in arr
        it isa AbstractString && it == required && return false
    end
    return true
end

# ── tree handler (§6.3) ───────────────────────────────────────────────────────────────
function resource_target(exec::Entity)
    r = efield(exec, "resource")
    r isa CborMap || return nothing
    targets = mapget(r, "targets")
    (targets isa AbstractVector && !isempty(targets)) || return nothing
    t = targets[1]
    return t isa AbstractString ? String(t) : nothing
end

# §1.4/§5.4 path-flex validation.
function path_flex_ok(target::AbstractString)::Bool
    occursin('\0', target) && return false
    body = target
    if startswith(target, "/")
        rest = target[2:end]
        i = findfirst('/', rest)
        i === nothing && return Capability.is_peer_id(rest)
        Capability.is_peer_id(rest[1:i-1]) || return false
        body = rest[i+1:end]
    end
    endswith(body, "/") && (body = body[1:end-1])
    isempty(body) && return true
    for seg in split(body, '/')
        (isempty(seg) || seg == "." || seg == "..") && return false
    end
    return true
end

"""
Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).

"When any handler returns a multi-entry result whose entries are tree paths, each entry
MUST be individually checked using check_path_permission. Entries for which
check_path_permission returns DENY MUST be omitted. The result's `count` field MUST
reflect the filtered entry count, not the source tree's total count."

This is the read path at its highest volume and it is the reason 0.8.2.21 refused to
carve reads out of the caller-specified-path rule: an unfiltered listing discloses the
EXISTENCE of every binding under a prefix to a caller whose capability covers none of
them.

The DIRECTORY itself is deliberately NOT checked — §6.3 makes each ENTRY the subject,
and testing the prefix would deny a listing to a caller whose grant covers children but
not the node above them, which is the ordinary shape of a narrowed grant.

`caller_cap === nothing` is the bootstrap/internal path and is NOT filtered: the
filter's subject is "the caller's verified capability", and where there is none there is
no caller to narrow.
"""
function build_listing(p::Peer_t, path::AbstractString;
                       caller_cap::Union{Nothing,Entity}=nothing,
                       handler_pattern::AbstractString="")::HandlerResult
    entries = store_listing(p.store, path)
    entry_pairs = Pair[]
    emitted = 0
    for le in entries
        # §6.3 CORE-TREE-DELETE-1: a leaf bound to a deletion-marker is a tombstone.
        if le.hash !== nothing
            bound = store_get(p.store, le.hash)
            bound !== nothing && bound.typ == "system/deletion-marker" && continue
        end
        # §6.3's per-entry check. `emitted` is what `count` is built from below, so an
        # omitted entry is omitted from the COUNT by construction — a count that still
        # reported the source total IS the disclosure the rule exists to prevent.
        if caller_cap !== nothing
            child = endswith(path, "/") ? "$(path)$(le.seg)" : "$(path)/$(le.seg)"
            Capability.check_path_permission(p.peer_id, "get", child, caller_cap,
                                             handler_pattern) || continue
        end
        fields = Pair[("has_children" => le.has_children)]
        le.hash === nothing || push!(fields, "hash" => le.hash)
        le_entity = make_entity("system/tree/listing-entry", CborMap(fields))
        push!(entry_pairs, le.seg => entity_tocbor(le_entity))
        emitted += 1
    end
    listing = make_entity("system/tree/listing",
        CborMap(Pair[("path" => String(path)),
                     ("entries" => CborMap(entry_pairs)),
                     ("count" => emitted),
                     ("offset" => 0)]))
    return okr(listing)
end

function tree_handler(p::Peer_t, exec::Entity;
                      caller_cap::Union{Nothing,Entity}=nothing,
                      handler_pattern::AbstractString="")::HandlerResult
    op = textfield(exec, "operation"); op = op === nothing ? "" : op
    # RULE G: the OPERATION is resolved first. Both ladders below sit inside their own
    # `op ==` arm and the function's last statement is the 501, so an unknown operation
    # cannot reach the §3.3 resource ladder at all — a peer that validates the resource
    # first answers a RESOURCE fault for an OPERATION fault on every unknown operation
    # (entity-system-conformance X9 / F52).
    (op == "get" || op == "put") || return err(501, "unsupported_operation")

    # §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on resource.targets: a
    # handler that counts the effective list and then indexes targets[1] has implemented
    # the arithmetic completely and is still reading a path no authorization covered.
    eff, had_resource = Capability.effective_targets(p.peer_id, exec)
    if op == "get"
        if !had_resource
            # THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION
            # IS WHAT SAYS SO. §3.3's "an empty effective list IS the absent case" is
            # scoped "for an operation that REQUIRES a resource" (0.8.2.24, N7); `get`
            # does not. For a resource-OPTIONAL operation 0.8.2.25 (N10) decides the
            # present-but-empty case by whether the absent case is WIDER than the request
            # — BROAD-RESULT refuses it, OPTIONAL-FILTER answers it empty.
            #
            # EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
            # resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root listing",
            # self-excluded case "400 path_required". Both arms are pinned by text and
            # neither is this peer's choice.
            return build_listing(p, "/$(p.peer_id)/"; caller_cap, handler_pattern)
        end
        # The self-excluded request: `resource` PRESENT, every target carved out by the
        # caller's own exclude. Serving it the absent case "answers a request for one
        # excluded path with a listing of the tree" (EXTENSION-TREE §2.2a) — wider than
        # what was asked for, which is what BROAD-RESULT means.
        isempty(eff) && return err(400, "path_required")
        length(eff) > 1 && return err(400, "ambiguous_resource")
        target = eff[1]
        path_flex_ok(target) || return err(400, "invalid_path")
        if isempty(target) || endswith(target, "/")
            return build_listing(p, canonicalize(p.peer_id, target); caller_cap, handler_pattern)
        end
        # A resource-requiring operation takes a CONCRETE path (0.8.2.20); a trailing
        # slash is a listing request rather than a pattern, so only a star makes the
        # subject a §5.4 pattern.
        occursin('*', target) && return err(400, "malformed_resource")
        path = canonicalize(p.peer_id, target)
        # §6.3: the handler MUST verify the CALLER's capability covers the path it is
        # about to read. Not a secondary check — the dispatch-level check never saw this
        # path if the caller excluded it.
        if caller_cap !== nothing
            Capability.check_path_permission(p.peer_id, "get", path, caller_cap,
                                             handler_pattern) ||
                return err(403, "capability_denied")
        end
        e = store_at(p.store, path)
        e === nothing && return err(404, "not_found")
        params = entityfield(exec, "params")
        if params !== nothing
            m = textfield(params, "mode")
            m == "hash" && return okr(make_entity("system/hash", e.hash))
        end
        return okr(e)
    else
        # Same ladder, with the two empties COLLAPSED rather than split: EXTENSION-TREE
        # §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's "an empty effective
        # list IS the absent case" applies in its unscoped form and both empties answer
        # `path_required`. That is the same table `get`'s branch cites, read one row down.
        #
        # Note the code change 0.8.2.20 forced: this branch answered `ambiguous_resource`
        # for a MISSING target, which 0.8.2.20 names as the exact inversion it forbids —
        # supply a resource is not disambiguate your request, and the code is what selects
        # between them.
        (had_resource && !isempty(eff)) || return err(400, "path_required")
        length(eff) > 1 && return err(400, "ambiguous_resource")
        target = eff[1]
        path_flex_ok(target) || return err(400, "invalid_path")
        occursin('*', target) && return err(400, "malformed_resource")
        path = canonicalize(p.peer_id, target)
        # §6.3, as in `get`: the caller's own capability must cover the path this handler
        # is about to write. BEFORE the CAS arm and before any store mutation — a 403
        # whose refusal arrives after the write would satisfy the status assertion and
        # have already leaked the effect.
        if caller_cap !== nothing
            Capability.check_path_permission(p.peer_id, "put", path, caller_cap,
                                             handler_pattern) ||
                return err(403, "capability_denied")
        end
        params = entityfield(exec, "params")
        raw_entity = params === nothing ? nothing : efield(params, "entity")
        expected = params === nothing ? nothing : bytesfield(params, "expected_hash")
        current = store_hash_at(p.store, path)
        if expected !== nothing
            zero33 = zeros(UInt8, 33)
            cas_ok = expected == zero33 ? current === nothing : (current !== nothing && current == expected)
            cas_ok || return err(409, "hash_mismatch")
        end
        raw_entity === nothing && return err(400, "unexpected_params")
        admitted = admit_put(raw_entity)
        admitted isa Entity || return admitted
        entity = admitted
        store_bind!(p.store, path, entity)
        return okr(make_entity("system/hash", entity.hash))
    end
end

# Digest byte length for a `content_hash_format` code per the §1.2 seed table, or
# `nothing` when this peer cannot VERIFY that code. The total wire length is this plus
# the varint prefix, which is not a constant of the code (§7.3): codes >= 0x80 occupy
# more than one byte.
hash_digest_len(code::Integer) = code == 0 ? 32 : (code == 1 ? 48 : nothing)

# PRESENCE, not truthiness. `mapget` answers `nothing` for an absent key AND for a key
# bound to a CBOR null, and §6.3 makes a null `data` a legal payload — so the presence
# test has to walk the pairs.
has_text_key(m::CborMap, key::AbstractString) = any(p -> p.first == key, m.pairs)
has_text_key(::Any, ::AbstractString) = false

"""
§6.3's `put` admission ladder (normative, 0.8.2.11).

`put` is a RECEIPT path: the submitter authors the entity, the peer validates what it
received (§1.8 item 1) and MUST NOT author a submitted entity's `content_hash` on the
submitter's behalf. Two ordered steps:

 1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any CBOR
    value; null is a legal payload), and a `content_hash` that is a well-formed
    system/hash whose total byte length matches its format code (§1.2). Any failure ->
    400 invalid_request. A well-formed hash naming a format code this peer cannot
    verify is the separate §1.2 ingest-dispatch case -> 400
    unsupported_content_hash_format.
 2. HASH — carried content_hash vs content_hash({type, data}). Disagreement -> 400
    hash_mismatch.

Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's inputs are
exactly what step 1 establishes, so a submission that is both malformed and mis-hashed
is step 1's and answers invalid_request.

Structural admission is not semantic validation: `data` is never checked against the
type named by `type`.

Returns the admitted `Entity`, or the refusal `HandlerResult`.
"""
function admit_put(v)
    refuse(code, message) = err(400, code, message)

    v isa CborMap || return refuse("invalid_request", "put: entity is not a map")
    typ = mapget(v, "type")
    (typ isa AbstractString && !isempty(typ)) ||
        return refuse("invalid_request", "put: entity.type absent, empty or not a text string")
    has_text_key(v, "data") || return refuse("invalid_request", "put: entity.data absent")
    data = mapget(v, "data")
    carried = mapget(v, "content_hash")
    (carried isa AbstractVector{UInt8} && !isempty(carried)) ||
        return refuse("invalid_request", "put: entity.content_hash absent or not a byte string")

    local format_code, consumed
    try
        format_code, consumed = decode_varint(carried, 1)
    catch
        return refuse("invalid_request", "put: entity.content_hash is not a well-formed system/hash")
    end
    digest_len = hash_digest_len(format_code)
    # §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
    # invalid_request: the shape is fine, the algorithm is what we lack.
    digest_len === nothing &&
        return refuse("unsupported_content_hash_format", "put: unsupported content_hash_format")
    length(carried) == consumed + digest_len ||
        return refuse("invalid_request", "put: content_hash length does not match its format code")

    content_hash(format_code, String(typ), data) == carried ||
        return refuse("hash_mismatch", "put: content_hash does not match content_hash({type, data})")

    # The carried hash IS the entity's address; recomputing it into the store would be
    # the authoring arm §6.3 forbids.
    return Entity(String(typ), data, Vector{UInt8}(carried))
end

# ── capability handler (§6.2) ─────────────────────────────────────────────────────────
is_zero_hash(h::AbstractVector{UInt8}) = all(==(0x00), h)

function req_grants(params)::Vector{Capability.Grant}
    params === nothing && return Capability.Grant[]
    arr = efield(params, "grants")
    arr isa AbstractVector || return Capability.Grant[]
    out = Capability.Grant[]
    for g in arr
        g isa CborMap && push!(out, Capability.parse_grant(g))
    end
    return out
end

# Raw grant array (CborMap entries) as sent, for minting the token verbatim.
function req_grants_raw(params)::Vector{Any}
    params === nothing && return Any[]
    arr = efield(params, "grants")
    arr isa AbstractVector ? Any[x for x in arr] : Any[]
end

"""Mint a token for `grantee_hash`, bounded as a subset of the caller's cap (§6.2)."""
function mint_bounded(p::Peer_t, env, caller_cap, params, grantee_hash::AbstractVector{UInt8},
                      parent::Union{Nothing,AbstractVector{UInt8}})::HandlerResult
    reqs = req_grants(params)
    bounded = begin
        if caller_cap === nothing
            false
        else
            parent_grants = grants_of_token(caller_cap)
            ok = true
            for c in reqs
                matched = any(pg -> grant_subset_local(p.peer_id, c, pg), parent_grants)
                matched || (ok = false; break)
            end
            ok
        end
    end
    bounded || return err(403, "scope_exceeds_authority")

    # §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and
    # convert the duration term against that same instant.
    #
    # Note what this is NOT: an authorization decision. An over-long ttl_ms from a
    # bounded caller MINTS a clamped token and returns 200 — "rejecting it is
    # non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
    # (parent: null), so §5.6's parent-child attenuation never reaches it; without
    # this clamp, temporal attenuation is the one dimension a requester could escape,
    # and policy withdrawal would have no bounded latency.
    created_at = now_ms()
    terms = Any[]
    if parent !== nothing                                              # absolute
        pt = resolve(env, p.store, parent)
        pt === nothing || push!(terms, uintfield(pt, "expires_at"))
    end
    caller_cap === nothing || push!(terms, uintfield(caller_cap, "expires_at"))  # absolute
    if params !== nothing                                              # duration
        ttl = uintfield(params, "ttl_ms")
        ttl === nothing || push!(terms, add_ttl(created_at, ttl))
    end
    defined = filter(!isnothing, terms)
    ceiling = isempty(defined) ? nothing : minimum(defined)

    token, sig = mint_token_at(p, created_at, grantee_hash, parent, req_grants_raw(params), ceiling)
    grant = make_entity("system/capability/grant", CborMap(Pair[("token" => token.hash)]))
    inc = Inc[token.hash => token,
              p.identity.peer_entity.hash => p.identity.peer_entity,
              sig.hash => sig]
    return okr(grant, inc)
end

function capability_handler(p::Peer_t, env, exec::Entity, caller_cap)::HandlerResult
    op = textfield(exec, "operation"); op = op === nothing ? "" : op
    params = entityfield(exec, "params")
    author = bytesfield(exec, "author")
    if op == "request"
        author === nothing && return err(403, "capability_denied")
        return mint_bounded(p, env, caller_cap, params, author, nothing)
    elseif op == "delegate"
        parent = params === nothing ? nothing : bytesfield(params, "parent")
        (parent === nothing) && return err(400, "unexpected_params")
        is_zero_hash(parent) && return err(400, "unexpected_params")
        (author === nothing || author != p.identity.peer_entity.hash) && return err(501, "unsupported_operation")
        return mint_bounded(p, env, caller_cap, params, author, parent)
    elseif op == "revoke"
        token_h = params === nothing ? nothing : bytesfield(params, "token")
        (token_h === nothing) && return err(400, "unexpected_params")
        is_zero_hash(token_h) && return err(400, "unexpected_params")
        marker = make_entity("system/capability/revocation",
            CborMap(Pair[("token" => Vector{UInt8}(token_h)), ("revoked_at" => now_ms())]))
        store_bind!(p.store, "/$(p.peer_id)/system/capability/revocations/$(bytes2hex(token_h))", marker)
        return okr(empty_params())
    elseif op == "configure"
        pp = params === nothing ? nothing : textfield(params, "peer_pattern")
        pp === nothing && return err(400, "unexpected_params")
        is_hex = length(pp) == 66 && all(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'), pp)
        (pp == "default" || is_hex || Capability.is_peer_id(pp)) || return err(400, "invalid_peer_pattern")
        store_bind!(p.store, "/$(p.peer_id)/system/capability/policy/$(pp)", params)
        return okr(empty_params())
    end
    return err(501, "unsupported_operation")
end

# ── handlers handler (§6.2 / §10.1) — register/unregister ─────────────────────────────
function register_pattern(exec::Entity)
    target = resource_target(exec)
    target === nothing && return (nothing, err(400, "ambiguous_resource"))
    prefix = "system/handler/"
    (startswith(target, prefix) && length(target) > length(prefix)) || return (nothing, err(400, "invalid_resource"))
    return (target[length(prefix)+1:end], nothing)
end

# §6.2: "system" itself or any "system/..." prefix is reserved for system handlers;
# user-installed handlers MUST NOT register there.
is_reserved_system_pattern(pattern::AbstractString) = pattern == "system" || startswith(pattern, "system/")

function register_handler_op(p::Peer_t, exec::Entity)::HandlerResult
    pattern, e = register_pattern(exec)
    pattern === nothing && return e
    # §6.2: refuse before any of the five normative writes below.
    is_reserved_system_pattern(pattern) && return err(403, "forbidden_pattern")
    req = entityfield(exec, "params")
    req === nothing && return err(400, "unexpected_params")
    req.typ == "system/handler/register-request" || return err(400, "unexpected_params")
    manifest = efield(req, "manifest")
    manifest_map = manifest isa CborMap ? manifest : CborMap(Pair[])
    name = begin
        v = mapget(manifest_map, "name")
        v isa AbstractString ? String(v) : pattern
    end
    operations = mapget(manifest_map, "operations")
    operations === nothing && (operations = CborMap(Pair[]))
    expr_path = begin
        v = mapget(manifest_map, "expression_path")
        v isa AbstractString ? String(v) : nothing
    end
    internal_scope = mapget(manifest_map, "internal_scope")
    grant_scope = begin
        rs = efield(req, "requested_scope")
        if rs isa AbstractVector
            Any[x for x in rs]
        elseif internal_scope isa AbstractVector
            Any[x for x in internal_scope]
        else
            Any[]
        end
    end

    interface_rel = "system/handler/$(pattern)"
    # (1) handler entity at the pattern path
    hps = Pair[("interface" => interface_rel)]
    expr_path === nothing || push!(hps, "expression_path" => expr_path)
    internal_scope === nothing || push!(hps, "internal_scope" => internal_scope)
    handler_e = make_entity("system/handler", CborMap(hps))
    store_bind!(p.store, "/$(p.peer_id)/$(pattern)", handler_e)

    # (2) associated types
    types = efield(req, "types")
    if types isa CborMap
        for pr in types.pairs
            pr.first isa AbstractString || continue
            te = make_entity("system/type", pr.second)
            store_bind!(p.store, "/$(p.peer_id)/system/type/$(pr.first)", te)
        end
    end

    # (3)+(4) self-issued signed handler grant at the §3.5 pointer
    token, sig = mint_token(p, p.identity.peer_entity.hash, nothing, grant_scope)
    store_bind!(p.store, "/$(p.peer_id)/system/capability/grants/$(pattern)", token)
    store_bind!(p.store, "/$(p.peer_id)/system/signature/$(bytes2hex(token.hash))", sig)

    # (5) handler interface entity (discovery index)
    iface_e = make_entity("system/handler/interface",
        CborMap(Pair[("pattern" => pattern), ("name" => name), ("operations" => operations)]))
    store_bind!(p.store, "/$(p.peer_id)/$(interface_rel)", iface_e)

    result = make_entity("system/handler/register-result",
        CborMap(Pair[("pattern" => pattern), ("grant" => token.data)]))
    return okr(result)
end

function unregister_handler_op(p::Peer_t, exec::Entity)::HandlerResult
    pattern, e = register_pattern(exec)
    pattern === nothing && return e
    grant_path = "/$(p.peer_id)/system/capability/grants/$(pattern)"
    g = store_at(p.store, grant_path)
    if g !== nothing
        store_unbind!(p.store, "/$(p.peer_id)/system/signature/$(bytes2hex(g.hash))")
        store_unbind!(p.store, grant_path)
    end
    store_unbind!(p.store, "/$(p.peer_id)/$(pattern)")
    store_unbind!(p.store, "/$(p.peer_id)/system/handler/$(pattern)")
    return okr(empty_params())
end

function handlers_handler(p::Peer_t, exec::Entity)::HandlerResult
    op = textfield(exec, "operation"); op = op === nothing ? "" : op
    op == "register" && return register_handler_op(p, exec)
    op == "unregister" && return unregister_handler_op(p, exec)
    return err(501, "unsupported_operation")
end

# §10.1 type handler — the core floor has no wire register op beyond the bootstrap.
type_handler(exec::Entity)::HandlerResult = err(501, "unsupported_operation")

# ── §6.13(a) entity-native dispatch — the register round-trip body ────────────────────
function entity_native_dispatch(p::Peer_t, handler_entity::Entity)::HandlerResult
    expr_path_rel = textfield(handler_entity, "expression_path")
    expr_path_rel === nothing && return err(501, "no_handler_body")
    expr = store_at(p.store, canonicalize(p.peer_id, expr_path_rel))
    expr === nothing && return err(404, "expression_not_found")
    if expr.typ == "compute/literal"
        value = efield(expr, "value")
        value === nothing && (value = nothing)
        result = make_entity("compute/result",
            CborMap(Pair[("value" => value), ("expression" => expr.hash)]))
        return okr(result)
    end
    return err(501, "unsupported_expression")
end

# ── §7a conformance handlers (behind --validate) ──────────────────────────────────────
"""§7a system/validate/echo: return the params entity verbatim (the value round-trips)."""
function echo_handler(exec::Entity)::HandlerResult
    params = entityfield(exec, "params")
    params === nothing && return okr(empty_params())
    return okr(params)
end

"""Decode an ARRAY of nested entities at `key`, falling back to the SINGULAR spelling as a
list of one (the §7a.1 transitional carriers).

An EMPTY vector means absent, not-a-list, or a MALFORMED array (a member that does not
decode) — never a silently shorter list, because the caller's all-or-none test would then
read a partial credential as a complete one."""
function entity_list_field(e::Entity, key::AbstractString, singular::AbstractString)::Vector{Entity}
    v = efield(e, key)
    if v isa AbstractVector
        out = Entity[]
        for item in v
            d = item isa CborMap ? (try entity_ofcbor(item) catch; nothing end) : nothing
            d === nothing && return Entity[]
            push!(out, d)
        end
        return out
    end
    one = entityfield(e, singular)
    return one === nothing ? Entity[] : Entity[one]
end

"""§7a system/validate/dispatch-outbound: originate one outbound EXECUTE via the §6.11
reentry seam back to the caller and return the downstream response (proves the target can
ORIGINATE). The reentry authority is caller-minted, carried in-band."""
function dispatch_outbound_handler(p::Peer_t, conn::Conn, env::Envelope, exec::Entity,
                                   handler_pattern::AbstractString)::HandlerResult
    out_fn = conn.outbound
    out_fn === nothing && return err(503, "no_outbound_seam")
    params = entityfield(exec, "params")
    params === nothing && return err(400, "unexpected_params")
    target = textfield(params, "target"); target === nothing && return err(400, "unexpected_params")
    operation = textfield(params, "operation"); operation === nothing && return err(400, "unexpected_params")
    value = efield(params, "value"); value === nothing && return err(400, "unexpected_params")
    # GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the single-granter
    # case is an array of ONE. They were singular, which made §1.4's multi-signature-root
    # rule ungateable on the wire: driving it needs two granter identities and two
    # signatures, and a single-credential carrier cannot express that input.
    #
    # TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one, because
    # THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle sends the SINGULAR
    # names; a plural-only peer reads the triple as absent there, takes the ambient arm and
    # refuses — measured on the `go` vanguard as 2 of 778 severities moving PASS -> FAIL.
    # REMOVE THIS FALLBACK AT THE ORACLE RE-PIN.
    cap_e = entityfield(params, "reentry_capability")
    granters = entity_list_field(params, "reentry_granters", "reentry_granter")
    cap_sigs = entity_list_field(params, "reentry_cap_signatures", "reentry_cap_signature")
    # The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED arm, all
    # three absent selects the AMBIENT arm, and a PARTIAL set is 400 invalid_params — a
    # partial credential is malformed, not ambient. An empty array is partial, not present.
    n_present = (cap_e === nothing ? 0 : 1) + (isempty(granters) ? 0 : 1) + (isempty(cap_sigs) ? 0 : 1)
    (n_present == 0 || n_present == 3) ||
        return err(400, "invalid_params")
    has_cred = n_present == 3
    cred = has_cred ? cap_e : nothing
    granter_list = has_cred ? granters : Entity[]
    sig_list = has_cred ? cap_sigs : Entity[]

    # §7a.1: `value` IS the outbound params entity data — pass it through (no re-wrap).
    inner = make_entity("primitive/any", value)
    # `target` arrives as any of §1.4's three spellings and the validator sends the SCHEMED
    # ABSOLUTE form. Both the handler-pattern dimension and the resource target want the
    # PEER-RELATIVE path — §1.4's PD-2 block says so for Dimension 1, and a resource target
    # carrying a scheme is not a path at all.
    rel_target = peer_relative_of(target)
    resource_v = CborMap(Pair[("targets" => Any["system/handler/$(rel_target)"])])

    # §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer, all four
    # dimensions, on THIS handler's own grant — with a target-minted credential relaxing
    # Dimension 4 and nothing else. Consulting only the presented credential here is the
    # §6.8 confused-deputy bypass.
    own_grant = store_at(p.store, grant_path_for(p.peer_id, handler_pattern))
    # §6.8: a handler with no valid grant does not run. Fail closed rather than falling
    # back to the credential, which is the substitution §6.8 forbids.
    own_grant === nothing && return err(403, "capability_denied")
    # §7a.2a: the credential, its granters and its signatures arrive NESTED IN PARAMS
    # (ratified shape (a), in-band), so they are NOT in `env` and a verifier handed that
    # alone cannot resolve a single link.
    bundle_inc = copy(env.included)
    if has_cred
        for e in vcat(Entity[cred], granter_list, sig_list)
            push!(bundle_inc, e.hash => e)
        end
    end
    bundle = Envelope(env.root, bundle_inc)
    # §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends the absolute
    # form, so the URI names the target. Where the uri is PEER-RELATIVE there is no peer in
    # it and the §6.11 seam's destination is the connection's remote, so that is the
    # fallback — without it Dimension 4 passes vacuously.
    uri_peer = extract_peer(p.peer_id, target)
    target_peer = (uri_peer == p.peer_id && conn.hello_peer_id !== nothing) ?
        conn.hello_peer_id : uri_peer
    have_relax, relax_scope = has_cred ?
        target_minted_peers_relaxation(bundle, p.store, p.peer_id, target_peer, cred) :
        (false, nothing)
    if !check_outbound_sub_dispatch(p.peer_id, target_peer, rel_target, operation,
                                    own_grant, resource_v, have_relax, relax_scope)
        # §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic transport-
        # or gateway-class code would launder an authorization verdict into a route fault.
        return err(403, "capability_denied")
    end

    req = build_reentry_execute(p, conn, target, rel_target, operation, inner, cred, granter_list, sig_list)
    resp = out_fn(req)
    resp === nothing && return err(504, "outbound_timeout")
    status = uintfield(resp.root, "status"); status = status === nothing ? 0 : status
    result = efield(resp.root, "result"); result === nothing && (result = nothing)
    out = make_entity("primitive/any", CborMap(Pair[("status" => status), ("result" => result)]))
    return okr(out)
end

"""`granters`/`cap_sigs` are PLURAL (GUIDE-CONFORMANCE §7a.1, 0.8.2.19) so a K-of-N root
can present every granter identity and every link signature. Every member goes into
`included` because §5.5's chain walk resolves granters and signers BY HASH out of that map.

`cred === nothing` is the AMBIENT arm: the EXECUTE carries no `capability` field at all. An
empty hash would NOT do — that is a present field resolving to nothing, which §5.2 reads as
an unresolvable capability rather than as its absence."""
function build_reentry_execute(p::Peer_t, conn::Conn, target::AbstractString,
                               rel_target::AbstractString, operation::AbstractString,
                               inner::Entity, cred, granters::Vector{Entity},
                               cap_sigs::Vector{Entity})::Envelope
    conn.out_counter += 1
    rid = "ro-$(conn.out_counter)"
    resource = CborMap(Pair[("targets" => Any["system/handler/$(rel_target)"])])
    exec = cred === nothing ?
        make_execute(request_id=rid, uri=String(target), operation=String(operation), params=inner,
                     author=p.identity.peer_entity.hash) :
        make_execute(request_id=rid, uri=String(target), operation=String(operation), params=inner,
                     author=p.identity.peer_entity.hash, capability=cred.hash)
    # attach the resource-target field (make_execute doesn't carry it; rebuild with it)
    exec = attach_resource(exec, resource)
    exec_sig = sign_entity(p.identity, exec)
    inc = Inc[]
    if cred !== nothing
        push!(inc, cred.hash => cred)
        for g in granters; push!(inc, g.hash => g); end
        for sg in cap_sigs; push!(inc, sg.hash => sg); end
    end
    push!(inc, exec_sig.hash => exec_sig)
    return Envelope(exec, inc)
end

# Rebuild an EXECUTE entity adding a `resource` field (kept immutable-friendly).
function attach_resource(exec::Entity, resource::CborMap)::Entity
    ps = copy(exec.data.pairs)
    push!(ps, Pair{Any,Any}("resource", resource))
    return make_entity(exec.typ, CborMap(ps))
end

function conformance_handler(p::Peer_t, conn::Conn, env::Envelope, exec::Entity, stripped::AbstractString)::HandlerResult
    stripped == "system/validate/echo" && return echo_handler(exec)
    # §1.4 PD-2 needs the OWNING handler's peer-relative pattern (Dimension 1 is matched
    # peer-relative) and the parent envelope (the §7a.2a bundle base).
    stripped == "system/validate/dispatch-outbound" &&
        return dispatch_outbound_handler(p, conn, env, exec, stripped)
    return err(501, "no_handler_body")
end

# ── dispatcher-level signature ingestion (§6.5) ───────────────────────────────────────
function ingest_signatures(p::Peer_t, env::Envelope)
    for (_, e) in env.included
        e.typ == "system/signature" || continue
        store_put!(p.store, e)
        signer_h = bytesfield(e, "signer"); signer_h === nothing && continue
        signer_peer = included_get(env, signer_h); signer_peer === nothing && continue
        store_put!(p.store, signer_peer)
        target = bytesfield(e, "target"); target === nothing && continue
        pk = bytesfield(signer_peer, "public_key"); pk === nothing && continue
        pid = peerid_of_pubkey(pk)
        store_bind!(p.store, "/$(pid)/system/signature/$(bytes2hex(target))", e)
    end
    return nothing
end

# ── handler resolution (§6.6) — backward tree-walk over store-bound system/handler ────
function resolve_handler(p::Peer_t, path::AbstractString)
    seg = path
    while true
        e = store_at(p.store, seg)
        (e !== nothing && e.typ == "system/handler") && return seg
        i = findlast('/', seg)
        i === nothing && break
        seg = seg[1:prevind(seg, i)]
    end
    return nothing
end

function strip_local(p::Peer_t, pattern::AbstractString)
    prefix = "/" * p.peer_id * "/"
    startswith(pattern, prefix) && return pattern[nextind(pattern, lastindex(prefix)):end]
    return pattern
end

# §6.11 reentry seam.
make_reenter(conn::Conn) = conn.outbound

# ── the dispatch chain (§6.5) ─────────────────────────────────────────────────────────
function dispatch_outcome(p::Peer_t, conn::Conn, env::Envelope)::HandlerResult
    exec = env.root
    uri = textfield(exec, "uri"); uri = uri === nothing ? "" : uri
    uri == "system/protocol/connect" && return connect_handler(p, conn, exec, env)   # §4.2 pre-auth

    ingest_signatures(p, env)
    # §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to
    # sit below the verdict, so a pre-establishment EXECUTE naming a FOREIGN namespace took
    # the 401 an unauthenticated request takes. §4.7's own reason: "a 401 directs the caller
    # to authenticate and retry, and for a foreign-namespace address that retry cannot
    # succeed at any authentication state — so the 401 names a remedy that does not exist."
    # §6.5 step 3 calls it "a gate, not an ordering preference" and §1.4 makes the downstream
    # permission check unreachable here.
    path = canonicalize(p.peer_id, Capability.normalize_uri(uri))
    extract_peer(p.peer_id, path) == p.peer_id || return err(400, "invalid_request")

    v = verify_request(env, p.store, p.peer_id)                # §6.5: AUTH BEFORE RESOLVE (F31)
    v == :authn_fail && return err(401, "authentication_failed")
    v == :unresolvable && return err(401, "unresolvable_grantee")
    v == :chain_too_deep && return err(400, "chain_depth_exceeded")
    v == :authz_deny && return err(403, "capability_denied")

    # (The §1.4 address gate that used to sit here has moved ABOVE the verdict — §4.7
    # 0.8.2.6 orders it before authentication. Reaching this line means the path is local.)
    pattern = resolve_handler(p, path)
    pattern === nothing && return err(404, "handler_not_found")

    cap_h = bytesfield(exec, "capability")
    caller_cap = cap_h === nothing ? nothing : included_get(env, cap_h)
    caller_cap === nothing && return err(403, "capability_denied")
    gframe = granter_frame(env, p.store, p.peer_id, caller_cap)
    check_permission(p.peer_id, gframe, exec, caller_cap, pattern) == :allow || return err(403, "capability_denied")

    stripped = strip_local(p, pattern)
    # `pattern` (not `stripped`) is the OWNING handler's pattern §6.3 asks for
    # (0.8.2.23): owner and runner coincide for the tree handler, so the distinction is
    # not observable here, but the value passed is the owner's because that is what the
    # parameter means. CARRIED from the dispatch check that already computed it and the
    # capability it already resolved, never recomputed — recomputing invites the two to
    # drift, and §6.8 is explicit that the authority is selected by who named the path.
    stripped == "system/tree" &&
        return tree_handler(p, exec; caller_cap, handler_pattern = pattern)
    stripped == "system/capability" && return capability_handler(p, env, exec, caller_cap)
    stripped == "system/handler" && return handlers_handler(p, exec)
    stripped == "system/type" && return type_handler(exec)
    if p.validate && startswith(stripped, "system/validate/")
        return conformance_handler(p, conn, env, exec, stripped)
    end
    # a dynamically-registered handler: dispatch its entity-native body (§6.13(a)).
    #
    # THE ENTITY-NATIVE PATH ANSWERS FIRST, and the discriminator is `expression_path`
    # rather than a status code. `core_register_body_binding` drives this branch on all 46
    # peers by binding a handler entity that CARRIES an expression; an in-process install
    # binds one that does not. So "has an expression_path" separates the two exactly, and
    # a 501 from a handler that DOES have one is a real refusal that must not silently
    # fall through to something else (checking `status == 501` would do precisely that).
    he = store_at(p.store, pattern)
    if he !== nothing && he.typ == "system/handler" && textfield(he, "expression_path") !== nothing
        return entity_native_dispatch(p, he)
    end

    # §6.13 HOST SEAM — a community-installed callable, consulted here and NOWHERE EARLIER.
    #
    # `register_handler!` is exported and `p.handlers` is a typed Dict with a documented
    # contract in handler.jl — `(ctx::HandlerContext) -> HandlerResult` — and until now
    # NOTHING READ THE DICT. It was written once, never consulted, and dispatch went
    # straight from the entity-native body to 501. That is the dangerous shape: an
    # exported entry point, a typed container and a doc comment naming it the seam, all
    # of which read as satisfied from every artifact a reviewer would open.
    #
    # ORDER IS LOAD-BEARING AND IT IS THE typescript H7 RULE: the built-in handlers above
    # and the §6.13(a) entity-native path answer FIRST, and the seam takes the FALLBACK
    # arm. `core_register_body_binding` drives the entity-native branch on all 46 peers,
    # so consulted BEFORE it an installed callable would silently own a check the peer is
    # measured on; consulted after, a peer with nothing installed is byte-identical to the
    # peer before this seam existed.
    h = get(p.handlers, stripped, nothing)
    if h !== nothing
        author = let a = bytesfield(exec, "author")
            a === nothing ? nothing : included_get(env, a)
        end
        return h(HandlerContext(p, conn, exec, env, author, make_reenter(conn)))
    end
    return err(501, "no_handler_body")
end

"""Dispatch one inbound EXECUTE → an owned response Envelope.

EVERY inbound root reaching here is ANSWERED — the `nothing` this used to return for a
non-EXECUTE root is gone (0.8.2.25, N12/N17). The return type stays nullable so the
transport's write guard keeps its shape. Any handler fault is caught → 500 (connection
stays up)."""
function dispatch(p::Peer_t, conn::Conn, env::Envelope)::Union{Nothing,Envelope}
    exec = env.root
    if exec.typ != "system/protocol/execute"
        # §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17):
        # "400 invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare
        # close — that is indistinguishable from a network fault."
        #
        # §3.3 read "the connection MUST be closed", assigning no code and requiring no
        # frame, and this peer did something weaker still: it returned `nothing` and the
        # reader wrote NOTHING while keeping the connection open, which is §4.11's other
        # non-conformant behaviour — the silent drop, "the weaker of the two precisely
        # because nothing surfaces it". This is a PRE-ADMISSION refusal: the root is not
        # an EXECUTE, so nothing was ever admitted and §4.9(c) does not reach it.
        #
        # request_id is read BEST-EFFORT. An arbitrary root type is under no obligation
        # to carry one, and §4.11 licenses the uncorrelated frame exactly there. We do
        # NOT close: on a multiplexed connection that would cost every ADMITTED in-flight
        # request its response, and §4.11 leaves the close to us.
        rid = let r = textfield(exec, "request_id"); r === nothing ? "" : r end
        st, res, inc = err(400, "invalid_request",
                           "root entity is neither EXECUTE nor EXECUTE_RESPONSE")
        return Envelope(make_response(request_id=rid, status=st, result=res), inc)
    end
    rid = textfield(exec, "request_id"); rid = rid === nothing ? "" : rid
    status, result, included = try
        dispatch_outcome(p, conn, env)
    catch e
        e isa InterruptException && rethrow()
        (500, error_result("internal_error"), NO_INCLUDED)
    end
    return Envelope(make_response(request_id=rid, status=status, result=result), included)
end

# ── bootstrap (§6.9 / §6.9a) ──────────────────────────────────────────────────────────
struct BootHandler
    pattern::String
    name::String
    operations::Vector{String}
end

const BOOTSTRAP_HANDLERS = BootHandler[
    BootHandler("system/tree", "Tree", ["get", "put"]),
    BootHandler("system/handler", "Handlers", ["register", "unregister"]),
    BootHandler("system/type", "Types", String[]),
    BootHandler("system/capability", "Capability", ["request", "delegate", "revoke"]),
    BootHandler("system/protocol/connect", "Connect", ["hello", "authenticate"])]

const CONFORMANCE_HANDLERS = BootHandler[
    BootHandler("system/validate/echo", "validate-echo", ["echo"]),
    BootHandler("system/validate/dispatch-outbound", "validate-dispatch-outbound", ["dispatch"])]

# operations map: {op_name → operation-spec DATA map (empty)}.
operations_map(ops::Vector{String}) = CborMap(Pair[(String(o) => CborMap(Pair[])) for o in ops])

"""A handler's OWN grant (§6.8) — the authority it spends when it dispatches onward, as
distinct from any capability a caller presents. §6.8 row 1: an access in service of a
caller's request needs the caller's verified capability AND this grant, and BOTH must
pass. Narrow for `dispatch-outbound`; empty for everything else."""
function own_grants_for(pattern::AbstractString)::Vector{Any}
    pattern == "system/validate/dispatch-outbound" || return Any[]
    scope(v) = CborMap(Pair[("include" => Any[v])])
    return Any[CborMap(Pair[("handlers" => scope("system/validate/echo")),
                            ("operations" => scope("echo")),
                            ("resources" => scope("system/handler/system/validate/echo"))])]
end

function bootstrap_handler!(p::Peer_t, bh::BootHandler)
    handler_e = make_entity("system/handler", CborMap(Pair[("interface" => "system/handler/$(bh.pattern)")]))
    store_bind!(p.store, "/$(p.peer_id)/$(bh.pattern)", handler_e)
    iface_e = make_entity("system/handler/interface",
        CborMap(Pair[("pattern" => bh.pattern), ("name" => bh.name),
                     ("operations" => operations_map(bh.operations))]))
    store_bind!(p.store, "/$(p.peer_id)/system/handler/$(bh.pattern)", iface_e)
    # §6.8: the grant MUST exist at `system/capability/grants/{pattern}` and a handler with
    # no valid grant does not run — so this bind is the ceiling row 1 intersects against,
    # not bookkeeping. NARROW for dispatch-outbound (GUIDE-CONFORMANCE §7a.1).
    token, _ = mint_token(p, p.identity.peer_entity.hash, nothing, own_grants_for(bh.pattern))
    store_bind!(p.store, "/$(p.peer_id)/system/capability/grants/$(bh.pattern)", token)
    return nothing
end

function create_peer(seed::AbstractVector{UInt8}; validate::Bool=false, open_grants::Bool=false)::Peer_t
    id = peer_identity(seed)
    st = ContentStore()
    p = Peer_t(id, id.peer_id, st, Dict{String,Function}(), validate, open_grants)

    # local identity entity (root-granter resolution + §3.13 self)
    store_put!(p.store, id.peer_entity)
    store_bind!(p.store, "/$(p.peer_id)/system/peer/self", id.peer_entity)

    # §9.5 core types
    publish_types!(p.store, p.peer_id)

    # bootstrap the MUST handlers (§6.2) + the §7a scaffolding when --validate.
    for bh in BOOTSTRAP_HANDLERS; bootstrap_handler!(p, bh); end
    if validate
        for bh in CONFORMANCE_HANDLERS; bootstrap_handler!(p, bh); end
    end

    # §6.9a peer-authority bootstrap: self-owner cap + default policy entry.
    policy_base = "/$(p.peer_id)/system/capability/policy/"
    owner, owner_sig = mint_token(p, id.peer_entity.hash, nothing, owner_grants(p.peer_id))
    store_bind!(p.store, policy_base * bytes2hex(id.peer_entity.hash), owner)
    store_bind!(p.store, "/$(p.peer_id)/system/signature/$(bytes2hex(owner.hash))", owner_sig)

    default_grants = open_grants ? open_grants_scope() : discovery_floor()
    default_entry = make_entity("system/capability/policy-entry",
        CborMap(Pair[("peer_pattern" => "default"), ("grants" => default_grants)]))
    store_bind!(p.store, policy_base * "default", default_entry)

    return p
end

"""Install a community handler at `pattern` (the extension seam)."""
#     register_handler!(p, pattern, h; operations=String[], name=pattern)
#
# Install a community handler at `pattern` (§6.13 host seam). `h` is any callable
# `(ctx::HandlerContext) -> HandlerResult` — the contract in `handler.jl`.
#
# BINDS THE §3.7 ENTITIES AS WELL AS THE CALLABLE, and that is the half that was missing.
# Writing the Dict alone left the handler UNREACHABLE by construction: §6.6 resolution
# walks the store for a `system/handler` entity, so a pattern with no entity bound answers
# `404 handler_not_found` and dispatch never reaches the map at all. The map was written
# once, read never, and every artifact a reviewer would open — an exported function, a
# typed `Dict{String,Function}`, a doc comment naming it the seam — read as satisfied.
#
# This is the same work the WIRE `system/handler:register` op does, and the two agree
# deliberately: an in-process install and a wire install must produce the same peer, or
# the in-process surface is a narrower one and the wire one is the only one under test.
function register_handler!(p::Peer_t, pattern::AbstractString, h::Function;
                           operations::Vector{String}=String[],
                           name::AbstractString=String(pattern))
    pat = String(pattern)
    p.handlers[pat] = h
    handler_e = make_entity("system/handler", CborMap(Pair[("interface" => "system/handler/$(pat)")]))
    store_bind!(p.store, "/$(p.peer_id)/$(pat)", handler_e)
    iface_e = make_entity("system/handler/interface",
        CborMap(Pair[("pattern" => pat), ("name" => String(name)),
                     ("operations" => operations_map(operations))]))
    store_bind!(p.store, "/$(p.peer_id)/system/handler/$(pat)", iface_e)
    return nothing
end

end # module Peer
