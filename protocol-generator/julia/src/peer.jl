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
                    matches_pattern
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
    ps = Pair[("granter" => p.identity.peer_entity.hash),
              ("grantee" => Vector{UInt8}(grantee_hash)),
              ("grants" => grants),
              ("created_at" => now_ms())]
    parent === nothing || push!(ps, "parent" => Vector{UInt8}(parent))
    token = make_entity("system/capability/token", CborMap(ps))
    store_put!(p.store, token)
    sig = sign_entity(p.identity, token)
    store_put!(p.store, sig)
    return token, sig
end

# ── helpers ───────────────────────────────────────────────────────────────────────────
err(status::Int, code::AbstractString)::HandlerResult = (status, error_result(code), NO_INCLUDED)
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
        params = entityfield(exec, "params")
        if params !== nothing
            negotiation_reject(params, "hash_formats", "ecfv1-sha256") && return err(400, "incompatible_hash_format")
            negotiation_reject(params, "key_types", "ed25519") && return err(400, "unsupported_key_type")
            pid = textfield(params, "peer_id")
            pid !== nothing && (conn.hello_peer_id = pid)
        end
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
        conn.established && return err(409, "connection_already_established")
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
    return err(501, "unsupported_operation")
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

function build_listing(p::Peer_t, path::AbstractString)::HandlerResult
    entries = store_listing(p.store, path)
    entry_pairs = Pair[]
    emitted = 0
    for le in entries
        # §6.3 CORE-TREE-DELETE-1: a leaf bound to a deletion-marker is a tombstone.
        if le.hash !== nothing
            bound = store_get(p.store, le.hash)
            bound !== nothing && bound.typ == "system/deletion-marker" && continue
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

function tree_handler(p::Peer_t, exec::Entity)::HandlerResult
    op = textfield(exec, "operation"); op = op === nothing ? "" : op
    target = resource_target(exec)
    if (op == "get" || op == "put") && target !== nothing && !path_flex_ok(target)
        return err(400, "invalid_path")
    end
    if op == "get"
        if target === nothing
            return build_listing(p, "/$(p.peer_id)/")
        end
        if isempty(target) || endswith(target, "/")
            return build_listing(p, canonicalize(p.peer_id, target))
        end
        path = canonicalize(p.peer_id, target)
        e = store_at(p.store, path)
        e === nothing && return err(404, "not_found")
        params = entityfield(exec, "params")
        if params !== nothing
            m = textfield(params, "mode")
            m == "hash" && return okr(make_entity("system/hash", e.hash))
        end
        return okr(e)
    elseif op == "put"
        target === nothing && return err(400, "ambiguous_resource")
        path = canonicalize(p.peer_id, target)
        params = entityfield(exec, "params")
        entity = params === nothing ? nothing : entityfield(params, "entity")
        expected = params === nothing ? nothing : bytesfield(params, "expected_hash")
        current = store_hash_at(p.store, path)
        if expected !== nothing
            zero33 = zeros(UInt8, 33)
            cas_ok = expected == zero33 ? current === nothing : (current !== nothing && current == expected)
            cas_ok || return err(409, "hash_mismatch")
        end
        entity === nothing && return err(400, "unexpected_params")
        store_bind!(p.store, path, entity)
        return okr(make_entity("system/hash", entity.hash))
    end
    return err(501, "unsupported_operation")
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
function mint_bounded(p::Peer_t, caller_cap, params, grantee_hash::AbstractVector{UInt8},
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
    token, sig = mint_token(p, grantee_hash, parent, req_grants_raw(params))
    grant = make_entity("system/capability/grant", CborMap(Pair[("token" => token.hash)]))
    inc = Inc[token.hash => token,
              p.identity.peer_entity.hash => p.identity.peer_entity,
              sig.hash => sig]
    return okr(grant, inc)
end

function capability_handler(p::Peer_t, exec::Entity, caller_cap)::HandlerResult
    op = textfield(exec, "operation"); op = op === nothing ? "" : op
    params = entityfield(exec, "params")
    author = bytesfield(exec, "author")
    if op == "request"
        author === nothing && return err(403, "capability_denied")
        return mint_bounded(p, caller_cap, params, author, nothing)
    elseif op == "delegate"
        parent = params === nothing ? nothing : bytesfield(params, "parent")
        (parent === nothing) && return err(400, "unexpected_params")
        is_zero_hash(parent) && return err(400, "unexpected_params")
        (author === nothing || author != p.identity.peer_entity.hash) && return err(501, "unsupported_operation")
        return mint_bounded(p, caller_cap, params, author, parent)
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

function register_handler_op(p::Peer_t, exec::Entity)::HandlerResult
    pattern, e = register_pattern(exec)
    pattern === nothing && return e
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

"""§7a system/validate/dispatch-outbound: originate one outbound EXECUTE via the §6.11
reentry seam back to the caller and return the downstream response (proves the target can
ORIGINATE). The reentry authority is caller-minted, carried in-band."""
function dispatch_outbound_handler(p::Peer_t, conn::Conn, exec::Entity)::HandlerResult
    out_fn = conn.outbound
    out_fn === nothing && return err(503, "no_outbound_seam")
    params = entityfield(exec, "params")
    params === nothing && return err(400, "unexpected_params")
    target = textfield(params, "target"); target === nothing && return err(400, "unexpected_params")
    operation = textfield(params, "operation"); operation === nothing && return err(400, "unexpected_params")
    value = efield(params, "value"); value === nothing && return err(400, "unexpected_params")
    cap_e = entityfield(params, "reentry_capability"); cap_e === nothing && return err(400, "unexpected_params")
    granter_e = entityfield(params, "reentry_granter"); granter_e === nothing && return err(400, "unexpected_params")
    capsig_e = entityfield(params, "reentry_cap_signature"); capsig_e === nothing && return err(400, "unexpected_params")

    # §7a.1: `value` IS the outbound params entity data — pass it through (no re-wrap).
    inner = make_entity("primitive/any", value)
    req = build_reentry_execute(p, conn, target, operation, inner, cap_e, granter_e, capsig_e)
    resp = out_fn(req)
    resp === nothing && return err(504, "outbound_timeout")
    status = uintfield(resp.root, "status"); status = status === nothing ? 0 : status
    result = efield(resp.root, "result"); result === nothing && (result = nothing)
    out = make_entity("primitive/any", CborMap(Pair[("status" => status), ("result" => result)]))
    return okr(out)
end

function build_reentry_execute(p::Peer_t, conn::Conn, target::AbstractString, operation::AbstractString,
                               inner::Entity, cap_e::Entity, granter_e::Entity, capsig_e::Entity)::Envelope
    conn.out_counter += 1
    rid = "ro-$(conn.out_counter)"
    resource = CborMap(Pair[("targets" => Any["system/handler/$(target)"])])
    exec = make_execute(request_id=rid, uri=String(target), operation=String(operation), params=inner,
                        author=p.identity.peer_entity.hash, capability=cap_e.hash)
    # attach the resource-target field (make_execute doesn't carry it; rebuild with it)
    exec = attach_resource(exec, resource)
    exec_sig = sign_entity(p.identity, exec)
    inc = Inc[cap_e.hash => cap_e, granter_e.hash => granter_e,
              capsig_e.hash => capsig_e, exec_sig.hash => exec_sig]
    return Envelope(exec, inc)
end

# Rebuild an EXECUTE entity adding a `resource` field (kept immutable-friendly).
function attach_resource(exec::Entity, resource::CborMap)::Entity
    ps = copy(exec.data.pairs)
    push!(ps, Pair{Any,Any}("resource", resource))
    return make_entity(exec.typ, CborMap(ps))
end

function conformance_handler(p::Peer_t, conn::Conn, exec::Entity, stripped::AbstractString)::HandlerResult
    stripped == "system/validate/echo" && return echo_handler(exec)
    stripped == "system/validate/dispatch-outbound" && return dispatch_outbound_handler(p, conn, exec)
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
    v = verify_request(env, p.store, p.peer_id)                # §6.5: AUTH BEFORE RESOLVE (F31)
    v == :authn_fail && return err(401, "authentication_failed")
    v == :unresolvable && return err(401, "unresolvable_grantee")
    v == :chain_too_deep && return err(400, "chain_depth_exceeded")
    v == :authz_deny && return err(403, "capability_denied")

    path = canonicalize(p.peer_id, Capability.normalize_uri(uri))
    tp = extract_peer(p.peer_id, path)
    tp == p.peer_id || return err(404, "handler_not_found")     # §1.4 must target local peer
    pattern = resolve_handler(p, path)
    pattern === nothing && return err(404, "handler_not_found")

    cap_h = bytesfield(exec, "capability")
    caller_cap = cap_h === nothing ? nothing : included_get(env, cap_h)
    caller_cap === nothing && return err(403, "capability_denied")
    gframe = granter_frame(env, p.store, p.peer_id, caller_cap)
    check_permission(p.peer_id, gframe, exec, caller_cap, pattern) == :allow || return err(403, "capability_denied")

    stripped = strip_local(p, pattern)
    stripped == "system/tree" && return tree_handler(p, exec)
    stripped == "system/capability" && return capability_handler(p, exec, caller_cap)
    stripped == "system/handler" && return handlers_handler(p, exec)
    stripped == "system/type" && return type_handler(exec)
    if p.validate && startswith(stripped, "system/validate/")
        return conformance_handler(p, conn, exec, stripped)
    end
    # a dynamically-registered handler: dispatch its entity-native body (§6.13(a)).
    he = store_at(p.store, pattern)
    (he !== nothing && he.typ == "system/handler") && return entity_native_dispatch(p, he)
    return err(501, "no_handler_body")
end

"""Dispatch one inbound EXECUTE → an owned response Envelope; a non-EXECUTE root is
ignored (`nothing`, §3.3). Any handler fault is caught → 500 (connection stays up)."""
function dispatch(p::Peer_t, conn::Conn, env::Envelope)::Union{Nothing,Envelope}
    exec = env.root
    exec.typ == "system/protocol/execute" || return nothing
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

function bootstrap_handler!(p::Peer_t, bh::BootHandler)
    handler_e = make_entity("system/handler", CborMap(Pair[("interface" => "system/handler/$(bh.pattern)")]))
    store_bind!(p.store, "/$(p.peer_id)/$(bh.pattern)", handler_e)
    iface_e = make_entity("system/handler/interface",
        CborMap(Pair[("pattern" => bh.pattern), ("name" => bh.name),
                     ("operations" => operations_map(bh.operations))]))
    store_bind!(p.store, "/$(p.peer_id)/system/handler/$(bh.pattern)", iface_e)
    token, _ = mint_token(p, p.identity.peer_entity.hash, nothing, Any[])
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
register_handler!(p::Peer_t, pattern::AbstractString, h::Function) = (p.handlers[String(pattern)] = h)

end # module Peer
