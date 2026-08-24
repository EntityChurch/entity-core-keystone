# Core type floor (V8 §9.5) — render-from-model (S4).
#
# The peer publishes its 53 core `system/type/<name>` entities at
# `/{peer}/system/type/{name}`. Each type's data is rendered NATIVELY from an in-code
# declaration here (the single source of truth) through the byte-green S2 codec; the
# resulting content_hash is byte-identical to the Go-rendered
# `type-registry-vectors-v1.cbor` set (the S8 drift target, checked by
# test/typedefs_bytecheck.jl). This is the render-from-model design every peer follows
# (mirrors Zig type_defs.zig / C# CoreTypeRegistry / TS core-type-registry.ts) — the
# profile's "render natively, don't ingest oracle bytes" durable lesson.
#
# Scope is core + operational + type-system bootstrap ONLY — 53 types. Extension
# vocabularies (compute/*, content/*, subscription/*, …) are NOT published by a core
# peer. The oracle's type_system category matches the 53 floor as a hard FAIL gate and
# WARNs (matched-if-present) on the non-floor types it also probes.
#
# Omit-empty semantics: an absent/false field drops the key, so the rendered ECF map is
# byte-identical to the Go reference encoder. The S2 codec sorts map keys canonically
# (RFC 8949 §4.2.1), so declaration order here is irrelevant to the bytes.
module TypeDefs

using ..Cbor: CborMap
using ..Model: Entity, make_entity
using ..Store: ContentStore, store_put!

export publish_types!, all_type_entities, CORE_TYPE_COUNT

# ── field-spec builders (system/type/field-spec shape, omit-empty) ────────────────────
# A field-spec is a CborMap; exactly the set keys present are rendered. Modifiers copy.
_addkey(m::CborMap, k, v) = CborMap(vcat(m.pairs, Pair{Any,Any}[Pair{Any,Any}(k, v)]))

fref(t::AbstractString)            = CborMap(Pair[("type_ref" => String(t))])
opt(s::CborMap)                    = _addkey(s, "optional", true)
sized(s::CborMap, n::Integer)      = _addkey(s, "byte_size", Int(n))
farray(elem::CborMap)              = CborMap(Pair[("array_of" => elem)])
fmap(value::CborMap)               = CborMap(Pair[("map_of" => value)])
fmap(value::CborMap, kt::AbstractString) = CborMap(Pair[("map_of" => value), ("key_type" => String(kt))])
funion(variants::Vector{CborMap})  = CborMap(Pair[("union_of" => Any[v for v in variants])])

# ── type-def builder (system/type entity data, omit-empty) ────────────────────────────
# fields: Vector of (name::String => field-spec::CborMap); layout: Vector{String}.
function type_data(name::AbstractString;
                   extends::Union{Nothing,AbstractString}=nothing,
                   fields=nothing,
                   layout::Union{Nothing,Vector{String}}=nothing)::CborMap
    ps = Pair[("name" => String(name))]
    extends === nothing || push!(ps, "extends" => String(extends))
    if fields !== nothing && !isempty(fields)
        fps = Pair[(String(k) => v) for (k, v) in fields]
        push!(ps, "fields" => CborMap(fps))
    end
    layout === nothing || isempty(layout) || push!(ps, "layout" => Any[s for s in layout])
    return CborMap(ps)
end

type_entity(name; kwargs...) = make_entity("system/type", type_data(name; kwargs...))

# reused nested specs
const sp_string        = fref("primitive/string")
const sp_any           = fref("primitive/any")
const sp_bytes         = fref("primitive/bytes")
const sp_uint          = fref("primitive/uint")
const sp_hash          = fref("system/hash")
const sp_core_entity   = fref("core/entity")
const sp_tree_path     = fref("system/tree/path")
const sp_type_name     = fref("system/type/name")
const sp_grant_entry   = fref("system/capability/grant-entry")
const sp_field_spec    = fref("system/type/field-spec")
const sp_op_spec       = fref("system/handler/operation-spec")
const sp_listing_entry = fref("system/tree/listing-entry")
const sp_type          = fref("system/type")
const sp_multi_granter = fref("system/capability/multi-granter")

# ── the 53 core type definitions (faithful port of the cross-blessed registry) ────────
function all_type_entities()::Vector{Entity}
    T = Entity[]
    push!(T,
        # primitives (8)
        type_entity("primitive/any"),
        type_entity("primitive/bool"),
        type_entity("primitive/bytes"),
        type_entity("primitive/float"),
        type_entity("primitive/int"),
        type_entity("primitive/null"),
        type_entity("primitive/string"),
        type_entity("primitive/uint"),

        # structural roots + envelopes (5)
        type_entity("entity"; fields=[
            "type" => fref("primitive/string"),
            "data" => fref("primitive/any")]),
        type_entity("core/entity"; fields=[
            "type" => fref("primitive/string"),
            "data" => fref("primitive/any"),
            "content_hash" => fref("system/hash")]),
        type_entity("core/envelope"; fields=[
            "root" => fref("core/entity"),
            "included" => opt(fmap(sp_core_entity, "system/hash"))]),
        type_entity("system/envelope"; extends="core/envelope"),
        type_entity("system/protocol/envelope"; extends="core/envelope"),

        # identity / hash / signature (4)
        type_entity("system/hash"; extends="primitive/bytes", fields=[
            "format_code" => sized(fref("primitive/uint"), 1),
            "digest" => fref("primitive/bytes")], layout=["format_code", "digest"]),
        type_entity("system/peer"; fields=[
            "key_type" => fref("primitive/string"),
            "peer_id" => fref("system/peer-id"),
            "public_key" => fref("primitive/bytes")]),
        type_entity("system/peer-id"; extends="primitive/string"),
        type_entity("system/signature"; fields=[
            "algorithm" => fref("primitive/string"),
            "signature" => fref("primitive/bytes"),
            "signer" => fref("system/hash"),
            "target" => fref("system/hash")]),

        # protocol surface (6)
        type_entity("system/protocol/connect/authenticate"; fields=[
            "key_type" => fref("primitive/string"),
            "nonce" => fref("primitive/bytes"),
            "peer_id" => fref("system/peer-id"),
            "public_key" => fref("primitive/bytes")]),
        type_entity("system/protocol/connect/hello"; fields=[
            "protocols" => farray(sp_string),
            "nonce" => fref("primitive/bytes"),
            "peer_id" => fref("system/peer-id"),
            "timestamp" => fref("primitive/uint"),
            "compression" => opt(farray(sp_string)),
            "encryption" => opt(farray(sp_string)),
            "hash_formats" => opt(farray(sp_string)),
            "key_types" => opt(farray(sp_string))]),
        type_entity("system/protocol/error"; fields=[
            "code" => fref("primitive/string"),
            "message" => opt(fref("primitive/string")),
            "rejected_marker" => opt(fref("system/hash"))]),
        type_entity("system/protocol/execute"; fields=[
            "operation" => fref("primitive/string"),
            "params" => fref("core/entity"),
            "request_id" => fref("primitive/string"),
            "uri" => fref("system/tree/path"),
            "author" => opt(fref("system/hash")),
            "bounds" => opt(fref("system/bounds")),
            "capability" => opt(fref("system/hash")),
            "deliver_to" => opt(fref("system/delivery-spec")),
            "deliver_token" => opt(fref("system/hash")),
            "durability_request" => opt(fref("system/durability-request")),
            "resource" => opt(fref("system/protocol/resource-target"))]),
        type_entity("system/protocol/execute/response"; fields=[
            "request_id" => fref("primitive/string"),
            "result" => fref("core/entity"),
            "status" => fref("primitive/uint"),
            "durability" => opt(fref("system/durability-result"))]),
        type_entity("system/protocol/resource-target"; fields=[
            "targets" => farray(sp_tree_path),
            "exclude" => opt(farray(sp_tree_path))]),

        # capability (12)
        type_entity("system/capability/grant"; fields=[
            "token" => fref("system/hash")]),
        type_entity("system/capability/grant-entry"; fields=[
            "handlers" => fref("system/capability/path-scope"),
            "operations" => fref("system/capability/id-scope"),
            "resources" => fref("system/capability/path-scope"),
            "allowances" => opt(fmap(sp_any)),
            "constraints" => opt(fmap(sp_any)),
            "peers" => opt(fref("system/capability/id-scope"))]),
        type_entity("system/capability/id-scope"; fields=[
            "include" => farray(sp_string),
            "exclude" => opt(farray(sp_string))]),
        type_entity("system/capability/path-scope"; fields=[
            "include" => farray(sp_tree_path),
            "exclude" => opt(farray(sp_tree_path))]),
        type_entity("system/capability/request"; fields=[
            "grants" => farray(sp_grant_entry),
            "ttl_ms" => opt(fref("primitive/uint"))]),
        type_entity("system/capability/revocation"; fields=[
            "token" => fref("system/hash"),
            "revoked_at" => fref("primitive/uint"),
            "reason" => opt(fref("primitive/string"))]),
        type_entity("system/capability/revoke-request"; fields=[
            "token" => fref("system/hash"),
            "reason" => opt(fref("primitive/string"))]),
        type_entity("system/capability/delegate-request"; fields=[
            "grants" => farray(sp_grant_entry),
            "parent" => fref("system/hash"),
            "ttl_ms" => opt(fref("primitive/uint"))]),
        type_entity("system/capability/delegation-caveats"; fields=[
            "max_delegation_depth" => opt(fref("primitive/uint")),
            "max_delegation_ttl" => opt(fref("primitive/uint")),
            "no_delegation" => opt(fref("primitive/bool"))]),
        type_entity("system/capability/policy-entry"; fields=[
            "grants" => farray(sp_grant_entry),
            "peer_pattern" => fref("primitive/string"),
            "notes" => opt(fref("primitive/string")),
            "ttl_ms" => opt(fref("primitive/uint"))]),
        type_entity("system/capability/token"; fields=[
            "created_at" => fref("primitive/uint"),
            "grantee" => fref("system/hash"),
            "granter" => funion(CborMap[sp_hash, sp_multi_granter]),
            "grants" => farray(sp_grant_entry),
            "delegation_caveats" => opt(fref("system/capability/delegation-caveats")),
            "expires_at" => opt(fref("primitive/uint")),
            "not_before" => opt(fref("primitive/uint")),
            "parent" => opt(fref("system/hash")),
            "resource_limits" => opt(fref("system/resource-limits"))]),
        type_entity("system/capability/multi-granter"; fields=[
            "signers" => farray(sp_hash),
            "threshold" => fref("primitive/uint")]),

        # handler machinery (6)
        type_entity("system/handler"; fields=[
            "interface" => fref("system/tree/path"),
            "expression_path" => opt(fref("system/tree/path")),
            "internal_scope" => opt(farray(sp_grant_entry)),
            "max_scope" => opt(farray(sp_grant_entry))]),
        type_entity("system/handler/interface"; fields=[
            "name" => fref("primitive/string"),
            "operations" => fmap(sp_op_spec),
            "pattern" => fref("system/tree/path")]),
        type_entity("system/handler/manifest"; extends="system/handler/interface", fields=[
            "name" => fref("primitive/string"),
            "operations" => fmap(sp_op_spec),
            "pattern" => fref("system/tree/path"),
            "expression_path" => opt(fref("system/tree/path")),
            "internal_scope" => opt(farray(sp_grant_entry)),
            "max_scope" => opt(farray(sp_grant_entry))]),
        type_entity("system/handler/operation-spec"; fields=[
            "input_type" => opt(fref("system/type/name")),
            "output_type" => opt(fref("system/type/name"))]),
        type_entity("system/handler/register-request"; fields=[
            "manifest" => fref("system/handler/manifest"),
            "requested_scope" => opt(farray(sp_grant_entry)),
            "types" => opt(fmap(sp_type))]),
        type_entity("system/handler/register-result"; fields=[
            "grant" => fref("system/capability/token"),
            "pattern" => fref("system/tree/path")]),

        # tree (5)
        type_entity("system/tree/get-request"; fields=[
            "limit" => opt(fref("primitive/uint")),
            "mode" => opt(fref("primitive/string")),
            "offset" => opt(fref("primitive/uint")),
            "tree_id" => opt(fref("primitive/string"))]),
        type_entity("system/tree/put-request"; fields=[
            "entity" => opt(fref("core/entity")),
            "expected_hash" => opt(fref("system/hash")),
            "tree_id" => opt(fref("primitive/string"))]),
        type_entity("system/tree/listing"; fields=[
            "count" => fref("primitive/uint"),
            "entries" => fmap(sp_listing_entry),
            "offset" => fref("primitive/uint"),
            "path" => fref("system/tree/path"),
            "next_page" => opt(fref("system/hash"))]),
        type_entity("system/tree/listing-entry"; fields=[
            "has_children" => fref("primitive/bool"),
            "hash" => opt(fref("system/hash"))]),
        type_entity("system/tree/path"; extends="primitive/string"),

        # type-system bootstrap (3)
        type_entity("system/type"; fields=[
            "name" => fref("system/type/name"),
            "extends" => opt(fref("system/type/name")),
            "fields" => opt(fmap(sp_field_spec)),
            "layout" => opt(farray(sp_string)),
            "type_args" => opt(fmap(sp_type_name)),
            "type_params" => opt(farray(sp_string))]),
        type_entity("system/type/field-spec"; fields=[
            "type_ref" => opt(fref("system/type/name")),
            "optional" => opt(fref("primitive/bool")),
            "array_of" => opt(fref("system/type/field-spec")),
            "map_of" => opt(fref("system/type/field-spec")),
            "union_of" => opt(farray(sp_field_spec)),
            "key_type" => opt(fref("system/type/name")),
            "byte_size" => opt(fref("primitive/uint")),
            "type_param" => opt(fref("primitive/string")),
            "type_args" => opt(fmap(sp_type_name)),
            "default" => opt(fref("primitive/any")),
            "constraints" => opt(farray(sp_core_entity))]),
        type_entity("system/type/name"; extends="primitive/string"),

        # operational (4)
        type_entity("system/bounds"; fields=[
            "budget" => opt(fref("primitive/uint")),
            "cascade_depth" => opt(fref("primitive/uint")),
            "chain_id" => opt(fref("primitive/string")),
            "parent_chain_id" => opt(fref("primitive/string")),
            "ttl" => opt(fref("primitive/uint")),
            "visited" => opt(farray(sp_tree_path))]),
        type_entity("system/resource-limits"; fields=[
            "max_budget" => opt(fref("primitive/uint")),
            "max_ttl" => opt(fref("primitive/uint")),
            "max_visited_length" => opt(fref("primitive/uint"))]),
        type_entity("system/delivery-spec"; fields=[
            "operation" => fref("primitive/string"),
            "uri" => fref("system/tree/path")]),
        type_entity("system/deletion-marker"),
    )
    return T
end

const CORE_TYPE_COUNT = 53

"""Seed every core type entity into the store at `/{peer}/system/type/<name>`."""
function publish_types!(st::ContentStore, local_peer::AbstractString)
    for e in all_type_entities()
        name = e.data.pairs[findfirst(p -> p.first == "name", e.data.pairs)].second
        store_put!(st, e; path="/$(local_peer)/system/type/$(name)")
    end
    return nothing
end

end # module TypeDefs
