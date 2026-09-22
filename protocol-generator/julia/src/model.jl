# Entity model (L-foundation) — the materialized `{type, data, content_hash}` form (§1.1,
# §3.4) and the protocol envelope (§3.1), lifted onto the S2 codec (`Cbor.CborMap`).
#
# An `Entity` is IMMUTABLE (Julia `struct`): its `data` value tree and 33-byte content_hash
# are computed once at `make_entity` and never mutated — the store and every outbound
# envelope share the same immutable entity by reference, which is part of why §7b store-safety
# is structural on the single Task scheduler (no in-place aliasing hazard; A-JULIA-005).
#
# Field access is by NAME over the ordered CborMap (the entity `data`), mirroring the codec's
# ordered-pair model. N4 validate-before-trust: `entity_ofcbor` RE-materialises a decoded wire
# entity through our own `content_hash`, trusting the recomputed hash — a wire `content_hash`
# that disagrees is a hard reject (§5.2), so a forwarded entity is canonical by construction.
module Model

using ..Cbor: CborMap, encode, decode, decode_salvage
using ..ContentHash: content_hash

export Entity, Envelope
export make_entity, entity_tocbor, entity_ofcbor
export envelope_tocbor, envelope_ofcbor, frame_ofenvelope, envelope_offrame, salvage_request_id
export efield, textfield, bytesfield, uintfield, entityfield, included_get, mapget

struct BadEntity <: Exception; msg::String; end

# A materialised entity: type name, an arbitrary ECF `data` value, and the 33-byte
# content_hash (format byte 0x00 ‖ 32-byte SHA-256).
struct Entity
    typ::String
    data::Any
    hash::Vector{UInt8}
end

"""Construct an entity, computing its content_hash under the ecfv1-sha256 floor (format 0)."""
make_entity(typ::AbstractString, data) =
    Entity(String(typ), data, content_hash(0, String(typ), data))

# ── field access over the ordered `data` map ────────────────────────────────────────────────
function mapget(m::CborMap, key::AbstractString)
    for p in m.pairs
        p.first == key && return p.second
    end
    return nothing
end
mapget(::Any, ::AbstractString) = nothing     # non-map data has no fields

efield(e::Entity, key::AbstractString) = mapget(e.data, key)

# Typed accessors return `nothing` (the profile's clean absent sentinel) on absence OR
# type-mismatch — the caller distinguishes by asking for the shape it needs.
textfield(e::Entity, key)  = (v = efield(e, key); v isa AbstractString ? String(v) : nothing)
bytesfield(e::Entity, key) = (v = efield(e, key); v isa AbstractVector{UInt8} ? v : nothing)
uintfield(e::Entity, key)  = (v = efield(e, key); v isa Integer ? v : nothing)

"""Parse a sub-entity carried as a CBOR-map field (e.g. `params`, `result`)."""
entityfield(e::Entity, key) = (v = efield(e, key); v isa CborMap ? entity_ofcbor(v) : nothing)

# ── entity ⇄ wire (§3.1: an entity is self-describing across serialization) ──────────────────
entity_tocbor(e::Entity) =
    CborMap(Pair[("type" => e.typ), ("data" => e.data), ("content_hash" => e.hash)])

"""Re-materialise a wire entity, recomputing the hash from {type,data} and rejecting a
mismatching carried content_hash (§5.2 validate-before-trust)."""
function entity_ofcbor(c::CborMap)::Entity
    typ = mapget(c, "type")
    typ isa AbstractString || throw(BadEntity("entity: missing/!text type"))
    haskey_data = false
    data = nothing
    for p in c.pairs
        p.first == "data" && (data = p.second; haskey_data = true)
    end
    haskey_data || throw(BadEntity("entity: missing data"))
    e = make_entity(typ, data)
    carried = mapget(c, "content_hash")
    if carried isa AbstractVector{UInt8} && carried != e.hash
        throw(BadEntity("entity: content_hash mismatch"))
    end
    return e
end

# ── envelope (§3.1): { root, included: {hash → entity} } ─────────────────────────────────────
struct Envelope
    root::Entity
    included::Vector{Pair{Vector{UInt8},Entity}}
end
Envelope(root::Entity) = Envelope(root, Pair{Vector{UInt8},Entity}[])

"""Resolve an included entity by its content_hash bytes (§3.1 by-hash reference)."""
function included_get(env::Envelope, h::AbstractVector{UInt8})
    for (k, v) in env.included
        k == h && return v
    end
    return nothing
end

function envelope_tocbor(env::Envelope)
    inc = CborMap(Pair[(k => entity_tocbor(v)) for (k, v) in env.included])
    return CborMap(Pair[("root" => entity_tocbor(env.root)), ("included" => inc)])
end

"""Build an envelope from a decoded CBOR value; validates each included key == its
entity hash (§3.1)."""
function envelope_ofcbor(c::CborMap)::Envelope
    rootc = mapget(c, "root")
    rootc isa CborMap || throw(BadEntity("envelope: missing root"))
    root = entity_ofcbor(rootc)
    included = Pair{Vector{UInt8},Entity}[]
    incc = mapget(c, "included")
    if incc isa CborMap
        for p in incc.pairs
            key = p.first
            key isa AbstractVector{UInt8} || throw(BadEntity("envelope: non-bytes included key"))
            ent = entity_ofcbor(p.second)
            key == ent.hash || throw(BadEntity("envelope: included key ≠ entity hash"))
            push!(included, Vector{UInt8}(key) => ent)
        end
    end
    return Envelope(root, included)
end

# ── frame (§1.6): [4-byte BE length][CBOR envelope] ─────────────────────────────────────────
frame_ofenvelope(env::Envelope)::Vector{UInt8} = encode(envelope_tocbor(env))

envelope_offrame(payload::AbstractVector{UInt8})::Envelope = envelope_ofcbor(decode(payload))

"""
§6.3 rejection reporting: recover ONLY the request_id from a frame the strict decoder
rejected, so the rejection can be delivered as a correlated `400 non_canonical_ecf`
response instead of silence. The frame stays rejected — nothing else is read out of
it. Returns `nothing` when even the request_id is unrecoverable (an unattributable
frame, where silence is the only option left).

The envelope and entity-wrapper shapes are fixed maps with no legal tag position
(§6.3), so a frame whose ONLY defect is a tag inside some entity's `data` still has a
structurally sound root — which is exactly the case this recovers.
"""
function salvage_request_id(payload::AbstractVector{UInt8})
    v = try
        decode_salvage(payload)
    catch
        return nothing
    end
    root = mapget(v, "root");            root isa CborMap || return nothing
    data = mapget(root, "data");         data isa CborMap || return nothing
    rid  = mapget(data, "request_id")
    return rid isa AbstractString ? String(rid) : nothing
end

end # module Model
