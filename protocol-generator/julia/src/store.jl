# Content-addressed store + tree binding (foundation, §3.4 / §4.8 / §7b).
#
# Two indices, both plain Julia `Dict`s:
#   • `by_hash`  — the content store: content_hash bytes (hex key) → Entity (§3.4).
#   • `by_path`  — the tree namespace: path String → content_hash (the peer's L0/L1 writes;
#                  handler manifests, types, seed caps live here and are resolved by path).
#
# §7b STORE-SAFETY IS STRUCTURAL (profile [async], A-JULIA-005). The core peer runs the
# SINGLE-THREADED Task scheduler: cooperative Tasks yield ONLY at I/O/await points, never
# mid-statement, so a `Dict` mutation (`put!`) between yields is indivisible w.r.t. every other
# Task. There is therefore NO data race to guard — no lock, no atomics, no RW-lock. This is the
# actor/CSP/event-loop "free store-safety" result (PHP/Dart/Tcl class) reached on a fourth
# substrate. (Julia ALSO has real shared-memory threads under JULIA_NUM_THREADS>1, which WOULD
# need locks — deliberately NOT used for the core peer; out of scope for --profile core.)
module Store

using ..Model: Entity

export ContentStore, store_put!, store_get, store_at, store_has
export store_bind!, store_unbind!, store_hash_at, store_listing, ListingEntry

hexkey(h::AbstractVector{UInt8}) = bytes2hex(h)

mutable struct ContentStore
    by_hash::Dict{String,Entity}
    by_path::Dict{String,Vector{UInt8}}
end
ContentStore() = ContentStore(Dict{String,Entity}(), Dict{String,Vector{UInt8}}())

"""Put an entity into the content store; optionally bind it at a tree `path`."""
function store_put!(st::ContentStore, e::Entity; path::Union{Nothing,AbstractString}=nothing)
    st.by_hash[hexkey(e.hash)] = e
    path === nothing || (st.by_path[String(path)] = e.hash)
    return e
end

"""Fetch by content_hash bytes, or `nothing` if absent."""
store_get(st::ContentStore, h::AbstractVector{UInt8}) = get(st.by_hash, hexkey(h), nothing)

"""Fetch the entity bound at a tree `path`, or `nothing`."""
function store_at(st::ContentStore, path::AbstractString)
    h = get(st.by_path, String(path), nothing)
    h === nothing ? nothing : get(st.by_hash, hexkey(h), nothing)
end

store_has(st::ContentStore, h::AbstractVector{UInt8}) = haskey(st.by_hash, hexkey(h))

# ── tree binding (§6.3) ────────────────────────────────────────────────────────────────
"""Bind entity `e` at tree `path` (and store it by hash). The §6.3 write primitive."""
store_bind!(st::ContentStore, path::AbstractString, e::Entity) = store_put!(st, e; path=path)

"""Remove a tree binding (the path index only; the entity stays content-addressed)."""
store_unbind!(st::ContentStore, path::AbstractString) = (delete!(st.by_path, String(path)); nothing)

"""The content_hash bound at `path`, or `nothing`."""
store_hash_at(st::ContentStore, path::AbstractString) = get(st.by_path, String(path), nothing)

# A tree listing entry: the child segment, its bound hash (or nothing if only a prefix),
# and whether it has deeper children (§6.3 system/tree/listing-entry).
struct ListingEntry
    seg::String
    hash::Union{Nothing,Vector{UInt8}}
    has_children::Bool
end

"""List the immediate children of `path` (a directory-style listing, §6.3). `path` may
carry a trailing slash. A child `seg` is a leaf (hash set) if `path/seg` is bound, and/or
has_children if any deeper `path/seg/...` is bound."""
function store_listing(st::ContentStore, path::AbstractString)::Vector{ListingEntry}
    base = String(path)
    endswith(base, "/") && (base = base[1:end-1])
    prefix = base * "/"
    # seg → (hash, has_children); preserve first-seen order.
    order = String[]
    leaf = Dict{String,Vector{UInt8}}()
    children = Set{String}()
    for (k, h) in st.by_path
        startswith(k, prefix) || continue
        rest = k[length(prefix)+1:end]
        isempty(rest) && continue
        i = findfirst('/', rest)
        seg = i === nothing ? rest : rest[1:i-1]
        seg in order || push!(order, seg)
        if i === nothing
            leaf[seg] = h
        else
            push!(children, seg)
        end
    end
    out = ListingEntry[]
    for seg in order
        push!(out, ListingEntry(seg, get(leaf, seg, nothing), seg in children))
    end
    return out
end

end # module Store
