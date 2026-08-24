# Type-registry byte-check (S8 drift target): every core type's content_hash MUST match
# the Go-rendered type-registry-vectors-v1.cbor set. Render-from-model, not byte-ingest.
# Run: julia --project=. test/typedefs_bytecheck.jl [path-to-vectors.cbor]
include(joinpath(@__DIR__, "..", "src", "EntityCore.jl"))
using .EntityCore
using .EntityCore: Cbor, TypeDefs
using .EntityCore.Cbor: decode, CborMap

vec_path = length(ARGS) >= 1 ? ARGS[1] :
    joinpath(@__DIR__, "..", "..", "shared", "test-vectors", "v0.8.0", "type-registry-vectors-v1.cbor")

bytes = read(vec_path)
fixture = decode(bytes)   # array of {name, tree_path, content_hash, data}

want = Dict{String,String}()
for v in fixture
    v isa CborMap || continue
    name = nothing; ch = nothing
    for p in v.pairs
        p.first == "name" && (name = p.second)
        p.first == "content_hash" && (ch = p.second)
    end
    (name isa AbstractString && ch isa AbstractString) || continue
    startswith(ch, "ecf-sha256:") || continue
    want[String(name)] = String(ch[length("ecf-sha256:")+1:end])
end

function run_check(types, want)
    mismatch = 0; matched = 0
    for e in types
        name = ""
        for p in e.data.pairs
            p.first == "name" && (name = p.second)
        end
        got = bytes2hex(e.hash[2:end])   # digest = hash minus the 1-byte format prefix
        exp = get(want, name, nothing)
        if exp === nothing
            println("MISSING from vectors: ", name); mismatch += 1
        elseif got == exp
            matched += 1
        else
            println("MISMATCH ", name, "\n  want ", exp, "\n  got  ", got); mismatch += 1
        end
    end
    println("type-registry: ", matched, "/", length(types), " byte-identical, ", mismatch, " mismatch")
    return mismatch
end

types = TypeDefs.all_type_entities()
mismatch = run_check(types, want)
exit(mismatch == 0 && length(types) == TypeDefs.CORE_TYPE_COUNT ? 0 : 1)
