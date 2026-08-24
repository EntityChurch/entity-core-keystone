# Shared ECF conformance harness logic (used by test/conformance.jl — the gate runner — and
# test/runtests.jl — the Test-stdlib suite). Defines `run_conformance(path; verbose)` which
# returns (pass, fail, cats, tally) and never calls exit().
#
# Loads the fixture WITH the hand-rolled decoder (F16 lesson: decode-verify), then per vector
# checks byte-identity (encode_equal) / rejection (decode_reject) per Appendix E. The fixture's
# `canonical` bytes are 3-way cross-blessed (Go × Rust × Python), so this is self-contained.

using EntityCore

function _mget(m::CborMap, key::AbstractString)
    for p in m.pairs
        p.first == key && return p.second
    end
    error("missing key: $key")
end
function _mhas(m::CborMap, key::AbstractString)
    for p in m.pairs
        p.first == key && return true
    end
    return false
end

_category(id::AbstractString) = (i = findfirst('.', id); i === nothing ? id : id[1:prevind(id, i)])

function _run_vector(vm::CborMap)
    id    = _mget(vm, "id")::String
    kind  = _mget(vm, "kind")::String
    canon = Vector{UInt8}(_mget(vm, "canonical"))
    cat   = _category(id)

    if kind == "decode_reject"
        try
            decode(canon)
            return (:fail, "decoder accepted a reject vector")
        catch
            return (:pass, "")
        end
    end

    local produced::Vector{UInt8}
    if cat == "content_hash"
        input = _mget(vm, "input")::CborMap
        typ  = _mget(input, "type")::String
        data = _mget(input, "data")
        fc   = _mhas(input, "format_code") ? Int(_mget(input, "format_code")) : 0
        produced = content_hash(fc, typ, data)
    elseif cat == "peer_id"
        input = _mget(vm, "input")::CborMap
        kt = Int(_mget(input, "key_type")); ht = Int(_mget(input, "hash_type"))
        dg = Vector{UInt8}(_mget(input, "digest"))
        produced = encode(peerid_format(kt, ht, dg))
    elseif cat == "signature"
        input = _mget(vm, "input")::CborMap
        seed = Vector{UInt8}(_mget(input, "seed"))
        entity = _mget(input, "entity")::CborMap
        msg = ecf_of_entity(_mget(entity, "type")::String, _mget(entity, "data"))
        produced = ed25519_sign(seed, msg)
    else
        produced = encode(_mget(vm, "input"))
    end

    produced == canon && return (:pass, "")
    return (:fail, "want $(bytes2hex(canon)) got $(bytes2hex(produced))")
end

"""Run the full corpus. Returns (pass, fail, cats::Vector{String}, tally::Dict)."""
function run_conformance(path::AbstractString; verbose::Bool = true)
    bytes = read(path)
    fixture = decode(bytes)
    fixture isa AbstractVector || error("fixture top-level is not a CBOR array")

    pass = 0; fail = 0
    cats = String[]; tally = Dict{String,Vector{Int}}()

    for vraw in fixture
        vm = vraw::CborMap
        id  = _mget(vm, "id")::String
        cat = _category(id)
        haskey(tally, cat) || (push!(cats, cat); tally[cat] = [0, 0])
        outcome = _run_vector(vm)
        tally[cat][2] += 1
        if outcome[1] == :pass
            pass += 1; tally[cat][1] += 1
        else
            fail += 1
            verbose && println("FAIL $id  $(outcome[2])")
        end
    end

    if verbose
        println("\n-- by category --")
        for cat in cats
            p, t = tally[cat]
            println("  ", rpad(cat, 14), " ", p, "/", t)
        end
        println("\nTOTAL: $pass passed, $fail failed (of $(pass + fail))")
    end
    return (pass, fail, cats, tally)
end
