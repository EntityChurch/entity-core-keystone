# §3.6 M3 multi-signature K-of-N — peer-side ACCEPT-path unit test.
#
# The validate-peer `multisig` category is rejection-heavy (malformed quorum → 403), which
# a fail-closed peer passes VACUOUSLY. This unit drives the direction that matters: a REAL
# 2-of-3 root (one signer = the local peer) with a threshold of valid signatures over the
# cap's content_hash MUST be ALLOWed — and each M3/M4/M6 invariant flip MUST deny. Mirrors
# the Zig capability.zig accept-path block. Run: julia --project=. test/multisig_accept.jl
include(joinpath(@__DIR__, "..", "src", "EntityCore.jl"))
using .EntityCore
using .EntityCore: Cbor, Model, Identity, Store, Capability
using .EntityCore.Cbor: CborMap
using .EntityCore.Model: Entity, Envelope, make_entity
using .EntityCore.Identity: peer_identity, sign_entity
using .EntityCore.Store: ContentStore

const PASS = Ref(0); const FAIL = Ref(0)
function check(name, cond)
    cond ? (PASS[] += 1) : (FAIL[] += 1)
    println("  [", cond ? "PASS" : "FAIL", "] ", name)
end

mk_multi_cap(grantee, signers, threshold, parent) = begin
    granter = CborMap(Pair[("signers" => Any[Vector{UInt8}(s) for s in signers]),
                           ("threshold" => Int(threshold))])
    ps = Pair[("granter" => granter), ("grantee" => Vector{UInt8}(grantee)), ("grants" => Any[])]
    parent === nothing || push!(ps, "parent" => Vector{UInt8}(parent))
    make_entity("system/capability/token", CborMap(ps))
end

# Assemble an envelope (cap root + included peers/signatures) and run the chain walk.
function verdict(local_peer, cap, extra::Vector{Entity})
    st = ContentStore()
    inc = Pair{Vector{UInt8},Entity}[cap.hash => cap]
    for e in extra
        push!(inc, e.hash => e)
    end
    env = Envelope(cap, inc)
    return Capability.verify_capability_chain(env, st, local_peer, cap)
end

function main()
    id1 = peer_identity(fill(0x01, 32))
    id2 = peer_identity(fill(0x02, 32))
    id3 = peer_identity(fill(0x03, 32))
    local_peer = id1.peer_id
    signers = [id1.peer_entity.hash, id2.peer_entity.hash, id3.peer_entity.hash]

    println("§3.6 M3 multi-sig K-of-N — accept + deny flips:")

    # valid 2-of-3, local in quorum, 2 valid sigs → ALLOW
    cap = mk_multi_cap(id1.peer_entity.hash, signers, 2, nothing)
    s1 = sign_entity(id1, cap); s2 = sign_entity(id2, cap)
    check("valid 2-of-3 peer-signed → ALLOW (M4 quorum + M6 root-at-local)",
          verdict(local_peer, cap, Entity[id1.peer_entity, id2.peer_entity, id3.peer_entity, s1, s2]) == :allow)

    # only 1 valid sig (< threshold) → DENY (M4)
    check("1 sig < threshold → DENY (M4)",
          verdict(local_peer, cap, Entity[id1.peer_entity, id2.peer_entity, id3.peer_entity, s1]) == :deny)

    # duplicate signature from one signer does NOT inflate the count → DENY (M4)
    check("duplicate signature does not inflate count → DENY (M4)",
          verdict(local_peer, cap, Entity[id1.peer_entity, id2.peer_entity, id3.peer_entity, s1, s1]) == :deny)

    # local peer not among signers → DENY (M6)
    two = [id2.peer_entity.hash, id3.peer_entity.hash]
    cap2 = mk_multi_cap(id1.peer_entity.hash, two, 2, nothing)
    n2 = sign_entity(id2, cap2); n3 = sign_entity(id3, cap2)
    check("local not in signers → DENY (M6)",
          verdict(local_peer, cap2, Entity[id2.peer_entity, id3.peer_entity, n2, n3]) == :deny)

    # threshold = 1 (M3 structure) → DENY even with valid sigs (precedence)
    cap3 = mk_multi_cap(id1.peer_entity.hash, signers, 1, nothing)
    t1 = sign_entity(id1, cap3); t2 = sign_entity(id2, cap3)
    check("threshold=1 (M3) → DENY despite valid sigs (precedence)",
          verdict(local_peer, cap3, Entity[id1.peer_entity, id2.peer_entity, id3.peer_entity, t1, t2]) == :deny)

    # duplicate signers (M3 structure) → DENY
    dup = [id1.peer_entity.hash, id1.peer_entity.hash]
    cap4 = mk_multi_cap(id1.peer_entity.hash, dup, 2, nothing)
    d1 = sign_entity(id1, cap4)
    check("duplicate signers (M3) → DENY",
          verdict(local_peer, cap4, Entity[id1.peer_entity, d1]) == :deny)

    # multi-sig off-root → DENY (root-only): single multi-sig child with a multi-sig parent
    parent = mk_multi_cap(id1.peer_entity.hash, signers, 2, nothing)
    child = mk_multi_cap(id1.peer_entity.hash, signers, 2, parent.hash)
    ps1 = sign_entity(id1, parent); ps2 = sign_entity(id2, parent)
    cs1 = sign_entity(id1, child); cs2 = sign_entity(id2, child)
    check("multi-sig off-root → DENY (root-only)",
          verdict(local_peer, child, Entity[id1.peer_entity, id2.peer_entity, id3.peer_entity, parent, ps1, ps2, cs1, cs2]) == :deny)

    # single-sig root still verifies (strict superset)
    cap5 = make_entity("system/capability/token",
        CborMap(Pair[("granter" => id1.peer_entity.hash), ("grantee" => id1.peer_entity.hash), ("grants" => Any[])]))
    ss = sign_entity(id1, cap5)
    check("single-sig root still verifies (superset)",
          verdict(local_peer, cap5, Entity[id1.peer_entity, ss]) == :allow)

    all_pass = FAIL[] == 0
    println("\n→ MULTISIG-ACCEPT: ", all_pass ? "PASS" : "FAIL", " (", PASS[], " pass, ", FAIL[], " fail)")
    return all_pass
end

exit(main() ? 0 : 1)
