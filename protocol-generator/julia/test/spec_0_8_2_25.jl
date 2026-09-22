#!/usr/bin/env julia
# The 0.8.2.20..25 peer-machinery units: §3.3's effective-targets ladder, §6.3's
# check_path_permission and listing filter, §5.4's sentinel as scoped at 0.8.2.24,
# §5.5a's typed subset, and §4.11's pre-admission refusal classification + emission.
#
# `runtests.jl` covers the CODEC. None of this is reachable from there, and the pinned
# 778-check set has no vector on any of it.
#
# EVERY LADDER CASE GOES THROUGH THE REAL DISPATCH CHAIN with a fully signed envelope,
# not through `tree_handler` directly. That is what makes the RULE G ordering claim an
# ordering claim at all, since a test that resolves the operation itself cannot see a
# handler that validates the resource first — and it is what makes the §6.3 check run on
# the authority the DISPATCH check resolved, which is the property §6.8 names.

using Test
using Sockets
using EntityCore
using EntityCore.Cbor: TagRejected
using EntityCore.Model: HashMismatch, BadEntity, efield, textfield, uintfield,
                        entityfield, entity_tocbor, entity_ofcbor, mapget,
                        envelope_offrame, frame_ofenvelope
using EntityCore.Wire: FrameTooLarge, TruncatedFrame, MAX_FRAME,
                       classify_pre_admission, is_framing_refusal,
                       make_execute, make_response, error_result, empty_params,
                       read_frame, write_frame
using EntityCore.Capability: Scope, Grant, ScopeKind, ID_SCOPE, PATH_SCOPE, NEVER_MATCH,
                             canonicalize, matches_pattern, matches_scope, grant_subset,
                             effective_targets, check_path_permission
using EntityCore.Identity: sign_entity
using EntityCore.Store: store_bind!

const LOCAL = "z6MkLocalPeerIdThatIsNotRealButIsLongEnoughToPassBase58Check"

sc(incl::Vector{String}, excl::Vector{String}=String[]) = Scope(incl, excl)

# A grant whose four dimensions move independently.
gr(; handlers=sc(["*"]), resources=sc(["*"]), operations=sc(["*"]), peers=nothing) =
    Grant(handlers, resources, operations, peers)

# ── the peer used by every dispatch-driven case ──────────────────────────────────────
const P = create_peer(fill(UInt8(0x5a), 32); open_grants=false)
const PID = P.peer_id
store_bind!(P.store, "/$(PID)/app/a", make_entity("primitive/any", CborMap(Pair[("v" => 1)])))
store_bind!(P.store, "/$(PID)/app/b", make_entity("primitive/any", CborMap(Pair[("v" => 2)])))

scope_cbor(incl::Vector{String}, excl::Vector{String}=String[]) = begin
    ps = Pair[("include" => Any[String(x) for x in incl])]
    isempty(excl) || push!(ps, "exclude" => Any[String(x) for x in excl])
    CborMap(ps)
end

# A SELF-ISSUED ROOT capability: granter == grantee == this peer's identity hash, which
# is what §5.5's root arm requires and what makes the token usable through the real
# dispatch chain rather than through a handler called directly.
function token(; handlers=["*"], operations=["*"], resources=["*"], resources_excl=String[])
    idh = P.identity.peer_entity.hash
    make_entity("system/capability/token", CborMap(Pair[
        ("granter" => idh),
        ("grantee" => idh),
        ("created_at" => 1700000000000),
        ("grants" => Any[CborMap(Pair[
            ("handlers" => scope_cbor(String.(handlers))),
            ("operations" => scope_cbor(String.(operations))),
            ("resources" => scope_cbor(String.(resources), String.(resources_excl))),
        ])]),
    ]))
end

resource_cbor(targets, excl=String[]) = targets === nothing ? nothing : begin
    ps = Pair[("targets" => Any[String(t) for t in targets])]
    isempty(excl) || push!(ps, "exclude" => Any[String(x) for x in excl])
    CborMap(ps)
end

# Build an EXECUTE carrying a `resource` (the builder has no such kwarg).
function exec_with(op::AbstractString, resource; params=empty_params(), cap=nothing)
    idh = P.identity.peer_entity.hash
    e = make_execute(request_id="r1", uri="system/tree", operation=String(op),
                     params=params,
                     author = cap === nothing ? nothing : idh,
                     capability = cap === nothing ? nothing : cap.hash)
    resource === nothing && return e
    ps = copy(e.data.pairs)
    push!(ps, Pair{Any,Any}("resource", resource))
    return make_entity(e.typ, CborMap(ps))
end

"""Drive one request through the REAL dispatch chain; returns `(status, code, result)`."""
function drive(op::AbstractString, resource; cap=token(), params=empty_params())
    id = P.identity
    ex = exec_with(op, resource; params, cap)
    # §5.2 demands a system/signature over the EXECUTE whose signer binds to `author`,
    # and a chain whose root is self-issued by this peer. Anything less is refused at the
    # verdict and every ladder assertion below would be reading a 401, not the handler.
    inc = [cap, id.peer_entity, sign_entity(id, cap), sign_entity(id, ex)]
    env = Envelope(ex, Pair{Vector{UInt8},Entity}[e.hash => e for e in inc])
    resp = dispatch(P, Conn(), env)
    @assert resp !== nothing "every inbound root is answered (N12/N17)"
    st = uintfield(resp.root, "status")
    res = entityfield(resp.root, "result")
    return (st === nothing ? 0 : Int(st),
            res === nothing ? "" : something(textfield(res, "code"), ""),
            res)
end

@testset "entity-core-protocol-julia 0.8.2.20..25" begin

@testset "effective_targets: the two-empties discriminator (N11, 0.8.2.25)" begin
    # N11 makes the discriminator a [MUST]: "that projection MUST NOT be lossy about its
    # own emptiness — narrow when narrowing leaves something, and retain the raw pair when
    # narrowing would empty it." This peer carries it as the second tuple element rather
    # than a `Union{Nothing,Vector}`, so the collapse is not one `something(x, [])` away.
    eff(r) = effective_targets(PID, exec_with("get", r))

    @test eff(nothing)[2] == false
    # PINS THE SHIPPED ANSWER to an open question rather than endorsing it: a `resource`
    # MAP with no `targets` key reads ABSENT on every 0.8.2.25 peer, while §3.2 says
    # `targets` "MUST contain at least one entry" (malformed, not absent). No disposition
    # is pinned and nothing in the check set drives it, so the behaviour is HELD.
    @test eff(CborMap(Pair[("exclude" => Any["a"])]))[2] == false

    survivors, had = eff(resource_cbor(["a"], ["a"]))
    @test had == true
    @test isempty(survivors)

    # 0.8.2.21: RAW survivors, not canonical forms — the value flows on to the store
    # lookup, which canonicalizes for itself.
    @test eff(resource_cbor(["app/x", "app/y"], ["app/y"]))[1] == ["app/x"]

    # §5.4's table rules the CALLER-exclude arm SEPARATELY from the grant arm and in the
    # opposite direction: canonicalize answers the sentinel, matches_pattern answers
    # false, and the target SURVIVES. INHERITED from the primitives, never restated.
    @test eff(resource_cbor(["app/a"], ["../nope"]))[1] == ["app/a"]
    # The accept-side control: without it a peer that ignored `exclude` entirely would
    # pass the row above for the wrong reason.
    @test isempty(eff(resource_cbor(["app/a"], ["app/a"]))[1])
end

@testset "RULE G: operation resolution precedes resource validation" begin
    # "Resolve the operation first; only then run the §3.3 ladder." A peer that validates
    # the resource first answers a RESOURCE fault for an OPERATION fault on every unknown
    # operation (entity-system-conformance X9 / F52).
    #
    # ON THIS SUBSTRATE THE ORDERING IS EXPLICIT: `tree_handler`'s first statement refuses
    # any operation that is not get/put, so the §3.3 ladder below it is unreachable for an
    # unknown one. The pair is asserted anyway because "it cannot happen" is a claim about
    # today's handler.
    st0, c0, _ = drive("bogusop", nothing)
    @test (st0, c0) == (501, "unsupported_operation")
    # THE CONTROL that makes this an ORDERING claim rather than a missing-501 claim: on
    # the peers that had the defect these two answered DIFFERENTLY.
    st1, c1, _ = drive("bogusop", resource_cbor(["app/a"]))
    @test (st1, c1) == (501, "unsupported_operation")
    # ...and a KNOWN operation still routes, or the two above are satisfied by a handler
    # that answers 501 to everything.
    @test drive("get", resource_cbor(["app/a"]))[1] == 200
end

@testset "the ladder, get (resource-OPTIONAL, BROAD-RESULT)" begin
    # EXTENSION-TREE §2.2a (v4.11) declares `get` resource-OPTIONAL and BROAD-RESULT:
    # absent-case answer "the root listing", self-excluded case "400 path_required".
    # 0.8.2.24 (N7) scopes §3.3's "an empty effective list IS the absent case" to "an
    # operation that REQUIRES a resource"; 0.8.2.25 (N10) decides the present-but-empty
    # case by whether the absent case is WIDER than the request.
    st, _, res = drive("get", nothing)
    @test st == 200
    @test res.typ == "system/tree/listing"
    @test textfield(res, "path") == "/$(PID)/"

    # THE TWO EMPTIES ARE DISTINCT. Collapsing them serves the ROOT LISTING to a request
    # that named one excluded path — wider than the request, which §3.3 forbids.
    @test drive("get", resource_cbor(["app/a"], ["app/a"]))[1:2] == (400, "path_required")

    @test drive("get", resource_cbor(["app/a", "app/b"]))[1:2] == (400, "ambiguous_resource")
    # ...and the exclude is what makes the COUNT an effective-set count rather than a raw
    # `targets` count: two targets, one excluded, ONE survivor -> it proceeds.
    @test drive("get", resource_cbor(["app/a", "app/b"], ["app/b"]))[1] == 200

    # THE MUST 0.8.2.20 NAMES: a handler that counts the effective list and then indexes
    # targets[1] has implemented the arithmetic completely and is still reading a path no
    # authorization covered. targets[1] is EXCLUDED here and the survivor is targets[2],
    # so the two readings return DIFFERENT entities.
    st2, _, res2 = drive("get", resource_cbor(["app/a", "app/b"], ["app/a"]))
    @test st2 == 200
    @test uintfield(res2, "v") == 2

    # 0.8.2.20: a resource-requiring operation takes a CONCRETE path. A trailing slash is
    # a LISTING request and is not a pattern — only a star makes it one.
    @test drive("get", resource_cbor(["app/*"]))[1:2] == (400, "malformed_resource")
    stl, _, resl = drive("get", resource_cbor(["app/"]))
    @test stl == 200 && resl.typ == "system/tree/listing"
end

@testset "the ladder, put (resource-REQUIRED)" begin
    # THE CODE CHANGE 0.8.2.20 FORCED. This branch answered `ambiguous_resource` for a
    # MISSING target, which 0.8.2.20 names as the exact inversion it forbids: the remedies
    # differ — supply a resource is not disambiguate your request — and the code selects
    # the remedy.
    @test drive("put", nothing)[1:2] == (400, "path_required")
    # BOTH empties collapse here: §2.2a declares `put` resource-REQUIRED.
    @test drive("put", resource_cbor(["app/a"], ["app/a"]))[2] == "path_required"
    # ...and more than one survivor is still ambiguous_resource, which says the two codes
    # have not simply been swapped.
    @test drive("put", resource_cbor(["app/a", "app/b"]))[2] == "ambiguous_resource"
end

@testset "section 6.3: the handler-level path check (0.8.2.20)" begin
    # THE F84 LAYER. §6.3: "not a secondary check ... the sole enforcement wherever the
    # subject is derived after dispatch."
    #
    # WHICH RUNG ANSWERS THE SCALAR 403 IS BOTH, measured rather than assumed: this peer's
    # dispatch-level resource check requires every non-caller-excluded target to be
    # covered, so for a SCALAR get the handler's derived path is always a path dispatch
    # already saw, and the two rungs are independently sufficient. The arm where §6.3 is
    # the ONLY thing standing is the LISTING, whose entries the dispatch check never sees
    # — measured below, and that is where a plant on the filter bites.
    narrow = token(resources=["*"], resources_excl=["app/b"])
    @test drive("get", resource_cbor(["app/b"]); cap=narrow)[1:2] == (403, "capability_denied")
    # CONTROL, in the SAME capability: a path the same grant covers is served.
    @test drive("get", resource_cbor(["app/a"]); cap=narrow)[1] == 200

    # The unit-level form, one dimension at a time. A predicate test built only from DENY
    # cases is indistinguishable from one asserting `false == false`, so the ACCEPT case
    # validates the fixture; one deny per DIMENSION says the predicate checks the
    # dimension rather than merely denying.
    @test check_path_permission(PID, "get", "app/a", token(), "system/tree")
    @test !check_path_permission(PID, "get", "app/a", token(operations=["put"]), "system/tree")
    @test !check_path_permission(PID, "get", "app/a", token(handlers=["system/other"]), "system/tree")
    # An empty `resources.include` is a LEGAL grant shape (§5.2) and denies every path
    # here, which is what that note says it should.
    @test !check_path_permission(PID, "get", "app/a", token(resources=String[]), "system/tree")
    # canonicalize is TOTAL and answers the sentinel, which matches no grant, so a
    # malformed path falls through to DENY rather than being matched.
    @test !check_path_permission(PID, "get", "../escape", token(), "system/tree")
end

@testset "section 6.3: the listing filter (0.8.2.21/.22)" begin
    # "Entries for which check_path_permission returns DENY MUST be omitted. The result's
    # `count` field MUST reflect the FILTERED entry count, not the source tree's total
    # count." A count that still reported the source total IS the disclosure the rule
    # exists to prevent, so it is asserted separately from the entry map.
    segs(res) = sort(String[String(p.first) for p in mapget(res.data, "entries").pairs])

    narrow = token(resources=["*"], resources_excl=["app/b"])
    st, _, res = drive("get", resource_cbor(["app/"]); cap=narrow)
    @test st == 200
    @test segs(res) == ["a"]
    @test uintfield(res, "count") == 1

    # The differential that attributes the row above to the FILTER rather than to the
    # store or the directory: same directory, a grant covering both, both entries.
    _, _, wide = drive("get", resource_cbor(["app/"]))
    @test segs(wide) == ["a", "b"]
    @test uintfield(wide, "count") == 2

    # The filter narrows on an INCLUDE too, not only on an exclude — a filter that only
    # consulted the exclude list would pass both rows above.
    #
    # SAY WHAT IS NOT ASSERTED HERE. §6.3's "the DIRECTORY itself is deliberately not
    # checked — each ENTRY is the subject" is NOT separately observable through the
    # dispatch chain on this peer: the dispatch-level check already requires the caller's
    # grant to cover the listing TARGET, so a grant covering only `app/a` is refused at
    # §5.2 before any listing is built, and a grant that does cover `app/` cannot
    # distinguish a filter that checks the prefix from one that does not. The property is
    # real and enforced in `build_listing` (the per-entry call is on the CHILD path); it
    # is recorded as not-driven rather than asserted by a case that would pass either way.
    dir_and_a = token(resources=["app/", "app/a"])
    st2, _, res2 = drive("get", resource_cbor(["app/"]); cap=dir_and_a)
    @test st2 == 200
    @test segs(res2) == ["a"]
    @test uintfield(res2, "count") == 1
end

@testset "section 5.4: the sentinel is scoped to path-scope (0.8.2.24 N2/N3)" begin
    # §5.4 at 0.8.2.24: "a capability carrying an unmatchable PATH-SCOPE pattern is
    # INVALID ... It does NOT reach `operations` or `peers` [MUST]". The un-scoped form
    # shipped at 0.8.2.21 ran an id pattern through the §5.4 PATH transforms purely to
    # classify it and then denied the WHOLE dimension.
    star_apply = "*" * "/apply"
    @test canonicalize(LOCAL, star_apply) == NEVER_MATCH
    # `*/apply` is an ordinary namespaced operation name: under the id-scope grammar a
    # LITERAL that matches nothing — a non-match, never a fault. Before the fix this
    # denied EVERY operation. Over-denial, invisible on a well-formed grant.
    @test matches_scope(LOCAL, "get", sc(["*"], [star_apply]), ID_SCOPE)
    # THE CONTROL that says the fix SCOPED the guard rather than deleting it: on a
    # PATH-scope dimension an unmatchable exclude must still DENY, or the grant is
    # silently wider than its author wrote.
    @test !matches_scope(LOCAL, "system/tree", sc(["*"], [star_apply]), PATH_SCOPE)
    # The second id-scope dimension, driven independently.
    @test canonicalize(LOCAL, "../elsewhere") == NEVER_MATCH
    @test matches_scope(LOCAL, LOCAL, sc([LOCAL], ["../elsewhere"]), ID_SCOPE)
    # The FIXTURE control: an ordinary MATCHABLE exclude still excludes on both kinds.
    @test !matches_scope(LOCAL, "get", sc(["*"], ["get"]), ID_SCOPE)
    @test !matches_scope(LOCAL, "system/tree", sc(["*"], ["system/tree"]), PATH_SCOPE)
end

@testset "section 5.5a: scope_subset is typed by scope kind (F50, 0.8.2.16)" begin
    # §3.6's grammar binds the SCOPE TYPE, not one function: "An implementation on the
    # canonicalizing reading is non-conformant and MUST adopt the literal matcher." F40
    # typed `matches_scope`; its §5.5a sibling was left on the path matcher for all four
    # dimensions. Driven through `grant_subset`, the public call site.
    star_apply = "*" * "/apply"
    # The formalization's two witnesses, on the OPERATIONS (id-scope) dimension. Under
    # the path matcher the parent canonicalizes to /{parent}/* and the child to the
    # sentinel, so both were refused. FAIL-CLOSED, which is why no hand-tried example
    # found it: nothing is over-granted, legitimate delegation is refused.
    @test grant_subset(LOCAL, LOCAL, LOCAL, gr(operations=sc([star_apply])), gr(operations=sc(["*"])))
    @test grant_subset(LOCAL, LOCAL, LOCAL, gr(operations=sc(["/tree/get"])), gr(operations=sc(["*"])))
    # THE DIFFERENTIAL that attributes the two rows above to the scope TYPE rather than to
    # `grant_subset` having been loosened: `resources` is path-scope, so the same two
    # patterns are still refused there.
    @test !grant_subset(LOCAL, LOCAL, LOCAL, gr(resources=sc([star_apply])), gr(resources=sc(["*"])))
    @test !grant_subset(LOCAL, LOCAL, LOCAL, gr(resources=sc(["/tree/get"])), gr(resources=sc(["*"])))
    # ...and an operations include no parent include covers is still refused, or the
    # accept rows are satisfied by a dimension that stopped being checked at all.
    @test !grant_subset(LOCAL, LOCAL, LOCAL, gr(operations=sc(["put"])), gr(operations=sc(["get"])))
    # The exclude arm of the subset test on the id dimension, independently.
    @test !grant_subset(LOCAL, LOCAL, LOCAL, gr(operations=sc(["*"])),
                        gr(operations=sc(["*"], ["delete"])))
    @test grant_subset(LOCAL, LOCAL, LOCAL, gr(operations=sc(["*"], ["delete"])),
                       gr(operations=sc(["*"], ["delete"])))
end

@testset "RULE F: the sentinel guard is reached from every match decision (K-6)" begin
    # 0.8.2.22: "a sentinel arm is a control-flow obligation, not a line ... the guard MUST
    # sit on every path that reaches the decision it protects." The `lean` bypass was a
    # GUARDED WRAPPER beside an UNGUARDED running matcher, with attenuation calling the
    # raw one.
    #
    # ALREADY SATISFIED BY CONSTRUCTION HERE, and these cases are the measurement that says
    # so. `matches_pattern` is the single definition and the sentinel test is its FIRST
    # statement, so the bypass shape cannot occur: the six call sites in src/ (its own
    # recursion, `covered`, `covered_frame`, `effective_targets`'s caller-exclude arm, and
    # `scope_subset`'s two path arms) all reach the same guarded body.
    #
    # WHICH ARM THE GUARD IS LOAD-BEARING FOR WAS MEASURED, NOT ASSUMED. Deleting it shows
    # the pattern-operand half is unreachable as a discriminator here:
    # `matches_pattern(x, NEVER_MATCH)` can only be true when `x == NEVER_MATCH`, because
    # the sentinel is neither a bare star nor a `/*/` form nor a `/*` suffix, so every
    # other arm falls through to the literal compare and answers false on its own. A case
    # that passes with the guard deleted is not a control for the guard.
    @test !matches_pattern(NEVER_MATCH, "*")          # the arm a bare star would allow
    @test !matches_pattern(NEVER_MATCH, NEVER_MATCH)  # a `path != pattern` guard passes this
    # The `lean` defect in this peer's own shape. The parent include is `/*` and NOT a bare
    # `*` deliberately: a bare star canonicalizes to `/{parent}/*`, which refuses a sentinel
    # child by prefix alone and would make this pass with the guard deleted. `/*` is already
    # absolute and its `/*` suffix arm covers any path beginning with a slash — including
    # the sentinel. Only the guard refuses it.
    @test !grant_subset(LOCAL, LOCAL, LOCAL, gr(resources=sc(["../escape"])),
                        gr(resources=sc(["/*"])))
end

@testset "section 4.11: the CODE belongs to the CAUSE (0.8.2.25, section 5.2a)" begin
    # Before 0.8.2.24 this peer answered `400 non_canonical_ecf` for every one of these,
    # which is the code-under-the-wrong-reason defect §5.2a names: a mis-keyed `included`
    # entry carries NO TAG, its encoding is canonical, and *re-encode* is not the remedy.
    rows = [
        # §4.10(a), mood raised SHOULD -> MUST at 0.8.2.25 (N14).
        (FrameTooLarge(99), 413, "payload_too_large"),
        # §5.2a / §1.8 resolution integrity. 0.8.2.24 rules non_canonical_ecf
        # NON-CONFORMANT here.
        (HashMismatch("x"), 400, "hash_mismatch"),
        # ENTITY-CBOR-ENCODING §6.3 — the tag-policy arm keeps its own code.
        (TagRejected(), 400, "non_canonical_ecf"),
        # §4.7 / §4.11 framing arm: bytes that never become an Envelope.
        (TruncatedFrame("x"), 400, "invalid_request"),
        (BadEntity("x"), 400, "invalid_request"),
        # The row that makes the split load-bearing: a non-minimal head is "non-canonical
        # CBOR" BY NAME and is NOT the tag-policy arm.
        (EntityCore.Cbor.NonCanonicalECF("x"), 400, "invalid_request"),
        (EntityCore.Cbor.DuplicateKey(), 400, "invalid_request"),
    ]
    @test length(rows) == 7   # examined-N, not merely "no failures"
    for (e, status, code) in rows
        st, cd, msg = classify_pre_admission(e)
        @test (st, cd) == (status, code)
        @test all(c -> UInt32(c) < 128, msg)   # a wire-visible message stays ASCII
    end

    # Which read failures are owed a frame AT ALL. A closed or reset socket is not a
    # refusal of anything and there is nobody left to answer.
    @test is_framing_refusal(FrameTooLarge(1))
    @test is_framing_refusal(TruncatedFrame("x"))
    @test !is_framing_refusal(EOFError())
    @test !is_framing_refusal(Base.IOError("reset", -1))
end

@testset "section 4.11: the decode boundary throws the CAUSE" begin
    good = make_entity("primitive/any", CborMap(Pair[("x" => 1)]))
    # The arc-probe B1/B2 input: a mis-keyed `included` entry. Its ENCODING is canonical;
    # what is false is the claim the KEY makes.
    payload = encode(CborMap(Pair[
        ("root" => entity_tocbor(make_execute(request_id="t1", uri="system/tree",
                                              operation="get", params=empty_params()))),
        ("included" => CborMap(Pair[(fill(UInt8(0x11), 33) => entity_tocbor(good))])),
    ]))
    caught = try; envelope_offrame(payload); nothing; catch e; e; end
    @test caught isa HashMismatch
    @test classify_pre_admission(caught)[1:2] == (400, "hash_mismatch")

    # The same obligation one level down: an entity whose CARRIED content_hash does not
    # bind to {type, data}.
    m = CborMap(Pair[("type" => good.typ), ("data" => good.data),
                     ("content_hash" => fill(UInt8(0x22), 33))])
    caught2 = try; entity_ofcbor(m); nothing; catch e; e; end
    @test caught2 isa HashMismatch
end

@testset "section 4.11: read_frame separates an ordinary close from a refusal" begin
    # A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing; a stream
    # that ends MID-FRAME is a framing refusal and is owed a coded frame. Both surface as
    # a short read, so the distinction can only be made where the frame boundary is known
    # — and getting it wrong in the other direction would answer 400 to every peer that
    # simply hangs up.
    rf(bytes) = try; read_frame(IOBuffer(bytes)); catch e; e; end
    @test rf(UInt8[]) isa EOFError
    # The arm the vanguard's first driver had no case for: its "truncated frame" case sent
    # a COMPLETE 4-byte prefix, so truncation was caught in the body read and the prefix
    # discrimination had nothing driving it.
    @test rf(UInt8[0x00, 0x00]) isa TruncatedFrame
    @test rf(UInt8[0x00, 0x00, 0x10, 0x00, 0xa1]) isa TruncatedFrame
    @test rf(UInt8[0x02, 0x00, 0x00, 0x00]) isa FrameTooLarge
    # A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
    # refused there as bytes that never become an Envelope.
    @test rf(UInt8[0x00, 0x00, 0x00, 0x00]) == UInt8[]
end

@testset "section 6.5 N12/N17: a non-EXECUTE root is ANSWERED, not dropped" begin
    # §6.5's "Other type?" arm, as rewritten at 0.8.2.25: "400 invalid_request, coded
    # frame; MAY then close. NOT a bare close — that is indistinguishable from a network
    # fault." This peer did something weaker still: it returned `nothing` and the reader
    # wrote NOTHING while keeping the connection open — §4.11's silent drop.
    root = make_entity("primitive/any", CborMap(Pair[("request_id" => "x-1")]))
    resp = dispatch(P, Conn(), Envelope(root, Pair{Vector{UInt8},Entity}[]))
    @test resp !== nothing
    @test uintfield(resp.root, "status") == 400
    res = entityfield(resp.root, "result")
    @test textfield(res, "code") == "invalid_request"
    # request_id is read BEST-EFFORT and correlated where the root carries one.
    @test textfield(resp.root, "request_id") == "x-1"
end

# ── §4.11 over a REAL socket ─────────────────────────────────────────────────────────
#
# A green mapping over a transport that never calls it is the `check_path_permission`
# shape all over again, so the emission is driven end to end.
#
# THE READ DEADLINE IS AN ASSERTION, NOT A CONVENIENCE. §4.11's non-conformant behaviour
# is NO RESPONSE, so a socket read with no deadline HANGS on the defect instead of
# failing on it — and a hung test reports nothing and blocks everything behind it. Every
# read below runs in a Task raced against a timer.
@testset "section 4.11: the frame obligation, over a real socket" begin
    framed(payload) = vcat(UInt8[(length(payload) >> 24) & 0xff,
                                 (length(payload) >> 16) & 0xff,
                                 (length(payload) >> 8) & 0xff,
                                 length(payload) & 0xff], Vector{UInt8}(payload))

    # A well-formed EXECUTE the peer MUST answer 200 — the positive control.
    function hello_frame()
        id = peer_identity(fill(UInt8(0x2a), 32))
        hello = make_entity("system/protocol/connect/hello", CborMap(Pair[
            ("peer_id" => id.peer_id),
            ("nonce" => fill(UInt8(0x01), 32)),
            ("protocols" => Any["entity-core/1.0"]),
            ("timestamp" => 1),
            ("hash_formats" => Any["ecfv1-sha256"]),
            ("key_types" => Any["ed25519"]),
        ]))
        ex = make_execute(request_id="ctl-1", uri="system/protocol/connect",
                          operation="hello", params=hello)
        return framed(frame_ofenvelope(Envelope(ex, Pair{Vector{UInt8},Entity}[])))
    end

    # Read one framed response under a deadline; `nothing` means the frame was DROPPED.
    function read_one(sock; secs=5.0)
        ch = Channel{Any}(1)
        t = @async try; put!(ch, read_frame(sock)); catch e; put!(ch, e); end
        timer = @async (sleep(secs); isopen(ch) && put!(ch, :timeout))
        v = take!(ch)
        v === :timeout && return nothing
        v isa Exception && return nothing
        env = envelope_offrame(v)
        res = entityfield(env.root, "result")
        return (Int(something(uintfield(env.root, "status"), 0)),
                res === nothing ? "" : something(textfield(res, "code"), ""),
                something(textfield(env.root, "request_id"), ""))
    end

    function with_peer(body)
        srv = listen(Sockets.localhost, 0)
        port = Int(getsockname(srv)[2])
        acc = @async while true
            s = try; accept(srv); catch; break; end
            @async serve_connection(P, s)
        end
        try
            body(port)
        finally
            try; close(srv); catch; end
        end
    end

    function drive_frames(frames, want, port)
        sock = connect(Sockets.localhost, port)
        out = []
        try
            for f in frames; write(sock, f); end
            flush(sock)
            for _ in 1:want
                r = read_one(sock)
                r === nothing && break
                push!(out, r)
            end
        finally
            try; close(sock); catch; end
        end
        return out
    end

    good = make_entity("primitive/any", CborMap(Pair[("x" => 1)]))
    mis_keyed = framed(encode(CborMap(Pair[
        ("root" => entity_tocbor(make_execute(request_id="t1", uri="system/tree",
                                              operation="get", params=empty_params()))),
        ("included" => CborMap(Pair[(fill(UInt8(0x11), 33) => entity_tocbor(good))])),
    ])))
    other_root = framed(frame_ofenvelope(Envelope(
        make_entity("primitive/any", CborMap(Pair[("request_id" => "x-1")])),
        Pair{Vector{UInt8},Entity}[])))
    not_an_envelope = framed(encode(CborMap(Pair[("nope" => 1)])))

    with_peer() do port
        # The control FIRST. If this fails, nothing below is a reading about the peer.
        @test drive_frames([hello_frame()], 1, port) == [(200, "", "ctl-1")]

        # Complete frames the decoder refused: the framing is intact, so the peer answers
        # and KEEPS SERVING. Each is followed by the control on the SAME connection — the
        # differential that says the answer was a refusal of the FRAME and not the
        # connection collapsing.
        got = drive_frames([mis_keyed, other_root, not_an_envelope, hello_frame()], 4, port)
        @test length(got) == 4
        @test got[1] == (400, "hash_mismatch", "t1")
        @test got[2] == (400, "invalid_request", "x-1")
        # §4.11's best-effort UNCORRELATED form: an empty request_id IS that form.
        @test got[3] == (400, "invalid_request", "")
        @test got[4] == (200, "", "ctl-1")

        # §4.10(a) N14: SHOULD -> MUST. The 413 goes out FIRST and the close comes after —
        # IN ADDITION to the frame, not instead of it.
        sock = connect(Sockets.localhost, port)
        big = MAX_FRAME + 1
        write(sock, UInt8[(big >> 24) & 0xff, (big >> 16) & 0xff, (big >> 8) & 0xff, big & 0xff])
        flush(sock)
        @test read_one(sock) == (413, "payload_too_large", "")
        try; close(sock); catch; end

        # A declared body that never arrives. The write side is shut down so the peer sees
        # EOF mid-frame rather than an idle connection.
        #
        # THIS IS THE CASE THE MANAGED-RUNTIME WARNING IS ABOUT: the response can only be
        # written AFTER the client's FIN, so it fails on any runtime whose socket layer
        # closes the write side on a remote half-close. Node needed `allowHalfOpen: true`
        # and the BEAM needed `exit_on_close: false`; this case MEASURES rather than
        # assumes that Julia's TCPSocket does not.
        sock2 = connect(Sockets.localhost, port)
        write(sock2, UInt8[0x00, 0x00, 0x10, 0x00, 0xa1])   # declared 4096, sent 1
        flush(sock2)
        Sockets.closewrite(sock2)
        @test read_one(sock2) == (400, "invalid_request", "")
        try; close(sock2); catch; end

        # The listener survived every refusal above.
        @test drive_frames([hello_frame()], 1, port) == [(200, "", "ctl-1")]
    end
end

end # outer testset
