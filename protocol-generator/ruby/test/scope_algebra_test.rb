# frozen_string_literal: true

require_relative "test_helper"

# The §5 scope algebra at 0.8.2.24/.25: the §5.4 sentinel scoped to PATH-SCOPE
# (RULE B / N2/N3), `scope_subset` typed by scope kind (RULE E / F50, ruled at
# 0.8.2.16), the sentinel guard's reachability from every matcher call site
# (RULE F / K-6), and §6.3's `check_path_permission` (RULE A).
#
# EVERY PREDICATE HERE CARRIES BOTH DIRECTIONS. A deny-only test of an
# authorization predicate is indistinguishable from one asserting `false == false`:
# a broken fixture denies everything and every deny case passes. The accept case is
# what validates the fixture, and one deny case PER DIMENSION is what says the
# predicate checks the dimension under test rather than merely being able to say no.
class ScopeAlgebraTest < Minitest::Test
  include EntityCore

  LOCAL = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA"
  REMOTE = "12D3KooWRemotePeerIdExampleBBBBBBBBBBBBBBBBBBB"

  def scope(incl, excl = [])
    Capability::Scope.new(incl: incl, excl: excl)
  end

  # ── RULE B — §5.4's sentinel is PATH-SCOPE only (0.8.2.24, N2/N3) ────────────

  # "A capability carrying an unmatchable PATH-SCOPE pattern is INVALID [MUST] ... It
  # does NOT reach `operations` or `peers` [MUST]."
  #
  # The id-scope case cannot be passed by accident: `*/apply` is an ordinary
  # namespaced operation name that PATH-canonicalizes to the sentinel, so on the
  # pre-.24 unscoped reading it DENIED THE WHOLE DIMENSION — `get`, included by a bare
  # `*`, came back false. The path-scope half is the other side and proves this is a
  # scope SPLIT rather than a removal: the sentinel still bites where the dimension is
  # a path.
  def test_sentinel_is_path_scope_only
    # id-scope: the sentinel MUST NOT be consulted. `*/apply` is a literal here and
    # carves out nothing, so `get` stays included.
    assert Capability.matches_scope(LOCAL, "get", scope(["*"], ["*/apply"]), :id)
    # The same holds for `peers`, the other id-scope dimension.
    assert Capability.matches_scope(LOCAL, LOCAL, scope(["*"], ["../nope"]), :id)
    # path-scope: UNCHANGED. An unmatchable exclude still denies, because there it
    # would otherwise carve out nothing and leave the grant silently wider than its
    # author wrote (0.8.2.21).
    refute Capability.matches_scope(LOCAL, "system/tree", scope(["*"], ["../nope"]), :path)
    # And a path-scope exclude that IS matchable still carves out only its own target —
    # the sentinel arm must not have swallowed the ordinary case.
    assert Capability.matches_scope(LOCAL, "system/tree", scope(["*"], ["system/secret"]), :path)
  end

  # ── RULE E — `scope_subset` is typed by scope kind (F50 / 0.8.2.16) ──────────

  # §3.6's grammar binds the scope TYPE, not one function: "An implementation on the
  # canonicalizing reading is non-conformant and MUST adopt the literal matcher."
  # `entity-core-formalization` (K-7) measured the divergence on `lean` at 2 of 64
  # include pairs and 2 of 64 exclude pairs, fail-CLOSED, with a 16-pair control
  # alphabet reporting 0 — which is why every hand-tried example missed it.
  #
  # `scope_subset` is private_class_method, so it is driven through `grant_subset`,
  # which is the only caller and is where the per-dimension kinds are named.
  def grant_rec(handlers: [], resources: [], operations: [], peers: nil,
                handlers_excl: [], operations_excl: [])
    Capability::GrantRec.new(
      handlers: scope(handlers, handlers_excl),
      resources: scope(resources),
      operations: scope(operations, operations_excl),
      peers: peers && scope(peers)
    )
  end

  def subset?(child, parent)
    Capability.grant_subset(LOCAL, LOCAL, LOCAL, child, parent)
  end

  def test_operations_subset_uses_the_literal_matcher
    # THE DISCRIMINATING PAIR (K-7's own witness). A child `operations` include of
    # `/tree/get` against a parent `*`:
    #   - literal (conformant):  parent `*` covers any id      -> subset
    #   - canonicalizing (pre-F50): child canonicalizes to `/tree/get` (already
    #     absolute), parent `*` matches anything -> ALSO subset.
    # so the include side needs the OTHER witness, `*/apply`, which canonicalizes to
    # the SENTINEL and is then refused by matches_pattern in either operand — the
    # fail-CLOSED direction K-7 measured.
    assert subset?(grant_rec(operations: ["*/apply"]), grant_rec(operations: ["*"])),
           "an ordinary namespaced operation name is a LITERAL under id-scope and is " \
           "covered by a bare `*`; the canonicalizing reading turns it into the §5.4 " \
           "sentinel and refuses it"
    # The EXCLUDE side, same witness, opposite direction: the child must inherit the
    # parent's exclude, and under the canonicalizing reading neither side can match.
    assert subset?(grant_rec(operations: ["*"], operations_excl: ["*/apply"]),
                   grant_rec(operations: ["*"], operations_excl: ["*/apply"]))
    # CONTROL, and it is what says the subset check still says NO: a child include the
    # parent genuinely does not cover.
    refute subset?(grant_rec(operations: ["get"]), grant_rec(operations: ["put"]))
    # CONTROL on the exclude arm: a parent exclude the child drops is NOT a subset.
    refute subset?(grant_rec(operations: ["*"]),
                   grant_rec(operations: ["*"], operations_excl: ["put"]))
  end

  def test_handlers_subset_still_canonicalizes
    # The path dimensions are UNCHANGED by F50 — a relative child pattern canonicalizes
    # against its frame and is covered by the parent's absolute form.
    assert subset?(grant_rec(handlers: ["system/tree"]),
                   grant_rec(handlers: ["/#{LOCAL}/system/tree"])),
           "handlers is PATH-scope: the frames are what make these two the same pattern"
    refute subset?(grant_rec(handlers: ["system/tree"]),
                   grant_rec(handlers: ["/#{REMOTE}/system/tree"]))
  end

  def test_peers_dimension_takes_the_id_matcher
    # `peers` is the fourth dimension and the second id-scope one. A peer_id is a
    # literal; the canonicalizing reading would rewrite it to `/{local}/{peer}` on one
    # side only when the two frames differ.
    assert subset?(grant_rec(operations: ["*"], peers: [LOCAL]),
                   grant_rec(operations: ["*"], peers: ["*"]))
    refute subset?(grant_rec(operations: ["*"], peers: [REMOTE]),
                   grant_rec(operations: ["*"], peers: [LOCAL]))
  end

  # ── RULE F — the sentinel guard sits on every path to the decision ───────────

  # 0.8.2.22: "a sentinel arm is a control-flow obligation, not a line ... the guard
  # MUST sit on every path that reaches the decision it protects."
  #
  # THIS PEER SATISFIES IT BY CONSTRUCTION AND THAT IS THE POINT OF THIS TEST: the
  # guard is the FIRST LINE OF `matches_pattern` itself ("NEVER_MATCH never matches, in
  # EITHER operand"), not a wrapper beside it, so there is no unguarded twin a call
  # site could reach instead. `lean`'s defect was two functions — `matchesSeg` raw and
  # `matchesSegNM` guarded — with `scopeSubset` calling the raw one. Ruby has one
  # function, so the enumeration below is the assertion: every matcher call site
  # (`covered`, `covered_frame`, `scope_subset`, `check_resource_scope`,
  # `check_path_permission`) routes through it.
  def test_never_match_is_refused_in_either_operand_from_every_surface
    nm = Capability::NEVER_MATCH
    refute Capability.matches_pattern(nm, "*"),        "sentinel as the VALUE"
    refute Capability.matches_pattern("/#{LOCAL}/x", nm), "sentinel as the PATTERN"
    refute Capability.matches_pattern(nm, nm),         "sentinel against ITSELF"
    # CONTROL: the bare-star arm sits directly below the guard and returns true for
    # everything else, which is exactly why the guard has to be first.
    assert Capability.matches_pattern("/#{LOCAL}/x", "*")

    # The surfaces. `matches_scope` path arm (include side, fail-CLOSED):
    refute Capability.matches_scope(LOCAL, "../nope", scope(["*"]), :path)
    # `scope_subset` via grant_subset — a sentinel child include is covered by nothing:
    refute subset?(grant_rec(handlers: ["../nope"]), grant_rec(handlers: ["*"]))
    # `check_resource_scope` via check_permission is covered by the E family of
    # arc-probe on the wire; `check_path_permission`'s sentinel arm is below.
  end

  # ── RULE A — §6.3 `check_path_permission` (0.8.2.20/.21/.22) ─────────────────

  def token_with(handlers:, operations:, resources:, resources_excl: [])
    grants = [{
      "handlers" => { "include" => handlers },
      "operations" => { "include" => operations },
      "resources" => resources_excl.empty? ? { "include" => resources }
                                           : { "include" => resources, "exclude" => resources_excl }
    }]
    Entity.make("system/capability/token", { "grants" => grants })
  end

  def test_check_path_permission_accepts_and_denies_per_dimension
    tok = token_with(handlers: ["system/tree"], operations: ["get"], resources: ["app/*"])
    path = "/#{LOCAL}/app/x"

    # THE ACCEPT CASE IS THE FIXTURE'S OWN TEST. Without it a grant map this function
    # cannot parse would deny everything and all three deny cases below would pass.
    assert Capability.check_path_permission(LOCAL, "get", path, tok, "system/tree"),
           "the fixture parses and the three dimensions line up"

    # ONE DENY PER DIMENSION, because a single deny cannot distinguish "the predicate
    # checks the dimension I care about" from "the predicate denies".
    refute Capability.check_path_permission(LOCAL, "get", path, tok, "system/other"),
           "handlers dimension (path-scope)"
    refute Capability.check_path_permission(LOCAL, "put", path, tok, "system/tree"),
           "operations dimension (id-scope)"
    refute Capability.check_path_permission(LOCAL, "get", "/#{LOCAL}/other/x", tok, "system/tree"),
           "resources dimension (path-scope)"
  end

  def test_check_path_permission_is_three_dimensions_not_four
    # §6.3's signature names handlers, operations and resources. `peers` is NOT
    # consulted: the path is local by construction here (§1.4's inbound rule refuses a
    # foreign namespace at §6.5 step 3, before any handler runs). A grant whose `peers`
    # scope excludes everything still authorizes a local path through this function.
    grants = [{
      "handlers" => { "include" => ["system/tree"] },
      "operations" => { "include" => ["get"] },
      "resources" => { "include" => ["app/*"] },
      "peers" => { "include" => [] }
    }]
    tok = Entity.make("system/capability/token", { "grants" => grants })
    assert Capability.check_path_permission(LOCAL, "get", "/#{LOCAL}/app/x", tok, "system/tree")
  end

  def test_empty_resources_include_denies_every_path
    # §5.2's note: an empty `resources.include` is a LEGAL grant shape (a handler that
    # touches no tree paths) and `covered` over an empty include list is false, so it
    # denies every path. Not a parse failure — the accept control above proves the
    # parser works.
    tok = token_with(handlers: ["*"], operations: ["*"], resources: [])
    refute Capability.check_path_permission(LOCAL, "get", "/#{LOCAL}/app/x", tok, "system/tree")
  end

  def test_malformed_path_falls_through_to_deny
    # A malformed path canonicalizes to NEVER_MATCH, which matches no grant, so it
    # falls through to DENY rather than being matched against anything — and rather
    # than escaping as a raise the §6.5 frame would answer 500 (0.8.2.20 made
    # canonicalize total for exactly this reason).
    tok = token_with(handlers: ["*"], operations: ["*"], resources: ["*"])
    assert Capability.check_path_permission(LOCAL, "get", "/#{LOCAL}/app/x", tok, "system/tree"),
           "control: the same token DOES authorize a well-formed path"
    refute Capability.check_path_permission(LOCAL, "get", "../escape", tok, "system/tree")
  end

  def test_frame_is_the_local_peer_not_the_granter
    # §6.3's block reads `matches_scope(canonical_path, grant.resources, "path-scope",
    # local_peer_id)` — there is NO granter parameter to pass. §5.5a governs chain
    # ATTENUATION, where the subject is a pattern compared against a parent's pattern;
    # this call site compares a CONCRETE local path. A bare `*` in `resources` therefore
    # canonicalizes to `/{local}/*` here whoever granted the capability.
    tok = token_with(handlers: ["*"], operations: ["*"], resources: ["*"])
    assert Capability.check_path_permission(LOCAL, "get", "/#{LOCAL}/app/x", tok, "system/tree")
    refute Capability.check_path_permission(LOCAL, "get", "/#{REMOTE}/app/x", tok, "system/tree"),
           "a bare `*` is granter-local, never universal (§5.5a); the frame here is the " \
           "LOCAL peer, so a foreign namespace is not covered"
  end
end
