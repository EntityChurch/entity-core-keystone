defmodule EntityCore.ScopeAlgebraTest do
  @moduledoc """
  The §5 scope algebra at 0.8.2.24/.25: the §5.4 sentinel scoped to PATH-SCOPE (RULE B /
  N2/N3), `scope_subset` typed by scope kind (RULE E / F50, ruled at 0.8.2.16), the
  sentinel guard's reachability from every matcher call site (RULE F / K-6), and §6.3's
  `check_path_permission` (RULE A).

  EVERY PREDICATE HERE CARRIES BOTH DIRECTIONS. A deny-only test of an authorization
  predicate is indistinguishable from one asserting `false == false`: a broken fixture
  denies everything and every deny case passes. The accept case is what validates the
  fixture, and one deny case PER DIMENSION is what says the predicate checks the
  dimension under test rather than merely being able to say no.
  """
  use ExUnit.Case, async: true

  alias EntityCore.{Capability, Model}

  @local "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA"
  @remote "12D3KooWRemotePeerIdExampleBBBBBBBBBBBBBBBBBBB"

  defp scope(incl, excl \\ []), do: %{"include" => incl, "exclude" => excl}

  defp token(grants), do: Model.make("system/capability/token", %{"grants" => grants})

  defp grant(opts) do
    %{
      "handlers" => scope(Keyword.get(opts, :handlers, []), Keyword.get(opts, :handlers_excl, [])),
      "resources" => scope(Keyword.get(opts, :resources, []), Keyword.get(opts, :resources_excl, [])),
      "operations" =>
        scope(Keyword.get(opts, :operations, []), Keyword.get(opts, :operations_excl, []))
    }
    |> then(fn g ->
      case Keyword.get(opts, :peers) do
        nil -> g
        p -> Map.put(g, "peers", scope(p))
      end
    end)
  end

  # ── RULE B — §5.4's sentinel is PATH-SCOPE only (0.8.2.24, N2/N3) ──────────

  describe "the §5.4 sentinel is scoped to path-scope" do
    # *"A capability carrying an unmatchable PATH-SCOPE pattern is INVALID `[MUST]` ...
    # It does NOT reach `operations` or `peers` `[MUST]`."*
    #
    # The id-scope case cannot be passed by accident: `*/apply` is an ordinary
    # namespaced operation name that PATH-canonicalizes to the sentinel, so on the
    # pre-.24 unscoped reading it DENIED THE WHOLE DIMENSION — `get`, included by a bare
    # `*`, came back false. The path-scope half is the other side and proves this is a
    # scope SPLIT rather than a removal: the sentinel still bites where the dimension is
    # a path.
    #
    # `matches_scope/4` is private, so the pair is driven through the public
    # `check_path_permission/5`, which names `operations` as id-scope and `handlers` /
    # `resources` as path-scope at its three call sites.
    test "an id-scope exclude that path-canonicalizes to the sentinel carves out nothing" do
      tok = token([grant(handlers: ["*"], operations: ["*"], operations_excl: ["*/apply"], resources: ["*"])])
      assert Capability.check_path_permission(@local, "get", "/#{@local}/app/x", tok, "system/tree")
    end

    test "a path-scope exclude that canonicalizes to the sentinel still denies" do
      tok = token([grant(handlers: ["*"], operations: ["*"], resources: ["*"], resources_excl: ["../nope"])])
      refute Capability.check_path_permission(@local, "get", "/#{@local}/app/x", tok, "system/tree")
    end

    test "a matchable path-scope exclude still carves out only its own target" do
      # The sentinel arm must not have swallowed the ordinary case.
      tok = token([grant(handlers: ["*"], operations: ["*"], resources: ["*"], resources_excl: ["app/secret"])])
      assert Capability.check_path_permission(@local, "get", "/#{@local}/app/x", tok, "system/tree")
      refute Capability.check_path_permission(@local, "get", "/#{@local}/app/secret", tok, "system/tree")
    end
  end

  # ── RULE E — `scope_subset` is typed by scope kind (F50 / 0.8.2.16) ────────

  describe "scope_subset is typed by scope kind" do
    # §3.6's grammar binds the scope TYPE, not one function: *"An implementation on the
    # canonicalizing reading is non-conformant and MUST adopt the literal matcher."*
    # `entity-core-formalization` (K-7) measured the divergence on `lean` at 2 of 64
    # include pairs and 2 of 64 exclude pairs, fail-CLOSED, with a 16-pair control
    # alphabet reporting 0 — which is why every hand-tried example missed it.
    #
    # `scope_subset` is private; `grant_subset_local/3` is the public §6.2 mint-time
    # surface that names the per-dimension kinds, so the pairs are driven through it.
    defp subset?(child, parent) do
      Capability.grant_subset_local(
        @local,
        Capability.parse_grant_entry(child),
        Capability.parse_grant_entry(parent)
      )
    end

    test "an ordinary namespaced operation name is a LITERAL and is covered by a bare *" do
      # THE DISCRIMINATING PAIR (K-7's own witness). `*/apply` PATH-canonicalizes to the
      # §5.4 sentinel, which `matches_pattern` then refuses in EITHER operand — the
      # fail-CLOSED direction K-7 measured. Under the conformant literal matcher a bare
      # `*` covers it.
      assert subset?(grant(operations: ["*/apply"]), grant(operations: ["*"]))
    end

    test "the exclude arm takes the literal matcher too" do
      assert subset?(
               grant(operations: ["*"], operations_excl: ["*/apply"]),
               grant(operations: ["*"], operations_excl: ["*/apply"])
             )
    end

    test "CONTROL: the subset check still says no" do
      # Without these the typing change would be satisfied by a function that returns
      # true unconditionally.
      refute subset?(grant(operations: ["get"]), grant(operations: ["put"]))
      refute subset?(grant(operations: ["*"]), grant(operations: ["*"], operations_excl: ["put"]))
    end

    test "the path dimensions still canonicalize" do
      assert subset?(grant(handlers: ["system/tree"]), grant(handlers: ["/#{@local}/system/tree"]))
      refute subset?(grant(handlers: ["system/tree"]), grant(handlers: ["/#{@remote}/system/tree"]))
    end

    test "peers is the second id-scope dimension" do
      assert subset?(grant(operations: ["*"], peers: [@local]), grant(operations: ["*"], peers: ["*"]))
      refute subset?(grant(operations: ["*"], peers: [@remote]), grant(operations: ["*"], peers: [@local]))
    end
  end

  # ── RULE F — the sentinel guard sits on every path to the decision ─────────

  describe "the NEVER_MATCH guard is on every path that reaches a match decision" do
    # 0.8.2.22: *"a sentinel arm is a control-flow obligation, not a line ... the guard
    # MUST sit on every path that reaches the decision it protects."*
    #
    # THIS PEER SATISFIES IT BY CONSTRUCTION AND THAT IS THE POINT OF THIS TEST: the
    # guard is the FIRST TWO CLAUSES OF `matches_pattern/2` itself, not a wrapper beside
    # it, so there is no unguarded twin a call site could reach instead. `lean`'s defect
    # was two functions — `matchesSeg` raw and `matchesSegNM` guarded — with
    # `scopeSubset` calling the raw one. Elixir has one function, and every matcher call
    # site (`do_matches_scope`, `check_resource_scope`, `scope_subset`,
    # `check_path_permission`, `effective_targets`) routes through it.
    test "the sentinel never matches, in either operand" do
      nm = Capability.never_match()
      refute Capability.matches_pattern(nm, "*")
      refute Capability.matches_pattern("/#{@local}/x", nm)
      refute Capability.matches_pattern(nm, nm)
      # CONTROL: the bare-star clause sits directly below the guard and returns true for
      # everything else, which is exactly why the guard has to be first.
      assert Capability.matches_pattern("/#{@local}/x", "*")
    end

    test "a sentinel include covers nothing (fail-CLOSED) at every surface" do
      tok = token([grant(handlers: ["*"], operations: ["*"], resources: ["../nope"])])
      refute Capability.check_path_permission(@local, "get", "/#{@local}/app/x", tok, "system/tree")
      refute subset?(grant(handlers: ["../nope"]), grant(handlers: ["*"]))
    end
  end

  # ── RULE A — §6.3 `check_path_permission` (0.8.2.20/.21/.22) ───────────────

  describe "check_path_permission" do
    test "accepts, then denies once per dimension" do
      tok = token([grant(handlers: ["system/tree"], operations: ["get"], resources: ["app/*"])])
      path = "/#{@local}/app/x"

      # THE ACCEPT CASE IS THE FIXTURE'S OWN TEST. Without it a grant map this function
      # cannot parse would deny everything and all three deny cases below would pass.
      assert Capability.check_path_permission(@local, "get", path, tok, "system/tree")

      # ONE DENY PER DIMENSION, because a single deny cannot distinguish "the predicate
      # checks the dimension I care about" from "the predicate denies".
      refute Capability.check_path_permission(@local, "get", path, tok, "system/other")
      refute Capability.check_path_permission(@local, "put", path, tok, "system/tree")
      refute Capability.check_path_permission(@local, "get", "/#{@local}/other/x", tok, "system/tree")
    end

    test "is three dimensions, not four" do
      # §6.3's signature names handlers, operations and resources. `peers` is NOT
      # consulted: the path is local by construction here (§1.4's inbound rule refuses a
      # foreign namespace at §6.5 step 3, before any handler runs). A grant whose `peers`
      # scope includes nothing still authorizes a local path through this function.
      tok = token([grant(handlers: ["system/tree"], operations: ["get"], resources: ["app/*"], peers: [])])
      assert Capability.check_path_permission(@local, "get", "/#{@local}/app/x", tok, "system/tree")
    end

    test "an empty resources.include denies every path" do
      # §5.2's note: an empty `resources.include` is a LEGAL grant shape (a handler that
      # touches no tree paths) and coverage over an empty include list is false, so it
      # denies every path. Not a parse failure — the accept control above proves the
      # parser works.
      tok = token([grant(handlers: ["*"], operations: ["*"], resources: [])])
      refute Capability.check_path_permission(@local, "get", "/#{@local}/app/x", tok, "system/tree")
    end

    test "a malformed path falls through to DENY rather than raising" do
      # A malformed path canonicalizes to the sentinel, which matches no grant, so it
      # falls through to DENY rather than being matched against anything — and rather
      # than escaping as a raise the §6.5 frame would answer 500 (0.8.2.20 made
      # `canonicalize` total for exactly this reason).
      tok = token([grant(handlers: ["*"], operations: ["*"], resources: ["*"])])
      assert Capability.check_path_permission(@local, "get", "/#{@local}/app/x", tok, "system/tree")
      refute Capability.check_path_permission(@local, "get", "../escape", tok, "system/tree")
    end

    test "the frame is the LOCAL peer, not the granter" do
      # §6.3's block reads `matches_scope(canonical_path, grant.resources, "path-scope",
      # local_peer_id)` — there is NO granter parameter to pass. §5.5a governs chain
      # ATTENUATION, where the subject is a pattern compared against a parent's pattern;
      # this call site compares a CONCRETE local path. A bare `*` in `resources`
      # therefore canonicalizes to `/{local}/*` here whoever granted the capability.
      tok = token([grant(handlers: ["*"], operations: ["*"], resources: ["*"])])
      assert Capability.check_path_permission(@local, "get", "/#{@local}/app/x", tok, "system/tree")
      refute Capability.check_path_permission(@local, "get", "/#{@remote}/app/x", tok, "system/tree")
    end
  end
end
