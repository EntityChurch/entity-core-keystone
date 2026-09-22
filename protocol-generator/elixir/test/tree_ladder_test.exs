defmodule EntityCore.TreeLadderTest do
  @moduledoc """
  §3.3's effective-targets ladder in the tree handler, the §6.3 path check it gates, the
  §6.3 listing filter, and the operation-before-resource ORDERING (RULE A + RULE G,
  0.8.2.20/.21/.22 + N7/N10/N11 at .24/.25).

  Driven through the REAL `Peer.tree_handler/3` with a real store, because the defect
  this work closes is a handler that implements §3.3's ARITHMETIC completely and then
  indexes `targets[0]` anyway: `Capability.effective_targets/2` alone cannot show that.
  """
  use ExUnit.Case, async: false

  alias EntityCore.{Capability, Model, Peer, Store, Wire}

  @seed :binary.copy(<<0x5A>>, 32)

  setup do
    peer = Peer.create(@seed)
    Store.bind(peer.store, "/" <> peer.local_peer <> "/app/a", Model.make("primitive/any", %{"v" => 1}))
    Store.bind(peer.store, "/" <> peer.local_peer <> "/app/b", Model.make("primitive/any", %{"v" => 2}))
    {:ok, peer: peer}
  end

  defp scope(incl, excl \\ []), do: %{"include" => incl, "exclude" => excl}

  # A capability whose `resources` cover `include` and exclude `excl`.
  defp cap(resources \\ ["*"], excl \\ []) do
    Model.make("system/capability/token", %{
      "grants" => [
        %{
          "handlers" => scope(["*"]),
          "operations" => scope(["*"]),
          "resources" => scope(resources, excl)
        }
      ]
    })
  end

  defp exec(resource, operation \\ "get", params \\ nil) do
    data = %{
      "request_id" => "r1",
      "uri" => "system/tree",
      "operation" => operation,
      "params" => Model.to_cbor(params || Wire.empty_params())
    }

    data = if resource == nil, do: data, else: Map.put(data, "resource", resource)
    Model.make("system/protocol/execute", data)
  end

  defp auth(token \\ nil), do: {token || cap(), "system/tree"}

  defp code(outcome), do: Model.text_field(outcome.result, "code")

  # ── effective_targets: THE TWO-EMPTIES DISCRIMINATOR (N11, 0.8.2.25) ───────

  # N11 makes the discriminator a `[MUST]`: *"where an implementation projects
  # `resource.targets` onto the effective set ahead of the handler, that projection MUST
  # NOT be lossy about its own emptiness — narrow when narrowing leaves something, and
  # retain the raw pair when narrowing would empty it."* This peer carries the
  # discriminator as `nil` vs `[]`; the property is the same and the spelling is the
  # substrate's.
  describe "effective_targets" do
    test "an absent resource is nil", %{peer: p} do
      assert Capability.effective_targets(p.local_peer, exec(nil)) == nil
    end

    test "a resource map with no targets key is reported absent, and that is OPEN", %{peer: p} do
      # PINS THE SHIPPED ANSWER TO AN OPEN QUESTION rather than endorsing it. §3.2 says
      # `targets` *"MUST contain at least one entry"*, which makes the shape MALFORMED
      # rather than absent — and N10's point is that a PRESENT `resource` must not be
      # served the wider absent-case answer. Nothing in the 778-check set drives it and
      # no disposition is pinned, so the behaviour is HELD rather than changed; this case
      # exists so that changing it is a DECISION and not a drift.
      #
      # It is also the discriminator the 0.8.2.25 vanguard's first plant pass was
      # missing: without it the "collapse the two empties" mutation ran GREEN, because
      # nothing else reaches this branch at all.
      assert Capability.effective_targets(p.local_peer, exec(%{})) == nil
      assert Capability.effective_targets(p.local_peer, exec(%{"exclude" => ["a"]})) == nil
    end

    test "present-but-empty is a LIST, not nil", %{peer: p} do
      assert Capability.effective_targets(p.local_peer, exec(%{"targets" => ["a"], "exclude" => ["a"]})) == []
      assert Capability.effective_targets(p.local_peer, exec(%{"targets" => []})) == []
    end

    test "an ill-typed targets is PRESENT, not absent", %{peer: p} do
      # `%{"targets" => 42}` is a PRESENT resource. Reporting it absent gives `get` the
      # root listing for a request that named something — N11's own defect one field
      # over, and the cell on which the two 0.8.2.25 vanguards diverged before being
      # corrected toward `go`.
      assert Capability.effective_targets(p.local_peer, exec(%{"targets" => 42})) == []
      assert Capability.effective_targets(p.local_peer, exec(%{"targets" => "a"})) == []
    end

    test "survivors keep the caller's own spelling", %{peer: p} do
      # 0.8.2.21: `effective_targets` yields RAW survivors, not canonical forms — the
      # value flows on to the store lookup, which canonicalizes for itself.
      assert Capability.effective_targets(
               p.local_peer,
               exec(%{"targets" => ["app/x", "app/y"], "exclude" => ["app/y"]})
             ) == ["app/x"]
    end
  end

  # ── RULE G — operation resolution precedes resource validation ─────────────

  describe "the operation is resolved before the resource ladder" do
    # This handler used to put an "any operation, no resource" arm ABOVE the
    # unknown-operation arm, so `system/tree:bogusop` with NO resource answered a
    # RESOURCE error for an OPERATION fault. `entity-system-conformance` measured it
    # independently across variants (X9 / F52).
    test "an unknown operation with no resource is 501, not a resource error", %{peer: p} do
      out = Peer.tree_handler(p, exec(nil, "bogusop"), auth())
      assert out.status == 501
      assert code(out) == "unsupported_operation"
    end

    test "CONTROL: the same unknown operation WITH a resource is also 501", %{peer: p} do
      # The control is what makes it an ORDERING defect rather than a missing 501 arm:
      # before the fix these two answered DIFFERENTLY.
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/a"]}, "bogusop"), auth())
      assert out.status == 501
      assert code(out) == "unsupported_operation"
    end
  end

  # ── the ladder, `get` (resource-OPTIONAL, BROAD-RESULT) ────────────────────

  describe "the §3.3 ladder in get" do
    test "an absent resource is the root listing", %{peer: p} do
      out = Peer.tree_handler(p, exec(nil), auth())
      assert out.status == 200
      assert out.result.type == "system/tree/listing"
      assert Model.field(out.result, "path") == "/" <> p.local_peer <> "/"
    end

    test "present-but-self-excluded is 400 path_required", %{peer: p} do
      # THE TWO EMPTIES ARE DISTINCT, and this is the pair that says so. Collapsing them
      # would serve the ROOT LISTING to a request that named one excluded path — the
      # wider-than-the-request answer §3.3 forbids and the live disclosure the 0.8.2.25
      # vanguard work surfaced.
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/a"], "exclude" => ["app/a"]}), auth())
      assert out.status == 400
      assert code(out) == "path_required"
    end

    test "more than one effective target is 400 ambiguous_resource", %{peer: p} do
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/a", "app/b"]}), auth())
      assert out.status == 400
      assert code(out) == "ambiguous_resource"

      # ...and the exclude is what makes the COUNT an effective-set count rather than a
      # raw `targets` count: two targets, one excluded, ONE survivor -> it proceeds.
      ok = Peer.tree_handler(p, exec(%{"targets" => ["app/a", "app/b"], "exclude" => ["app/b"]}), auth())
      assert ok.status == 200
    end

    test "the selection is the SURVIVOR, never targets[0]", %{peer: p} do
      # THE MUST 0.8.2.20 NAMES: a handler that counts the effective list and then
      # indexes `targets[0]` has implemented the arithmetic completely and is still
      # reading a path no authorization covered. Here `targets[0]` is EXCLUDED and the
      # single survivor is `targets[1]`, so the two readings return different entities.
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/a", "app/b"], "exclude" => ["app/a"]}), auth())
      assert out.status == 200
      assert Model.field(out.result, "v") == 2
    end

    test "a pattern target is 400 malformed_resource; a trailing slash is a listing", %{peer: p} do
      # 0.8.2.20: a resource-requiring operation takes a CONCRETE path. A trailing "/" is
      # a listing request and is NOT a pattern — only a `*` makes it one.
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/*"]}), auth())
      assert out.status == 400
      assert code(out) == "malformed_resource"

      listing = Peer.tree_handler(p, exec(%{"targets" => ["app/"]}), auth())
      assert listing.status == 200
      assert listing.result.type == "system/tree/listing"
    end

    test "the caller-exclude arm is fail-OPEN on an unmatchable pattern", %{peer: p} do
      # §5.4 rules the caller-exclude arm separately from the GRANT arm: `canonicalize`
      # answers the sentinel, `matches_pattern` then answers false, and the target simply
      # SURVIVES. The matchable control beside it is what says the exclude works at all —
      # without it a peer that ignored `exclude` entirely would pass this.
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/a"], "exclude" => ["../nope"]}), auth())
      assert out.status == 200
      assert Model.field(out.result, "v") == 1

      denied = Peer.tree_handler(p, exec(%{"targets" => ["app/a"], "exclude" => ["app/a"]}), auth())
      assert denied.status == 400
    end
  end

  # ── the ladder, `put` (resource-REQUIRED) ──────────────────────────────────

  test "put answers path_required for a MISSING target, not ambiguous_resource", %{peer: p} do
    # THE CODE CHANGE 0.8.2.20 FORCED. This branch answered `ambiguous_resource` for a
    # MISSING target, which 0.8.2.20 names as the exact inversion it forbids: the
    # remedies differ — *supply a resource* is not *disambiguate your request* — and the
    # code is what selects the remedy.
    out = Peer.tree_handler(p, exec(nil, "put"), auth())
    assert out.status == 400
    assert code(out) == "path_required"

    # BOTH empties collapse here, because §2.2a declares `put` resource-REQUIRED:
    empty = Peer.tree_handler(p, exec(%{"targets" => ["app/a"], "exclude" => ["app/a"]}, "put"), auth())
    assert code(empty) == "path_required"

    # ...and more than one survivor is still `ambiguous_resource`, which is what says the
    # two codes have not simply been swapped.
    many = Peer.tree_handler(p, exec(%{"targets" => ["app/a", "app/b"]}, "put"), auth())
    assert code(many) == "ambiguous_resource"
  end

  # ── §6.3: the handler-level path check (0.8.2.20) ──────────────────────────

  describe "the §6.3 path check" do
    test "get denies a path the caller's own capability excludes", %{peer: p} do
      # THE F84 DEFECT. The caller's own `exclude` removes `app/b` from the DISPATCH
      # check's view entirely, so `check_permission` never sees it; without §6.3's own
      # check the handler then serves it. §6.3: *"not a secondary check ... the sole
      # enforcement wherever the subject is derived after dispatch."*
      narrow = auth(cap(["*"], ["app/b"]))
      denied = Peer.tree_handler(p, exec(%{"targets" => ["app/b"]}), narrow)
      assert denied.status == 403
      assert code(denied) == "capability_denied"

      # CONTROL, in the same capability: a path the SAME grant does cover is served.
      ok = Peer.tree_handler(p, exec(%{"targets" => ["app/a"]}), narrow)
      assert ok.status == 200
    end

    test "put denies, and nothing is written", %{peer: p} do
      narrow = auth(cap(["*"], ["app/b"]))
      e = Model.make("primitive/any", %{"v" => 9})
      params = Model.make("primitive/any", %{"entity" => Model.to_cbor(e)})
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/b"]}, "put", params), narrow)
      assert out.status == 403
      assert code(out) == "capability_denied"
      # A 403 whose refusal arrives AFTER the store write would satisfy the status
      # assertion alone, so the store is read back.
      assert Model.field(Store.get_at(p.store, "/" <> p.local_peer <> "/app/b"), "v") == 2
    end

    test "an unauthenticated context is not path-checked", %{peer: p} do
      # The bootstrap/internal path. The filter's subject is *"the caller's verified
      # capability"*, and where there is none there is no caller to narrow.
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/a"]}), nil)
      assert out.status == 200
    end
  end

  # ── §6.3: the listing filter (0.8.2.21/.22) ────────────────────────────────

  describe "the §6.3 listing filter" do
    test "entries the caller cannot get are omitted and count follows", %{peer: p} do
      # *"Entries for which `check_path_permission` returns DENY MUST be omitted. The
      # result's `count` field MUST reflect the FILTERED entry count, not the source
      # tree's total count."* A count that still reports the source total IS the
      # disclosure the rule exists to prevent, so it is asserted separately.
      narrow = auth(cap(["*"], ["app/b"]))
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/"]}), narrow)
      assert out.status == 200
      assert Model.field(out.result, "entries") |> Map.keys() |> Enum.sort() == ["a"]
      assert Model.field(out.result, "count") == 1

      # CONTROL, and it is the one that makes the filter case mean anything: the same
      # listing under a capability that covers both names both.
      wide = Peer.tree_handler(p, exec(%{"targets" => ["app/"]}), auth())
      assert Model.field(wide.result, "entries") |> Map.keys() |> Enum.sort() == ["a", "b"]
      assert Model.field(wide.result, "count") == 2
    end

    test "the directory itself is not checked", %{peer: p} do
      # §6.3 makes each ENTRY the subject. Testing the PREFIX would deny a listing to a
      # caller whose grant covers children but not the node above them, which is the
      # ordinary shape of a narrowed grant — so this grant, which covers `app/*` and not
      # `app` itself, must still get its listing.
      child_only = auth(cap(["app/*"]))
      out = Peer.tree_handler(p, exec(%{"targets" => ["app/"]}), child_only)
      assert out.status == 200
      assert Model.field(out.result, "entries") |> Map.keys() |> Enum.sort() == ["a", "b"]
    end
  end
end
