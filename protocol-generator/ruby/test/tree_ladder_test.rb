# frozen_string_literal: true

require_relative "test_helper"

# §3.3's effective-targets ladder in the tree handler, the §6.3 path check it gates,
# and the §6.3 listing filter (RULE A, 0.8.2.20/.21/.22 + N7/N10/N11 at .24/.25).
#
# Driven through the REAL TreeHandler with a real store, because the defect this work
# closes is a handler that implements §3.3's ARITHMETIC completely and then indexes
# `targets[0]` anyway: `effective_targets` alone cannot show that, and the arc-probe
# wire drive cannot show the two-empties discriminator on a resource-OPTIONAL
# operation without a capability it has to mint for itself.
class TreeLadderTest < Minitest::Test
  include EntityCore

  def setup
    @peer = Peer.create(("\x5a".chr * 32).b, open_grants: false, conformance: false)
    @local = @peer.local_peer
    @handler = Peer::TreeHandler.new(@peer)
    @peer.store.bind("/#{@local}/app/a", Entity.make("primitive/any", { "v" => 1 }))
    @peer.store.bind("/#{@local}/app/b", Entity.make("primitive/any", { "v" => 2 }))
  end

  # A capability whose `resources` cover `pattern` and exclude `excl`.
  def cap(resources: ["*"], resources_excl: [], operations: ["*"], handlers: ["*"])
    scope = { "include" => resources }
    scope["exclude"] = resources_excl unless resources_excl.empty?
    grants = [{
      "handlers" => { "include" => handlers },
      "operations" => { "include" => operations },
      "resources" => scope
    }]
    Entity.make("system/capability/token", { "grants" => grants })
  end

  def ctx(resource, caller_cap: cap, operation: "get")
    exec = Wire.make_execute("r1", "system/tree", operation, Wire.empty_params,
                             resource: resource)
    HandlerContext.new(exec: exec, conn: Conn.new, included: [], caller_cap: caller_cap,
                       env: Envelope.new(exec), handler_pattern: "system/tree")
  end

  def code_of(outcome)
    outcome.result.text("code")
  end

  # ── effective_targets: THE TWO-EMPTIES DISCRIMINATOR (N11, 0.8.2.25) ────────

  # N11 makes the discriminator a [MUST]: "where an implementation projects
  # `resource.targets` onto the effective set ahead of the handler, that projection
  # MUST NOT be lossy about its own emptiness — narrow when narrowing leaves
  # something, and retain the raw pair when narrowing would empty it." This peer
  # carries the discriminator as `nil` vs `[]`; the property is the same and the
  # spelling is the substrate's.
  def eff(resource)
    Capability.effective_targets(@local, Wire.make_execute(
                                           "r1", "system/tree", "get", Wire.empty_params,
                                           resource: resource
                                         ))
  end

  def test_absent_resource_is_nil
    assert_nil eff(nil)
  end

  def test_targets_key_absent_is_reported_absent_and_that_is_the_open_question
    # PINS THE SHIPPED ANSWER TO AN OPEN QUESTION rather than endorsing it. A
    # `resource` MAP carrying no `targets` key is reported ABSENT by every 0.8.2.25
    # peer, so `get` serves it the root listing. §3.2 says `targets` "MUST contain at
    # least one entry", which makes the shape MALFORMED rather than absent — and N10's
    # point is that a PRESENT `resource` must not be served the wider absent-case
    # answer. Nothing in the 778-check set drives it and no disposition is pinned, so
    # the behaviour is HELD rather than changed; this case exists so that changing it
    # is a DECISION and not a drift.
    #
    # It is also the discriminator the vanguard's first plant pass was missing:
    # without it the "collapse the two empties" mutation ran GREEN, because nothing
    # else reaches this branch at all.
    assert_nil eff({})
    assert_nil eff({ "exclude" => ["a"] })
  end

  def test_present_but_empty_is_a_list_not_nil
    assert_equal [], eff({ "targets" => ["a"], "exclude" => ["a"] })
    assert_equal [], eff({ "targets" => [] })
  end

  def test_ill_typed_targets_is_present_not_absent
    # `{"targets": 42}` is a PRESENT resource. Reporting it absent gives `get` the root
    # listing for a request that named something — N11's own defect one field over,
    # and the cell on which the two 0.8.2.25 vanguards diverged before being corrected
    # toward `go`.
    assert_equal [], eff({ "targets" => 42 })
    assert_equal [], eff({ "targets" => "a" })
  end

  def test_survivors_keep_the_callers_own_spelling
    # 0.8.2.21: `effective_targets` yields RAW survivors, not canonical forms — the
    # value flows on to the store lookup, which canonicalizes for itself.
    assert_equal ["app/x"], eff({ "targets" => %w[app/x app/y], "exclude" => ["app/y"] })
  end

  # ── RULE G — operation resolution precedes resource validation ──────────────

  # "Resolve the operation first; only then run the §3.3 ladder." A peer that validates
  # the resource first answers a RESOURCE fault for an OPERATION fault on every unknown
  # operation — measured independently by `entity-system-conformance` (X9 / F52) on the
  # peers whose tree handler is one match over (operation, resource).
  #
  # ON THIS SUBSTRATE THE ORDERING IS STRUCTURAL AND THAT IS THE FINDING, not a fix:
  # `Handler#handle` resolves the wire operation against the subclass's declared `ops`
  # list and reaches `op_get`/`op_put` ONLY for a known operation, so a resource ladder
  # cannot run ahead of it. The case is here anyway because "it cannot happen" is a claim
  # about today's dispatcher, and this is the assertion that keeps it one.
  def test_an_unknown_operation_is_501_with_or_without_a_resource
    out = @handler.handle("bogusop", ctx(nil))
    assert_equal 501, out.status
    assert_equal "unsupported_operation", code_of(out)
    # CONTROL, and it is what makes this an ORDERING claim rather than a missing-501
    # claim: before the fix, on the peers that had it, these two answered DIFFERENTLY.
    withres = @handler.handle("bogusop", ctx({ "targets" => ["app/a"] }))
    assert_equal 501, withres.status
    assert_equal "unsupported_operation", code_of(withres)
    # ...and a KNOWN operation still routes, or the two cases above are satisfied by a
    # dispatcher that answers 501 to everything.
    assert_equal 200, @handler.handle("get", ctx({ "targets" => ["app/a"] })).status
  end

  # ── the ladder, `get` (resource-OPTIONAL, BROAD-RESULT) ─────────────────────

  # EXTENSION-TREE §2.2a (v4.11) declares `get` resource-OPTIONAL and BROAD-RESULT:
  # absent-case answer "the root listing", self-excluded case "400 path_required".
  # 0.8.2.24 (N7) scopes §3.3's "an empty effective list IS the absent case" to "an
  # operation that REQUIRES a resource", and 0.8.2.25 (N10) decides the
  # present-but-empty case by whether the absent case is WIDER than the request.
  def test_get_absent_resource_is_the_root_listing
    out = @handler.op_get(ctx(nil))
    assert_equal 200, out.status
    assert_equal "system/tree/listing", out.result.type
    assert_equal "/#{@local}/", out.result.text("path")
  end

  def test_get_present_but_self_excluded_is_path_required
    # THE TWO EMPTIES ARE DISTINCT, and this is the pair that says so. Collapsing them
    # would serve the ROOT LISTING to a request that named one excluded path — the
    # wider-than-the-request answer §3.3 forbids and the live disclosure the 0.8.2.25
    # vanguard work surfaced.
    out = @handler.op_get(ctx({ "targets" => ["app/a"], "exclude" => ["app/a"] }))
    assert_equal 400, out.status
    assert_equal "path_required", code_of(out)
  end

  def test_get_more_than_one_effective_target_is_ambiguous_resource
    out = @handler.op_get(ctx({ "targets" => %w[app/a app/b] }))
    assert_equal 400, out.status
    assert_equal "ambiguous_resource", code_of(out)
    # ...and the exclude is what makes the COUNT an effective-set count rather than a
    # raw `targets` count: two targets, one excluded, ONE survivor -> it proceeds.
    ok = @handler.op_get(ctx({ "targets" => %w[app/a app/b], "exclude" => ["app/b"] }))
    assert_equal 200, ok.status
  end

  def test_the_selection_is_the_survivor_never_targets_zero
    # THE MUST 0.8.2.20 NAMES: a handler that counts the effective list and then
    # indexes `targets[0]` has implemented the arithmetic completely and is still
    # reading a path no authorization covered. Here `targets[0]` is EXCLUDED and the
    # single survivor is `targets[1]`, so the two readings return different entities.
    out = @handler.op_get(ctx({ "targets" => %w[app/a app/b], "exclude" => ["app/a"] }))
    assert_equal 200, out.status
    assert_equal 2, out.result.field("v"), "the survivor app/b, not the excluded app/a"
  end

  def test_a_pattern_target_is_malformed_resource
    # 0.8.2.20: a resource-requiring operation takes a CONCRETE path. A trailing "/" is
    # a listing request and is NOT a pattern — only a `*` makes it one.
    out = @handler.op_get(ctx({ "targets" => ["app/*"] }))
    assert_equal 400, out.status
    assert_equal "malformed_resource", code_of(out)
    listing = @handler.op_get(ctx({ "targets" => ["app/"] }))
    assert_equal 200, listing.status
    assert_equal "system/tree/listing", listing.result.type
  end

  def test_caller_exclude_is_fail_open_on_an_unmatchable_pattern
    # §5.4 rules the caller-exclude arm separately from the GRANT arm: `canonicalize`
    # answers the sentinel, `matches_pattern` then answers false, and the target simply
    # SURVIVES. The matchable control beside it is what says the exclude works at all —
    # without it a peer that ignored `exclude` entirely would pass this.
    out = @handler.op_get(ctx({ "targets" => ["app/a"], "exclude" => ["../nope"] }))
    assert_equal 200, out.status
    assert_equal 1, out.result.field("v")
    denied = @handler.op_get(ctx({ "targets" => ["app/a"], "exclude" => ["app/a"] }))
    assert_equal 400, denied.status
  end

  # ── the ladder, `put` (resource-REQUIRED) ───────────────────────────────────

  def test_put_missing_resource_is_path_required_not_ambiguous_resource
    # THE CODE CHANGE 0.8.2.20 FORCED. This branch answered `ambiguous_resource` for a
    # MISSING target, which 0.8.2.20 names as the exact inversion it forbids: the
    # remedies differ — *supply a resource* is not *disambiguate your request* — and
    # the code is what selects the remedy.
    out = @handler.op_put(ctx(nil, operation: "put"))
    assert_equal 400, out.status
    assert_equal "path_required", code_of(out)
    # BOTH empties collapse here, because §2.2a declares `put` resource-REQUIRED:
    empty = @handler.op_put(ctx({ "targets" => ["app/a"], "exclude" => ["app/a"] },
                                operation: "put"))
    assert_equal "path_required", code_of(empty)
    # ...and more than one survivor is still `ambiguous_resource`, which is what says
    # the two codes have not simply been swapped.
    many = @handler.op_put(ctx({ "targets" => %w[app/a app/b] }, operation: "put"))
    assert_equal "ambiguous_resource", code_of(many)
  end

  # ── §6.3: the handler-level path check (0.8.2.20) ───────────────────────────

  def test_get_denies_a_path_the_callers_capability_excludes
    # THE F84 DEFECT. The caller's own `exclude` removes `app/b` from the DISPATCH
    # check's view entirely, so `check_permission` never sees it; without §6.3's own
    # check the handler then serves it. §6.3: "not a secondary check ... the sole
    # enforcement wherever the subject is derived after dispatch."
    narrow = cap(resources: ["*"], resources_excl: ["app/b"])
    denied = @handler.op_get(ctx({ "targets" => ["app/b"] }, caller_cap: narrow))
    assert_equal 403, denied.status
    assert_equal "capability_denied", code_of(denied)
    # CONTROL, in the same capability: a path the SAME grant does cover is served.
    ok = @handler.op_get(ctx({ "targets" => ["app/a"] }, caller_cap: narrow))
    assert_equal 200, ok.status
  end

  def test_put_denies_a_path_the_callers_capability_excludes
    narrow = cap(resources: ["*"], resources_excl: ["app/b"])
    e = Entity.make("primitive/any", { "v" => 9 })
    params = Entity.make("primitive/any", { "entity" => e.to_cbor })
    exec = Wire.make_execute("r1", "system/tree", "put", params,
                             resource: { "targets" => ["app/b"] })
    c = HandlerContext.new(exec: exec, conn: Conn.new, included: [], caller_cap: narrow,
                           env: Envelope.new(exec), handler_pattern: "system/tree")
    out = @handler.op_put(c)
    assert_equal 403, out.status
    assert_equal "capability_denied", code_of(out)
    # ...and nothing was written: `app/b` still holds what `setup` bound. A 403 whose
    # refusal arrives AFTER the store write would satisfy the status assertion alone.
    assert_equal 2, @peer.store.get_at("/#{@local}/app/b").field("v")
  end

  def test_an_unauthenticated_context_is_not_path_checked
    # The bootstrap/internal path. The filter's subject is "the caller's verified
    # capability", and where there is none there is no caller to narrow.
    out = @handler.op_get(ctx({ "targets" => ["app/a"] }, caller_cap: nil))
    assert_equal 200, out.status
  end

  # ── §6.3: the listing filter (0.8.2.21/.22) ─────────────────────────────────

  def test_listing_omits_entries_the_caller_cannot_get_and_count_follows
    # "Entries for which check_path_permission returns DENY MUST be omitted. The
    # result's `count` field MUST reflect the FILTERED entry count, not the source
    # tree's total count." A count that still reports the source total IS the
    # disclosure the rule exists to prevent, so it is asserted separately.
    narrow = cap(resources: ["*"], resources_excl: ["app/b"])
    out = @handler.op_get(ctx({ "targets" => ["app/"] }, caller_cap: narrow))
    assert_equal 200, out.status
    entries = out.result.field("entries")
    assert_equal ["a"], entries.keys.sort
    assert_equal 1, out.result.field("count"), "count follows the FILTERED total"

    # CONTROL, and it is the one that makes the filter case mean anything: the same
    # listing under a capability that covers both names both.
    wide = @handler.op_get(ctx({ "targets" => ["app/"] }, caller_cap: cap))
    assert_equal %w[a b], wide.result.field("entries").keys.sort
    assert_equal 2, wide.result.field("count")
  end

  def test_the_directory_itself_is_not_checked
    # §6.3 makes each ENTRY the subject. Testing the PREFIX would deny a listing to a
    # caller whose grant covers children but not the node above them, which is the
    # ordinary shape of a narrowed grant — so this grant, which covers `app/*` and not
    # `app` itself, must still get its listing.
    child_only = cap(resources: ["app/*"])
    out = @handler.op_get(ctx({ "targets" => ["app/"] }, caller_cap: child_only))
    assert_equal 200, out.status
    assert_equal %w[a b], out.result.field("entries").keys.sort
  end
end
