require "./spec_helper"

# §3.3's effective-targets ladder in the tree handler, the §6.3 path check it gates,
# and the §6.3 listing filter (RULE A, 0.8.2.20/.21/.22 + N7/N10/N11 at .24/.25).
#
# Driven through the REAL TreeHandler with a real store, because the defect this work
# closes is a handler that implements §3.3's ARITHMETIC completely and then indexes
# `targets[0]` anyway: `effective_targets` alone cannot show that, and the arc-probe
# wire drive cannot show the two-empties discriminator on a resource-OPTIONAL
# operation without a capability it has to mint for itself.
#
# EVERY CASE GOES THROUGH `handle(operation, ctx)`, the public entry point, rather
# than through `op_get`/`op_put`. That is not a style choice: it is what makes the
# RULE G ordering claim below an ordering claim at all, since a test that calls
# `op_get` directly has resolved the operation itself and cannot see a handler that
# validates the resource first.
include EntityCore

private def coerce_map(h) : ::Hash(Cbor::EcValue, Cbor::EcValue)
  Cbor.coerce(h).as(::Hash(Cbor::EcValue, Cbor::EcValue))
end

# A capability whose `resources` cover `include` and carve out `exclude`.
private def cap(resources = ["*"], resources_excl = [] of String,
                operations = ["*"], handlers = ["*"]) : Entity
  res = {"include" => resources} of String => Array(String)
  res["exclude"] = resources_excl unless resources_excl.empty?
  Entity.build("system/capability/token", {
    "grants" => [{
      "handlers"   => {"include" => handlers},
      "operations" => {"include" => operations},
      "resources"  => res,
    }],
  })
end

describe "tree handler — the §3.3 effective-targets ladder (RULE A)" do
  peer = Peer.create(Bytes.new(32) { 0x5a_u8 }, open_grants: false, conformance: false)
  local = peer.local_peer
  handler = Peer::TreeHandler.new(peer)
  peer.store.bind("/#{local}/app/a", Entity.build("primitive/any", {"v" => 1}))
  peer.store.bind("/#{local}/app/b", Entity.build("primitive/any", {"v" => 2}))

  # `resource` is nil for "no resource at all", or a plain map literal.
  ctx = ->(resource : ::Hash(Cbor::EcValue, Cbor::EcValue)?, caller_cap : Entity?, params : Entity) do
    exec = Wire.make_execute("r1", "system/tree", "get", params, resource: resource)
    HandlerContext.new(exec, Conn.new, [] of Envelope::Included, caller_cap,
      Envelope.new(exec), "system/tree")
  end
  # A `get`-shaped context. The operation string on the EXECUTE is cosmetic here —
  # `handle` routes on its own argument — so the two are kept in step by the caller.
  get_ctx = ->(resource : ::Hash(Cbor::EcValue, Cbor::EcValue)?) do
    ctx.call(resource, cap.as(Entity?), Wire.empty_params)
  end
  code_of = ->(o : Outcome) { o.result.text("code") }

  # ── effective_targets: THE TWO-EMPTIES DISCRIMINATOR (N11, 0.8.2.25) ────────

  # N11 makes the discriminator a [MUST]: "where an implementation projects
  # `resource.targets` onto the effective set ahead of the handler, that projection
  # MUST NOT be lossy about its own emptiness — narrow when narrowing leaves
  # something, and retain the raw pair when narrowing would empty it." This peer
  # carries it as the second element of the returned tuple.
  eff = ->(resource : ::Hash(Cbor::EcValue, Cbor::EcValue)?) do
    Capability.effective_targets(local,
      Wire.make_execute("r1", "system/tree", "get", Wire.empty_params, resource: resource))
  end

  it "reports an ABSENT resource as absent" do
    eff.call(nil)[1].should be_false
  end

  it "reports a resource map with no `targets` key as absent, and that is an OPEN question" do
    # PINS THE SHIPPED ANSWER rather than endorsing it. A `resource` MAP carrying no
    # `targets` key is reported ABSENT by every 0.8.2.25 peer, so `get` serves it the
    # root listing. §3.2 says `targets` "MUST contain at least one entry", which makes
    # the shape MALFORMED rather than absent — and N10's point is that a PRESENT
    # `resource` must not be served the wider absent-case answer. Nothing in the
    # 778-check set drives it and no disposition is pinned, so the behaviour is HELD
    # rather than changed; this case exists so that changing it is a DECISION.
    eff.call(coerce_map({"exclude" => ["a"]}))[1].should be_false
  end

  it "reports a PRESENT but fully-excluded resource as present-with-an-empty-list" do
    survivors, had = eff.call(coerce_map({"targets" => ["a"], "exclude" => ["a"]}))
    had.should be_true
    survivors.should be_empty
  end

  it "keeps the caller's OWN SPELLING for the survivors" do
    # 0.8.2.21: `effective_targets` yields RAW survivors, not canonical forms — the
    # value flows on to the store lookup, which canonicalizes for itself.
    eff.call(coerce_map({"targets" => ["app/x", "app/y"], "exclude" => ["app/y"]}))[0]
      .should eq(["app/x"])
  end

  # ── RULE G — operation resolution precedes resource validation ──────────────

  it "answers 501 for an unknown operation WITH and WITHOUT a resource" do
    # "Resolve the operation first; only then run the §3.3 ladder." A peer that
    # validates the resource first answers a RESOURCE fault for an OPERATION fault on
    # every unknown operation — measured independently by `entity-system-conformance`
    # (X9 / F52) on the peers whose tree handler is one match over
    # (operation, resource).
    #
    # ON THIS SUBSTRATE THE ORDERING IS STRUCTURAL AND THAT IS THE FINDING, not a
    # fix: `TreeHandler#handle` is a `case operation` whose `else` is the 501, and the
    # §3.3 ladder lives inside `op_get`/`op_put`, which only a known operation
    # reaches. The pair is asserted anyway because "it cannot happen" is a claim about
    # today's dispatcher, and this is what keeps it one.
    res = handler.handle("bogusop", get_ctx.call(nil))
    res.status.should eq(501)
    code_of.call(res).should eq("unsupported_operation")
    # THE CONTROL that makes this an ORDERING claim rather than a missing-501 claim:
    # on the peers that had the defect, these two answered DIFFERENTLY.
    withres = handler.handle("bogusop", get_ctx.call(coerce_map({"targets" => ["app/a"]})))
    withres.status.should eq(501)
    code_of.call(withres).should eq("unsupported_operation")
    # ...and a KNOWN operation still routes, or the two above are satisfied by a
    # handler that answers 501 to everything.
    handler.handle("get", get_ctx.call(coerce_map({"targets" => ["app/a"]}))).status.should eq(200)
  end

  # ── the ladder, `get` (resource-OPTIONAL, BROAD-RESULT) ─────────────────────

  # EXTENSION-TREE §2.2a (v4.11) declares `get` resource-OPTIONAL and BROAD-RESULT:
  # absent-case answer "the root listing", self-excluded case "400 path_required".
  # 0.8.2.24 (N7) scopes §3.3's "an empty effective list IS the absent case" to "an
  # operation that REQUIRES a resource", and 0.8.2.25 (N10) decides the
  # present-but-empty case by whether the absent case is WIDER than the request.

  it "serves the root listing for an ABSENT resource" do
    res = handler.handle("get", get_ctx.call(nil))
    res.status.should eq(200)
    res.result.type.should eq("system/tree/listing")
    res.result.text("path").should eq("/#{local}/")
  end

  it "answers 400 path_required for a PRESENT but self-excluded resource" do
    # THE TWO EMPTIES ARE DISTINCT, and this is the pair that says so. Collapsing them
    # would serve the ROOT LISTING to a request that named one excluded path — the
    # wider-than-the-request answer §3.3 forbids, and the live disclosure the 0.8.2.25
    # vanguard work surfaced.
    res = handler.handle("get", get_ctx.call(coerce_map({"targets" => ["app/a"], "exclude" => ["app/a"]})))
    res.status.should eq(400)
    code_of.call(res).should eq("path_required")
  end

  it "answers 400 ambiguous_resource for more than one EFFECTIVE target" do
    res = handler.handle("get", get_ctx.call(coerce_map({"targets" => ["app/a", "app/b"]})))
    res.status.should eq(400)
    code_of.call(res).should eq("ambiguous_resource")
    # ...and the exclude is what makes the COUNT an effective-set count rather than a
    # raw `targets` count: two targets, one excluded, ONE survivor -> it proceeds.
    ok = handler.handle("get", get_ctx.call(coerce_map({"targets" => ["app/a", "app/b"], "exclude" => ["app/b"]})))
    ok.status.should eq(200)
  end

  it "selects the SURVIVOR, never targets[0]" do
    # THE MUST 0.8.2.20 NAMES: a handler that counts the effective list and then
    # indexes `targets[0]` has implemented the arithmetic completely and is still
    # reading a path no authorization covered. Here `targets[0]` is EXCLUDED and the
    # single survivor is `targets[1]`, so the two readings return different entities.
    res = handler.handle("get", get_ctx.call(coerce_map({"targets" => ["app/a", "app/b"], "exclude" => ["app/a"]})))
    res.status.should eq(200)
    res.result.field("v").should eq(Cbor::EcInt.from(2))
  end

  it "answers 400 malformed_resource for a PATTERN target but serves a trailing slash" do
    # 0.8.2.20: a resource-requiring operation takes a CONCRETE path. A trailing "/"
    # is a listing request and is NOT a pattern — only a star makes it one.
    res = handler.handle("get", get_ctx.call(coerce_map({"targets" => ["app/*"]})))
    res.status.should eq(400)
    code_of.call(res).should eq("malformed_resource")
    listing = handler.handle("get", get_ctx.call(coerce_map({"targets" => ["app/"]})))
    listing.status.should eq(200)
    listing.result.type.should eq("system/tree/listing")
  end

  # ── the ladder, `put` (resource-REQUIRED) ───────────────────────────────────

  it "answers 400 path_required for a MISSING put target, not ambiguous_resource" do
    # THE CODE CHANGE 0.8.2.20 FORCED. This branch answered `ambiguous_resource` for a
    # MISSING target, which 0.8.2.20 names as the exact inversion it forbids: the
    # remedies differ — supply a resource is not disambiguate your request — and the
    # code is what selects the remedy.
    res = handler.handle("put", get_ctx.call(nil))
    res.status.should eq(400)
    code_of.call(res).should eq("path_required")
    # BOTH empties collapse here, because §2.2a declares `put` resource-REQUIRED:
    empty = handler.handle("put", get_ctx.call(coerce_map({"targets" => ["app/a"], "exclude" => ["app/a"]})))
    code_of.call(empty).should eq("path_required")
    # ...and more than one survivor is still `ambiguous_resource`, which is what says
    # the two codes have not simply been swapped.
    many = handler.handle("put", get_ctx.call(coerce_map({"targets" => ["app/a", "app/b"]})))
    code_of.call(many).should eq("ambiguous_resource")
  end

  # ── §6.3: the handler-level path check (0.8.2.20) ───────────────────────────

  it "denies a GET on a path the caller's own capability excludes" do
    # THE F84 DEFECT. The caller's own `exclude` removes `app/b` from the DISPATCH
    # check's view entirely, so `check_permission` never sees it; without §6.3's own
    # check the handler then serves it. §6.3: "not a secondary check ... the sole
    # enforcement wherever the subject is derived after dispatch."
    narrow = cap(resources: ["*"], resources_excl: ["app/b"])
    denied = handler.handle("get",
      ctx.call(coerce_map({"targets" => ["app/b"]}), narrow.as(Entity?), Wire.empty_params))
    denied.status.should eq(403)
    code_of.call(denied).should eq("capability_denied")
    # CONTROL, in the SAME capability: a path the same grant does cover is served.
    ok = handler.handle("get",
      ctx.call(coerce_map({"targets" => ["app/a"]}), narrow.as(Entity?), Wire.empty_params))
    ok.status.should eq(200)
  end

  it "denies a PUT on an excluded path and writes nothing" do
    narrow = cap(resources: ["*"], resources_excl: ["app/b"])
    e = Entity.build("primitive/any", {"v" => 9})
    params = Entity.build("primitive/any", {"entity" => e.to_cbor})
    res = handler.handle("put",
      ctx.call(coerce_map({"targets" => ["app/b"]}), narrow.as(Entity?), params))
    res.status.should eq(403)
    code_of.call(res).should eq("capability_denied")
    # ...and nothing was written: `app/b` still holds what the setup bound. A 403
    # whose refusal arrives AFTER the store write would satisfy the status assertion
    # on its own, which is why the store is read here.
    peer.store.get_at("/#{local}/app/b").not_nil!.field("v").should eq(Cbor::EcInt.from(2))
  end

  it "does NOT path-check an unauthenticated context" do
    # The bootstrap/internal path. The filter's subject is "the caller's verified
    # capability", and where there is none there is no caller to narrow.
    res = handler.handle("get",
      ctx.call(coerce_map({"targets" => ["app/a"]}), nil, Wire.empty_params))
    res.status.should eq(200)
  end

  # ── §6.3: the listing filter (0.8.2.21/.22) ─────────────────────────────────

  it "omits listing entries the caller cannot get, and `count` follows the FILTER" do
    # "Entries for which check_path_permission returns DENY MUST be omitted. The
    # result's `count` field MUST reflect the FILTERED entry count, not the source
    # tree's total count." A count that still reports the source total IS the
    # disclosure the rule exists to prevent, so it is asserted separately from the
    # entry map — a filter that omits the entry and leaves the count names how many
    # bindings the caller was not allowed to see.
    narrow = cap(resources: ["*"], resources_excl: ["app/b"])
    res = handler.handle("get",
      ctx.call(coerce_map({"targets" => ["app/"]}), narrow.as(Entity?), Wire.empty_params))
    res.status.should eq(200)
    entries = res.result.field("entries").as(::Hash(Cbor::EcValue, Cbor::EcValue))
    entries.map { |k, _v| k.as(String) }.sort.should eq(["a"])
    res.result.field("count").should eq(Cbor::EcInt.from(1))
  end

  it "leaves a listing UNFILTERED for an unauthenticated caller" do
    # The bootstrap control, and the differential that attributes the row above to the
    # FILTER rather than to the store or the directory being wrong: same directory,
    # no capability, both entries.
    res = handler.handle("get",
      ctx.call(coerce_map({"targets" => ["app/"]}), nil, Wire.empty_params))
    entries = res.result.field("entries").as(::Hash(Cbor::EcValue, Cbor::EcValue))
    entries.map { |k, _v| k.as(String) }.sort.should eq(["a", "b"])
    res.result.field("count").should eq(Cbor::EcInt.from(2))
  end

  it "does NOT check the directory itself, only its entries" do
    # §6.3 makes each ENTRY the subject. Testing the prefix would deny a listing to a
    # caller whose grant covers children but not the node above them, which is the
    # ordinary shape of a narrowed grant — so a grant covering only `app/a` must still
    # be able to LIST `app/`.
    only_a = cap(resources: ["app/a"])
    res = handler.handle("get",
      ctx.call(coerce_map({"targets" => ["app/"]}), only_a.as(Entity?), Wire.empty_params))
    res.status.should eq(200)
    entries = res.result.field("entries").as(::Hash(Cbor::EcValue, Cbor::EcValue))
    entries.map { |k, _v| k.as(String) }.sort.should eq(["a"])
  end
end
