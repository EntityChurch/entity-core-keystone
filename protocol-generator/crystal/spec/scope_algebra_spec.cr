require "./spec_helper"

# The §5 scope algebra at 0.8.2.24/.25 — the two rulings that changed what an
# existing matcher must answer, plus the call-site enumeration RULE F asks for.
#
# Both are UNIT-level on purpose. §5.5a attenuation and the id-scope/path-scope
# split are decided inside pure functions whose inputs a wire drive cannot reach
# directly: `arc-probe` can show a grant being honoured or refused, it cannot show
# WHICH matcher decided. The pinned 778-check set has no vector on either.
include EntityCore

private def scope(incl : Array(String), excl : Array(String) = [] of String)
  Capability::Scope.new(incl, excl)
end

# A grant whose four dimensions are set independently, so a subset test can move
# exactly one of them.
private def grant(handlers = scope(["*"]), resources = scope(["*"]),
                  operations = scope(["*"]), peers : Capability::Scope? = nil)
  Capability::GrantRec.new(handlers, resources, operations, peers)
end

LOCAL = "z6MkLocalPeerIdThatIsNotRealButIsLongEnoughToPassBase58Check"

# An EXECUTE carrying a `resource` with both halves, for the effective-targets arm.
private def exec_with(targets : Array(String), excludes : Array(String))
  m = ::Hash(Cbor::EcValue, Cbor::EcValue).new
  m["targets"] = targets.map { |t| t.as(Cbor::EcValue) }
  m["exclude"] = excludes.map { |t| t.as(Cbor::EcValue) }
  Wire.make_execute("r1", "system/tree", "get", Wire.empty_params, resource: m)
end

describe "scope algebra — the sentinel is scoped to path-scope (0.8.2.24 N2/N3)" do
  # §5.4 at 0.8.2.24: "a capability carrying an unmatchable PATH-SCOPE pattern is
  # INVALID ... It does NOT reach `operations` or `peers` [MUST]".
  #
  # The un-scoped form we shipped at 0.8.2.21 transcribed §5.2's exclude loop
  # before that loop grew its type dispatch, so an id-scope pattern was run through
  # the §5.4 PATH transforms purely to classify it and the whole dimension was then
  # denied on a property unrelated to whether the exclude carves anything out.

  it "an operations exclude that path-canonicalizes to the sentinel does NOT deny the dimension" do
    # `*/apply` is an ordinary namespaced operation name. Under the id-scope
    # grammar it is a LITERAL that matches nothing, which is a non-match and never
    # a fault; under the §5.4 path transforms it canonicalizes to the sentinel.
    # Before the fix this denied EVERY operation. Over-denial, and invisible on any
    # well-formed grant.
    Capability.canonicalize(LOCAL, "*/apply").should eq(Capability::NEVER_MATCH)
    Capability.matches_scope(LOCAL, "get", scope(["*"], ["*/apply"]), Capability::ScopeKind::Id)
      .should be_true
  end

  it "the same exclude on a PATH-scope dimension still denies (0.8.2.21 is intact)" do
    # The control that says the fix SCOPED the guard rather than deleting it. An
    # unmatchable exclude is fail-OPEN if left to the matcher — it carves out
    # nothing and the grant is silently wider than its author wrote — so on a
    # path-scope dimension it must still deny.
    Capability.matches_scope(LOCAL, "system/tree", scope(["*"], ["*/apply"]),
      Capability::ScopeKind::Path).should be_false
  end

  it "a peers exclude naming a relative-traversal form does not deny the dimension" do
    # The second id-scope dimension, driven independently: a claim about
    # `operations` alone would not say the guard moved off `peers` too.
    Capability.canonicalize(LOCAL, "../elsewhere").should eq(Capability::NEVER_MATCH)
    Capability.matches_scope(LOCAL, LOCAL, scope([LOCAL], ["../elsewhere"]),
      Capability::ScopeKind::Id).should be_true
  end

  it "an ordinary matchable exclude still excludes on both scope kinds" do
    # The FIXTURE control. Three deny cases and no accept case cannot tell a
    # working matcher from one that denies everything; three accept cases and no
    # deny case cannot tell it from one that allows everything.
    Capability.matches_scope(LOCAL, "get", scope(["*"], ["get"]), Capability::ScopeKind::Id)
      .should be_false
    Capability.matches_scope(LOCAL, "system/tree", scope(["*"], ["system/tree"]),
      Capability::ScopeKind::Path).should be_false
  end
end

describe "scope algebra — scope_subset is typed by scope kind (F50, 0.8.2.16)" do
  # §3.6's grammar binds the SCOPE TYPE, not one function: "An implementation on
  # the canonicalizing reading is non-conformant and MUST adopt the literal
  # matcher." F40 typed `matches_scope`; its §5.5a sibling was left on the path
  # matcher for all four dimensions.
  #
  # Driven through `grant_subset`, which is the public call site — a test that
  # called the private helper directly would prove the helper can dispatch and say
  # nothing about whether the four dimensions NAME their kind.

  it "an operations include the id matcher covers is accepted where the path matcher refuses" do
    # The formalization's witness. Under id-scope a bare `*` covers everything;
    # under the path matcher the parent canonicalizes to `/{parent}/*` and the
    # child to the sentinel, so the pair is refused. FAIL-CLOSED, which is exactly
    # why no hand-tried example found it: nothing is over-granted, legitimate
    # delegation is refused.
    child = grant(operations: scope(["*/apply"]))
    parent = grant(operations: scope(["*"]))
    Capability.grant_subset(LOCAL, LOCAL, LOCAL, child, parent).should be_true
  end

  it "the second witness: an absolute-looking operation name under a bare star" do
    child = grant(operations: scope(["/tree/get"]))
    parent = grant(operations: scope(["*"]))
    Capability.grant_subset(LOCAL, LOCAL, LOCAL, child, parent).should be_true
  end

  it "the SAME two patterns on the RESOURCES dimension are still path-matched" do
    # The differential that attributes the two rows above to the scope TYPE rather
    # than to `grant_subset` having been loosened. `resources` is path-scope, so
    # the sentinel and the `/{peer}/*` frame still apply and the pair is refused.
    Capability.grant_subset(LOCAL, LOCAL, LOCAL,
      grant(resources: scope(["*/apply"])), grant(resources: scope(["*"]))).should be_false
    Capability.grant_subset(LOCAL, LOCAL, LOCAL,
      grant(resources: scope(["/tree/get"])), grant(resources: scope(["*"]))).should be_false
  end

  it "an operations include NO parent include covers is still refused" do
    # The accept side above cannot distinguish "the id matcher was used" from "the
    # operations dimension stopped being checked".
    Capability.grant_subset(LOCAL, LOCAL, LOCAL,
      grant(operations: scope(["put"])), grant(operations: scope(["get"]))).should be_false
  end

  it "a parent operations EXCLUDE not inherited by the child is refused" do
    # The exclude arm of the subset test, on the id dimension, independently: the
    # include arm alone would not say the exclude arm is typed.
    Capability.grant_subset(LOCAL, LOCAL, LOCAL,
      grant(operations: scope(["*"])),
      grant(operations: scope(["*"], ["delete"]))).should be_false
    Capability.grant_subset(LOCAL, LOCAL, LOCAL,
      grant(operations: scope(["*"], ["delete"])),
      grant(operations: scope(["*"], ["delete"]))).should be_true
  end
end

describe "scope algebra — the sentinel guard is reached from every match decision (RULE F, K-6)" do
  # 0.8.2.22: "a sentinel arm is a control-flow obligation, not a line ... the
  # guard MUST sit on every path that reaches the decision it protects." The `lean`
  # bypass was a GUARDED WRAPPER beside an UNGUARDED running matcher, with
  # attenuation calling the raw one.
  #
  # ALREADY SATISFIED BY CONSTRUCTION HERE, and this is the measurement that says
  # so rather than a claim. `matches_pattern` is the single definition and the
  # sentinel test is its FIRST statement, so the bypass shape cannot occur: the six
  # call sites in src/ (its own recursion, `covered`, `covered_frame`,
  # `effective_targets`'s caller-exclude arm, and `scope_subset`'s two path arms)
  # all reach the same guarded body. Asserted here in BOTH operands, because the
  # arm below `matches_pattern`'s guard returns true for a bare star and safety
  # must not rest on a value merely looking unmatchable.

  # WHICH OF THESE THE GUARD IS ACTUALLY LOAD-BEARING FOR WAS MEASURED, NOT
  # ASSUMED, and the measurement moved two of them. Deleting the guard and
  # re-running showed that in THIS peer's matcher the pattern-operand half is
  # unreachable as a discriminator: `matches_pattern(x, NEVER_MATCH)` can only be
  # true when `x == NEVER_MATCH`, because the sentinel is neither a bare star, nor
  # a `/*/` form, nor a `/*` suffix, so every other arm falls through to the
  # literal compare and answers false on its own. The PATH operand and the
  # self-pair are the two inputs where removing the guard changes an answer, and
  # they are the two asserted here. A case that passes with the guard deleted is
  # not a control for the guard — it is a control for the fall-through.

  it "refuses the sentinel as the PATH operand" do
    # The arm that makes the guard load-bearing: a bare star pattern returns true
    # for anything, so safety must not rest on a value merely LOOKING unmatchable.
    Capability.matches_pattern(Capability::NEVER_MATCH, "*").should be_false
  end

  it "refuses the sentinel against ITSELF" do
    # The case a guard written as `path != pattern` would pass, and the only input
    # where the PATTERN-operand half of the guard decides anything.
    Capability.matches_pattern(Capability::NEVER_MATCH, Capability::NEVER_MATCH).should be_false
  end

  it "the guard is reached through ATTENUATION, not only through matches_scope" do
    # The `lean` defect in this peer's own shape. The parent include is `/*` and
    # not a bare `*` DELIBERATELY: a bare star canonicalizes to `/{parent}/*`,
    # which refuses a sentinel child by prefix alone and would make this case pass
    # with the guard deleted. `/*` is already absolute, so it survives
    # canonicalization unchanged and its `/*` suffix arm covers any path beginning
    # with a slash — including the sentinel. Only the guard refuses it.
    Capability.grant_subset(LOCAL, LOCAL, LOCAL,
      grant(resources: scope(["../escape"])), grant(resources: scope(["/*"]))).should be_false
  end
end

describe "scope algebra — the caller-exclude arm is fail-OPEN on the sentinel (0.8.2.21)" do
  it "an unmatchable CALLER exclude carves out nothing and the target survives" do
    # §5.4's table rules the caller-exclude arm SEPARATELY from the grant arm, and
    # in the opposite direction: in a GRANT exclude the sentinel denies everything
    # (the grant would otherwise be silently wider than its author wrote), while on
    # the caller's OWN exclude it simply carves out nothing. The asymmetry is
    # INHERITED from the primitives here rather than restated — which is the thing
    # this case exists to pin, because restating it is how the two readings drift.
    eff, had = Capability.effective_targets(LOCAL, exec_with(["/#{LOCAL}/a"], ["../nope"]))
    had.should be_true
    eff.should eq(["/#{LOCAL}/a"])
  end

  it "a MATCHABLE caller exclude does remove its target" do
    # The accept-side control. Without it, a peer that ignored `exclude` entirely
    # would pass the case above for the wrong reason.
    eff, had = Capability.effective_targets(LOCAL, exec_with(["/#{LOCAL}/a"], ["/#{LOCAL}/a"]))
    had.should be_true
    eff.should be_empty
  end
end
