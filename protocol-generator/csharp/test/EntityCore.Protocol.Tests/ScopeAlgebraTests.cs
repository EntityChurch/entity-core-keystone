using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// The §5 scope algebra at the unit level: §5.2's effective-target projection (0.8.2.20,
/// N11), §6.3's <c>check_path_permission</c>, the §5.4 sentinel's scoping to PATH-SCOPE
/// (0.8.2.24 N2/N3) and §5.5a's <c>scope_subset</c> typed by scope kind (F50, ruled at
/// 0.8.2.16).
/// <para>
/// AUTHORED HERE BECAUSE THE PINNED CHECK SET HAS NO VECTOR ON THIS SURFACE. Every one of
/// these behaviours is measurable on the wire by <c>tools/arc-probe</c> and by nothing in
/// the 778-check core gate, so a unit that regresses silently is exactly what
/// <c>run-s2.sh</c> is for.
/// </para>
/// </summary>
public sealed class ScopeAlgebraTests
{
    private const string Local = "z6MkLocalPeerIdentityBase58PlaceholderAAAAAAAAAAA";

    // ── §5.2 effective targets (0.8.2.20 / N11) ────────────────────────────────────

    /// <summary>
    /// The pair — survivors AND "was there a resource at all" — is §3.3's NON-LOSSY
    /// PROJECTION <c>[MUST]</c> (0.8.2.25, N11). A function returning only a list collapses
    /// <c>[qA] exclude [qA]</c> to <c>[]</c> and deletes the two-empties discriminator
    /// before any handler can read it.
    /// </summary>
    [Fact]
    public void EffectiveTargets_SeparatesTheTwoEmpties()
    {
        Permissions.EffectiveTargetSet absent = Permissions.EffectiveTargets(ExecuteWith(null), Local);
        Assert.False(absent.HasResource);
        Assert.Empty(absent.Survivors);

        Permissions.EffectiveTargetSet selfExcluded = Permissions.EffectiveTargets(
            ExecuteWith(Resource(new[] { "qA" }, new[] { "qA" })), Local);
        Assert.True(selfExcluded.HasResource);           // the discriminator N11 requires
        Assert.Empty(selfExcluded.Survivors);
    }

    /// <summary>
    /// The caller's own exclude removes entries BEFORE anything else looks at the request,
    /// and survivors come back in the caller's OWN SPELLING — 0.8.2.21 is explicit that
    /// <c>effective_targets</c> yields raw survivors, and the value flows on to a tree
    /// lookup that canonicalizes for itself.
    /// </summary>
    [Fact]
    public void EffectiveTargets_NarrowsAndKeepsTheCallersSpelling()
    {
        Permissions.EffectiveTargetSet one = Permissions.EffectiveTargets(
            ExecuteWith(Resource(new[] { "qA", "qB" }, new[] { "qA" })), Local);
        Assert.True(one.HasResource);
        Assert.Equal(new[] { "qB" }, one.Survivors);     // raw, not "/{local}/qB"

        Permissions.EffectiveTargetSet two = Permissions.EffectiveTargets(
            ExecuteWith(Resource(new[] { "qA", "qB" }, null)), Local);
        Assert.Equal(new[] { "qA", "qB" }, two.Survivors);
    }

    /// <summary>
    /// The caller-exclude arm is fail-OPEN on an unmatchable pattern; §5.4 rules it
    /// separately from the grant arm, where the same value is fail-CLOSED. INHERITED from
    /// the primitives rather than restated: the pattern canonicalizes to the sentinel and
    /// <see cref="Paths.MatchesPattern"/> then answers false, so the target survives.
    /// </summary>
    [Fact]
    public void EffectiveTargets_UnmatchableCallerExcludeCarvesOutNothing()
    {
        Permissions.EffectiveTargetSet r = Permissions.EffectiveTargets(
            ExecuteWith(Resource(new[] { "qA" }, new[] { "../nope" })), Local);
        Assert.Equal(new[] { "qA" }, r.Survivors);
    }

    /// <summary>
    /// A PRESENT-BUT-ILL-TYPED <c>targets</c> is PRESENT, with an empty survivor list.
    /// Reporting it absent would serve the WIDER absent-case answer to a request that named
    /// a resource — N11's own defect one field over, and the divergence the two vanguards
    /// found between themselves.
    /// </summary>
    [Fact]
    public void EffectiveTargets_IllTypedTargetsAreStillPresent()
    {
        EcfValue resource = Ecf.Map(("targets", Ecf.Text("not-an-array")));
        Permissions.EffectiveTargetSet r = Permissions.EffectiveTargets(ExecuteWith(resource), Local);
        Assert.True(r.HasResource);
        Assert.Empty(r.Survivors);

        // A resource map with no `targets` key at all is ABSENT, not present-and-empty:
        // there is no target list to have been emptied.
        Permissions.EffectiveTargetSet noKey =
            Permissions.EffectiveTargets(ExecuteWith(Ecf.Map(("exclude", Ecf.Array(Ecf.Text("x"))))), Local);
        Assert.False(noKey.HasResource);
    }

    // ── §6.3 check_path_permission ─────────────────────────────────────────────────

    /// <summary>
    /// ONE ACCEPT AND ONE DENY PER DIMENSION. The accept case is what validates the
    /// FIXTURE: a predicate test built only from deny cases is indistinguishable from one
    /// asserting <c>False == False</c>, because a broken fixture denies everything for
    /// free. One deny per dimension is what says the predicate checks the dimension rather
    /// than merely being able to say no.
    /// </summary>
    [Fact]
    public void CheckPathPermission_AcceptsInGrantAndDeniesPerDimension()
    {
        CapabilityToken cap = Token(Grant(
            handlers: Scope0("system/tree"),
            resources: Scope0("q/*"),
            operations: Scope0("get")));

        Assert.True(Permissions.CheckPathPermission("get", "q/a", cap, "system/tree", Local));

        // resources: a path outside the grant.
        Assert.False(Permissions.CheckPathPermission("get", "other/a", cap, "system/tree", Local));
        // operations: id-scope, literal.
        Assert.False(Permissions.CheckPathPermission("put", "q/a", cap, "system/tree", Local));
        // handlers: a different owning handler.
        Assert.False(Permissions.CheckPathPermission("get", "q/a", cap, "system/capability", Local));
    }

    /// <summary>
    /// An empty <c>resources.include</c> is a legal grant shape (§5.2: handlers that touch
    /// no tree paths) and DENIES every path — <c>covered</c> over an empty include list is
    /// false, which is what that note says it should be.
    /// </summary>
    [Fact]
    public void CheckPathPermission_EmptyResourceIncludeDeniesEveryPath()
    {
        CapabilityToken cap = Token(Grant(
            handlers: Scope0("system/tree"),
            resources: new Scope(System.Array.Empty<string>(), null),
            operations: Scope0("get")));
        Assert.False(Permissions.CheckPathPermission("get", "q/a", cap, "system/tree", Local));
    }

    /// <summary>
    /// Canonicalization is TOTAL in a matcher position (0.8.2.20): a malformed path answers
    /// the sentinel, which matches no grant, so it falls through to DENY rather than
    /// escaping as a throw the §6.5 frame would answer with the ADMISSION disposition.
    /// </summary>
    [Fact]
    public void CheckPathPermission_MalformedPathDeniesRatherThanThrowing()
    {
        CapabilityToken cap = Token(Grant(
            handlers: Scope0("system/tree"),
            resources: Scope0("*"),
            operations: Scope0("get")));
        // The wide-open control first, or "false everywhere" would satisfy this vacuously.
        Assert.True(Permissions.CheckPathPermission("get", "q/a", cap, "system/tree", Local));
        Assert.False(Permissions.CheckPathPermission("get", "q//a", cap, "system/tree", Local));
        Assert.False(Permissions.CheckPathPermission("get", "../escape", cap, "system/tree", Local));
    }

    // ── §5.4 sentinel, SCOPED TO PATH-SCOPE (0.8.2.24 N2/N3) ───────────────────────

    /// <summary>
    /// <em>"a capability carrying an unmatchable PATH-SCOPE pattern is INVALID … It does
    /// NOT reach <c>operations</c> or <c>peers</c> <c>[MUST]</c>"</em>.
    /// <para>
    /// The unscoped guard ran an id pattern through the §5.4 transforms purely to classify
    /// it and then denied the WHOLE dimension on a property unrelated to whether the
    /// exclude carves anything out: <c>*/apply</c>, an ordinary namespaced operation name,
    /// path-canonicalizes to the sentinel. Over-denial, invisible on any well-formed grant.
    /// </para>
    /// </summary>
    [Fact]
    public void Sentinel_DeniesOnPathScopeOnly()
    {
        var idScope = new Scope(new[] { "*" }, new[] { "*/apply" });
        // The ID arm: `*/apply` is a literal that simply does not equal `compute`, so the
        // include still carries and the dimension is NOT denied.
        Assert.True(idScope.Matches("compute", Local, ScopeKind.Id));
        // …and it still EXCLUDES what it literally names, or the guard has merely been
        // deleted rather than scoped.
        Assert.False(idScope.Matches("*/apply", Local, ScopeKind.Id));

        // The PATH arm keeps 0.8.2.21's rule: an unmatchable exclude DENIES rather than
        // carving out nothing.
        var pathScope = new Scope(new[] { "*" }, new[] { "../nope" });
        Assert.False(pathScope.Matches("q/a", Local, ScopeKind.Path));
        // Control: the identical include with no unmatchable exclude allows.
        Assert.True(new Scope(new[] { "*" }, null).Matches("q/a", Local, ScopeKind.Path));
    }

    // ── §5.5a scope_subset typed by scope kind (F50 / 0.8.2.16) ────────────────────

    /// <summary>
    /// §3.6's id-scope grammar binds the scope TYPE, not one function — <em>"An
    /// implementation on the canonicalizing reading is non-conformant and MUST adopt the
    /// literal matcher"</em> — so the rule F40 landed on <see cref="Scope.Matches"/> reaches
    /// <c>scope_subset</c> too.
    /// <para>
    /// <c>*/apply</c> is the witness and it is fail-CLOSED: under the canonicalizing
    /// reading it becomes the §5.4 sentinel, which matches nothing in either operand, so a
    /// legitimate child <c>operations</c> include was refused against a parent of <c>*</c>.
    /// The literal matcher covers it.
    /// </para>
    /// </summary>
    [Fact]
    public void ScopeSubset_OperationsUseTheLiteralMatcher()
    {
        GrantEntry wideOpen = Grant(Scope0("*"), Scope0("*"), Scope0("*"));

        GrantEntry namespacedOp = Grant(Scope0("system/tree"), Scope0("q/*"), Scope0("*/apply"));
        Assert.True(Attenuation.GrantsWithinAuthority(new[] { namespacedOp }, new[] { wideOpen }, Local));

        // The EXCLUDE arm of the same pair: a parent exclude the child repeats verbatim is
        // inherited under the literal matcher and was not under the canonicalizing one.
        GrantEntry parentEx = Grant(Scope0("*"), Scope0("*"),
            new Scope(new[] { "*" }, new[] { "*/apply" }));
        GrantEntry childEx = Grant(Scope0("system/tree"), Scope0("q/*"),
            new Scope(new[] { "*" }, new[] { "*/apply" }));
        Assert.True(Attenuation.GrantsWithinAuthority(new[] { childEx }, new[] { parentEx }, Local));

        // THE MATCHER HALF, and it is here because its plant RAN GREEN without it. The
        // `*/apply` cases above are decided by the FRAME (the sentinel), so replacing only
        // the `Covers` local with the path matcher left every assertion passing — an inert
        // control. This pair separates the two matchers on strings the frame leaves alone:
        // §5.4's peer-wildcard walk makes `MatchesPattern("/x/get", "/*/get")` TRUE while
        // §3.6's literal matcher answers FALSE. Under the canonicalizing reading the child
        // therefore reads as covered by a parent it does not literally match, and the child
        // grant comes out WIDER than its parent — the delegation-chain widening F50 names.
        GrantEntry peerWildcardOp = Grant(Scope0("system/tree"), Scope0("q/*"), Scope0("/x/get"));
        GrantEntry peerWildcardParent = Grant(Scope0("*"), Scope0("*"), Scope0("/*/get"));
        Assert.False(
            Attenuation.GrantsWithinAuthority(new[] { peerWildcardOp }, new[] { peerWildcardParent }, Local),
            "operations must use the LITERAL matcher, not the peer-wildcard walk");

        // CONTROL — the typing must not turn scope_subset into a rubber stamp: an
        // operations include the parent does not literally cover is still refused.
        GrantEntry notCovered = Grant(Scope0("system/tree"), Scope0("q/*"), Scope0("put"));
        GrantEntry narrowParent = Grant(Scope0("*"), Scope0("*"), Scope0("get"));
        Assert.False(Attenuation.GrantsWithinAuthority(new[] { notCovered }, new[] { narrowParent }, Local));

        // CONTROL — the PATH dimensions keep the canonicalizing matcher: a resources
        // include outside the parent's subtree is refused.
        GrantEntry widerResource = Grant(Scope0("system/tree"), Scope0("other/*"), Scope0("get"));
        GrantEntry narrowResource = Grant(Scope0("*"), Scope0("q/*"), Scope0("*"));
        Assert.False(Attenuation.GrantsWithinAuthority(new[] { widerResource }, new[] { narrowResource }, Local));
    }

    // ── fixtures ───────────────────────────────────────────────────────────────────

    private static Scope Scope0(params string[] include) => new(include, null);

    private static GrantEntry Grant(Scope handlers, Scope resources, Scope operations) =>
        new(handlers, resources, operations, null, null, null);

    private static CapabilityToken Token(params GrantEntry[] grants)
    {
        byte[] hash = new byte[33];
        Entity entity = Entity.Create(TypeNames.CapabilityToken, Ecf.Map(
            ("grants", Ecf.Array(grants.Select(g => g.ToEcf()))),
            ("granter", Ecf.Bytes(hash)),
            ("grantee", Ecf.Bytes(hash)),
            ("created_at", Ecf.Uint(1_700_000_000_000))));
        return new CapabilityToken(entity);
    }

    private static EcfValue Resource(IEnumerable<string> targets, IEnumerable<string>? exclude) => Ecf.Map(
        ("targets", Ecf.Array(targets.Select(Ecf.Text))),
        ("exclude", exclude is null ? null : Ecf.Array(exclude.Select(Ecf.Text))));

    /// <summary>
    /// An EXECUTE carrying <paramref name="resource"/> VERBATIM — built through
    /// <see cref="Ecf"/> rather than <see cref="ResourceTarget"/>, because that type is an
    /// ADMISSION parser and would refuse exactly the shapes these cases are about.
    /// </summary>
    private static Execute ExecuteWith(EcfValue? resource) => new(Entity.Create(TypeNames.Execute, Ecf.Map(
        ("request_id", Ecf.Text("t")),
        ("uri", Ecf.Text("system/tree")),
        ("operation", Ecf.Text("get")),
        ("resource", resource),
        ("params", Ecf.EmptyMap))));
}
