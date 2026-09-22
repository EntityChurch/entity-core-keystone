using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Capability;

/// <summary>
/// Which §5.2 matcher a grant dimension uses (0.8.1, F40). <see cref="Scope.Matches"/>
/// takes it as a required argument — no default — so a new call site cannot silently
/// inherit the wrong matcher, which is exactly the F40 defect.
/// </summary>
internal enum ScopeKind
{
    /// <summary><c>operations</c>, <c>peers</c> — <c>system/capability/id-scope</c>.</summary>
    Id,

    /// <summary><c>handlers</c>, <c>resources</c> — <c>system/capability/path-scope</c>.</summary>
    Path,
}

/// <summary>
/// A grant scope dimension (V7 §3.6): <c>{include, exclude?}</c>. Both
/// <c>system/capability/path-scope</c> (handlers, resources) and
/// <c>system/capability/id-scope</c> (operations, peers) share this shape, but §5.2
/// matches each <em>by its scope type</em> (0.8.1, F40) — see <see cref="Matches"/>.
/// </summary>
internal sealed record Scope(IReadOnlyList<string> Include, IReadOnlyList<string>? Exclude)
{
    public static readonly Scope Empty = new(System.Array.Empty<string>(), null);

    public EcfValue ToEcf() => Ecf.Map(
        ("include", Ecf.Array(Include.Select(Ecf.Text))),
        ("exclude", Exclude is null ? null : Ecf.Array(Exclude.Select(Ecf.Text))));

    public static Scope FromEcf(EcfValue value)
    {
        IReadOnlyList<string> include = Ecf.AsArray(Ecf.Require(value, "include")).Select(Ecf.AsText).ToList();
        EcfValue? exclude = Ecf.Field(value, "exclude");
        IReadOnlyList<string>? excludes = exclude is null
            ? null
            : Ecf.AsArray(exclude).Select(Ecf.AsText).ToList();
        return new Scope(include, excludes);
    }

    /// <summary>
    /// §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard
    /// forms — bare <c>*</c> and a trailing <c>/*</c> segment-prefix. None of the §5.4
    /// path transforms apply, so a pattern carrying path syntax is matched as a literal
    /// string: a non-match, never a fault.
    /// </summary>
    internal static bool MatchesIdPattern(string value, string pattern)
    {
        if (pattern == "*")
        {
            return true;
        }
        if (pattern.Length >= 2 && pattern.EndsWith("/*", StringComparison.Ordinal))
        {
            return value.StartsWith(pattern[..^1], StringComparison.Ordinal);
        }
        return value == pattern;
    }

    /// <summary>
    /// True if <paramref name="value"/> is included and not excluded by this scope
    /// (§5.2 <c>matches_scope</c>). <paramref name="kind"/> selects the matcher by scope
    /// type: <c>Path</c> (handlers, resources) canonicalizes both sides; <c>Id</c>
    /// (operations, peers) compares literally. The two MUST NOT be interchanged.
    /// </summary>
    public bool Matches(string value, string localPeerId, ScopeKind kind)
    {
        // 0.8.2.21 — an unmatchable exclude DENIES rather than carving out nothing, and
        // SCOPED TO PATH-SCOPE at 0.8.2.24 (N2/N3). §5.2's exclude loop tests the sentinel
        // INSIDE `if dimension_type == "system/capability/path-scope"`, and §5.4's rule is
        // likewise "a capability carrying an unmatchable PATH-SCOPE pattern is INVALID …
        // It does NOT reach `operations` or `peers` [MUST]".
        //
        // This guard used to sit OUTSIDE the type dispatch, transcribing §5.2's loop
        // before that loop grew its type test — which ran an id pattern through the §5.4
        // transforms purely to classify it and then DENIED THE WHOLE DIMENSION on a
        // property unrelated to whether the exclude carves anything out: an
        // <c>operations</c> exclude of <c>*/apply</c>, an ordinary namespaced operation
        // name, path-canonicalizes to the sentinel and denied every operation.
        // Over-denial, invisible on any well-formed grant.
        //
        // The id arm reaches the literal matcher below unguarded, which is correct: under
        // the id-scope grammar every non-`*` pattern is a literal, and a literal is never
        // structurally unmatchable, so there is nothing here for the sentinel to detect.
        if (kind == ScopeKind.Path && Exclude is not null && Paths.ExcludeIsUnmatchable(Exclude, localPeerId))
        {
            return false;
        }
        string canonicalValue = kind == ScopeKind.Path ? Paths.Canonicalize(value, localPeerId) : value;

        bool Covers(string pattern) => kind == ScopeKind.Id
            ? MatchesIdPattern(value, pattern)
            : Paths.MatchesPattern(canonicalValue, Paths.Canonicalize(pattern, localPeerId));

        bool matched = false;
        foreach (string pattern in Include)
        {
            if (Covers(pattern))
            {
                matched = true;
                break;
            }
        }
        if (!matched)
        {
            return false;
        }

        if (Exclude is not null)
        {
            foreach (string pattern in Exclude)
            {
                if (Covers(pattern))
                {
                    return false;
                }
            }
        }
        return true;
    }
}
