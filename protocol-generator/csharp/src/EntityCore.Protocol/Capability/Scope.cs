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
