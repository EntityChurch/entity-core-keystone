using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Capability;

/// <summary>
/// A grant scope dimension (V7 §3.6): <c>{include, exclude?}</c>. Both
/// <c>system/capability/path-scope</c> (handlers, resources) and
/// <c>system/capability/id-scope</c> (operations, peers) share this shape, and
/// <see cref="Matches"/> works uniformly across both (§5.2 <c>matches_scope</c>).
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
    /// True if <paramref name="value"/> is included and not excluded by this scope
    /// (§5.2 <c>matches_scope</c>). Value and patterns are canonicalized uniformly,
    /// so the same routine serves both path and identifier dimensions.
    /// </summary>
    public bool Matches(string value, string localPeerId)
    {
        string canonicalValue = Paths.Canonicalize(value, localPeerId);

        bool matched = false;
        foreach (string pattern in Include)
        {
            if (Paths.MatchesPattern(canonicalValue, Paths.Canonicalize(pattern, localPeerId)))
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
                if (Paths.MatchesPattern(canonicalValue, Paths.Canonicalize(pattern, localPeerId)))
                {
                    return false;
                }
            }
        }
        return true;
    }
}
