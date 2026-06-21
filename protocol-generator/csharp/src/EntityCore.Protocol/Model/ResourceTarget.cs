using EntityCore.Protocol.Codec;

namespace EntityCore.Protocol.Model;

/// <summary>
/// A <c>system/protocol/resource-target</c> (V7 §3.2): the data paths an operation
/// accesses (<c>targets</c>, at least one) plus optional <c>exclude</c> paths. The
/// dispatcher checks this against <c>grant.resources</c> before handler dispatch.
/// </summary>
internal sealed record ResourceTarget(IReadOnlyList<string> Targets, IReadOnlyList<string>? Exclude)
{
    public EcfValue ToEcf() => Ecf.Map(
        ("targets", Ecf.Array(Targets.Select(Ecf.Text))),
        ("exclude", Exclude is null ? null : Ecf.Array(Exclude.Select(Ecf.Text))));

    public static ResourceTarget FromEcf(EcfValue value)
    {
        IReadOnlyList<string> targets = Ecf.AsArray(Ecf.Require(value, "targets")).Select(Ecf.AsText).ToList();
        if (targets.Count == 0)
        {
            throw new EntityProtocolException("resource-target.targets MUST contain at least one entry (§3.2)");
        }
        EcfValue? exclude = Ecf.Field(value, "exclude");
        IReadOnlyList<string>? excludes = exclude is null
            ? null
            : Ecf.AsArray(exclude).Select(Ecf.AsText).ToList();
        return new ResourceTarget(targets, excludes);
    }
}
