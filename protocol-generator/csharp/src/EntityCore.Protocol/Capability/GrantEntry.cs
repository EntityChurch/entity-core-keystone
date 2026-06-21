using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Capability;

/// <summary>
/// A <c>system/capability/grant-entry</c> (V7 §3.6): one self-describing
/// authorization — which <c>handlers</c> may be called, which <c>resources</c>
/// (data paths) may be accessed, which <c>operations</c> are allowed, which
/// <c>peers</c> are in scope, plus domain-specific narrowing <c>constraints</c> and
/// expanding <c>allowances</c>.
/// </summary>
internal sealed record GrantEntry(
    Scope Handlers,
    Scope Resources,
    Scope Operations,
    Scope? Peers,
    EcfValue? Constraints,
    EcfValue? Allowances)
{
    /// <summary>Peer scope, defaulting to the local peer only when absent (§3.6).</summary>
    public Scope EffectivePeers(string localPeerId) =>
        Peers ?? new Scope(new[] { localPeerId }, null);

    public EcfValue ToEcf() => Ecf.Map(
        ("handlers", Handlers.ToEcf()),
        ("resources", Resources.ToEcf()),
        ("operations", Operations.ToEcf()),
        ("peers", Peers?.ToEcf()),
        ("constraints", Constraints),
        ("allowances", Allowances));

    public static GrantEntry FromEcf(EcfValue value)
    {
        Scope handlers = Scope.FromEcf(Ecf.Require(value, "handlers"));
        Scope resources = Scope.FromEcf(Ecf.Require(value, "resources"));
        Scope operations = Scope.FromEcf(Ecf.Require(value, "operations"));
        EcfValue? peers = Ecf.Field(value, "peers");
        return new GrantEntry(
            handlers,
            resources,
            operations,
            peers is null ? null : Scope.FromEcf(peers),
            Ecf.Field(value, "constraints"),
            Ecf.Field(value, "allowances"));
    }
}
