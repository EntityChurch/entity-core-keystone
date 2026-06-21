using EntityCore.Protocol.Codec;

namespace EntityCore.Protocol.Model;

/// <summary>
/// A typed view over a <c>system/protocol/execute</c> entity (V7 §3.2). One of the
/// two wire message types. Carries a request id, target uri, operation, an entity
/// <c>params</c>, and — for authenticated requests — <c>author</c> and
/// <c>capability</c> reference hashes. The signature is a separate
/// <c>system/signature</c> entity found by target-matching in the envelope.
/// </summary>
internal sealed class Execute
{
    public Execute(Entity entity)
    {
        if (entity.Type != TypeNames.Execute)
        {
            throw new EntityProtocolException($"expected {TypeNames.Execute}, got '{entity.Type}'");
        }
        Entity = entity;
    }

    /// <summary>The underlying materialized entity (its content hash is the signature target).</summary>
    public Entity Entity { get; }

    public string RequestId => Ecf.RequireText(Entity.Data, "request_id");

    public string Uri => Ecf.RequireText(Entity.Data, "uri");

    public string Operation => Ecf.RequireText(Entity.Data, "operation");

    /// <summary>The <c>params</c> entity (materialized; §3.4).</summary>
    public Entity Params => Entity.FromDecoded(Ecf.Require(Entity.Data, "params"));

    /// <summary>Author identity hash, or null on a pre-auth connect request (§3.2, §4.2).</summary>
    public byte[]? Author => Ecf.OptBytes(Entity.Data, "author");

    /// <summary>Capability token hash, or null on a pre-auth connect request.</summary>
    public byte[]? Capability => Ecf.OptBytes(Entity.Data, "capability");

    /// <summary>The optional resource target (§3.2), or null when absent.</summary>
    public ResourceTarget? Resource
    {
        get
        {
            EcfValue? r = Ecf.Field(Entity.Data, "resource");
            return r is null ? null : ResourceTarget.FromEcf(r);
        }
    }

    /// <summary>
    /// Build a <c>system/protocol/execute</c> entity. <paramref name="paramsEntity"/>
    /// is spliced verbatim (fidelity). <paramref name="author"/> /
    /// <paramref name="capability"/> are omitted for connect-path requests (§4.2).
    /// </summary>
    public static Execute Build(
        string requestId,
        string uri,
        string operation,
        Entity paramsEntity,
        byte[]? author = null,
        byte[]? capability = null,
        ResourceTarget? resource = null,
        EcfValue? bounds = null)
    {
        EcfValue data = Ecf.Map(
            ("request_id", Ecf.Text(requestId)),
            ("uri", Ecf.Text(uri)),
            ("operation", Ecf.Text(operation)),
            ("resource", resource?.ToEcf()),
            ("params", new EcfValue.PreEncoded(paramsEntity.WireBytes)),
            ("bounds", bounds),
            ("author", author is null ? null : Ecf.Bytes(author)),
            ("capability", capability is null ? null : Ecf.Bytes(capability)));
        return new Execute(Entity.Create(TypeNames.Execute, data));
    }
}
