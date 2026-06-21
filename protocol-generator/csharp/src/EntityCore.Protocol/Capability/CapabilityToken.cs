using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Capability;

/// <summary>
/// A multi-signature granter (V7 §3.6 M3): <c>{signers, threshold}</c>. A capability
/// whose <c>granter</c> is this shape (rather than a single <c>system/hash</c>) is
/// authorized by a k-of-n quorum and is <strong>root-only</strong> (<c>parent: null</c>).
/// Parsing is total — a malformed shape yields an empty/zero structure that fails
/// validation, never a throw (so an inbound multi-sig EXECUTE rejects, never hangs).
/// </summary>
internal sealed record MultiSigGranter(IReadOnlyList<byte[]> Signers, ulong Threshold)
{
    public static MultiSigGranter FromEcf(EcfValue value)
    {
        var signers = new List<byte[]>();
        ulong threshold = 0;
        if (value is EcfValue.Map)
        {
            if (Ecf.Field(value, "signers") is EcfValue.Array arr)
            {
                foreach (EcfValue item in arr.Items)
                {
                    if (item is EcfValue.Bytes b)
                    {
                        signers.Add(b.Value.ToArray());
                    }
                }
            }
            if (Ecf.Field(value, "threshold") is EcfValue.Integer { Negative: false } t)
            {
                threshold = t.Argument;
            }
        }
        return new MultiSigGranter(signers, threshold);
    }
}

/// <summary>Delegation caveats on a token (V7 §3.6, §5.7).</summary>
internal sealed record DelegationCaveats(bool? NoDelegation, ulong? MaxDelegationDepth, ulong? MaxDelegationTtl)
{
    public static DelegationCaveats? FromEcf(EcfValue? value)
    {
        if (value is null)
        {
            return null;
        }
        bool? noDelegation = Ecf.Field(value, "no_delegation") is { } nd ? Ecf.AsBool(nd) : null;
        return new DelegationCaveats(noDelegation, Ecf.OptUint(value, "max_delegation_depth"), Ecf.OptUint(value, "max_delegation_ttl"));
    }
}

/// <summary>
/// A typed view over a <c>system/capability/token</c> entity (V7 §3.6). Carries
/// the grant list, the <c>granter</c> / <c>grantee</c> identity hashes, an optional
/// delegation <c>parent</c>, temporal bounds, and delegation caveats. The token is
/// signed by the granter; the signature is found by target-matching in the
/// envelope (§3.6).
/// </summary>
internal sealed class CapabilityToken
{
    public CapabilityToken(Entity entity)
    {
        if (entity.Type != TypeNames.CapabilityToken)
        {
            throw new EntityProtocolException($"expected {TypeNames.CapabilityToken}, got '{entity.Type}'");
        }
        Entity = entity;
        Grants = Ecf.AsArray(Ecf.Require(entity.Data, "grants")).Select(GrantEntry.FromEcf).ToList();

        // The granter is a union (§3.6): a single system/hash (single-sig) or a
        // {signers, threshold} multi-granter (multi-sig, root-only). Parse totally —
        // never throw on the multi-sig shape (that would swallow the response).
        EcfValue granterField = Ecf.Require(entity.Data, "granter");
        if (granterField is EcfValue.Bytes gb)
        {
            Granter = gb.Value.ToArray();
            MultiGranter = null;
        }
        else
        {
            Granter = null;
            MultiGranter = MultiSigGranter.FromEcf(granterField);
        }

        Grantee = Ecf.RequireBytes(entity.Data, "grantee");
        Parent = Ecf.OptBytes(entity.Data, "parent");
        CreatedAt = Ecf.RequireUint(entity.Data, "created_at");
        ExpiresAt = Ecf.OptUint(entity.Data, "expires_at");
        NotBefore = Ecf.OptUint(entity.Data, "not_before");
        Caveats = DelegationCaveats.FromEcf(Ecf.Field(entity.Data, "delegation_caveats"));
    }

    public Entity Entity { get; }

    public IReadOnlyList<GrantEntry> Grants { get; }

    /// <summary>The single-sig granter identity hash, or null when <see cref="MultiGranter"/> is set.</summary>
    public byte[]? Granter { get; }

    /// <summary>The multi-sig granter (§3.6 M3), or null for a single-sig token.</summary>
    public MultiSigGranter? MultiGranter { get; }

    /// <summary>True when this token is granted by a k-of-n quorum (root-only, §3.6 M3).</summary>
    public bool IsMultiSig => MultiGranter is not null;

    public byte[] Grantee { get; }

    public byte[]? Parent { get; }

    public ulong CreatedAt { get; }

    public ulong? ExpiresAt { get; }

    public ulong? NotBefore { get; }

    public DelegationCaveats? Caveats { get; }

    public byte[] ContentHash => Entity.ContentHash;

    public string ContentHashHex => Entity.ContentHashHex;

    /// <summary>
    /// Build and self-sign a root capability token granted by <paramref name="granter"/>
    /// to <paramref name="granteeHash"/>. Returns the token plus its signature
    /// entity (the granter signs the token's content hash, §3.6).
    /// </summary>
    public static (CapabilityToken Token, Entity Signature) CreateRoot(
        PeerIdentity granter,
        byte[] granteeHash,
        IReadOnlyList<GrantEntry> grants,
        ulong createdAt,
        ulong? expiresAt = null)
    {
        EcfValue data = Ecf.Map(
            ("grants", Ecf.Array(grants.Select(g => g.ToEcf()))),
            ("granter", Ecf.Bytes(granter.IdentityHash)),
            ("grantee", Ecf.Bytes(granteeHash)),
            ("created_at", Ecf.Uint(createdAt)),
            ("expires_at", expiresAt is null ? null : Ecf.Uint(expiresAt.Value)));
        Entity entity = Entity.Create(TypeNames.CapabilityToken, data);
        Entity signature = Signatures.Sign(entity, granter);
        return (new CapabilityToken(entity), signature);
    }
}
