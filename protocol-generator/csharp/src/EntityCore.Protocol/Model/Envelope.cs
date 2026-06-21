using EntityCore.Protocol.Codec;

namespace EntityCore.Protocol.Model;

/// <summary>
/// A wire envelope (V7 §3.1): a <c>root</c> entity plus an <c>included</c> map of
/// supporting entities keyed by content hash (capabilities, identities,
/// signatures, and any entity the root references).
/// <para>
/// The <c>included</c> map is load-bearing and MUST survive every dispatch surface
/// (N5 / §3.3) — this type preserves it whole. Entities are spliced verbatim on
/// encode (their original <see cref="Entity.WireBytes"/>) so forwarding never
/// re-serializes (N4 / §1.8).
/// </para>
/// </summary>
internal sealed class Envelope
{
    private readonly Dictionary<string, Entity> _included;

    public Envelope(Entity root, IEnumerable<Entity> included)
    {
        Root = root;
        _included = new Dictionary<string, Entity>();
        foreach (Entity entity in included)
        {
            _included[entity.ContentHashHex] = entity;
        }
    }

    /// <summary>The primary entity — determines behavior (EXECUTE → process as request).</summary>
    public Entity Root { get; }

    /// <summary>Supporting entities, keyed by lowercase hex of their content hash.</summary>
    public IReadOnlyDictionary<string, Entity> Included => _included;

    /// <summary>Resolve a reference by content hash; null on miss.</summary>
    public Entity? Find(ReadOnlySpan<byte> contentHash) =>
        _included.TryGetValue(Hashes.Hex(contentHash), out Entity? entity) ? entity : null;

    /// <summary>Encode the envelope to wire bytes, splicing entity originals verbatim.</summary>
    public byte[] Encode()
    {
        var includedPairs = new List<KeyValuePair<EcfValue, EcfValue>>(_included.Count);
        foreach (Entity entity in _included.Values)
        {
            includedPairs.Add(new KeyValuePair<EcfValue, EcfValue>(
                new EcfValue.Bytes(entity.ContentHash),
                new EcfValue.PreEncoded(entity.WireBytes)));
        }

        var envelope = new EcfValue.Map(new[]
        {
            new KeyValuePair<EcfValue, EcfValue>(new EcfValue.Text("root"), new EcfValue.PreEncoded(Root.WireBytes)),
            new KeyValuePair<EcfValue, EcfValue>(new EcfValue.Text("included"), new EcfValue.Map(includedPairs)),
        });
        return CanonicalCbor.Encode(envelope);
    }

    /// <summary>
    /// Decode and validate a wire envelope. Each entity's hash is checked on
    /// receipt (§1.8.1), and each included entry's content hash MUST match its map
    /// key (§3.1).
    /// </summary>
    public static Envelope Decode(ReadOnlyMemory<byte> wireBytes)
    {
        EcfValue value = CanonicalCbor.Decode(wireBytes);
        Entity root = Entity.FromDecoded(Ecf.Require(value, "root"));

        var included = new List<Entity>();
        EcfValue? includedValue = Ecf.Field(value, "included");
        if (includedValue is EcfValue.Map map)
        {
            foreach (KeyValuePair<EcfValue, EcfValue> pair in map.Pairs)
            {
                if (pair.Key is not EcfValue.Bytes keyBytes)
                {
                    throw new EntityProtocolException("envelope included map key must be a byte string (§3.1)");
                }
                Entity entity = Entity.FromDecoded(pair.Value);
                if (!Hashes.Equal(keyBytes.Value.Span, entity.ContentHash))
                {
                    throw new EntityProtocolException("included entity content_hash does not match its map key (§3.1)");
                }
                included.Add(entity);
            }
        }
        else if (includedValue is not null)
        {
            throw new EntityProtocolException("envelope 'included' must be a map");
        }

        return new Envelope(root, included);
    }
}
