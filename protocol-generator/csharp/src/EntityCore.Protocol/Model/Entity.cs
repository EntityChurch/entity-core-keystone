using EntityCore.Protocol.Codec;

namespace EntityCore.Protocol.Model;

/// <summary>
/// A materialized entity — <c>{type, data, content_hash}</c> (V7 §1.1, §3.4). The
/// fundamental data unit: a typed payload with content-addressed identity.
/// <para>
/// Entity fidelity (§1.8) is load-bearing. An entity decoded from the wire retains
/// its exact original bytes in <see cref="WireBytes"/>; forwarding re-emits those
/// bytes verbatim and never re-serializes the decoded structure. The content hash
/// is computed once over <c>{type, data}</c> and trusted thereafter.
/// </para>
/// </summary>
internal sealed class Entity
{
    private Entity(string type, EcfValue data, byte[] contentHash, ReadOnlyMemory<byte> wireBytes)
    {
        Type = type;
        Data = data;
        ContentHash = contentHash;
        WireBytes = wireBytes;
    }

    /// <summary>Semantic type path, e.g. <c>"system/protocol/execute"</c>.</summary>
    public string Type { get; }

    /// <summary>Decoded typed payload.</summary>
    public EcfValue Data { get; }

    /// <summary>33-byte content hash (format code + SHA-256 digest), validated.</summary>
    public byte[] ContentHash { get; }

    /// <summary>
    /// The exact <c>{type, data, content_hash}</c> wire bytes. For a locally-built
    /// entity these are the canonical encoding; for a decoded entity they are the
    /// original received bytes (§1.8 forward-original).
    /// </summary>
    public ReadOnlyMemory<byte> WireBytes { get; }

    public string ContentHashHex => Hashes.Hex(ContentHash);

    /// <summary>
    /// Build an entity from <c>{type, data}</c>: canonical-encode the hashable form,
    /// derive the content hash under <paramref name="contentHashFormat"/> (default
    /// <c>0x00</c> SHA-256 — the §9.1 home format), and produce the full wire bytes.
    /// A non-default format is the agility path (e.g. a SHA-384 home network).
    /// </summary>
    public static Entity Create(string type, EcfValue data, ulong contentHashFormat = HashFormats.Sha256)
    {
        byte[] hashable = CanonicalCbor.Encode(Ecf.Map(("type", new EcfValue.Text(type)), ("data", data)));
        byte[] contentHash = HashFormats.ContentHash(contentHashFormat, hashable);
        byte[] wire = CanonicalCbor.Encode(new EcfValue.Map(new[]
        {
            new KeyValuePair<EcfValue, EcfValue>(new EcfValue.Text("type"), new EcfValue.Text(type)),
            new KeyValuePair<EcfValue, EcfValue>(new EcfValue.Text("data"), data),
            new KeyValuePair<EcfValue, EcfValue>(new EcfValue.Text("content_hash"), new EcfValue.Bytes(contentHash)),
        }));
        return new Entity(type, data, contentHash, wire);
    }

    /// <summary>
    /// Decode a wire entity and validate its content hash on receipt (§1.8.1,
    /// §7.2). Throws <see cref="EntityProtocolException"/> on a hash mismatch or a
    /// malformed shape.
    /// </summary>
    public static Entity Decode(ReadOnlyMemory<byte> wireBytes)
    {
        EcfValue value = CanonicalCbor.Decode(wireBytes);
        string type = Ecf.RequireText(value, "type");
        EcfValue data = Ecf.Require(value, "data");
        byte[] declared = Ecf.RequireBytes(value, "content_hash");

        // Wire-acceptance carve-out (§7.65): recompute under the format the entity
        // declares, so an entity authored under any supported home format validates.
        ulong format = HashFormats.ReadFormatCode(declared);
        byte[] hashable = CanonicalCbor.Encode(Ecf.Map(("type", new EcfValue.Text(type)), ("data", data)));
        byte[] expected = HashFormats.ContentHash(format, hashable);
        if (!Hashes.Equal(expected, declared))
        {
            throw new EntityProtocolException(
                $"content_hash mismatch on '{type}': computed {Hashes.Hex(expected)}, declared {Hashes.Hex(declared)}");
        }

        return new Entity(type, data, declared, wireBytes);
    }

    /// <summary>
    /// Build an entity from an already-decoded envelope sub-value. The envelope is
    /// decoded in strict canonical mode, so re-encoding this sub-map reproduces its
    /// exact original bytes (ECF canonical form is unique) — non-canonical input
    /// was rejected at the envelope boundary. This recovers the per-entity byte
    /// boundaries the whole-envelope decode flattened, then validates the hash.
    /// </summary>
    public static Entity FromDecoded(EcfValue entityMap) => Decode(CanonicalCbor.Encode(entityMap));
}
