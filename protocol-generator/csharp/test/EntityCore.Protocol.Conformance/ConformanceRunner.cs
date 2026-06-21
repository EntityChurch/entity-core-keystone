using EntityCore.Protocol.Codec;

namespace EntityCore.Protocol.Conformance;

/// <summary>Outcome of a single conformance vector.</summary>
public sealed record VectorResult(string Id, string Kind, string Category, bool Pass, string? Message);

/// <summary>Aggregate result of a conformance run.</summary>
public sealed record ConformanceReport(IReadOnlyList<VectorResult> Results)
{
    /// <summary>True iff every vector passed.</summary>
    public bool AllPass => Results.All(r => r.Pass);

    /// <summary>Per-category (pass, total) counts in first-seen order.</summary>
    public IReadOnlyList<(string Category, int Pass, int Total)> ByCategory()
    {
        var order = new List<string>();
        var pass = new Dictionary<string, int>();
        var total = new Dictionary<string, int>();
        foreach (VectorResult r in Results)
        {
            if (!total.ContainsKey(r.Category))
            {
                order.Add(r.Category);
                pass[r.Category] = 0;
                total[r.Category] = 0;
            }
            total[r.Category]++;
            if (r.Pass)
            {
                pass[r.Category]++;
            }
        }
        return order.Select(c => (c, pass[c], total[c])).ToList();
    }
}

/// <summary>
/// Drives the vendored, cross-blessed conformance fixture
/// (<c>conformance-vectors-v1.cbor</c>) through the native C# codec and diffs the
/// output, byte-for-byte, against each vector's baked <c>canonical</c> bytes.
/// Twin of the Rust/C <c>conformance_harness</c>. Agreement here means this impl
/// matches the Go/Rust/Py 3-way consensus.
/// </summary>
public static class ConformanceRunner
{
    /// <summary>Load the fixture from <paramref name="corpusPath"/> and run all vectors.</summary>
    public static ConformanceReport Run(string corpusPath)
    {
        byte[] bytes = File.ReadAllBytes(corpusPath);
        EcfValue corpus = CanonicalCbor.Parse(bytes);
        if (corpus is not EcfValue.Array array)
        {
            throw new InvalidOperationException("fixture top-level is not a CBOR array");
        }

        var results = new List<VectorResult>();
        foreach (EcfValue item in array.Items)
        {
            if (item is not EcfValue.Map map)
            {
                continue;
            }
            string id = Text(map, "id") ?? "<no-id>";
            string kind = Text(map, "kind") ?? "<no-kind>";
            int dot = id.IndexOf('.');
            string category = dot >= 0 ? id[..dot] : id;

            bool pass;
            string? message = null;
            try
            {
                pass = RunVector(kind, category, map, out message);
            }
            catch (Exception ex)
            {
                pass = false;
                message = $"threw {ex.GetType().Name}: {ex.Message}";
            }
            results.Add(new VectorResult(id, kind, category, pass, pass ? null : message));
        }
        return new ConformanceReport(results);
    }

    private static bool RunVector(string kind, string category, EcfValue.Map map, out string? message)
    {
        message = null;

        if (kind == "decode_reject")
        {
            byte[]? canon = Bytes(map, "canonical");
            if (canon is null)
            {
                message = "missing canonical bytes";
                return false;
            }
            try
            {
                CanonicalCbor.Decode(canon);
            }
            catch (EntityCodecException)
            {
                return true; // correctly rejected
            }
            message = "decoder ACCEPTED bytes it must reject";
            return false;
        }

        // encode_equal
        byte[]? canonical = Bytes(map, "canonical");
        if (canonical is null)
        {
            message = "missing canonical bytes";
            return false;
        }
        EcfValue? input = Field(map, "input");
        if (input is null)
        {
            message = "missing input";
            return false;
        }

        byte[] got = category switch
        {
            "content_hash" => RunContentHash(input),
            "peer_id" => RunPeerId(input),
            "signature" => RunSignature(input),
            _ => CanonicalCbor.Encode(input), // Class A + nested + envelope: bare canonical encode
        };

        if (got.AsSpan().SequenceEqual(canonical))
        {
            return true;
        }
        message = $"got {Hex(got)} != want {Hex(canonical)}";
        return false;
    }

    private static byte[] RunContentHash(EcfValue input)
    {
        var m = (EcfValue.Map)input;
        string type = Text(m, "type") ?? throw new EntityCodecException("content_hash: missing type");
        EcfValue data = Field(m, "data") ?? throw new EntityCodecException("content_hash: missing data");
        byte[] dataBytes = CanonicalCbor.Encode(data);
        ulong formatCode = UInt(m, "format_code") ?? 0;
        return EntityCodec.ContentHash(type, dataBytes, formatCode);
    }

    private static byte[] RunPeerId(EcfValue input)
    {
        var m = (EcfValue.Map)input;
        ulong keyType = UInt(m, "key_type") ?? throw new EntityCodecException("peer_id: missing key_type");
        ulong hashType = UInt(m, "hash_type") ?? throw new EntityCodecException("peer_id: missing hash_type");
        byte[] digest = Bytes(m, "digest") ?? throw new EntityCodecException("peer_id: missing digest");
        string id = EntityCodec.FormatPeerId(keyType, hashType, digest);
        return CanonicalCbor.Encode(new EcfValue.Text(id));
    }

    private static byte[] RunSignature(EcfValue input)
    {
        var m = (EcfValue.Map)input;
        byte[] seed = Bytes(m, "seed") ?? throw new EntityCodecException("signature: missing seed");
        EcfValue entity = Field(m, "entity") ?? throw new EntityCodecException("signature: missing entity");
        byte[] message = CanonicalCbor.Encode(entity);
        return EntityCodec.Sign(seed, message);
    }

    // ── fixture field accessors over the decoded value tree ──

    private static EcfValue? Field(EcfValue.Map map, string key)
    {
        foreach (KeyValuePair<EcfValue, EcfValue> pair in map.Pairs)
        {
            if (pair.Key is EcfValue.Text t && t.Value == key)
            {
                return pair.Value;
            }
        }
        return null;
    }

    private static string? Text(EcfValue.Map map, string key) =>
        Field(map, key) is EcfValue.Text t ? t.Value : null;

    private static byte[]? Bytes(EcfValue.Map map, string key) =>
        Field(map, key) is EcfValue.Bytes b ? b.Value.ToArray() : null;

    private static ulong? UInt(EcfValue.Map map, string key) =>
        Field(map, key) is EcfValue.Integer { Negative: false } i ? i.Argument : null;

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}
