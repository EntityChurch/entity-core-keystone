using EntityCore.Protocol.Codec;

namespace EntityCore.Protocol.Model;

/// <summary>
/// Ergonomic constructors and accessors over the codec's internal
/// <see cref="EcfValue"/> tree. The peer layer builds protocol entity <c>data</c>
/// maps and reads decoded ones through these helpers, so the rest of the peer
/// never touches <see cref="EcfValue"/> records directly.
/// <para>
/// Field accessors are strict: a missing or wrong-typed field throws
/// <see cref="EntityProtocolException"/>. This keeps malformed wire entities from
/// propagating untyped nulls into the dispatch chain.
/// </para>
/// </summary>
internal static class Ecf
{
    // ----- builders -------------------------------------------------------

    public static EcfValue Uint(ulong value) => new EcfValue.Integer(false, value);

    public static EcfValue Text(string value) => new EcfValue.Text(value);

    public static EcfValue Bytes(ReadOnlyMemory<byte> value) => new EcfValue.Bytes(value);

    public static EcfValue Bool(bool value) => new EcfValue.Bool(value);

    public static readonly EcfValue Null = new EcfValue.Null();

    /// <summary>The canonical empty map (single byte <c>0xA0</c> on the wire — N3).</summary>
    public static EcfValue EmptyMap => new EcfValue.Map(System.Array.Empty<KeyValuePair<EcfValue, EcfValue>>());

    public static EcfValue Array(params EcfValue[] items) => new EcfValue.Array(items);

    public static EcfValue Array(IEnumerable<EcfValue> items) => new EcfValue.Array(items.ToList());

    /// <summary>
    /// Build a map from <c>(key, value)</c> pairs. <c>null</c> values are dropped
    /// — this is the ECF convention that an absent optional field is encoded by
    /// omitting the key entirely (§1.3), so callers pass a null to mean "absent".
    /// </summary>
    public static EcfValue Map(params (string Key, EcfValue? Value)[] pairs)
    {
        var list = new List<KeyValuePair<EcfValue, EcfValue>>(pairs.Length);
        foreach ((string key, EcfValue? value) in pairs)
        {
            if (value is not null)
            {
                list.Add(new KeyValuePair<EcfValue, EcfValue>(new EcfValue.Text(key), value));
            }
        }
        return new EcfValue.Map(list);
    }

    // ----- accessors ------------------------------------------------------

    /// <summary>Look up a field in a map value; returns null if absent.</summary>
    public static EcfValue? Field(EcfValue value, string key)
    {
        if (value is not EcfValue.Map map)
        {
            throw new EntityProtocolException($"expected a map to read field '{key}'");
        }
        foreach (KeyValuePair<EcfValue, EcfValue> pair in map.Pairs)
        {
            if (pair.Key is EcfValue.Text t && t.Value == key)
            {
                return pair.Value is EcfValue.Null ? null : pair.Value;
            }
        }
        return null;
    }

    public static EcfValue Require(EcfValue value, string key) =>
        Field(value, key) ?? throw new EntityProtocolException($"missing required field '{key}'");

    public static string AsText(EcfValue value) =>
        value is EcfValue.Text t
            ? t.Value
            : throw new EntityProtocolException("expected a text string");

    public static ulong AsUint(EcfValue value) =>
        value is EcfValue.Integer { Negative: false } i
            ? i.Argument
            : throw new EntityProtocolException("expected an unsigned integer");

    public static byte[] AsBytes(EcfValue value) =>
        value is EcfValue.Bytes b
            ? b.Value.ToArray()
            : throw new EntityProtocolException("expected a byte string");

    public static bool AsBool(EcfValue value) =>
        value is EcfValue.Bool b
            ? b.Value
            : throw new EntityProtocolException("expected a boolean");

    public static IReadOnlyList<EcfValue> AsArray(EcfValue value) =>
        value is EcfValue.Array a
            ? a.Items
            : throw new EntityProtocolException("expected an array");

    public static string RequireText(EcfValue value, string key) => AsText(Require(value, key));

    public static ulong RequireUint(EcfValue value, string key) => AsUint(Require(value, key));

    public static byte[] RequireBytes(EcfValue value, string key) => AsBytes(Require(value, key));

    public static string? OptText(EcfValue value, string key)
    {
        EcfValue? f = Field(value, key);
        return f is null ? null : AsText(f);
    }

    public static ulong? OptUint(EcfValue value, string key)
    {
        EcfValue? f = Field(value, key);
        return f is null ? null : AsUint(f);
    }

    public static byte[]? OptBytes(EcfValue value, string key)
    {
        EcfValue? f = Field(value, key);
        return f is null ? null : AsBytes(f);
    }

    /// <summary>
    /// Enumerate a map's text-keyed entries in their encoded order. Used by the
    /// attenuation checks that compare constraint / allowance maps key-by-key.
    /// </summary>
    public static IEnumerable<(string Key, EcfValue Value)> Entries(EcfValue value)
    {
        if (value is not EcfValue.Map map)
        {
            throw new EntityProtocolException("expected a map");
        }
        foreach (KeyValuePair<EcfValue, EcfValue> pair in map.Pairs)
        {
            if (pair.Key is EcfValue.Text t)
            {
                yield return (t.Value, pair.Value);
            }
        }
    }

    /// <summary>Canonical-encode a value to ECF bytes.</summary>
    public static byte[] Encode(EcfValue value) => CanonicalCbor.Encode(value);

    /// <summary>Strict canonical decode of ECF bytes (rejects tags, non-canonical).</summary>
    public static EcfValue Decode(ReadOnlyMemory<byte> bytes) => CanonicalCbor.Decode(bytes);
}
