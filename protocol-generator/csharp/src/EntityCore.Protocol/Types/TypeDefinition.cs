using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Types;

/// <summary>
/// A field spec inside a <see cref="TypeDefinition"/> — the C# model of the
/// reference <c>system/type/field-spec</c> shape (TYPE-SYSTEM §4.2). Exactly one
/// structural carrier is set: a <see cref="TypeRef"/>, an <see cref="ArrayOf"/>,
/// a <see cref="MapOf"/>, or a <see cref="UnionOf"/>. Every field is encoded with
/// omit-empty semantics (an absent/false/zero value drops the key) so the rendered
/// CBOR is byte-identical to the Go reference encoder (ECF canonical form).
/// </summary>
internal sealed record FSpec
{
    public string? TypeRef { get; init; }
    public bool Optional { get; init; }
    public FSpec? ArrayOf { get; init; }
    public FSpec? MapOf { get; init; }
    public IReadOnlyList<FSpec>? UnionOf { get; init; }
    public string? KeyType { get; init; }
    public ulong? ByteSize { get; init; }

    /// <summary>This spec marked optional (the §1.3 absent-key convention at validate time).</summary>
    public FSpec Opt() => this with { Optional = true };

    /// <summary>This spec with a fixed encoded byte width (e.g. <c>format_code</c> = 1 byte).</summary>
    public FSpec Size(ulong bytes) => this with { ByteSize = bytes };

    /// <summary>Render to the ECF data map (omit-empty; key order applied at encode time).</summary>
    public EcfValue ToData() => Ecf.Map(
        ("type_ref", TypeRef is null ? null : Ecf.Text(TypeRef)),
        ("optional", Optional ? Ecf.Bool(true) : null),
        ("array_of", ArrayOf?.ToData()),
        ("map_of", MapOf?.ToData()),
        ("union_of", UnionOf is null ? null
            : new EcfValue.Array(UnionOf.Select(u => u.ToData()).ToList())),
        ("key_type", KeyType is null ? null : Ecf.Text(KeyType)),
        ("byte_size", ByteSize is null ? null : Ecf.Uint(ByteSize.Value)));

    public static FSpec Ref(string typeRef) => new() { TypeRef = typeRef };
    public static FSpec Array(FSpec element) => new() { ArrayOf = element };
    public static FSpec Map(FSpec value, string? keyType = null) => new() { MapOf = value, KeyType = keyType };
    public static FSpec Union(params FSpec[] variants) => new() { UnionOf = variants };
}

/// <summary>
/// A core type definition — the C# model of a <c>system/type</c> entity's data
/// payload (TYPE-SYSTEM §4.1). Rendered natively via <see cref="ToEntity"/> through
/// the byte-green <see cref="CanonicalCbor"/> path; the resulting <c>content_hash</c>
/// is diffed against the Go-rendered vector set (S8 drift target). This is the peer's
/// single source of truth for its published types (memory: type-registry-render-design).
/// </summary>
internal sealed record TypeDefinition
{
    public required string Name { get; init; }
    public string? Extends { get; init; }
    public IReadOnlyList<KeyValuePair<string, FSpec>>? Fields { get; init; }
    public IReadOnlyList<string>? Layout { get; init; }

    /// <summary>Location-index path: <c>system/type/&lt;name&gt;</c> (TypeDefinition.TreePath).</summary>
    public string TreePath => "system/type/" + Name;

    public EcfValue ToData()
    {
        EcfValue? fields = null;
        if (Fields is { Count: > 0 })
        {
            fields = new EcfValue.Map(Fields
                .Select(f => new KeyValuePair<EcfValue, EcfValue>(Ecf.Text(f.Key), f.Value.ToData()))
                .ToList());
        }
        EcfValue? layout = null;
        if (Layout is { Count: > 0 })
        {
            layout = new EcfValue.Array(Layout.Select(s => (EcfValue)new EcfValue.Text(s)).ToList());
        }
        return Ecf.Map(
            ("name", Ecf.Text(Name)),
            ("extends", Extends is null ? null : Ecf.Text(Extends)),
            ("fields", fields),
            ("layout", layout));
    }

    public Entity ToEntity() => Entity.Create("system/type", ToData());
}
