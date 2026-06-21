namespace EntityCore.Protocol.Codec;

/// <summary>
/// In-memory model of a single ECF (Entity Canonical Form) data item.
/// <para>
/// This is the internal canonical-CBOR value tree the codec encodes from and
/// decodes into. It deliberately mirrors the value model used by the reference
/// implementations (Go/Rust/C) so the canonical obligations N1–N4 map across
/// languages. Integers are kept in CBOR head form (sign + raw argument) to
/// preserve the full unsigned 64-bit range without an <c>Int128</c> hop.
/// </para>
/// </summary>
internal abstract record EcfValue
{
    /// <summary>A CBOR integer in head form: <c>value = Negative ? -1 - Argument : Argument</c>.</summary>
    public sealed record Integer(bool Negative, ulong Argument) : EcfValue;

    /// <summary>A floating-point value. Encoded with shortest-form minimization (Rule 4).</summary>
    public sealed record Float(double Value) : EcfValue;

    /// <summary>A CBOR byte string (major type 2).</summary>
    public sealed record Bytes(ReadOnlyMemory<byte> Value) : EcfValue;

    /// <summary>A CBOR text string (major type 3), always valid UTF-8.</summary>
    public sealed record Text(string Value) : EcfValue;

    /// <summary>A CBOR array (major type 4).</summary>
    public sealed record Array(IReadOnlyList<EcfValue> Items) : EcfValue;

    /// <summary>A CBOR map (major type 5). Key ordering is applied at encode time.</summary>
    public sealed record Map(IReadOnlyList<KeyValuePair<EcfValue, EcfValue>> Pairs) : EcfValue;

    /// <summary>A CBOR boolean.</summary>
    public sealed record Bool(bool Value) : EcfValue;

    /// <summary>A CBOR null (major type 7, value 22).</summary>
    public sealed record Null : EcfValue;

    /// <summary>
    /// Already-canonical CBOR bytes spliced verbatim at encode time. This is the
    /// N4 fidelity carrier: opaque entity <c>data</c> is forwarded byte-for-byte,
    /// never decoded-and-re-encoded.
    /// </summary>
    public sealed record PreEncoded(ReadOnlyMemory<byte> Value) : EcfValue;
}
