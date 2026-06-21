using System.Formats.Cbor;

namespace EntityCore.Protocol.Codec;

/// <summary>
/// The canonical-CBOR engine for ECF. Encoding leans on
/// <see cref="System.Formats.Cbor"/> in <see cref="CborConformanceMode.Ctap2Canonical"/>
/// for structure, integer minimization (Rule 1), definite lengths (Rule 3), and
/// length-then-lexicographic map-key ordering (Rule 2 / RFC 8949 §4.2.1, which
/// coincides with CTAP2 ordering for ECF's text- and byte-string keys).
/// <para>
/// The one canonical obligation the in-box library does not perform is Rule 4
/// shortest-float minimization — it writes the precision it is handed — so that
/// pass is hand-rolled in <see cref="EncodeFloat"/> and spliced via
/// <see cref="CborWriter.WriteEncodedValue"/>. This matches what every reference
/// impl had to do (eval risk R1).
/// </para>
/// Decoding is strict: it rejects CBOR tags anywhere (N2), indefinite lengths,
/// non-canonical encodings (Ctap2 mode), and trailing bytes.
/// </summary>
internal static class CanonicalCbor
{
    /// <summary>Encode a value tree to canonical ECF bytes.</summary>
    internal static byte[] Encode(EcfValue value)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        Write(writer, value);
        return writer.Encode();
    }

    /// <summary>
    /// Strict canonical decode. Throws <see cref="EntityCodecException"/> on any
    /// tag, indefinite length, non-canonical encoding, or trailing input.
    /// </summary>
    internal static EcfValue Decode(ReadOnlyMemory<byte> data)
    {
        CborReader reader;
        try
        {
            reader = new CborReader(data, CborConformanceMode.Ctap2Canonical);
        }
        catch (Exception ex) when (ex is CborContentException or ArgumentException)
        {
            throw new EntityCodecException("malformed CBOR", ex);
        }

        EcfValue value = ReadValue(reader);
        if (reader.BytesRemaining != 0)
        {
            throw new EntityCodecException("trailing bytes after top-level item");
        }
        return value;
    }

    /// <summary>
    /// Lenient parse used only to load the (already-canonical) conformance
    /// fixture. Tags are still rejected; canonical ordering is not re-checked.
    /// </summary>
    internal static EcfValue Parse(ReadOnlyMemory<byte> data)
    {
        var reader = new CborReader(data, CborConformanceMode.Lax);
        return ReadValue(reader);
    }

    private static void Write(CborWriter writer, EcfValue value)
    {
        switch (value)
        {
            case EcfValue.Integer i:
                if (i.Negative)
                {
                    writer.WriteCborNegativeIntegerRepresentation(i.Argument);
                }
                else
                {
                    writer.WriteUInt64(i.Argument);
                }
                break;

            case EcfValue.Float f:
                writer.WriteEncodedValue(EncodeFloat(f.Value));
                break;

            case EcfValue.Bytes b:
                writer.WriteByteString(b.Value.Span);
                break;

            case EcfValue.Text t:
                writer.WriteTextString(t.Value);
                break;

            case EcfValue.Array a:
                writer.WriteStartArray(a.Items.Count);
                foreach (EcfValue item in a.Items)
                {
                    Write(writer, item);
                }
                writer.WriteEndArray();
                break;

            case EcfValue.Map m:
                // Ctap2Canonical sorts the pairs by encoded key on WriteEndMap.
                writer.WriteStartMap(m.Pairs.Count);
                foreach (KeyValuePair<EcfValue, EcfValue> pair in m.Pairs)
                {
                    Write(writer, pair.Key);
                    Write(writer, pair.Value);
                }
                writer.WriteEndMap();
                break;

            case EcfValue.Bool bo:
                writer.WriteBoolean(bo.Value);
                break;

            case EcfValue.Null:
                writer.WriteNull();
                break;

            case EcfValue.PreEncoded p:
                // Verbatim splice (N4). In Ctap2 mode this still validates the
                // bytes are well-formed canonical CBOR, but never re-serializes.
                writer.WriteEncodedValue(p.Value.Span);
                break;

            default:
                throw new EntityCodecException($"unencodable value: {value.GetType().Name}");
        }
    }

    private static EcfValue ReadValue(CborReader reader)
    {
        CborReaderState state;
        try
        {
            state = reader.PeekState();
        }
        catch (CborContentException ex)
        {
            throw new EntityCodecException("malformed CBOR", ex);
        }

        try
        {
            switch (state)
            {
                case CborReaderState.Tag:
                    // N2: CBOR major-type-6 tags are forbidden anywhere in ECF.
                    throw new EntityCodecException("CBOR tag forbidden in ECF");

                case CborReaderState.UnsignedInteger:
                    return new EcfValue.Integer(false, reader.ReadUInt64());

                case CborReaderState.NegativeInteger:
                    return new EcfValue.Integer(true, reader.ReadCborNegativeIntegerRepresentation());

                case CborReaderState.ByteString:
                    return new EcfValue.Bytes(reader.ReadByteString());

                case CborReaderState.TextString:
                    return new EcfValue.Text(reader.ReadTextString());

                case CborReaderState.StartArray:
                    return ReadArray(reader);

                case CborReaderState.StartMap:
                    return ReadMap(reader);

                case CborReaderState.Boolean:
                    return new EcfValue.Bool(reader.ReadBoolean());

                case CborReaderState.Null:
                    reader.ReadNull();
                    return new EcfValue.Null();

                case CborReaderState.HalfPrecisionFloat:
                    return new EcfValue.Float((double)reader.ReadHalf());

                case CborReaderState.SinglePrecisionFloat:
                    return new EcfValue.Float(reader.ReadSingle());

                case CborReaderState.DoublePrecisionFloat:
                    return new EcfValue.Float(reader.ReadDouble());

                default:
                    // Undefined, simple values, indefinite-length markers, etc.
                    throw new EntityCodecException($"non-canonical or unsupported CBOR item: {state}");
            }
        }
        catch (CborContentException ex)
        {
            throw new EntityCodecException("malformed CBOR", ex);
        }
        catch (InvalidOperationException ex)
        {
            // Thrown by the reader on a conformance-mode violation (e.g. a
            // non-minimal integer or out-of-order map key) — still a rejection.
            throw new EntityCodecException("non-canonical CBOR", ex);
        }
    }

    private static EcfValue ReadArray(CborReader reader)
    {
        reader.ReadStartArray();
        var items = new List<EcfValue>();
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            items.Add(ReadValue(reader));
        }
        reader.ReadEndArray();
        return new EcfValue.Array(items);
    }

    private static EcfValue ReadMap(CborReader reader)
    {
        reader.ReadStartMap();
        var pairs = new List<KeyValuePair<EcfValue, EcfValue>>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            EcfValue key = ReadValue(reader);
            EcfValue val = ReadValue(reader);
            pairs.Add(new KeyValuePair<EcfValue, EcfValue>(key, val));
        }
        reader.ReadEndMap();
        return new EcfValue.Map(pairs);
    }

    /// <summary>
    /// Shortest-form float encoding (RFC 8949 Rule 4 + ECF Rule 4a specials).
    /// Specials encode as canonical half floats; otherwise the smallest of
    /// f16 ⊂ f32 ⊂ f64 that round-trips the value exactly is chosen. Port of the
    /// reference C impl's <c>encode_float</c>.
    /// </summary>
    internal static byte[] EncodeFloat(double f)
    {
        if (double.IsNaN(f))
        {
            return new byte[] { 0xf9, 0x7e, 0x00 }; // canonical quiet NaN
        }
        if (double.IsInfinity(f))
        {
            return new byte[] { 0xf9, (byte)(f > 0 ? 0x7c : 0xfc), 0x00 };
        }
        if (f == 0.0)
        {
            return new byte[] { 0xf9, (byte)(double.IsNegative(f) ? 0x80 : 0x00), 0x00 };
        }

        // f is finite and nonzero. f16 ⊂ f32 ⊂ f64, so test f32-exactness first.
        float single = (float)f;
        if ((double)single == f)
        {
            var half = (Half)single;
            if ((double)(float)half == f)
            {
                ushort bits = BitConverter.HalfToUInt16Bits(half);
                return new byte[] { 0xf9, (byte)(bits >> 8), (byte)bits };
            }

            uint sbits = BitConverter.SingleToUInt32Bits(single);
            return new byte[]
            {
                0xfa,
                (byte)(sbits >> 24), (byte)(sbits >> 16), (byte)(sbits >> 8), (byte)sbits,
            };
        }

        ulong dbits = BitConverter.DoubleToUInt64Bits(f);
        var result = new byte[9];
        result[0] = 0xfb;
        for (int i = 0; i < 8; i++)
        {
            result[1 + i] = (byte)(dbits >> (56 - 8 * i));
        }
        return result;
    }
}
