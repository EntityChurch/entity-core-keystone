namespace EntityCore.Protocol.Codec;

/// <summary>
/// Unsigned LEB128 varint primitive (N1). All format-code / key-type / hash-type
/// framing routes through this — never fixed-width bytes — so synthetic codes
/// ≥ 0x80 widen correctly (forward-compat).
/// </summary>
internal static class Leb128
{
    /// <summary>Encode an unsigned value as LEB128.</summary>
    internal static byte[] Encode(ulong value)
    {
        // Max 10 bytes for a 64-bit value.
        Span<byte> scratch = stackalloc byte[10];
        int n = 0;
        do
        {
            byte b = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0)
            {
                b |= 0x80;
            }
            scratch[n++] = b;
        }
        while (value != 0);
        return scratch[..n].ToArray();
    }

    /// <summary>
    /// Decode a LEB128 value starting at <paramref name="offset"/>, advancing it
    /// past the consumed bytes. Throws <see cref="EntityCodecException"/> on
    /// truncation or 64-bit overflow.
    /// </summary>
    internal static ulong Decode(ReadOnlySpan<byte> input, ref int offset)
    {
        ulong result = 0;
        int shift = 0;
        while (offset < input.Length)
        {
            if (shift >= 64)
            {
                throw new EntityCodecException("LEB128 overflow");
            }
            byte b = input[offset++];
            result |= (ulong)(b & 0x7f) << shift;
            if ((b & 0x80) == 0)
            {
                return result;
            }
            shift += 7;
        }
        throw new EntityCodecException("truncated LEB128");
    }
}
