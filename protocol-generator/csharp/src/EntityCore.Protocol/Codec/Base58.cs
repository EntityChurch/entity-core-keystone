namespace EntityCore.Protocol.Codec;

/// <summary>
/// Base58 with the Bitcoin alphabet (V7 §8.5). Hand-rolled rather than taking a
/// NuGet dependency: the algorithm is small, and it sidesteps a supply-chain pin
/// (S11) for a ~40-line primitive. Used by peer-id format/parse.
/// </summary>
internal static class Base58
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private static readonly int[] Reverse = BuildReverse();

    private static int[] BuildReverse()
    {
        var map = new int[128];
        Array.Fill(map, -1);
        for (int i = 0; i < Alphabet.Length; i++)
        {
            map[Alphabet[i]] = i;
        }
        return map;
    }

    /// <summary>Encode bytes (big-endian) to a Base58 string.</summary>
    internal static string Encode(ReadOnlySpan<byte> input)
    {
        if (input.Length == 0)
        {
            return string.Empty;
        }

        // Count leading zero bytes — each maps to a leading '1'.
        int leadingZeros = 0;
        while (leadingZeros < input.Length && input[leadingZeros] == 0)
        {
            leadingZeros++;
        }

        // Base-256 → base-58 by repeated division of a big-endian work buffer.
        var digits = new byte[input.Length * 138 / 100 + 1]; // ceil(log(256)/log(58))
        int digitCount = 0;
        for (int i = leadingZeros; i < input.Length; i++)
        {
            int carry = input[i];
            int j = 0;
            for (int k = digits.Length - 1; (carry != 0 || j < digitCount) && k >= 0; k--, j++)
            {
                carry += 256 * digits[k];
                digits[k] = (byte)(carry % 58);
                carry /= 58;
            }
            digitCount = j;
        }

        // Skip leading zeros in the base-58 buffer.
        int start = digits.Length - digitCount;
        while (start < digits.Length && digits[start] == 0)
        {
            start++;
        }

        var sb = new System.Text.StringBuilder(leadingZeros + (digits.Length - start));
        sb.Append('1', leadingZeros);
        for (int i = start; i < digits.Length; i++)
        {
            sb.Append(Alphabet[digits[i]]);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Decode a Base58 string to bytes. Throws <see cref="EntityCodecException"/>
    /// on an invalid character.
    /// </summary>
    internal static byte[] Decode(string input)
    {
        if (input.Length == 0)
        {
            return System.Array.Empty<byte>();
        }

        int leadingOnes = 0;
        while (leadingOnes < input.Length && input[leadingOnes] == '1')
        {
            leadingOnes++;
        }

        var bytes = new byte[input.Length * 733 / 1000 + 1]; // ceil(log(58)/log(256))
        int byteCount = 0;
        foreach (char c in input)
        {
            int value = c < 128 ? Reverse[c] : -1;
            if (value < 0)
            {
                throw new EntityCodecException($"invalid Base58 character '{c}'");
            }

            int carry = value;
            int j = 0;
            for (int k = bytes.Length - 1; (carry != 0 || j < byteCount) && k >= 0; k--, j++)
            {
                carry += 58 * bytes[k];
                bytes[k] = (byte)(carry % 256);
                carry /= 256;
            }
            byteCount = j;
        }

        int start = bytes.Length - byteCount;
        while (start < bytes.Length && bytes[start] == 0)
        {
            start++;
        }

        var result = new byte[leadingOnes + (bytes.Length - start)];
        // leading '1's are leading zero bytes; result is already zero-filled there.
        for (int i = start, w = leadingOnes; i < bytes.Length; i++, w++)
        {
            result[w] = bytes[i];
        }
        return result;
    }
}
