namespace EntityCore.Protocol.Model;

/// <summary>
/// Helpers for <c>system/hash</c> values (V7 §1.2): a flat byte string of a
/// multicodec-style varint format code followed by the digest. For ECFv1-SHA-256
/// (the only format this peer emits) that is the single byte <c>0x00</c> followed
/// by a 32-byte SHA-256 digest — 33 bytes total.
/// </summary>
internal static class Hashes
{
    /// <summary>Length of an ECFv1-SHA-256 content hash: <c>0x00</c> + 32-byte digest.</summary>
    public const int ContentHashLength = 33;

    /// <summary>
    /// The reserved zero hash — 33 all-zero bytes. Never a valid content hash, so
    /// it is unambiguous as a sentinel (CAS-create marker §3.9; rejected as a cap
    /// grantee §3.6 / §5.5).
    /// </summary>
    public static byte[] Zero() => new byte[ContentHashLength];

    /// <summary>Byte-wise equality over the full hash bytes, format code included (§5.3).</summary>
    public static bool Equal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.SequenceEqual(b);

    public static bool IsZero(ReadOnlySpan<byte> hash)
    {
        foreach (byte b in hash)
        {
            if (b != 0)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Lowercase hex of the full hash bytes (format code included) — the
    /// invariant-pointer path encoding (§3.5) and the key for in-memory maps.
    /// </summary>
    public static string Hex(ReadOnlySpan<byte> hash) => Convert.ToHexStringLower(hash);
}
