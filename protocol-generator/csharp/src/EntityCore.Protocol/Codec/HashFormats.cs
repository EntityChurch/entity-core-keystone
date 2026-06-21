using System.Security.Cryptography;

namespace EntityCore.Protocol.Codec;

/// <summary>
/// The <c>content_hash_format</c> registry (V7 §1.2). A content hash is a flat byte
/// string: a LEB128 varint <em>format code</em> followed by the digest the code
/// names. The format code is <strong>intrinsic to the hash</strong> ("interpretation",
/// not "routing" — v7.68 §1.2 reframe): byte-equality over the full hash, format code
/// included (§5.3).
///
/// <para>
/// This is the hash half of the crypto-agility seam (RESYNC v7.56→v7.70 §3). Adding a
/// second hash family is a registry entry, not a rewrite. The conformance floor (§9.1)
/// is SHA-256 (<c>0x00</c>); SHA-384 (<c>0x01</c>) is validated, not required —
/// so a default Ed25519+SHA-256 peer never leaves the <c>0x00</c> path and stays
/// byte-identical to the S2 codec.
/// </para>
/// </summary>
internal static class HashFormats
{
    /// <summary>ECFv1 SHA-256 — production / §9.1 floor.</summary>
    public const ulong Sha256 = 0x00;

    /// <summary>ECFv1 SHA-384 — validated (v7.67), not required.</summary>
    public const ulong Sha384 = 0x01;

    /// <summary>Reserved per §1.2 — never a valid format code.</summary>
    public const ulong Reserved = 0xFF;

    /// <summary>True if <paramref name="code"/> names a hash family this peer can interpret.</summary>
    public static bool IsSupported(ulong code) => code is Sha256 or Sha384;

    /// <summary>
    /// The hash-format names this peer accepts, for the §4.5 <c>hello.hash_formats</c>
    /// advertisement. SHA-256 (the §9.1 floor) leads; SHA-384 is the validated agility
    /// family.
    /// </summary>
    public static readonly IReadOnlyList<string> SupportedNames = new[] { "ecfv1-sha256", "ecfv1-sha384" };

    /// <summary>Negotiation name for a supported format code (inverse of the advertisement).</summary>
    public static string Name(ulong code) => code switch
    {
        Sha256 => "ecfv1-sha256",
        Sha384 => "ecfv1-sha384",
        _ => throw Unsupported(code),
    };

    /// <summary>Raw digest length in bytes for a supported format code.</summary>
    public static int DigestLength(ulong code) => code switch
    {
        Sha256 => 32,
        Sha384 => 48,
        _ => throw Unsupported(code),
    };

    /// <summary>Compute the raw digest of <paramref name="data"/> under format <paramref name="code"/>.</summary>
    public static byte[] Digest(ulong code, ReadOnlySpan<byte> data) => code switch
    {
        Sha256 => SHA256.HashData(data),
        Sha384 => SHA384.HashData(data),
        _ => throw Unsupported(code),
    };

    /// <summary>
    /// Build a wire content hash: <c>LEB128(code) || Digest(code, ecfBytes)</c>. For the
    /// default SHA-256 format this is <c>0x00 || SHA256(ecfBytes)</c> — 33 bytes,
    /// byte-identical to the S2 codec.
    /// </summary>
    public static byte[] ContentHash(ulong code, ReadOnlySpan<byte> ecfBytes)
    {
        byte[] prefix = Leb128.Encode(code);
        byte[] digest = Digest(code, ecfBytes);
        var hash = new byte[prefix.Length + digest.Length];
        prefix.CopyTo(hash, 0);
        digest.CopyTo(hash.AsSpan(prefix.Length));
        return hash;
    }

    /// <summary>
    /// Read the leading format-code varint of a wire content hash. Surfaces the
    /// multi-byte LEB128 path (the <c>VARINT-MULTIBYTE-1</c> agility probe) and the
    /// unsupported/reserved rejections (<c>unsupported_content_hash_format</c>).
    /// </summary>
    public static ulong ReadFormatCode(ReadOnlySpan<byte> contentHash)
    {
        int offset = 0;
        return Leb128.Decode(contentHash, ref offset);
    }

    private static EntityCodecException Unsupported(ulong code) =>
        new($"unsupported_content_hash_format: 0x{code:x}");
}
