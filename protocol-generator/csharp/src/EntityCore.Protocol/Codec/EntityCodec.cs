using System.Security.Cryptography;
using NSec.Cryptography;

namespace EntityCore.Protocol.Codec;

/// <summary>
/// The Entity Core codec surface: canonical entity encoding, content hashing,
/// peer-id format/parse, and Ed25519 sign/verify. Native implementation over
/// <see cref="System.Formats.Cbor"/> (canonical CBOR), <c>System.Security.Cryptography</c>
/// (SHA-256/SHA-384, via <see cref="HashFormats"/>), and <c>NSec.Cryptography</c>
/// (Ed25519 / libsodium), per the C# profile. Content hashing dispatches through the
/// <see cref="HashFormats"/> crypto-agility registry; the default <c>0x00</c> SHA-256
/// path is byte-identical to the S2 codec.
/// </summary>
public static class EntityCodec
{
    /// <summary>
    /// Encode an entity (<c>{data, type}</c>) to canonical ECF bytes.
    /// <paramref name="canonicalData"/> is the already-canonical CBOR encoding of
    /// the entity's <c>data</c> field; it is spliced verbatim (N4 fidelity —
    /// never decoded and re-encoded).
    /// </summary>
    public static byte[] EncodeEntity(string type, ReadOnlySpan<byte> canonicalData)
    {
        ArgumentNullException.ThrowIfNull(type);
        var entity = new EcfValue.Map(new[]
        {
            new KeyValuePair<EcfValue, EcfValue>(
                new EcfValue.Text("data"), new EcfValue.PreEncoded(canonicalData.ToArray())),
            new KeyValuePair<EcfValue, EcfValue>(
                new EcfValue.Text("type"), new EcfValue.Text(type)),
        });
        return CanonicalCbor.Encode(entity);
    }

    private const int ContentHashDigestLength = 32;

    /// <summary>
    /// The codec-primitive content hash: <c>LEB128(formatCode) || SHA256(ECF({data,
    /// type}))</c>. The format code contributes only the varint prefix, never the
    /// hashed body — so the corpus's synthetic large prefixes (e.g. the N1
    /// <c>format_code=128</c> varint-width probe) encode faithfully. This is a
    /// codec-mechanics surface; family-selecting content_hash_format dispatch
    /// (SHA-256 vs SHA-384, reject-unknown) lives at the entity layer via
    /// <see cref="HashFormats"/> (and <see cref="Model.Entity"/>).
    /// </summary>
    public static byte[] ContentHash(string type, ReadOnlySpan<byte> canonicalData, ulong formatCode = 0)
    {
        byte[] body = EncodeEntity(type, canonicalData);
        byte[] digest = SHA256.HashData(body);
        byte[] prefix = Leb128.Encode(formatCode);

        var result = new byte[prefix.Length + ContentHashDigestLength];
        prefix.CopyTo(result, 0);
        digest.CopyTo(result.AsSpan(prefix.Length));
        return result;
    }

    /// <summary>
    /// Format a peer-id string: <c>Base58(LEB128(keyType) || LEB128(hashType) || digest)</c>
    /// (V7 §1.2 / §7.3).
    /// </summary>
    public static string FormatPeerId(ulong keyType, ulong hashType, ReadOnlySpan<byte> digest)
    {
        byte[] keyTypeBytes = Leb128.Encode(keyType);
        byte[] hashTypeBytes = Leb128.Encode(hashType);

        var raw = new byte[keyTypeBytes.Length + hashTypeBytes.Length + digest.Length];
        int offset = 0;
        keyTypeBytes.CopyTo(raw, offset);
        offset += keyTypeBytes.Length;
        hashTypeBytes.CopyTo(raw, offset);
        offset += hashTypeBytes.Length;
        digest.CopyTo(raw.AsSpan(offset));

        return Base58.Encode(raw);
    }

    /// <summary>Parse a Base58 peer-id back into its components.</summary>
    public static PeerId ParsePeerId(string peerId)
    {
        ArgumentNullException.ThrowIfNull(peerId);
        byte[] raw = Base58.Decode(peerId);
        int offset = 0;
        ulong keyType = Leb128.Decode(raw, ref offset);
        ulong hashType = Leb128.Decode(raw, ref offset);
        byte[] digest = raw[offset..];
        return new PeerId(keyType, hashType, digest);
    }

    /// <summary>
    /// Ed25519-sign a message with a 32-byte seed (raw private key), returning
    /// the 64-byte detached signature. Ed25519 is deterministic (RFC 8032).
    /// </summary>
    public static byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message)
    {
        using var key = Key.Import(SignatureAlgorithm.Ed25519, seed, KeyBlobFormat.RawPrivateKey);
        return SignatureAlgorithm.Ed25519.Sign(key, message);
    }

    /// <summary>
    /// Verify a 64-byte Ed25519 signature over <paramref name="message"/> against
    /// a 32-byte raw public key.
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        var key = PublicKey.Import(SignatureAlgorithm.Ed25519, publicKey, KeyBlobFormat.RawPublicKey);
        return SignatureAlgorithm.Ed25519.Verify(key, message, signature);
    }

    /// <summary>Derive the 32-byte raw Ed25519 public key from a 32-byte seed.</summary>
    public static byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed)
    {
        using var key = Key.Import(SignatureAlgorithm.Ed25519, seed, KeyBlobFormat.RawPrivateKey);
        return key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }
}
