using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace EntityCore.Protocol.Codec;

/// <summary>
/// A signature key family — the operations the protocol needs from a <c>key_type</c>
/// (V7 §1.5). Each algorithm has two surfaces (v7.66): a string <see cref="Name"/>
/// carried in <c>system/peer.data.key_type</c> and a binary <see cref="WireCode"/>
/// varint carried in the <c>peer_id</c> wire prefix.
/// </summary>
internal interface IKeyAlgorithm
{
    /// <summary>Entity-data form, e.g. <c>"ed25519"</c> / <c>"ed448"</c> (§3.5).</summary>
    string Name { get; }

    /// <summary>peer_id wire-prefix varint, e.g. <c>0x01</c> / <c>0x02</c> (§1.5).</summary>
    ulong WireCode { get; }

    /// <summary>Raw public-key length in bytes (32 Ed25519, 57 Ed448).</summary>
    int PublicKeySize { get; }

    /// <summary>Derive the raw public key from a raw secret seed.</summary>
    byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed);

    /// <summary>Deterministically sign (RFC 8032) <paramref name="message"/> with a raw secret seed.</summary>
    byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message);

    /// <summary>Verify a detached signature over <paramref name="message"/> against a raw public key.</summary>
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);
}

/// <summary>
/// The <c>key_type</c> registry (V7 §1.5) — the key half of the crypto-agility seam
/// (RESYNC v7.56→v7.70 §3). Dispatch by code or by name; a second key family is a
/// registry entry, not a rewrite. The conformance floor (§9.1) is Ed25519
/// (<c>0x01</c>); Ed448 (<c>0x02</c>) is validated, not required — so a default peer
/// never leaves the Ed25519 path.
///
/// <para>
/// Provider independence is deliberate: Ed25519 comes from NSec/libsodium (via
/// <see cref="EntityCodec"/>), Ed448 from BouncyCastle — two independent crypto
/// sources behind one seam, the strongest agility proof. Swapping a provider (e.g.
/// Ed448 → the FFI <c>libentitycore_codec</c>) is a single registry edit.
/// </para>
/// </summary>
internal static class KeyTypes
{
    /// <summary>Ed25519 — production / §9.1 floor.</summary>
    public const ulong Ed25519Code = 0x01;

    /// <summary>Ed448 — validated (v7.67), not required.</summary>
    public const ulong Ed448Code = 0x02;

    /// <summary>Test-only path-exercise stub (v7.66) — synthetic key, no signing.</summary>
    public const ulong ExperimentalTestCode = 0xFE;

    /// <summary>Reserved per §1.5 — never a valid key_type.</summary>
    public const ulong Reserved = 0xFF;

    /// <summary>The size cutoff (bytes) that selects the canonical peer_id form (§1.5).</summary>
    private const int IdentityMultihashCutoff = 32;

    private static readonly Ed25519Algorithm Ed25519Impl = new();
    private static readonly Ed448Algorithm Ed448Impl = new();
    private static readonly ExperimentalTestAlgorithm ExperimentalTestImpl = new();

    /// <summary>The default key family for a freshly generated identity — the §9.1 floor.</summary>
    public static IKeyAlgorithm Default => Ed25519Impl;

    /// <summary>Resolve a key family by its wire <paramref name="code"/> (§1.5).</summary>
    public static IKeyAlgorithm ByCode(ulong code) => code switch
    {
        Ed25519Code => Ed25519Impl,
        Ed448Code => Ed448Impl,
        ExperimentalTestCode => ExperimentalTestImpl,
        Reserved => throw new EntityCodecException("reserved key_type 255 (§1.5)"),
        _ => throw new EntityCodecException($"unsupported_key_type: 0x{code:x}"),
    };

    /// <summary>
    /// The key-type names this peer accepts, for the §4.5 <c>hello.key_types</c>
    /// advertisement. Ed25519 (the §1.5 floor) leads; Ed448 is the validated agility
    /// family. The experimental-test family is not advertised.
    /// </summary>
    public static readonly IReadOnlyList<string> SupportedNames = new[] { "ed25519", "ed448" };

    /// <summary>Resolve a key family by its entity-data <paramref name="name"/> (§3.5).</summary>
    public static IKeyAlgorithm ByName(string name) => name switch
    {
        "ed25519" => Ed25519Impl,
        "ed448" => Ed448Impl,
        "experimental-test" => ExperimentalTestImpl,
        _ => throw new EntityCodecException($"unsupported_key_type: '{name}'"),
    };

    /// <summary>True if <paramref name="code"/> names a key family this peer can interpret.</summary>
    public static bool IsSupported(ulong code) =>
        code is Ed25519Code or Ed448Code or ExperimentalTestCode;

    /// <summary>
    /// True if <paramref name="code"/> is a key family this peer will accept on the
    /// handshake — i.e. one it can sign/verify with (Ed25519, Ed448). The 0xFE
    /// experimental-test stub is interpretable (<see cref="IsSupported"/>) but has no
    /// signing primitive, so it is <em>not</em> a valid handshake identity: a peer_id
    /// carrying it (or any unallocated/reserved code) is rejected at the earliest
    /// handshake boundary with <c>unsupported_key_type</c> (v7.66 §4.4 surface 6 /
    /// V7 §4.7 registry pin).
    /// </summary>
    public static bool IsHandshakeSupported(ulong code) =>
        code is Ed25519Code or Ed448Code;

    /// <summary>
    /// The canonical <c>(hash_type, digest)</c> for a peer_id under the V7 §1.5
    /// size-cutoff rule: a public key that fits the identity-multihash bound
    /// (≤ 32 bytes) is embedded raw under <c>hash_type=0x00</c>; anything larger is
    /// SHA-256-hashed under <c>hash_type=0x01</c>. Uniform across key families —
    /// Ed25519 (32 B) → identity-multihash; Ed448 (57 B) / ML-DSA / the 0xFE stub →
    /// SHA-256-form.
    /// </summary>
    public static (ulong HashType, byte[] Digest) CanonicalPeerIdParts(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length <= IdentityMultihashCutoff)
        {
            return (0x00, publicKey.ToArray()); // identity-multihash
        }
        return (0x01, SHA256.HashData(publicKey)); // SHA-256-form
    }

    /// <summary>Ed25519 (§9.1 floor) — backed by NSec/libsodium via <see cref="EntityCodec"/>.</summary>
    private sealed class Ed25519Algorithm : IKeyAlgorithm
    {
        public string Name => "ed25519";
        public ulong WireCode => Ed25519Code;
        public int PublicKeySize => 32;
        public byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed) => EntityCodec.PublicKeyFromSeed(seed);
        public byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message) => EntityCodec.Sign(seed, message);
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) =>
            EntityCodec.Verify(publicKey, message, signature);
    }

    /// <summary>
    /// Ed448 (validated) — backed by BouncyCastle, an independent crypto source. Pure
    /// Ed448 (RFC 8032, empty context); the 57-byte secret seed is passed verbatim
    /// (the SHAKE256 expansion happens inside the library).
    /// </summary>
    private sealed class Ed448Algorithm : IKeyAlgorithm
    {
        public string Name => "ed448";
        public ulong WireCode => Ed448Code;
        public int PublicKeySize => 57;

        public byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed)
        {
            var priv = new Ed448PrivateKeyParameters(seed.ToArray());
            return priv.GeneratePublicKey().GetEncoded();
        }

        public byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message)
        {
            var priv = new Ed448PrivateKeyParameters(seed.ToArray());
            var signer = new Ed448Signer([]); // empty context = pure Ed448
            signer.Init(forSigning: true, priv);
            byte[] msg = message.ToArray();
            signer.BlockUpdate(msg, 0, msg.Length);
            return signer.GenerateSignature();
        }

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            var pub = new Ed448PublicKeyParameters(publicKey.ToArray());
            var verifier = new Ed448Signer([]);
            verifier.Init(forSigning: false, pub);
            byte[] msg = message.ToArray();
            verifier.BlockUpdate(msg, 0, msg.Length);
            return verifier.VerifySignature(signature.ToArray());
        }
    }

    /// <summary>
    /// The v7.66 <c>0xFE</c> test-only stub: a synthetic 64-byte key with no real
    /// crypto. It exercises the per-key_type non-crypto code paths (peer-entity
    /// construction, content_hash, the &gt;32-byte SHA-256-form peer_id) without a
    /// signing primitive. Signing/verifying with it is a programming error.
    /// </summary>
    private sealed class ExperimentalTestAlgorithm : IKeyAlgorithm
    {
        public string Name => "experimental-test";
        public ulong WireCode => ExperimentalTestCode;
        public int PublicKeySize => 64;
        public byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed) =>
            throw new EntityCodecException("experimental-test key_type is a non-crypto path-exercise stub");
        public byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message) =>
            throw new EntityCodecException("experimental-test key_type cannot sign");
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) =>
            throw new EntityCodecException("experimental-test key_type cannot verify");
    }
}
