using System.Security.Cryptography;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Identity;

/// <summary>
/// A local peer's cryptographic identity (V7 §1.5): a signature keypair of some
/// <see cref="KeyType"/>, the derived Base58 peer id (§7.4 / §1.5 size-cutoff), the
/// materialized canonical <c>system/peer</c> entity (§3.5, §7.65), and that entity's
/// content hash — the <em>identity hash</em> used in the <c>author</c>, <c>granter</c>,
/// <c>grantee</c>, and <c>signer</c> reference fields throughout the protocol.
/// <para>
/// The default key family is Ed25519 (the §9.1 floor); a non-default family (e.g.
/// Ed448) flows through the same paths via the <see cref="KeyTypes"/> seam.
/// </para>
/// </summary>
internal sealed class PeerIdentity
{
    private readonly byte[] _seed;
    private readonly IKeyAlgorithm _keyType;

    private PeerIdentity(byte[] seed, IKeyAlgorithm keyType, byte[] publicKey, string peerId, Entity peerEntity)
    {
        _seed = seed;
        _keyType = keyType;
        PublicKey = publicKey;
        PeerId = peerId;
        PeerEntity = peerEntity;
    }

    /// <summary>Raw public key (32 bytes Ed25519, 57 bytes Ed448).</summary>
    public byte[] PublicKey { get; }

    /// <summary>The key family backing this identity.</summary>
    public IKeyAlgorithm KeyType => _keyType;

    /// <summary>The <c>key_type</c> name carried in <c>system/peer.data</c> (e.g. <c>"ed25519"</c>).</summary>
    public string KeyTypeName => _keyType.Name;

    /// <summary>Canonical Base58 peer id, <c>Base58(varint(key_type) || varint(hash_type) || digest)</c> (§1.5).</summary>
    public string PeerId { get; }

    /// <summary>The materialized canonical <c>system/peer</c> entity for this identity.</summary>
    public Entity PeerEntity { get; }

    /// <summary>Content hash of <see cref="PeerEntity"/> — this identity's reference hash.</summary>
    public byte[] IdentityHash => PeerEntity.ContentHash;

    /// <summary>Generate a fresh Ed25519 identity (the §9.1 floor) from a random seed.</summary>
    public static PeerIdentity Generate() => FromSeed(RandomNumberGenerator.GetBytes(32));

    /// <summary>Construct an Ed25519 identity from a 32-byte seed (deterministic).</summary>
    public static PeerIdentity FromSeed(byte[] seed) => FromSeed(seed, KeyTypes.Default);

    /// <summary>Construct an identity from a raw secret seed under an explicit key family.</summary>
    public static PeerIdentity FromSeed(byte[] seed, IKeyAlgorithm keyType)
    {
        byte[] publicKey = keyType.PublicKeyFromSeed(seed);
        string peerId = DerivePeerId(publicKey, keyType);
        Entity peerEntity = PeerEntities.Build(keyType, publicKey);
        return new PeerIdentity(seed, keyType, publicKey, peerId, peerEntity);
    }

    /// <summary>Sign a message (full content-hash bytes) with this identity's private key (§7.3).</summary>
    public byte[] Sign(ReadOnlySpan<byte> message) => _keyType.Sign(_seed, message);

    /// <summary>
    /// Derive the canonical Base58 peer id from a raw public key under
    /// <paramref name="keyType"/> (§1.5 / §7.65): identity-multihash for keys that fit
    /// the ≤32-byte bound, SHA-256-form otherwise.
    /// </summary>
    public static string DerivePeerId(ReadOnlySpan<byte> publicKey, IKeyAlgorithm keyType)
    {
        (ulong hashType, byte[] digest) = KeyTypes.CanonicalPeerIdParts(publicKey);
        return EntityCodec.FormatPeerId(keyType.WireCode, hashType, digest);
    }
}
