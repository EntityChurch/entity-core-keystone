using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Identity;

/// <summary>
/// Build and read <c>system/peer</c> entities (V7 §3.5, §7.65). The canonical peer
/// entity is <c>{key_type, public_key}</c> — a pure function of the keypair.
/// <para>
/// <strong>v7.65 canonicalization:</strong> <c>peer_id</c> is <em>not</em> part of
/// the hashable basis (it is a projection of the public key, not canonical), so it is
/// dropped from the entity. <c>content_hash(system/peer)</c> is therefore a pure
/// function of <c>(public_key, key_type)</c>, and the same identity yields the same
/// hash regardless of which address universe its peer_id projects into.
/// </para>
/// </summary>
internal static class PeerEntities
{
    /// <summary>The §9.1 floor key-type name; retained for the handshake announcement default.</summary>
    public const string Ed25519 = "ed25519";

    /// <summary>
    /// Materialize a <c>system/peer</c> entity from a key family and raw public key.
    /// Field order is the ECF-canonical lexicographic <c>key_type</c> then
    /// <c>public_key</c> (the Ctap2 encoder sorts regardless).
    /// </summary>
    public static Entity Build(IKeyAlgorithm keyType, ReadOnlyMemory<byte> publicKey) =>
        Entity.Create("system/peer", Ecf.Map(
            ("key_type", Ecf.Text(keyType.Name)),
            ("public_key", Ecf.Bytes(publicKey))));

    /// <summary>Read the raw public key from a <c>system/peer</c> entity.</summary>
    public static byte[] PublicKey(Entity peer)
    {
        if (peer.Type != "system/peer")
        {
            throw new EntityProtocolException($"expected system/peer entity, got '{peer.Type}'");
        }
        return Ecf.RequireBytes(peer.Data, "public_key");
    }

    /// <summary>Resolve the key family of a <c>system/peer</c> entity from its <c>key_type</c> name.</summary>
    public static IKeyAlgorithm KeyAlgorithm(Entity peer) =>
        KeyTypes.ByName(Ecf.RequireText(peer.Data, "key_type"));

    /// <summary>
    /// Derive the canonical Base58 <c>peer_id</c> of a <c>system/peer</c> entity
    /// (§1.5 / §7.65). The peer_id is no longer stored in the entity — it is a
    /// projection of <c>(public_key, key_type)</c> under the size-cutoff rule.
    /// </summary>
    public static string PeerId(Entity peer)
    {
        IKeyAlgorithm keyType = KeyAlgorithm(peer);
        byte[] publicKey = PublicKey(peer);
        (ulong hashType, byte[] digest) = KeyTypes.CanonicalPeerIdParts(publicKey);
        return EntityCodec.FormatPeerId(keyType.WireCode, hashType, digest);
    }
}
