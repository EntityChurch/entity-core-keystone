namespace EntityCore.Protocol.Codec;

/// <summary>
/// The decoded components of a peer-id: the key-type and hash-type varints plus
/// the raw public-key hash digest. See <see cref="EntityCodec.ParsePeerId"/>.
/// </summary>
/// <param name="KeyType">Key-type varint (e.g. 1 = Ed25519).</param>
/// <param name="HashType">Hash-type varint (e.g. 1 = SHA-256).</param>
/// <param name="Digest">The public-key hash digest bytes.</param>
public sealed record PeerId(ulong KeyType, ulong HashType, byte[] Digest);
