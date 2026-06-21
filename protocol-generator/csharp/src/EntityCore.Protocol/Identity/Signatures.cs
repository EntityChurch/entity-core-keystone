using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Identity;

/// <summary>
/// Construct and verify <c>system/signature</c> entities (V7 §3.5, §7.3).
/// Signatures point <em>to</em> the content they sign (target-matching), are made
/// over the full <c>system/hash</c> bytes (format code + digest), and carry the
/// <c>signer</c> field that verification MUST check against the expected identity.
/// </summary>
internal static class Signatures
{
    public const string Ed25519 = "ed25519";

    /// <summary>
    /// Sign <paramref name="target"/> with <paramref name="signer"/>'s key and
    /// produce the detached <c>system/signature</c> entity (§4.6 construction). The
    /// <c>algorithm</c> field records the signer's key family so verification can
    /// dispatch the right verifier.
    /// </summary>
    public static Entity Sign(Entity target, PeerIdentity signer)
    {
        byte[] signatureBytes = signer.Sign(target.ContentHash);
        return Build(target.ContentHash, signer.IdentityHash, signatureBytes, signer.KeyTypeName);
    }

    /// <summary>Materialize a <c>system/signature</c> entity from its parts.</summary>
    public static Entity Build(byte[] targetHash, byte[] signerHash, byte[] signatureBytes, string algorithm = Ed25519) =>
        Entity.Create("system/signature", Ecf.Map(
            ("target", Ecf.Bytes(targetHash)),
            ("signer", Ecf.Bytes(signerHash)),
            ("algorithm", Ecf.Text(algorithm)),
            ("signature", Ecf.Bytes(signatureBytes))));

    public static byte[] Target(Entity signature) => Ecf.RequireBytes(signature.Data, "target");

    public static byte[] Signer(Entity signature) => Ecf.RequireBytes(signature.Data, "signer");

    /// <summary>
    /// Cryptographically verify a signature entity against the signer's peer
    /// entity. Checks the algorithm and the Ed25519 signature over the signature's
    /// <c>target</c> bytes. The caller is responsible for the <c>signer</c>-matches-
    /// expected-identity check (§3.5: "Implementations MUST NOT skip this check").
    /// </summary>
    public static bool Verify(Entity signature, Entity signerPeer)
    {
        if (signature.Type != "system/signature")
        {
            return false;
        }
        string? algorithm = Ecf.OptText(signature.Data, "algorithm");
        if (algorithm is null)
        {
            return false;
        }

        IKeyAlgorithm verifier;
        try
        {
            verifier = KeyTypes.ByName(algorithm);
        }
        catch (EntityCodecException)
        {
            return false; // unknown algorithm → not verifiable
        }

        byte[] target = Target(signature);
        byte[] signatureBytes = Ecf.RequireBytes(signature.Data, "signature");
        byte[] publicKey = PeerEntities.PublicKey(signerPeer);
        return verifier.Verify(publicKey, target, signatureBytes);
    }
}
