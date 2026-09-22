namespace EntityCore.Protocol;

/// <summary>
/// A §1.8 / §3.1 RESOLUTION-INTEGRITY failure: an entity whose carried
/// <c>content_hash</c> is not <c>content_hash({type, data})</c>, or an <c>included</c>
/// entry whose MAP KEY does not bind to the entity filed under it.
/// <para>
/// §5.2a pins this arm: <em>"A peer that refuses at the decode boundary MUST answer
/// <c>400 hash_mismatch</c> <c>[MUST]</c>"</em> (mood corrected 0.8.2.24), and in the
/// same breath <em>"<c>400 non_canonical_ecf</c> is NOT conformant here <c>[MUST]</c>"</em>.
/// That code is <c>ENTITY-CBOR-ENCODING</c> §5.4's, for a CBOR TAG-POLICY violation, and a
/// mis-keyed included entry carries no tag. Its encoding is canonical; what is false is the
/// claim the KEY makes, so the remedy <c>non_canonical_ecf</c> selects (<em>re-encode</em>)
/// sends an honest caller to the wrong layer. This peer answered <c>non_canonical_ecf</c>
/// for every decode-boundary refusal until 0.8.2.24 (measured on the wire: arc-probe
/// B1/B2).
/// </para>
/// <para>
/// A SUBCLASS RATHER THAN A MESSAGE, because a classifier that has to recognise the cause
/// by matching on <c>Message</c> is one string edit away from silently re-collapsing the
/// two codes. It is <c>internal</c> on purpose: this assembly's public surface is its
/// exception roots plus <c>PeerId</c>, and a refusal-cause discriminator consumed only by
/// the transport belongs inside it. Callers that catch
/// <see cref="EntityProtocolException"/> — the <c>put</c> admission ladder among them —
/// keep catching this unchanged.
/// </para>
/// </summary>
internal sealed class HashMismatchException : EntityProtocolException
{
    /// <summary>Create a resolution-integrity exception with a message.</summary>
    public HashMismatchException(string message)
        : base(message)
    {
    }
}
