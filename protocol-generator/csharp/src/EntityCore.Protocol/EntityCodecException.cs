namespace EntityCore.Protocol;

/// <summary>
/// Raised when codec input is malformed or violates an ECF canonical rule:
/// a non-canonical encoding, a forbidden CBOR tag, an invalid peer-id, or
/// truncated framing.
/// </summary>
public sealed class EntityCodecException : EntityCoreException
{
    /// <summary>Create a codec exception with a message.</summary>
    public EntityCodecException(string message)
        : base(message)
    {
    }

    /// <summary>Create a codec exception with a message and an inner cause.</summary>
    public EntityCodecException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>
    /// True when the refusal is specifically a CBOR major-type-6 tag in a position ECF
    /// forbids (<c>ENTITY-CBOR-ENCODING</c> §6.3) — the ONE decode-boundary cause that
    /// keeps <c>400 non_canonical_ecf</c> under §4.11 while every other one moves to a
    /// different code.
    /// <para>
    /// A FLAG RATHER THAN A SUBCLASS, and rather than a match on <see cref="Exception.Message"/>.
    /// This type is <c>public sealed</c>: subclassing it would both widen the published
    /// surface of an assembly whose public types are its exception roots plus
    /// <c>PeerId</c>, and break <c>Assert.Throws&lt;EntityCodecException&gt;</c>, which is
    /// an EXACT-type assertion in xUnit. A message match is what §4.11 warns against —
    /// one string edit away from silently re-collapsing the codes. The member is
    /// <c>internal</c>, so it is a discriminator for this assembly and its test assemblies
    /// and not part of the public contract.
    /// </para>
    /// </summary>
    internal bool TagRejected { get; init; }
}
