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
}
