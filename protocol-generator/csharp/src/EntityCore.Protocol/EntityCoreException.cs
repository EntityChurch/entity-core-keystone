namespace EntityCore.Protocol;

/// <summary>
/// Base type for every exception raised by the Entity Core protocol peer. The
/// profile-defined hierarchy hangs the codec, protocol, and transport families
/// off this root; the codec layer (S2) ships <see cref="EntityCodecException"/>,
/// the rest land with the peer machinery (S3).
/// </summary>
public class EntityCoreException : Exception
{
    /// <summary>Create an exception with a message.</summary>
    public EntityCoreException(string message)
        : base(message)
    {
    }

    /// <summary>Create an exception with a message and an inner cause.</summary>
    public EntityCoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
