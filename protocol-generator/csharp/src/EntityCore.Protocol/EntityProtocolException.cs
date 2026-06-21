namespace EntityCore.Protocol;

/// <summary>
/// A protocol-layer fault: a malformed envelope, a failed integrity check, a
/// handshake-sequence violation, or any other deviation from the V7 wire contract
/// above the codec. Carries an optional protocol <see cref="Status"/> (the
/// EXECUTE_RESPONSE status code, §3.3) so the dispatcher can surface the right
/// numeric category to the caller.
/// </summary>
public class EntityProtocolException : EntityCoreException
{
    /// <summary>Create a protocol exception, optionally tagging the wire status code.</summary>
    public EntityProtocolException(string message, int status = 400)
        : base(message)
    {
        Status = status;
    }

    /// <summary>Create a protocol exception with an inner cause.</summary>
    public EntityProtocolException(string message, Exception innerException, int status = 400)
        : base(message, innerException)
    {
        Status = status;
    }

    /// <summary>The EXECUTE_RESPONSE status code this fault maps to (§3.3, §8.3).</summary>
    public int Status { get; }
}
