namespace EntityCore.Protocol;

/// <summary>
/// A response arrived but was malformed — a decode failure on the wire envelope,
/// a missing required field, or an error response (<c>status &gt;= 400</c>) lacking
/// the required <c>code</c> field. Surfaced as <c>protocol_error</c> / status 502
/// (V7 §6.12).
/// </summary>
public sealed class ProtocolErrorException : EntityTransportException
{
    /// <summary>Create a protocol-error transport fault.</summary>
    public ProtocolErrorException(string message)
        : base("protocol_error", 502, message)
    {
    }

    /// <summary>Create a protocol-error transport fault with an inner cause.</summary>
    public ProtocolErrorException(string message, Exception innerException)
        : base("protocol_error", 502, message, innerException)
    {
    }
}
