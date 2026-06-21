namespace EntityCore.Protocol;

/// <summary>
/// The transport closed before a response arrived — the peer closed the
/// connection, a local error closed it, or the reader task exited while requests
/// were still pending (§6.11 teardown contract). Surfaced as
/// <c>connection_broken</c> / status 503 (V7 §6.12).
/// </summary>
public sealed class ConnectionBrokenException : EntityTransportException
{
    /// <summary>Create a connection-broken fault.</summary>
    public ConnectionBrokenException(string message)
        : base("connection_broken", 503, message)
    {
    }

    /// <summary>Create a connection-broken fault with an inner cause.</summary>
    public ConnectionBrokenException(string message, Exception innerException)
        : base("connection_broken", 503, message, innerException)
    {
    }
}
