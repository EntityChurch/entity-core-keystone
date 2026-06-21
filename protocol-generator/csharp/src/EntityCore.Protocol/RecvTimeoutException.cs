namespace EntityCore.Protocol;

/// <summary>
/// The per-request deadline (§6.11(c)) fired before any response was received.
/// Surfaced as <c>recv_timeout</c> / status 503 (V7 §6.12).
/// </summary>
public sealed class RecvTimeoutException : EntityTransportException
{
    /// <summary>Create a recv-timeout fault.</summary>
    public RecvTimeoutException(string message)
        : base("recv_timeout", 503, message)
    {
    }
}
