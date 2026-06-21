namespace EntityCore.Protocol;

/// <summary>
/// A per-request transport fault: no usable <c>EXECUTE_RESPONSE</c> arrived for an
/// outbound EXECUTE (V7 §6.12). The three concrete codes —
/// <see cref="RecvTimeoutException"/>, <see cref="ConnectionBrokenException"/>, and
/// <see cref="ProtocolErrorException"/> — carry the canonical <see cref="Code"/> /
/// <see cref="Status"/> pairs so downstream consumers record the right marker.
/// </summary>
public class EntityTransportException : EntityCoreException
{
    /// <summary>Create a transport exception with its §6.12 code and status.</summary>
    public EntityTransportException(string code, int status, string message)
        : base(message)
    {
        Code = code;
        Status = status;
    }

    /// <summary>Create a transport exception with an inner cause.</summary>
    public EntityTransportException(string code, int status, string message, Exception innerException)
        : base(message, innerException)
    {
        Code = code;
        Status = status;
    }

    /// <summary>The §6.12 transport error code (e.g. <c>"recv_timeout"</c>).</summary>
    public string Code { get; }

    /// <summary>The status the transport surfaces for this fault (§6.12).</summary>
    public int Status { get; }
}
