namespace EntityCore.Protocol;

/// <summary>
/// The <c>hello</c> step of connection establishment failed — incompatible
/// protocols, hash formats, or key types (V7 §4.5, §4.7), or a sequence error.
/// Carries the connection error <see cref="Code"/> (§4.7) alongside the status.
/// </summary>
public sealed class HelloFailedException : EntityProtocolException
{
    /// <summary>Create a hello failure with its connection error code and status.</summary>
    public HelloFailedException(string code, string message, int status = 400)
        : base(message, status)
    {
        Code = code;
    }

    /// <summary>The §4.7 connection error code (e.g. <c>"incompatible_protocol"</c>).</summary>
    public string Code { get; }
}
