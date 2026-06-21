namespace EntityCore.Protocol;

/// <summary>
/// Authentication failed during connection establishment — an invalid nonce
/// signature, a public key that does not match the claimed peer id, or an
/// unsupported key type (V7 §4.6, §4.7). Maps to status 401 by default.
/// </summary>
public sealed class AuthenticationException : EntityProtocolException
{
    /// <summary>Create an authentication failure with its connection error code.</summary>
    public AuthenticationException(string code, string message, int status = 401)
        : base(message, status)
    {
        Code = code;
    }

    /// <summary>The §4.7 connection error code (e.g. <c>"invalid_signature"</c>).</summary>
    public string Code { get; }
}
