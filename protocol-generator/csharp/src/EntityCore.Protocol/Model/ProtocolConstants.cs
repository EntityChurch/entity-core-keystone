namespace EntityCore.Protocol.Model;

/// <summary>Entity type-path constants for the core protocol (V7 §3).</summary>
internal static class TypeNames
{
    public const string Execute = "system/protocol/execute";
    public const string ExecuteResponse = "system/protocol/execute/response";
    public const string Error = "system/protocol/error";
    public const string ResourceTarget = "system/protocol/resource-target";
    public const string Peer = "system/peer";
    public const string Signature = "system/signature";
    public const string CapabilityToken = "system/capability/token";
    public const string CapabilityGrant = "system/capability/grant";
    public const string CapabilityRequest = "system/capability/request";
    public const string CapabilityPolicyEntry = "system/capability/policy-entry";
    public const string CapabilityRevocation = "system/capability/revocation";
    public const string DeletionMarker = "system/deletion-marker";
    public const string Handler = "system/handler";
    public const string HandlerInterface = "system/handler/interface";
    public const string HandlerRegisterRequest = "system/handler/register-request";
    public const string HandlerRegisterResult = "system/handler/register-result";
    public const string HandlerUnregisterRequest = "system/handler/unregister-request";
    public const string Type = "system/type";
    public const string Hello = "system/protocol/connect/hello";
    public const string Authenticate = "system/protocol/connect/authenticate";
    public const string PrimitiveAny = "primitive/any";

    // Entity-native body-binding seam (v7.74 §6.13(a)/§10.1 register round-trip). These
    // are compute-extension type *labels* the core peer reads/emits to honour the §10.1
    // dispatch round-trip; they are NOT part of the §9.5 core type floor (not published
    // at system/type/*). See A-011: the §10.1 gate's body-binding seam pulls these
    // shapes into the core gate even though compute is an extension.
    public const string ComputeLiteral = "compute/literal";
    public const string ComputeResult = "compute/result";
}

/// <summary>EXECUTE_RESPONSE status codes (V7 §3.3, §8.3).</summary>
internal static class Status
{
    public const int Ok = 200;
    public const int BadRequest = 400;
    public const int Unauthorized = 401;
    public const int Forbidden = 403;
    public const int NotFound = 404;
    public const int Conflict = 409;
    public const int RateLimited = 429;
    public const int InternalError = 500;
    public const int NotSupported = 501;
    public const int ServiceUnavailable = 503;
}

/// <summary>Well-known protocol strings (V7 §8.4, §4.1).</summary>
internal static class Protocols
{
    public const string Version = "entity-core/1.0";
    public const string ConnectPath = "system/protocol/connect";
    public const string DefaultHashFormat = "ecfv1-sha256";
    public const string DefaultKeyType = "ed25519";
}
