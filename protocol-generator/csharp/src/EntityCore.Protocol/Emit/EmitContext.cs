using EntityCore.Protocol.Codec;

namespace EntityCore.Protocol.Emit;

/// <summary>
/// The execution-context core fields (V7 §6.8a / SYSTEM-COMPOSITION C3). These are the
/// RESERVED field <em>names</em> — the collision contract — carried on a tree-change
/// event's <c>context</c>. The representation is impl-defined (§9.4); this record is the
/// C# idiom (S6). On a core peer most slots are inert (no cascade, no handler chain): the
/// type pins the names so an extension layering compute / cascade above core cannot
/// collide on them. (<c>capability</c> was dropped as redundant with
/// <c>caller_capability</c> / <c>handler_grant</c>.)
/// </summary>
internal sealed record EmitContext(
    string? ChainId = null,
    string? ParentChainId = null,
    byte[]? Author = null,
    byte[]? CallerCapability = null,
    string? RequestId = null,
    EcfValue? Bounds = null,
    ulong? CascadeDepth = null,
    byte[]? HandlerGrant = null,
    string? HandlerPattern = null,
    string? Operation = null);
