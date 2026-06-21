using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Store;

namespace EntityCore.Protocol.Handlers;

/// <summary>
/// The outcome of a handler operation: a status, a result entity (the operation's
/// declared output type), and any entities the handler bundles into the response
/// envelope's <c>included</c> map (protocol entities — capabilities, identities,
/// signatures, §3.1).
/// </summary>
internal sealed record HandlerResult(int Status, Entity Result, IReadOnlyList<Entity> Included)
{
    public static HandlerResult Ok(Entity result, IReadOnlyList<Entity>? included = null) =>
        new(Model.Status.Ok, result, included ?? System.Array.Empty<Entity>());

    public static HandlerResult Of(int status, Entity result, IReadOnlyList<Entity>? included = null) =>
        new(status, result, included ?? System.Array.Empty<Entity>());
}

/// <summary>
/// Peer-level services a handler dispatches against (V7 §6.8). The handler acts as
/// the local peer for its sub-requests; its authority is its own grant, not the
/// caller's capability (§6.8 "no silent escalation").
/// </summary>
internal interface IPeerServices
{
    string LocalPeerId { get; }

    PeerIdentity LocalIdentity { get; }

    EntityTree Tree { get; }

    ContentStore ContentStore { get; }

    /// <summary>The §6.10 emit pathway — where an extension registers a consumer (§6.13(c)).</summary>
    Emit.EmitBus Emit { get; }

    /// <summary>Current time, ms since epoch (the clock used for temporal checks).</summary>
    ulong NowMs { get; }
}

/// <summary>
/// Per-request execution context handed to a handler (V7 §6.5 step 7, §6.8). Holds
/// the EXECUTE, the resolved pattern/suffix, the caller's verified capability, the
/// handler's own grant, the envelope (for <c>included</c> resolution, N5), and —
/// for connection-path dispatch — the per-connection state.
/// </summary>
internal sealed class HandlerContext
{
    public required IPeerServices Peer { get; init; }

    public required Execute Execute { get; init; }

    public required Envelope Envelope { get; init; }

    /// <summary>Peer-relative handler pattern, e.g. <c>"system/tree"</c>.</summary>
    public required string Pattern { get; init; }

    /// <summary>URI remainder after the handler pattern (for internal routing, §6.4).</summary>
    public required string Suffix { get; init; }

    public CapabilityToken? CallerCapability { get; init; }

    public CapabilityToken? HandlerGrant { get; init; }

    public byte[]? Author { get; init; }

    /// <summary>Per-connection state — present only for connection-path dispatch (§4).</summary>
    public ConnectionState? Connection { get; init; }

    /// <summary>
    /// The §6.13(b) handler-facing outbound-dispatch seam — non-null when the request
    /// arrived over a reentrant connection. A handler originates an outbound EXECUTE
    /// through here; it routes via §6.11 transport reentry. Core handlers do not originate.
    /// </summary>
    public IOutboundDispatch? Outbound { get; init; }

    public string Operation => Execute.Operation;

    public Entity Params => Execute.Params;

    public ResourceTarget? Resource => Execute.Resource;

    public string LocalPeerId => Peer.LocalPeerId;
}

/// <summary>
/// The authority a handler presents on an outbound EXECUTE (V7 §5.8 chain inclusion):
/// the capability the target peer accepts, its granter identity, and the capability
/// signature. The handler dispatches under its own authority (§6.8 — no silent
/// escalation of the caller's), so it supplies the bundle it holds for the target.
/// </summary>
internal sealed record OutboundAuthority(CapabilityToken Capability, Entity GranterPeer, Entity CapabilitySignature);

/// <summary>
/// The handler-facing outbound-dispatch seam (V7 §6.13(b)): a handler servicing an
/// inbound EXECUTE may initiate an outbound EXECUTE, routed through the §6.11 transport
/// reentry contract (reader-task + <c>request_id</c> correlation). Present on every peer
/// even though no <em>core</em> handler originates — a handler registered at runtime
/// (§6.13(a)) may, and the substrate must support it the moment it is installed.
/// </summary>
internal interface IOutboundDispatch
{
    /// <summary>
    /// Build, sign (as the local peer), and send an authenticated outbound EXECUTE; await
    /// the correlated EXECUTE_RESPONSE. The full authority chain travels in <c>included</c>.
    /// </summary>
    Task<ExecuteResponse> ExecuteAsync(
        string uri, string operation, Entity paramsEntity, ResourceTarget? resource,
        OutboundAuthority authority, TimeSpan timeout, CancellationToken ct = default);
}

/// <summary>A registered handler's executable contract (V7 §6.1). The dispatch target.</summary>
internal interface IHandler
{
    /// <summary>Peer-relative pattern path this handler is registered at.</summary>
    string Pattern { get; }

    /// <summary>Human-readable handler name (for the interface entity, §3.7).</summary>
    string Name { get; }

    /// <summary>Operation names this handler declares (for the interface entity).</summary>
    IReadOnlyList<string> Operations { get; }

    Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct);
}
