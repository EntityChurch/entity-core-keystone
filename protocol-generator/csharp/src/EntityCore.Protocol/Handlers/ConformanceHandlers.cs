using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Handlers;

/// <summary>
/// The <c>system/validate/*</c> conformance test-handlers (GUIDE-CONFORMANCE §7a).
/// These are <b>not core protocol</b> — they are conformance scaffolding, present only
/// in a peer's conformance build (opt-in via the <c>conformanceHandlers</c> peer flag,
/// surfaced as the host <c>--validate</c> switch), off by default. They give a black-box
/// validator a native, compute-free way to drive the two extensibility hooks that have no
/// other wire-reachable trigger in a core-only peer:
/// <list type="bullet">
///   <item><see cref="EchoHandler"/> — proves the §6.13(a) resolve→dispatch half (closes A-011,
///     replacing the compute/literal round-trip).</item>
///   <item><see cref="DispatchOutboundHandler"/> — proves the §6.13(b)/§6.11 outbound seam by
///     originating one outbound EXECUTE back over the inbound connection (the §6.11 reentry
///     surface — the only origination path reachable in core; closes A-013).</item>
/// </list>
/// </summary>
internal static class ConformancePatterns
{
    public const string Echo = "system/validate/echo";
    public const string DispatchOutbound = "system/validate/dispatch-outbound";
}

/// <summary>
/// §7a <c>system/validate/echo</c>. EXECUTE returns, verbatim, the params entity it was
/// given (the literal value carried in params round-trips out). Native body, no compute —
/// this is the portable replacement for the A-011 <c>compute/literal</c> dispatch step.
/// </summary>
internal sealed class EchoHandler : IHandler
{
    public string Pattern => ConformancePatterns.Echo;
    public string Name => "validate-echo";
    public IReadOnlyList<string> Operations { get; } = new[] { "echo" };

    public Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct) =>
        Task.FromResult(HandlerResult.Ok(ctx.Params));
}

/// <summary>
/// §7a <c>system/validate/dispatch-outbound</c>. EXECUTE originates exactly one outbound
/// EXECUTE — via the §6.13(b) handler-reachable outbound closure (<c>ctx.Outbound</c>,
/// the §6.11 reentry sender) — back to the calling peer, invoking <c>operation</c> on the
/// <c>target</c> pattern with the carried <c>value</c>, and returns that downstream
/// response. This proves the target can <em>originate</em>, not just respond.
///
/// <para>Authority: the reentry direction (this peer → caller) can only be authorized by
/// the caller, so the caller supplies the capability it minted for this peer in the params
/// (the three authority entities, each embedded as a nested entity). This mirrors the
/// B-rooted dispatch capability the wire harness already constructs for cross-peer
/// remote-execute — here carried in-band rather than via a continuation wrapper.</para>
/// </summary>
internal sealed class DispatchOutboundHandler : IHandler
{
    private static readonly TimeSpan OutboundTimeout = TimeSpan.FromSeconds(10);

    public string Pattern => ConformancePatterns.DispatchOutbound;
    public string Name => "validate-dispatch-outbound";
    public IReadOnlyList<string> Operations { get; } = new[] { "dispatch" };

    public async Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct)
    {
        if (ctx.Outbound is null)
        {
            return Errors.Error(Status.ServiceUnavailable, "no_outbound_seam",
                "dispatch-outbound requires a live §6.11 reentry connection (handler was not dispatched over a connection)");
        }

        EcfValue p = ctx.Params.Data;
        string target = Ecf.RequireText(p, "target");        // handler pattern at the caller, e.g. system/validate/echo
        string operation = Ecf.RequireText(p, "operation");  // operation to invoke there, e.g. echo
        EcfValue value = Ecf.Require(p, "value");            // value to round-trip, so the loop is verifiable

        // The caller-minted reentry authority (this peer is the grantee), carried in-band.
        var cap = new CapabilityToken(Entity.FromDecoded(Ecf.Require(p, "reentry_capability")));
        Entity granter = Entity.FromDecoded(Ecf.Require(p, "reentry_granter"));
        Entity capSig = Entity.FromDecoded(Ecf.Require(p, "reentry_cap_signature"));
        var authority = new OutboundAuthority(cap, granter, capSig);

        // §7a.1: the `value` field IS the outbound params entity data — pass it
        // through (the reference uses it directly). Re-wrapping as {"value": value}
        // double-wraps, so the echo's result.value returns a map (keystone §7b t1_2).
        Entity inner = Entity.Create(TypeNames.PrimitiveAny, value);
        var resource = new ResourceTarget(new[] { "system/handler/" + target }, null);

        ExecuteResponse downstream = await ctx.Outbound.ExecuteAsync(
            target, operation, inner, resource, authority, OutboundTimeout, ct).ConfigureAwait(false);

        // Return the downstream response so the validator sees the full round-trip.
        Entity result = Entity.Create(TypeNames.PrimitiveAny, Ecf.Map(
            ("status", Ecf.Uint((ulong)downstream.StatusCode)),
            ("result", new EcfValue.PreEncoded(downstream.Result.WireBytes))));
        return HandlerResult.Ok(result);
    }
}
