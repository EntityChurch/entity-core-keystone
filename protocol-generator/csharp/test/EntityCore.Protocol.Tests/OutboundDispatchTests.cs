using EntityCore.Protocol;
using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Dispatch;
using EntityCore.Protocol.Handlers;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Transport;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// F2 (v7.74 §6.13(b)) — the handler-facing outbound-dispatch seam. Proves the closure
/// builds a correctly-signed authenticated EXECUTE routed through the §6.11 reentry sender,
/// and that a handler invoked over a real connection receives a live <c>ctx.Outbound</c>.
/// </summary>
public sealed class OutboundDispatchTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private sealed class FakeSender : IReentrantSender
    {
        private int _counter;
        public Envelope? Sent { get; private set; }

        public string NextRequestId() => "out-" + System.Threading.Interlocked.Increment(ref _counter);

        public Task<Envelope> SendRequestAsync(Envelope request, TimeSpan timeout, CancellationToken ct)
        {
            Sent = request;
            string requestId = new Execute(request.Root).RequestId;
            ExecuteResponse resp = ExecuteResponse.Build(requestId, Status.Ok, PeerSession.EmptyParams());
            return Task.FromResult(new Envelope(resp.Entity, System.Array.Empty<Entity>()));
        }
    }

    [Fact]
    public async Task OutboundDispatch_BuildsSignedReentrantExecute()
    {
        PeerIdentity local = PeerIdentity.Generate();
        PeerIdentity target = PeerIdentity.Generate(); // the cap granter (the peer being called)
        (CapabilityToken cap, Entity capSig) = CapabilityToken.CreateRoot(
            target, local.IdentityHash, SeedPolicy.OpenGrants(), 1000);
        var authority = new OutboundAuthority(cap, target.PeerEntity, capSig);

        var sender = new FakeSender();
        var outbound = new OutboundDispatch(local, sender);
        ExecuteResponse resp = await outbound.ExecuteAsync(
            "system/tree", "get", PeerSession.EmptyParams(),
            new ResourceTarget(new[] { "system/handler/system/tree" }, null), authority, Timeout);

        Assert.Equal(Status.Ok, resp.StatusCode);
        Assert.NotNull(sender.Sent);

        // The outbound EXECUTE is authored + signed by the local peer, carries the supplied
        // capability, and bundles the full authority chain in included (§5.8).
        var sentExecute = new Execute(sender.Sent!.Root);
        Assert.Equal("get", sentExecute.Operation);
        Assert.Equal(local.IdentityHash, sentExecute.Author);
        Assert.Equal(cap.ContentHash, sentExecute.Capability);

        Entity? sig = ChainVerifier.FindSignature(sender.Sent!, sentExecute.Entity.ContentHash);
        Assert.NotNull(sig);
        Assert.True(Signatures.Verify(sig!, local.PeerEntity));
        Assert.NotNull(sender.Sent!.Find(cap.ContentHash));        // capability token
        Assert.NotNull(sender.Sent!.Find(target.IdentityHash));    // granter identity
    }

    /// <summary>A native handler that reports whether the §6.13(b) outbound seam reached it.</summary>
    private sealed class OutboundProbeHandler : IHandler
    {
        public string Pattern => "app/probe/outbound";
        public string Name => "outbound-probe";
        public IReadOnlyList<string> Operations { get; } = new[] { "check" };

        public Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct) =>
            Task.FromResult(HandlerResult.Ok(Entity.Create(TypeNames.PrimitiveAny,
                Ecf.Map(("has_outbound", Ecf.Bool(ctx.Outbound is not null))))));
    }

    [Fact]
    public async Task Handler_ReceivesOutboundSeam_OverConnection()
    {
        await using var responder = new Peer(seedPolicy: SeedPolicy.DebugOpen());
        responder.RegisterHandler(new OutboundProbeHandler());
        await using var initiator = new Peer();
        responder.ListenAsync(0);

        PeerSession session = await initiator.ConnectAsync("127.0.0.1", responder.Port, Timeout);
        ExecuteResponse resp = await session.ExecuteAsync(
            "app/probe/outbound", "check", PeerSession.EmptyParams(), null, Timeout);

        Assert.Equal(Status.Ok, resp.StatusCode);
        Assert.True(Ecf.AsBool(Ecf.Require(resp.Result.Data, "has_outbound")),
            "handler dispatched over a connection MUST receive a live ctx.Outbound (§6.13(b))");
    }
}
