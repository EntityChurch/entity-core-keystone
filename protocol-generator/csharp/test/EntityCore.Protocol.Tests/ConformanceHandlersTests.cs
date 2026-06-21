using EntityCore.Protocol;
using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Transport;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// GUIDE-CONFORMANCE §7a — the <c>system/validate/*</c> conformance test-handlers, driven
/// black-box over the wire exactly as <c>validate-peer</c> would. These prove the two
/// extensibility hooks that have no other wire-reachable trigger in a core-only peer:
/// <c>echo</c> (the §6.13(a) resolve→dispatch half, closing A-011) and
/// <c>dispatch-outbound</c> (the §6.13(b)/§6.11 outbound seam via reentry, closing A-013).
/// Also pins the §7a.2 "off by default" install lifecycle.
/// </summary>
public sealed class ConformanceHandlersTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task Echo_ReturnsParamsValue_OverTheWire()
    {
        await using var peer = new Peer(seedPolicy: SeedPolicy.DebugOpen(), conformanceHandlers: true);
        await using var client = new Peer();
        peer.ListenAsync(0);

        PeerSession session = await client.ConnectAsync("127.0.0.1", peer.Port, Timeout);
        Entity prm = Entity.Create(TypeNames.PrimitiveAny, Ecf.Map(("value", Ecf.Text("ping-42"))));
        ExecuteResponse resp = await session.ExecuteAsync(
            "system/validate/echo", "echo", prm,
            new ResourceTarget(new[] { "system/handler/system/validate/echo" }, null), Timeout);

        Assert.Equal(Status.Ok, resp.StatusCode);
        Assert.Equal("ping-42", Ecf.AsText(Ecf.Require(resp.Result.Data, "value")));
    }

    [Fact]
    public async Task DispatchOutbound_OriginatesReentryExecuteBackToCaller()
    {
        // target = the peer under validation (listens, A-role originator). caller = the
        // validator (dials target; conformance mode so it can SERVE target's reentry echo).
        await using var target = new Peer(seedPolicy: SeedPolicy.DebugOpen(), conformanceHandlers: true);
        await using var caller = new Peer(seedPolicy: SeedPolicy.DebugOpen(), conformanceHandlers: true);
        target.ListenAsync(0);

        PeerSession session = await caller.ConnectAsync("127.0.0.1", target.Port, Timeout);

        // The reentry direction (target → caller) can only be authorized by the caller, so
        // the caller mints a cap granting the TARGET authority to execute back at the caller,
        // and carries it (+ granter identity + signature) in-band in the dispatch params.
        (CapabilityToken cap, Entity capSig) = CapabilityToken.CreateRoot(
            caller.LocalIdentity, target.LocalIdentity.IdentityHash, SeedPolicy.OpenGrants(), 1000);

        Entity prm = Entity.Create(TypeNames.PrimitiveAny, Ecf.Map(
            ("target", Ecf.Text("system/validate/echo")),
            ("operation", Ecf.Text("echo")),
            ("value", Ecf.Text("round-trip-99")),
            ("reentry_capability", new EcfValue.PreEncoded(cap.Entity.WireBytes)),
            ("reentry_granter", new EcfValue.PreEncoded(caller.LocalIdentity.PeerEntity.WireBytes)),
            ("reentry_cap_signature", new EcfValue.PreEncoded(capSig.WireBytes))));

        ExecuteResponse resp = await session.ExecuteAsync(
            "system/validate/dispatch-outbound", "dispatch", prm,
            new ResourceTarget(new[] { "system/handler/system/validate/dispatch-outbound" }, null), Timeout);

        Assert.Equal(Status.Ok, resp.StatusCode);
        // The handler originated an outbound EXECUTE and returned the downstream response.
        Assert.Equal(200ul, Ecf.AsUint(Ecf.Require(resp.Result.Data, "status")));
        Entity downstream = Entity.FromDecoded(Ecf.Require(resp.Result.Data, "result"));
        Assert.Equal("round-trip-99", Ecf.AsText(Ecf.Require(downstream.Data, "value")));
    }

    [Fact]
    public async Task ConformanceHandlers_AreOffByDefault()
    {
        // §7a.2: a default (production) peer must NOT carry the conformance handlers —
        // dispatch-outbound is a standing outbound originator. EXECUTE must miss (404).
        await using var peer = new Peer(seedPolicy: SeedPolicy.DebugOpen()); // no conformanceHandlers
        await using var client = new Peer();
        peer.ListenAsync(0);

        PeerSession session = await client.ConnectAsync("127.0.0.1", peer.Port, Timeout);
        ExecuteResponse resp = await session.ExecuteAsync(
            "system/validate/echo", "echo",
            Entity.Create(TypeNames.PrimitiveAny, Ecf.Map(("value", Ecf.Text("x")))),
            new ResourceTarget(new[] { "system/handler/system/validate/echo" }, null), Timeout);

        Assert.Equal(Status.NotFound, resp.StatusCode);
    }
}
