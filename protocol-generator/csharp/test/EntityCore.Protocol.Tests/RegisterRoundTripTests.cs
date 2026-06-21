using EntityCore.Protocol;
using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Transport;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// F1 (v7.74 §6.13(a) / §6.2) — the handlers-handler register/unregister round-trip,
/// mirroring the entity-core-go <c>core_register_gate.go</c> §10.1 contract end-to-end
/// over real loopback: bind a body, register (5 writes), dispatch the entity-native
/// body, unregister (writer symmetry). Proves register is behavioral, not a 501 stub,
/// before the Go gate lands in our oracle.
/// </summary>
public sealed class RegisterRoundTripTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    private const string Pattern = "app/validate/core-register/echo";
    private const string ExprPath = Pattern + "/expr";
    private const string InstallTarget = "system/handler/" + Pattern;

    [Fact]
    public async Task Register_FiveWrites_Dispatch_Unregister()
    {
        // The responder runs the degenerate default→* seed policy so the initiator's
        // authenticate grant covers register + tree:put (the §10.1 gate's debug surface).
        await using var responder = new Peer(seedPolicy: SeedPolicy.DebugOpen());
        await using var initiator = new Peer();
        responder.ListenAsync(0);
        PeerSession session = await initiator.ConnectAsync("127.0.0.1", responder.Port, Timeout);

        // Step 1 — body-binding seam: put a compute/literal(42) at the expression path.
        Entity literal = Entity.Create(TypeNames.ComputeLiteral, Ecf.Map(("value", Ecf.Uint(42))));
        ExecuteResponse put = await TreePut(session, ExprPath, literal);
        Assert.Equal(Status.Ok, put.StatusCode);

        // Step 2 — wire register.
        ExecuteResponse reg = await session.ExecuteAsync(
            uri: "system/handler", operation: "register",
            paramsEntity: BuildRegisterRequest(),
            resource: new ResourceTarget(new[] { InstallTarget }, null), timeout: Timeout);
        Assert.Equal(Status.Ok, reg.StatusCode);
        Assert.Equal(TypeNames.HandlerRegisterResult, reg.Result.Type);
        Assert.Equal(Pattern, Ecf.RequireText(reg.Result.Data, "pattern"));

        // Step 3 — the five normative writes landed in the tree.
        Assert.Equal(TypeNames.HandlerInterface, (await TreeGet(session, InstallTarget)).Result.Type);   // 5. interface
        Assert.Equal(TypeNames.Handler, (await TreeGet(session, Pattern)).Result.Type);                  // 1. manifest
        ExecuteResponse grantGet = await TreeGet(session, "system/capability/grants/" + Pattern);        // 3. grant
        Assert.Equal(TypeNames.CapabilityToken, grantGet.Result.Type);
        string grantHashHex = grantGet.Result.ContentHashHex;
        ExecuteResponse sigGet = await TreeGet(session, "system/signature/" + grantHashHex);             // 4. grant-sig
        Assert.Equal(TypeNames.Signature, sigGet.Result.Type);

        // Step 4 — dispatch round-trip: the entity-native body returns the literal 42.
        ExecuteResponse dispatch = await session.ExecuteAsync(
            uri: Pattern, operation: "compute",
            paramsEntity: PeerSession.EmptyParams(), resource: null, timeout: Timeout);
        Assert.Equal(Status.Ok, dispatch.StatusCode);
        Assert.Equal(TypeNames.ComputeResult, dispatch.Result.Type);
        Assert.Equal(42UL, Ecf.RequireUint(dispatch.Result.Data, "value"));

        // Step 5 — unregister, and the grant-signature is removed too (writer symmetry).
        ExecuteResponse unreg = await session.ExecuteAsync(
            uri: "system/handler", operation: "unregister",
            paramsEntity: PeerSession.EmptyParams(),
            resource: new ResourceTarget(new[] { InstallTarget }, null), timeout: Timeout);
        Assert.Equal(Status.Ok, unreg.StatusCode);
        Assert.Equal(Status.NotFound, (await TreeGet(session, "system/signature/" + grantHashHex)).StatusCode);
        Assert.Equal(Status.NotFound, (await TreeGet(session, Pattern)).StatusCode);
    }

    private static Entity BuildRegisterRequest()
    {
        var wildcard = new GrantEntry(
            Handlers: new Scope(new[] { "*" }, null),
            Resources: new Scope(new[] { "*", "/*/*" }, null),
            Operations: new Scope(new[] { "*" }, null),
            Peers: null, Constraints: null, Allowances: null);

        EcfValue manifest = Ecf.Map(
            ("pattern", Ecf.Text(Pattern)),
            ("name", Ecf.Text("echo")),
            ("operations", Ecf.Map(("compute", Ecf.Map(
                ("input_type", Ecf.Text("primitive/any")),
                ("output_type", Ecf.Text("primitive/any")))))),
            ("expression_path", Ecf.Text(ExprPath)),
            ("internal_scope", Ecf.Array(wildcard.ToEcf())));

        return Entity.Create(TypeNames.HandlerRegisterRequest, Ecf.Map(
            ("manifest", manifest),
            ("requested_scope", Ecf.Array(wildcard.ToEcf()))));
    }

    private static Task<ExecuteResponse> TreePut(PeerSession session, string path, Entity entity)
    {
        Entity putReq = Entity.Create("system/tree/put-request", Ecf.Map(
            ("entity", new EcfValue.PreEncoded(entity.WireBytes))));
        return session.ExecuteAsync("system/tree", "put", putReq,
            new ResourceTarget(new[] { path }, null), Timeout);
    }

    private static Task<ExecuteResponse> TreeGet(PeerSession session, string path) =>
        session.ExecuteAsync("system/tree", "get",
            Entity.Create("system/tree/get-request", Ecf.EmptyMap),
            new ResourceTarget(new[] { path }, null), Timeout);
}
