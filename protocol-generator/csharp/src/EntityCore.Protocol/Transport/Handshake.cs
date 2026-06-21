using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Handlers;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Transport;

/// <summary>
/// Drives connection establishment (V7 §4.1). The initiator sends <c>hello</c> then
/// <c>authenticate</c>; the responder, having returned its hello data in the hello
/// response, sends its own <c>authenticate</c> in the reverse direction. Each
/// authenticate response carries that side's initial capability (§4.4). Total: 3
/// EXECUTE + 3 EXECUTE_RESPONSE.
/// </summary>
internal static class Handshake
{
    /// <summary>Initiator side: <c>hello</c> → <c>authenticate</c>, returning this peer's session on the remote.</summary>
    public static async Task<PeerSession> InitiateAsync(
        PeerConnection conn, PeerIdentity local, ConnectionState state, TimeSpan timeout, CancellationToken ct)
    {
        // We have sent hello, so an inbound reverse-authenticate is in order (§4.2).
        state.HelloReceived = true;

        Entity helloEntity = ConnectHandler.BuildHello(local, NowMs());
        // Retain our challenge nonce so the responder's reverse authenticate (leg 3)
        // can be verified to echo it (§4.6 PoP step 1, symmetric).
        state.SentNonce = Ecf.RequireBytes(helloEntity.Data, "nonce");
        Envelope r1 = await SendConnectAsync(conn, "hello", helloEntity, System.Array.Empty<Entity>(), timeout, ct)
            .ConfigureAwait(false);
        ExecuteResponse resp1 = RequireOk(r1, "hello");

        Entity remoteHello = resp1.Result;
        string remotePeerId = Ecf.RequireText(remoteHello.Data, "peer_id");
        byte[] remoteNonce = Ecf.RequireBytes(remoteHello.Data, "nonce");
        state.RemotePeerId = remotePeerId;

        return await AuthenticateAsync(conn, local, remoteNonce, remotePeerId, timeout, ct).ConfigureAwait(false);
    }

    /// <summary>Responder side: await the inbound hello, then send the reverse <c>authenticate</c> (§4.1 E3).</summary>
    public static async Task<PeerSession> RespondAsync(
        PeerConnection conn, PeerIdentity local, ConnectionState state, TimeSpan timeout, CancellationToken ct)
    {
        RemoteHelloInfo info = await state.InboundHello.Task.WaitAsync(timeout, ct).ConfigureAwait(false);
        // §4.1 leg-3 ordering: hold the reverse authenticate until the leg-2 response
        // (to the initiator's authenticate) has been written. A sequential initiator
        // reads exactly one frame for its authenticate response; sending leg 3 before
        // that frame makes it read our EXECUTE where it expects its EXECUTE_RESPONSE.
        await state.AuthResponseSent.Task.WaitAsync(timeout, ct).ConfigureAwait(false);
        return await AuthenticateAsync(conn, local, info.Nonce, info.PeerId, timeout, ct).ConfigureAwait(false);
    }

    private static async Task<PeerSession> AuthenticateAsync(
        PeerConnection conn, PeerIdentity local, byte[] remoteNonce, string remotePeerId,
        TimeSpan timeout, CancellationToken ct)
    {
        Entity authEntity = Entity.Create(TypeNames.Authenticate, Ecf.Map(
            ("peer_id", Ecf.Text(local.PeerId)),
            ("public_key", Ecf.Bytes(local.PublicKey)),
            ("key_type", Ecf.Text(local.KeyTypeName)),
            ("nonce", Ecf.Bytes(remoteNonce))));
        Entity authSignature = Signatures.Sign(authEntity, local);

        Envelope response = await SendConnectAsync(
            conn, "authenticate", authEntity, new[] { local.PeerEntity, authSignature }, timeout, ct)
            .ConfigureAwait(false);
        ExecuteResponse resp = RequireOk(response, "authenticate");

        // Parse the initial capability grant (§4.4): token + granter + signature in included.
        Entity grant = resp.Result;
        byte[] tokenHash = Ecf.RequireBytes(grant.Data, "token");
        Entity tokenEntity = response.Find(tokenHash)
            ?? throw new EntityProtocolException("authenticate grant omits the capability token");
        var capability = new CapabilityToken(tokenEntity);
        Entity granterPeer = response.Find(capability.Granter)
            ?? throw new EntityProtocolException("authenticate grant omits the granter identity");
        Entity capSignature = ChainVerifier.FindSignature(response, capability.ContentHash)
            ?? throw new EntityProtocolException("authenticate grant omits the capability signature");

        return new PeerSession(conn, local, remotePeerId, capability, granterPeer, capSignature);
    }

    private static Task<Envelope> SendConnectAsync(
        PeerConnection conn, string operation, Entity paramsEntity, IReadOnlyList<Entity> included,
        TimeSpan timeout, CancellationToken ct)
    {
        // Connect-path EXECUTEs carry no author/capability (§4.2 pre-authorization).
        Execute execute = Execute.Build(conn.NextRequestId(), Protocols.ConnectPath, operation, paramsEntity);
        return conn.SendRequestAsync(new Envelope(execute.Entity, included), timeout, ct);
    }

    private static ExecuteResponse RequireOk(Envelope response, string step)
    {
        var resp = new ExecuteResponse(response.Root);
        if (resp.StatusCode != Status.Ok)
        {
            string code = Ecf.OptText(resp.Result.Data, "code") ?? "unknown";
            string message = Ecf.OptText(resp.Result.Data, "message") ?? "";
            throw new HelloFailedException(code, $"{step} failed: {resp.StatusCode} {code} {message}", resp.StatusCode);
        }
        return resp;
    }

    private static ulong NowMs() => (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}
