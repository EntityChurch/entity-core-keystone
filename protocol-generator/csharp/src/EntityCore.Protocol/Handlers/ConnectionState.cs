using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Handlers;

/// <summary>The remote peer's hello data (id + nonce) learned from an inbound hello (§3.8).</summary>
internal sealed record RemoteHelloInfo(string PeerId, byte[] Nonce);

/// <summary>
/// Per-connection handshake state (V7 §4). The connection handler enforces
/// ordering against this — <c>hello</c> before <c>authenticate</c> (§4.2) — and
/// rejects further connection requests once <see cref="Established"/> (status 409).
/// Connection state is per-connection; a new connection needs a fresh handshake.
/// </summary>
internal sealed class ConnectionState
{
    private readonly object _lock = new();
    private bool _helloReceived;
    private bool _established;

    /// <summary>True once a valid <c>hello</c> has been processed on this connection.</summary>
    public bool HelloReceived
    {
        get { lock (_lock) { return _helloReceived; } }
        set { lock (_lock) { _helloReceived = value; } }
    }

    /// <summary>True once authentication completed and the initial capability was issued.</summary>
    public bool Established
    {
        get { lock (_lock) { return _established; } }
        set { lock (_lock) { _established = value; } }
    }

    /// <summary>The remote peer's id, learned from its <c>hello</c> / <c>authenticate</c>.</summary>
    public string? RemotePeerId { get; set; }

    /// <summary>The remote peer's <c>system/peer</c> entity, learned at authenticate.</summary>
    public Entity? RemotePeerEntity { get; set; }

    /// <summary>
    /// The nonce this peer put in its own <c>hello</c> on this connection (the
    /// challenge). The remote's <c>authenticate</c> MUST echo it back; verifying the
    /// echo binds the proof-of-possession to <em>this</em> connection's challenge
    /// (§3.8, §4.6 PoP step 1) and defeats cross-connection signature replay (F12).
    /// </summary>
    public byte[]? SentNonce { get; set; }

    /// <summary>
    /// Completed by the connect handler when an inbound <c>hello</c> is processed
    /// (responder role). The reverse-direction handshake driver awaits this to learn
    /// the remote's nonce before sending its own <c>authenticate</c> (§4.1 E3).
    /// </summary>
    public TaskCompletionSource<RemoteHelloInfo> InboundHello { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Completed after this peer (responder role) has written the EXECUTE_RESPONSE
    /// to the initiator's <c>authenticate</c> (§4.1 leg 2). The reverse-direction
    /// handshake driver awaits this before sending its own <c>authenticate</c>
    /// EXECUTE (leg 3), so leg 3 never races ahead of leg 2's response on the wire —
    /// the §4.1 ordering a sequential initiator (e.g. validate-peer) depends on.
    /// </summary>
    public TaskCompletionSource AuthResponseSent { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
}
