using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Dispatch;
using EntityCore.Protocol.Handlers;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Store;
using EntityCore.Protocol.Transport;
using EntityCore.Protocol.Types;

namespace EntityCore.Protocol;

/// <summary>
/// An Entity Core protocol peer (V7 Layers 0–4): identity, the codec, the entity
/// tree + content store, the bootstrap system handlers, the dispatch chain, and TCP
/// transport. Listens for inbound connections and dials outbound ones; both
/// directions complete the §4.1 handshake. No standard extensions are bundled —
/// community handlers register above the dispatcher boundary.
/// </summary>
internal sealed class Peer : IPeerServices, IAsyncDisposable
{
    private readonly PeerIdentity _identity;
    private readonly Emit.EmitBus _emit;
    private readonly EntityTree _tree;
    private readonly ContentStore _store;
    private readonly HandlerRegistry _registry;
    private readonly Dispatcher _dispatcher;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly ConcurrentBag<PeerConnection> _connections = new();
    private TcpListener? _listener;
    private Task _acceptLoop = Task.CompletedTask;
    private readonly SeedPolicy _seedPolicy;

    /// <param name="identity">Peer identity; a fresh keypair is generated when null.</param>
    /// <param name="seedPolicy">
    /// The §6.9a identity → capability seed policy materialized at L0 and consulted at
    /// §4.6 authenticate (the <c>with_seed_policy</c> builder affordance). Defaults to
    /// the conformant <see cref="SeedPolicy.Standard"/> (default → §4.4 discovery floor),
    /// or — when <paramref name="debugOpenGrants"/> is set — the degenerate
    /// <see cref="SeedPolicy.DebugOpen"/> (default → <c>*</c>).
    /// </param>
    /// <param name="debugOpenGrants">
    /// Debug-only: select the degenerate <c>default → *</c> seed policy (the retired
    /// <c>--debug-open-grants</c> behaviour, now routed through the real §6.9a mechanism
    /// rather than a hardcoded fork). Deprecated in v7.74, removed in v7.75. Ignored when
    /// an explicit <paramref name="seedPolicy"/> is supplied. The conformant default is false.
    /// </param>
    /// <param name="conformanceHandlers">
    /// Conformance-build opt-in (GUIDE-CONFORMANCE §7a): register the <c>system/validate/*</c>
    /// test-handlers (<c>echo</c> + <c>dispatch-outbound</c>) so a black-box validator can
    /// drive the §6.13(a)/(b) extensibility hooks. These are conformance scaffolding, <b>not
    /// core protocol</b>, and <b>off by default</b> — <c>dispatch-outbound</c> is an outbound
    /// originator that must never be live in a production install. Surfaced as the host
    /// <c>--validate</c> switch. The conformant production default is false.
    /// </param>
    public Peer(PeerIdentity? identity = null, SeedPolicy? seedPolicy = null, bool debugOpenGrants = false,
        bool conformanceHandlers = false)
    {
        _identity = identity ?? PeerIdentity.Generate();
        _seedPolicy = seedPolicy ?? (debugOpenGrants ? SeedPolicy.DebugOpen() : SeedPolicy.Standard());
        _emit = new Emit.EmitBus();
        _store = new ContentStore(_emit);
        _tree = new EntityTree(_store, _emit);
        _registry = new HandlerRegistry(this);
        _dispatcher = new Dispatcher(this, _registry);
        Bootstrap();
        if (conformanceHandlers)
        {
            RegisterConformanceHandlers();
        }
    }

    /// <summary>
    /// GUIDE-CONFORMANCE §7a: register the two <c>system/validate/*</c> conformance
    /// test-handlers as native handlers (same install path as any native handler — the
    /// five normative writes). Called only on the conformance opt-in; never in a default /
    /// production peer (the §7a.2 "not in base install" requirement).
    /// </summary>
    private void RegisterConformanceHandlers()
    {
        _registry.Register(new EchoHandler());
        _registry.Register(new DispatchOutboundHandler());
    }

    // ----- IPeerServices --------------------------------------------------

    public string LocalPeerId => _identity.PeerId;

    public PeerIdentity LocalIdentity => _identity;

    public EntityTree Tree => _tree;

    public ContentStore ContentStore => _store;

    public Emit.EmitBus Emit => _emit;

    public ulong NowMs => (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>The port the listener is bound to (valid after <see cref="ListenAsync"/>).</summary>
    public int Port { get; private set; }

    // ----- lifecycle ------------------------------------------------------

    private void Bootstrap()
    {
        // Bootstrap handlers (§6.9): tree + connect + handlers + capability are MUST.
        // The handlers handler (§6.2 / §6.13(a)) executes register/unregister behaviorally
        // — a 501 stub is non-conformant. (Types handler SHOULD remains A-007.)
        _registry.Register(new ConnectHandler());
        _registry.Register(new TreeHandler());
        _registry.Register(new HandlersHandler());
        _registry.Register(new CapabilityHandler());

        // Local peer entity at system/peer/self (§3.13), tree-walkable.
        _tree.Put("/" + LocalPeerId + "/system/peer/self", _identity.PeerEntity);

        // Core type registry → system/type/* (TYPE-SYSTEM §8–§10). Core + operational
        // + type-system bootstrap only (53 types; refined G4 / F17). Rendered natively
        // and proven byte-identical to the oracle's registry (CoreTypeRegistryTests).
        CoreTypeRegistry.Seed(_tree, LocalPeerId);

        // §6.9a Peer Authority Bootstrap: materialize the seed capability entities into
        // the tree at L0 (pre-capability) — the self-owner cap plus the seed-policy
        // entries the §4.6 authenticate lookup reads back.
        SeedAuthorityBootstrap();
    }

    /// <summary>
    /// §6.9a Bootstrap L0 write-set (item 4): materialize the seed capability entities.
    /// <list type="number">
    /// <item>The <c>self</c>-owner capability — a root cap, full scope over the local
    ///   namespace <c>/{peer_id}/*</c>, grantee = the peer's own identity, in the
    ///   §6.9a.0 detached-signature shape (keystone S8-uniform): the cap token at the
    ///   hex policy path, its self-signature at the §3.5 invariant pointer.</item>
    /// <item>The <c>default</c> seed entry — the fallback scope template for any other
    ///   authenticated identity, stored as a <c>policy-entry</c> at the sentinel path.</item>
    /// <item>Any explicitly-named operator / admin / reader entries (§6.9a.1).</item>
    /// </list>
    /// Read back by <see cref="Handlers.ConnectHandler"/> at §4.6 authenticate via the
    /// v7.64 dual-form lookup (hex → Base58 → <c>default</c>).
    /// </summary>
    private void SeedAuthorityBootstrap()
    {
        string policyBase = "/" + LocalPeerId + "/system/capability/policy/";

        // (1) self-owner capability (§6.9a.0 shape 1 — detached-signature).
        (CapabilityToken ownerCap, Entity ownerSig) = CapabilityToken.CreateRoot(
            _identity, _identity.IdentityHash, SeedPolicy.OwnerGrants(LocalPeerId), NowMs);
        _tree.Put(policyBase + Hashes.Hex(_identity.IdentityHash), ownerCap.Entity);
        _tree.Put("/" + LocalPeerId + "/system/signature/" + ownerCap.ContentHashHex, ownerSig);

        // (2) default seed entry — the fallback scope for any other authenticated identity.
        _tree.Put(policyBase + "default", PolicyEntryEntity("default", _seedPolicy.DefaultGrants));

        // (3) explicitly-named operator/admin/reader entries.
        foreach (SeedPolicyEntry entry in _seedPolicy.NamedEntries)
        {
            _tree.Put(policyBase + entry.Key, PolicyEntryEntity(entry.Key, entry.Grants));
        }
    }

    /// <summary>Build a <c>system/capability/policy-entry</c> carrying a scope template (§6.9a.0 shape 2 / v7.62 §4).</summary>
    private static Entity PolicyEntryEntity(string peerPattern, IReadOnlyList<GrantEntry> grants) =>
        Entity.Create(TypeNames.CapabilityPolicyEntry, Ecf.Map(
            ("peer_pattern", Ecf.Text(peerPattern)),
            ("grants", Ecf.Array(grants.Select(g => g.ToEcf())))));

    /// <summary>
    /// Install a native (in-process) handler post-bootstrap — the seam an SDK / native
    /// extension uses to add a handler with a compiled body (complementing the wire
    /// <c>register</c> of §6.13(a), which installs entity-native bodies). Writes the same
    /// manifest / interface / grant / grant-signature entities as a bootstrap handler.
    /// </summary>
    public void RegisterHandler(IHandler handler) => _registry.Register(handler);

    /// <summary>Begin listening on loopback at <paramref name="port"/> (0 = auto-assign).</summary>
    public void ListenAsync(int port)
    {
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_shutdown.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client = await _listener!.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                client.NoDelay = true;
                var state = new ConnectionState();
                var conn = new PeerConnection(client.GetStream(), _dispatcher, state);
                _connections.Add(conn);
                conn.Start();

                // Reverse-direction handshake (§4.1 E3): the responder sends its own
                // authenticate once it has the initiator's hello. Fire-and-forget —
                // it completes the mutual handshake; its session is not needed here.
                _ = RespondInBackgroundAsync(conn, state, ct);
            }
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            // Clean shutdown.
        }
        catch (ObjectDisposedException)
        {
            // Listener stopped.
        }
    }

    private async Task RespondInBackgroundAsync(PeerConnection conn, ConnectionState state, CancellationToken ct)
    {
        try
        {
            await Handshake.RespondAsync(conn, _identity, state, TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The reverse handshake is best-effort; failures don't affect the
            // initiator's already-established session.
        }
    }

    /// <summary>Dial a peer at <paramref name="host"/>:<paramref name="port"/> and complete the handshake.</summary>
    public async Task<PeerSession> ConnectAsync(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(host, port, ct).ConfigureAwait(false);
        var state = new ConnectionState();
        var conn = new PeerConnection(client.GetStream(), _dispatcher, state);
        _connections.Add(conn);
        conn.Start();
        return await Handshake.InitiateAsync(conn, _identity, state, timeout, ct).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await _shutdown.CancelAsync().ConfigureAwait(false);
        _listener?.Stop();
        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch
        {
            // Accept-loop teardown errors are expected during shutdown.
        }
        foreach (PeerConnection conn in _connections)
        {
            await conn.DisposeAsync().ConfigureAwait(false);
        }
        _shutdown.Dispose();
    }
}
