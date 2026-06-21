using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Transport;

/// <summary>
/// An authenticated session over an established connection: the capability the
/// remote peer issued at connect (§4.4) plus the entities needed to re-present its
/// authority chain on every request (§5.8 chain inclusion). Builds, signs, and
/// sends authenticated EXECUTEs and returns the correlated response.
/// </summary>
internal sealed class PeerSession
{
    private readonly PeerConnection _connection;
    private readonly PeerIdentity _local;
    private readonly CapabilityToken _capability;
    private readonly Entity _granterPeer;
    private readonly Entity _capabilitySignature;

    public PeerSession(
        PeerConnection connection,
        PeerIdentity local,
        string remotePeerId,
        CapabilityToken capability,
        Entity granterPeer,
        Entity capabilitySignature)
    {
        _connection = connection;
        _local = local;
        RemotePeerId = remotePeerId;
        _capability = capability;
        _granterPeer = granterPeer;
        _capabilitySignature = capabilitySignature;
    }

    /// <summary>The peer id of the remote endpoint this session authenticates against.</summary>
    public string RemotePeerId { get; }

    /// <summary>The capability this session wields (granted by the remote peer at connect).</summary>
    public CapabilityToken Capability => _capability;

    /// <summary>
    /// Build, sign, and send an authenticated EXECUTE; await the correlated
    /// EXECUTE_RESPONSE. The full authority chain travels in <c>included</c> (§5.8):
    /// the capability token, the granter and grantee identities, the capability
    /// signature, and the EXECUTE signature.
    /// </summary>
    public async Task<ExecuteResponse> ExecuteAsync(
        string uri, string operation, Entity paramsEntity, ResourceTarget? resource,
        TimeSpan timeout, CancellationToken ct = default)
    {
        Execute execute = Execute.Build(
            requestId: _connection.NextRequestId(),
            uri: uri,
            operation: operation,
            paramsEntity: paramsEntity,
            author: _local.IdentityHash,
            capability: _capability.ContentHash,
            resource: resource);

        Entity executeSignature = Signatures.Sign(execute.Entity, _local);

        var included = new List<Entity>
        {
            _capability.Entity,
            _granterPeer,         // capability granter (remote peer identity)
            _local.PeerEntity,    // grantee + author (this peer's identity)
            _capabilitySignature,
            executeSignature,
        };

        var request = new Envelope(execute.Entity, included);
        Envelope response = await _connection.SendRequestAsync(request, timeout, ct).ConfigureAwait(false);
        return new ExecuteResponse(response.Root);
    }

    /// <summary>Empty-params entity for operations that take no params (§3.2): <c>0xA0</c>.</summary>
    public static Entity EmptyParams() => Entity.Create(TypeNames.PrimitiveAny, Ecf.EmptyMap);
}
