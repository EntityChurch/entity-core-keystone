using EntityCore.Protocol.Handlers;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Transport;

namespace EntityCore.Protocol.Dispatch;

/// <summary>
/// The production <see cref="IOutboundDispatch"/> (V7 §6.13(b)): builds, signs, and sends
/// an outbound EXECUTE as the local peer and awaits the correlated EXECUTE_RESPONSE via the
/// §6.11 reentry seam (<see cref="IReentrantSender"/>) — typically the very connection the
/// handler is servicing (§4.8 inbound-concurrent-with-outbound). Mirrors
/// <see cref="PeerSession"/>'s send path, factored to reuse the reentrant sender so a
/// handler can originate without owning a session object.
/// </summary>
internal sealed class OutboundDispatch : IOutboundDispatch
{
    private readonly PeerIdentity _local;
    private readonly IReentrantSender _sender;

    public OutboundDispatch(PeerIdentity local, IReentrantSender sender)
    {
        _local = local;
        _sender = sender;
    }

    public async Task<ExecuteResponse> ExecuteAsync(
        string uri, string operation, Entity paramsEntity, ResourceTarget? resource,
        OutboundAuthority? authority, TimeSpan timeout, CancellationToken ct = default)
    {
        Execute execute = Execute.Build(
            requestId: _sender.NextRequestId(),
            uri: uri,
            operation: operation,
            paramsEntity: paramsEntity,
            author: _local.IdentityHash,
            // §1.4 PD-2 AMBIENT arm: no credential, so no `capability` field at all.
            capability: authority?.Capability.ContentHash,
            resource: resource);

        Entity executeSignature = Signatures.Sign(execute.Entity, _local);

        var included = new List<Entity>();
        if (authority is not null)
        {
            included.Add(authority.Capability.Entity);
            // Every granter and every signature: §5.5's chain walk resolves them BY HASH
            // out of this map.
            included.AddRange(authority.GranterPeers);
            included.AddRange(authority.CapabilitySignatures);
        }
        included.Add(_local.PeerEntity);   // grantee + author (this peer's identity)
        included.Add(executeSignature);

        Envelope response = await _sender.SendRequestAsync(
            new Envelope(execute.Entity, included), timeout, ct).ConfigureAwait(false);
        return new ExecuteResponse(response.Root);
    }
}
