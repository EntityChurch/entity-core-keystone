using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Transport;

/// <summary>
/// The §6.11 transport-reentry seam: send an EXECUTE envelope and await its correlated
/// EXECUTE_RESPONSE over a connection, concurrently with that connection's inbound
/// dispatch (§4.8). <see cref="PeerConnection"/> is the production implementation (its
/// reader task demuxes responses by <c>request_id</c>); tests supply a fake.
/// <para>
/// This is the seam a handler's outbound dispatch (v7.74 §6.13(b)) routes through: a
/// handler servicing an inbound EXECUTE can originate an outbound EXECUTE back over the
/// same connection and await the response, without the reader ever blocking on it.
/// </para>
/// </summary>
internal interface IReentrantSender
{
    /// <summary>A connection-scoped unique request id (§6.11 informative).</summary>
    string NextRequestId();

    /// <summary>Send an EXECUTE envelope and await its correlated EXECUTE_RESPONSE (§6.11).</summary>
    Task<Envelope> SendRequestAsync(Envelope request, TimeSpan timeout, CancellationToken ct);
}
