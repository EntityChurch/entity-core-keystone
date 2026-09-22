using System.Collections.Concurrent;
using System.Formats.Cbor;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Dispatch;
using EntityCore.Protocol.Handlers;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Transport;

/// <summary>
/// A single peer-to-peer connection over a stream. Implements the §6.11 transport
/// reentry contract: one reader task demultiplexes inbound frames, routing
/// EXECUTE_RESPONSEs to awaiting callers by <c>request_id</c> (N7) and dispatching
/// inbound EXECUTEs <em>concurrently</em> with outbound sends (N6) — inbound
/// processing never blocks on outbound dispatch. Per-request deadlines are enforced
/// at the request layer, not via a connection-wide deadline (§6.11(c)).
/// </summary>
internal sealed class PeerConnection : IReentrantSender, IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly Dispatcher _dispatcher;
    private readonly ConnectionState _state;
    private readonly int _maxFrameBytes;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<Envelope>> _pending = new();
    private int _requestCounter;
    private Task _readerTask = Task.CompletedTask;

    public PeerConnection(Stream stream, Dispatcher dispatcher, ConnectionState state,
        int maxFrameBytes = FrameCodec.DefaultMaxFrameBytes)
    {
        _stream = stream;
        _dispatcher = dispatcher;
        _state = state;
        _maxFrameBytes = maxFrameBytes;
    }

    public ConnectionState State => _state;

    /// <summary>Generate a connection-scoped unique request id (§6.11 informative).</summary>
    public string NextRequestId() => "req-" + Interlocked.Increment(ref _requestCounter);

    /// <summary>Begin the reader loop. Returns immediately; reading proceeds in the background.</summary>
    public void Start() => _readerTask = Task.Run(() => ReadLoopAsync(_cts.Token));

    /// <summary>
    /// Send an EXECUTE envelope and await its correlated EXECUTE_RESPONSE (§6.11).
    /// Throws <see cref="RecvTimeoutException"/> on deadline, or
    /// <see cref="ConnectionBrokenException"/> if the connection drops first.
    /// </summary>
    public async Task<Envelope> SendRequestAsync(Envelope request, TimeSpan timeout, CancellationToken ct)
    {
        string requestId = new Execute(request.Root).RequestId;
        var tcs = new TaskCompletionSource<Envelope>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(requestId, tcs))
        {
            throw new EntityProtocolException($"duplicate in-flight request_id '{requestId}'");
        }

        try
        {
            await WriteAsync(request, ct).ConfigureAwait(false);

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _cts.Token);
            deadline.CancelAfter(timeout);
            try
            {
                return await tcs.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested && !_cts.IsCancellationRequested)
            {
                throw new RecvTimeoutException($"no response for request '{requestId}' within {timeout}");
            }
        }
        finally
        {
            _pending.TryRemove(requestId, out _);
        }
    }

    private async Task WriteAsync(Envelope envelope, CancellationToken ct)
    {
        byte[] bytes = envelope.Encode();
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await FrameCodec.WriteFrameAsync(_stream, bytes, ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                byte[]? frame;
                try
                {
                    frame = await FrameCodec.ReadFrameAsync(_stream, _maxFrameBytes, ct).ConfigureAwait(false);
                }
                catch (Exception) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception e) when (FrameCodec.FramingRefusal(e))
                {
                    // The stream is desynchronized on both REFUSABLE arms — an oversize
                    // body was never drained, a truncated one never arrived — so the coded
                    // frame goes out and THEN the connection closes. §4.11 makes the frame
                    // mandatory and leaves the close to us; closing is the only sound
                    // choice once the framing is lost, and it is a CHOICE rather than an
                    // alternative to answering. An ordinary hangup is not a refusal and
                    // gets nothing, which is what `FramingRefusal` separates.
                    //
                    // §4.11's best-effort UNCORRELATED form: no request_id can be recovered
                    // from a frame whose body never arrived, and guessing one would
                    // correlate the refusal to somebody else's in-flight request.
                    await RefusePreAdmissionAsync(string.Empty, FrameCodec.PreAdmissionRefusal(e), ct)
                        .ConfigureAwait(false);
                    break;
                }

                if (frame is null)
                {
                    break; // clean EOF
                }

                Envelope envelope;
                try
                {
                    envelope = Envelope.Decode(frame);
                }
                catch (EntityCoreException e)
                {
                    // A COMPLETE frame the decoder refused. The framing is intact, so we
                    // answer and KEEP SERVING — and the refusal MUST be a status rather
                    // than silence (§4.11; §4.9(c) says the same from the other direction).
                    // This used to `break`, which left the read loop AND left the socket
                    // open: the oracle's every later request then went to a socket nobody
                    // was reading, so each one waited out its own timeout instead of
                    // failing fast. That is where this peer's 18-minute run and its nine
                    // starved categories came from.
                    //
                    // THE CODE IS THE CAUSE'S (§4.11, §5.2a). This answered
                    // `non_canonical_ecf` for every cause until 0.8.2.24/.25 pinned them
                    // apart: a mis-keyed `included` entry is `400 hash_mismatch` (its
                    // encoding is canonical — what is false is the claim the key makes), a
                    // tag-policy violation keeps `non_canonical_ecf`, and everything else
                    // that never becomes an Envelope is `400 invalid_request`.
                    await RefusePreAdmissionAsync(
                        SalvageRequestId(frame), FrameCodec.PreAdmissionRefusal(e), ct).ConfigureAwait(false);
                    continue;
                }

                string rootType = envelope.Root.Type;
                if (rootType == TypeNames.ExecuteResponse)
                {
                    RouteResponse(envelope);
                }
                else if (rootType == TypeNames.Execute)
                {
                    // N6: dispatch concurrently — do NOT block the reader on the handler.
                    _ = Task.Run(() => DispatchInboundAsync(envelope, ct), ct);
                }
                else
                {
                    // §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
                    // invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a
                    // bare close — that is indistinguishable from a network fault."
                    //
                    // §3.3 read "the connection MUST be closed", assigning no code and
                    // requiring no frame, and this loop did exactly that: a bare `break`.
                    // This is a PRE-ADMISSION refusal — the root is not an EXECUTE, so
                    // nothing was ever admitted and §4.9(c) does not reach it. §9.1's floor
                    // row that MANDATED the bare close was REPLACED at the same revision
                    // (N18).
                    //
                    // The request_id is read best-effort: an arbitrary root type is under
                    // no obligation to carry one, and §4.11 licenses the uncorrelated frame
                    // exactly there. We do NOT close — on a multiplexed connection that
                    // would cost every ADMITTED in-flight request its response, and §4.11
                    // leaves the close to us.
                    string rid;
                    try
                    {
                        rid = Ecf.OptText(envelope.Root.Data, "request_id") ?? string.Empty;
                    }
                    catch (EntityCoreException)
                    {
                        rid = string.Empty;
                    }
                    await RefusePreAdmissionAsync(rid, (Status.BadRequest, "invalid_request",
                        "root entity is neither EXECUTE nor EXECUTE_RESPONSE"), ct).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            FailPending(new ConnectionBrokenException("connection closed"));
        }
    }

    private void RouteResponse(Envelope envelope)
    {
        try
        {
            string requestId = new ExecuteResponse(envelope.Root).RequestId;
            if (_pending.TryGetValue(requestId, out TaskCompletionSource<Envelope>? tcs))
            {
                tcs.TrySetResult(envelope);
            }
        }
        catch (EntityProtocolException)
        {
            // Malformed response root — no request_id to route to; drop.
        }
    }

    private async Task DispatchInboundAsync(Envelope request, CancellationToken ct)
    {
        try
        {
            bool establishedBefore = _state.Established;
            // Pass this connection as the §6.11 reentry sender so a handler servicing this
            // inbound EXECUTE can originate an outbound EXECUTE back over it (§6.13(b), §4.8).
            Envelope response = await _dispatcher.DispatchAsync(request, _state, this, ct).ConfigureAwait(false);
            await WriteAsync(response, ct).ConfigureAwait(false);

            // §4.1 ordering: the dispatch that flips the connection to Established is
            // the initiator's authenticate (leg 2). Only once its response is on the
            // wire may the responder send its reverse authenticate (leg 3) — signal
            // the reverse-handshake driver here, after the write, so leg 2's response
            // always precedes leg 3.
            if (!establishedBefore && _state.Established)
            {
                _state.AuthResponseSent.TrySetResult();
            }
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            // Shutting down.
        }
        catch (Exception)
        {
            // A failed write or dispatch crash tears the connection down.
            await _cts.CancelAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Recover ONLY the <c>request_id</c> from a frame the strict decoder rejected, so the
    /// refusal can be delivered CORRELATED rather than as §4.11's uncorrelated best-effort
    /// frame. Empty when nothing is recoverable.
    /// <para>
    /// The frame stays rejected: nothing is built from it, nothing is stored, and a tag is
    /// never interpreted — the salvage decode exists solely to read back the correlation
    /// key. The envelope and entity-wrapper shapes are fixed maps with no legal tag
    /// position, so a frame whose ONLY defect is a tag inside some entity's <c>data</c>
    /// still has a structurally sound root, which is exactly the case worth recovering (and
    /// the one CAP-6a's &gt;2^64 half arrives as).
    /// </para>
    /// </summary>
    private static string SalvageRequestId(ReadOnlyMemory<byte> frame)
    {
        try
        {
            EcfValue salvaged = CanonicalCbor.DecodeSalvage(frame);
            EcfValue root = Ecf.Require(salvaged, "root");
            return Ecf.RequireText(Ecf.Require(root, "data"), "request_id");
        }
        catch (Exception ex) when (ex is EntityCoreException or CborContentException
                                      or InvalidOperationException or ArgumentException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
    /// refused BEFORE it becomes an admitted request.
    /// <para>
    /// <em>"A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on
    /// the wire <c>[MUST]</c> — correlated by <c>request_id</c> where the id is available,
    /// and otherwise as a best-effort coded frame carrying no correlation."</em>
    /// </para>
    /// <para>
    /// §4.9(c)'s deliver-or-signal rule is scoped to <em>"every request the peer
    /// ADMITS"</em> and therefore reaches none of these, which is why §4.11 exists. Both of
    /// the non-conformant behaviours it names separately were present on this peer:
    /// DROPPING the frame (the un-salvageable decode arm, <em>"the weaker of the two
    /// precisely because nothing surfaces it"</em>) and CLOSING with no coded frame (the
    /// oversize and truncated arms, and the non-EXECUTE root's bare <c>break</c>).
    /// </para>
    /// <para>
    /// AN EMPTY <paramref name="requestId"/> IS THE BEST-EFFORT FORM, not a bug: it is what
    /// the section prescribes where no id can be recovered.
    /// </para>
    /// </summary>
    private async Task RefusePreAdmissionAsync(
        string requestId, (int Status, string Code, string Message) refusal, CancellationToken ct)
    {
        try
        {
            ExecuteResponse response = ExecuteResponse.Error(
                requestId, refusal.Status, refusal.Code, refusal.Message);
            await WriteAsync(new Envelope(response.Entity, System.Array.Empty<Entity>()), ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // A write failure here is a dead socket, not a protocol decision; the read
            // loop's own error handling tears the connection down on the next iteration.
        }
    }

    private void FailPending(Exception error)
    {
        foreach (KeyValuePair<string, TaskCompletionSource<Envelope>> kv in _pending)
        {
            kv.Value.TrySetException(error);
        }
        _pending.Clear();
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        try
        {
            await _readerTask.ConfigureAwait(false);
        }
        catch
        {
            // Reader teardown errors are expected during close.
        }
        _stream.Dispose();
        _cts.Dispose();
        _writeLock.Dispose();
    }
}
