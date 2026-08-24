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

                if (frame is null)
                {
                    break; // clean EOF
                }

                Envelope envelope;
                try
                {
                    envelope = Envelope.Decode(frame);
                }
                catch (EntityCoreException)
                {
                    // §6.3: "Rejection returns `400 non_canonical_ecf`" — the frame is
                    // refused (above), and that refusal MUST be a STATUS, not silence.
                    // This used to `break`, which left the read loop AND left the socket
                    // open: the oracle's every later request then went to a socket nobody
                    // was reading, so each one waited out its own timeout instead of
                    // failing fast. That is where this peer's 18-minute run and its nine
                    // starved categories came from. §4.9(c) deliver-or-signal says the
                    // same from the other direction. Answer, then keep serving.
                    await RejectNonCanonicalAsync(frame, ct).ConfigureAwait(false);
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
                    break; // neither EXECUTE nor EXECUTE_RESPONSE → invalid, close (§3.3)
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
    /// Answer a frame the strict decoder rejected with <c>400 non_canonical_ecf</c> (§6.3),
    /// recovering ONLY the <c>request_id</c> so the sender can correlate the refusal.
    /// <para>
    /// The frame stays rejected: nothing is built from it, nothing is stored, and the tag
    /// is never interpreted — the salvage decode exists solely to read back the
    /// correlation key. The envelope and entity-wrapper shapes are fixed maps with no
    /// legal tag position, so a frame whose ONLY defect is a tag inside some entity's
    /// <c>data</c> still has a structurally sound root, which is exactly the case this
    /// recovers (and the one CAP-6a's &gt;2^64 half arrives as). If even the request_id is
    /// unrecoverable there is nobody to answer, so the frame is dropped — the one case
    /// where silence is all that is available.
    /// </para>
    /// </summary>
    private async Task RejectNonCanonicalAsync(ReadOnlyMemory<byte> frame, CancellationToken ct)
    {
        string requestId;
        try
        {
            EcfValue salvaged = CanonicalCbor.DecodeSalvage(frame);
            EcfValue root = Ecf.Require(salvaged, "root");
            requestId = Ecf.RequireText(Ecf.Require(root, "data"), "request_id");
        }
        catch (Exception ex) when (ex is EntityCoreException or CborContentException
                                      or InvalidOperationException or ArgumentException)
        {
            return; // no correlatable request_id — nothing to answer
        }

        try
        {
            ExecuteResponse response = ExecuteResponse.Error(
                requestId, Status.BadRequest, "non_canonical_ecf",
                "frame is not canonical ECF (§6.3): CBOR tags are forbidden anywhere in an entity");
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
