using System.Collections.Concurrent;
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
                    break; // malformed frame → close connection (Layer 0, §6.7)
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
