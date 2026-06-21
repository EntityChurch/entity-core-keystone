import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import '../codec/ecf_value.dart';
import 'cbor.dart';
import 'dispatch.dart';
import 'entity.dart';
import 'envelope.dart';
import 'identity.dart';
import 'peer.dart';
import 'wire.dart' as wire;

/// Transport (L4): TCP listener + dialer, per-connection reader, §6.11
/// request_id demux, the §4.8 inbound-concurrent-with-outbound dispatch, and the
/// §6.13(b) reentry seam. Plus the initiator dialer/handshake that drives the
/// loopback.
///
/// **Concurrency model (profile [async]): the single event-loop isolate + Dart
/// async I/O.** This is the Dart-native shape (closest to TypeScript's Promise
/// event loop; vs Kotlin coroutines / Java threads). `dart:io` sockets are
/// `Stream<Uint8List>`-based and NON-blocking — there is NO blocking `read()` to
/// move off a pool (the §7b "blocking I/O on a cooperative pool" trap simply does
/// not arise: Dart has no such blocking syscall on the event loop). One reader
/// per connection consumes the byte stream into length-prefixed frames and
/// demuxes (§6.11): an EXECUTE_RESPONSE completes its awaiting outbound caller by
/// request_id through a `Map<String, Completer<Envelope?>>` correlation table
/// (the Future analogue of Kotlin's CompletableDeferred); an inbound EXECUTE is
/// dispatched WITHOUT awaiting it inline (the dispatch Future runs concurrently
/// on the same event loop, §4.8) so a handler that originates an outbound EXECUTE
/// (§6.13(b)) and `await`s its response does NOT stall the reader. Writes are
/// naturally serialized (a single isolate; one `socket.add` at a time).
/// TCP_NODELAY is set on every socket (§7b throughput, profile tcp_nodelay).

/// Per-connection IO: the framed stream, the §6.11 demux table, the reader.
final class _Io {
  _Io(this._socket) {
    _socket.setOption(SocketOption.tcpNoDelay, true); // §7b: TCP_NODELAY
  }

  final Socket _socket;

  // request_id → completion; the reader completes it with the correlated reply.
  final Map<String, Completer<Envelope?>> _pending = {};

  // Frame reassembly buffer with a consumed-offset cursor (`_lo`). Frames are
  // parsed out of `_acc[_lo.._hi]` WITHOUT re-copying the whole buffer per frame
  // (the old `BytesBuilder.toBytes()`-per-iteration was O(n²) and starved the
  // event loop under sustained C×K load → t2_1 drops + accept-loop stalls). The
  // buffer is compacted (shift the unconsumed tail to the front) only when the
  // cursor has advanced, and grown geometrically only when actually needed.
  Uint8List _acc = Uint8List(0);
  int _lo = 0; // first unconsumed byte
  int _hi = 0; // one past the last buffered byte
  bool _closed = false;

  /// Called on close to release this connection from the owning listener.
  void Function()? onClose;

  void writeFramed(Envelope env) {
    final payload = wire.frameOfEnvelope(env);
    final len = payload.length;
    final hdr = Uint8List(4)
      ..[0] = (len >> 24) & 0xff
      ..[1] = (len >> 16) & 0xff
      ..[2] = (len >> 8) & 0xff
      ..[3] = len & 0xff;
    _socket.add(hdr);
    _socket.add(payload);
  }

  /// §6.13(b) outbound primitive: send a request envelope, await its correlated
  /// EXECUTE_RESPONSE (§6.11). The reader routes the response. Returns null if
  /// the connection closes first or the wait times out (§6.12).
  Future<Envelope?> outbound(Envelope request) async {
    final requestId = request.root.text('request_id') ?? '';
    final completer = Completer<Envelope?>();
    _pending[requestId] = completer;
    try {
      writeFramed(request);
      if (_closed) return null;
      return await completer.future.timeout(const Duration(seconds: 30),
          onTimeout: () => null);
    } on wire.EntityTransportException {
      return null;
    } finally {
      _pending.remove(requestId);
    }
  }

  void _routeResponse(Envelope env) {
    final requestId = env.root.text('request_id') ?? '';
    final c = _pending.remove(requestId);
    if (c != null && !c.isCompleted) c.complete(env);
  }

  /// Drive the reader loop: consume the socket byte stream into frames; demux
  /// (§6.11). [onExecute] is invoked for an inbound EXECUTE (its response is
  /// written back); responses route to the pending table.
  void startReader(Future<Envelope?> Function(Envelope) onExecute) {
    _socket.listen(
      (chunk) {
        _append(chunk);
        _drainFrames(onExecute);
      },
      onError: (_) => close(),
      onDone: close,
      cancelOnError: true,
    );
  }

  /// Append a freshly-read chunk to the tail of the accumulator. Compacts (drops
  /// already-consumed bytes by shifting the live window to offset 0) before
  /// growing, so the buffer tracks the in-flight window — not the lifetime total.
  void _append(Uint8List chunk) {
    final live = _hi - _lo;
    final need = live + chunk.length;
    if (need > _acc.length) {
      // Grow geometrically; this also compacts (live window copied to front).
      var cap = _acc.length == 0 ? 8192 : _acc.length;
      while (cap < need) {
        cap <<= 1;
      }
      final next = Uint8List(cap);
      next.setRange(0, live, _acc, _lo);
      _acc = next;
      _lo = 0;
      _hi = live;
    } else if (_lo > 0) {
      // Fits, but compact the live window to the front to keep room at the tail.
      _acc.setRange(0, live, _acc, _lo);
      _lo = 0;
      _hi = live;
    }
    _acc.setRange(_hi, _hi + chunk.length, chunk);
    _hi += chunk.length;
  }

  void _drainFrames(Future<Envelope?> Function(Envelope) onExecute) {
    while (true) {
      final avail = _hi - _lo;
      if (avail < 4) break;
      final p = _lo;
      final len = (_acc[p] << 24) |
          (_acc[p + 1] << 16) |
          (_acc[p + 2] << 8) |
          _acc[p + 3];
      if (len < 0 || len > wire.maxFrame) {
        // §4.10(a): a length prefix over the bound ends the connection.
        close();
        return;
      }
      if (avail < 4 + len) break; // wait for more
      // Copy out exactly this frame's payload (the decoder may retain views).
      final payload = Uint8List.fromList(
          Uint8List.sublistView(_acc, p + 4, p + 4 + len));
      _lo = p + 4 + len; // O(1) cursor advance — no whole-buffer rebuild
      Envelope env;
      try {
        env = wire.envelopeOfFrame(payload);
      } catch (_) {
        continue; // §4.9: skip a malformed frame, keep serving
      }
      if (env.root.type == 'system/protocol/execute/response') {
        _routeResponse(env);
      } else {
        // §4.8 inbound concurrent with outbound: dispatch WITHOUT awaiting
        // inline (the Future runs on the same event loop) so a handler can
        // reenter (§6.11) without blocking this reader.
        unawaited(_serveInbound(env, onExecute));
      }
    }
    // Once the buffer is fully consumed, reset the cursor + release the backing
    // store so an idle/long-lived connection doesn't pin a grown buffer.
    if (_lo == _hi) {
      _lo = 0;
      _hi = 0;
      if (_acc.length > 8192) _acc = Uint8List(0);
    }
  }

  Future<void> _serveInbound(
      Envelope env, Future<Envelope?> Function(Envelope) onExecute) async {
    Envelope? resp;
    try {
      resp = await onExecute(env);
    } catch (_) {
      resp = Envelope(wire.makeResponse(env.root.text('request_id') ?? '', 500,
          wire.errorResult('internal_error', null)));
    }
    if (resp != null && !_closed) {
      try {
        writeFramed(resp);
      } catch (_) {
        // write failure ends this exchange; reader keeps going
      }
    }
  }

  void close() {
    if (_closed) return;
    _closed = true;
    for (final c in _pending.values) {
      if (!c.isCompleted) c.complete(null);
    }
    // Release the reassembly buffer so a closed conn pins no memory.
    _acc = Uint8List(0);
    _lo = 0;
    _hi = 0;
    try {
      _socket.destroy();
    } catch (_) {
      // best-effort
    }
    // Detach from the owning listener (prevents an unbounded _conns leak across
    // connection churn — t2_2). Fire once.
    final cb = onClose;
    onClose = null;
    cb?.call();
  }
}

/// A running listener: the bound port plus a handle to stop it.
final class Listener {
  Listener(this._server, this.port);
  final ServerSocket _server;
  final int port;
  // Live connections only — entries removed on close (no churn leak; t2_2).
  final Set<_Io> _conns = {};

  Future<void> close() async {
    for (final io in List.of(_conns)) {
      io.close();
    }
    _conns.clear();
    await _server.close();
  }
}

/// Bind 127.0.0.1:port (0 = auto) and spawn the accept loop.
Future<Listener> startListener(Peer peer, int port) async {
  // A generous backlog so a burst of churn connects (t2_2) is not refused while
  // the event loop drains in-flight work.
  final server = await ServerSocket.bind(
      InternetAddress.loopbackIPv4, port,
      shared: false, backlog: 1024);
  final listener = Listener(server, server.port);
  server.listen((client) {
    final io = _Io(client);
    listener._conns.add(io);
    io.onClose = () => listener._conns.remove(io);
    final conn = Conn();
    // wire the §6.13(b) outbound seam to this connection (§6.11 reentry).
    conn.outbound = (env) => io.outbound(env);
    io.startReader((env) => peer.dispatch(conn, env));
  });
  return listener;
}

// ══════════════════════════════════════════════════════════════════════════════
// Client side — the dialer + initiator handshake (drives the two-peer loopback)
// ══════════════════════════════════════════════════════════════════════════════

/// A dialed, authenticated session (§4.4): the IO, the minted cap + granter + sig.
final class Session {
  Session._(this._io, this._local);
  final _Io _io;
  final Identity _local;
  int _reqCounter = 0;

  String? remotePeerId;
  Entity? capability;

  /// The remote peer identity that granted the session cap (the §4.4 granter).
  Entity? granterPeer;

  /// The signature over the session cap (travels with it in `included`).
  Entity? capSignature;

  String _nextRequestId() => 'req-${++_reqCounter}';

  /// Send REQUEST and await its correlated EXECUTE_RESPONSE (request_id demux).
  Future<Envelope?> send(Envelope request) => _io.outbound(request);

  /// Build, sign, and send an authenticated EXECUTE; await the response. The full
  /// §5.8 authority chain travels in `included`.
  Future<Envelope?> execute(
      String uri, String operation, Entity params, EcfMap? resource) async {
    final cap = capability!;
    final exec = wire.makeExecute(_nextRequestId(), uri, operation, params,
        author: _local.identityHash(),
        capability: cap.hash(),
        resource: resource);
    final execSig = await _local.sign(exec);
    final inc = [
      Included(cap.hash(), cap),
      Included(granterPeer!.hash(), granterPeer!),
      Included(_local.identityHash(), _local.peerEntity),
      Included(capSignature!.hash(), capSignature!),
      Included(execSig.hash(), execSig),
    ];
    return send(Envelope(exec, inc));
  }

  void close() => _io.close();
}

/// Open a client connection to host:port and start its reader, then drive the
/// §4.1 forward handshake. Returns the authenticated session.
Future<Session> dial(Peer initiator, String host, int port) async {
  final Socket sock;
  try {
    sock = await Socket.connect(host, port);
  } on SocketException catch (e) {
    throw wire.EntityTransportException('dial failed', e);
  }
  final io = _Io(sock);
  final session = Session._(io, initiator.identity);
  // the client reader: a core responder sends only EXECUTE_RESPONSEs; route
  // them. A reentrant inbound EXECUTE (§6.11) is dispatched too.
  final conn = Conn();
  conn.outbound = (env) => io.outbound(env);
  io.startReader((env) => initiator.dispatch(conn, env));
  await _handshake(session, initiator.identity);
  return session;
}

/// Drive the §4.1 forward handshake as initiator: hello then authenticate. On
/// success, populate the session with the §4.4 capability the responder minted.
Future<void> _handshake(Session s, Identity local) async {
  // ── hello ──
  final hello = Entity.make(
      'system/protocol/connect/hello',
      cmap([
        'peer_id', local.peerId,
        'nonce', cbytes(_randomNonce()),
        'protocols', textArray(['entity-core/1.0']),
        'timestamp', EcfInt.of(DateTime.now().millisecondsSinceEpoch),
        'hash_formats', textArray(['ecfv1-sha256']),
        'key_types', textArray(['ed25519']),
      ]));
  final r1 = await s.send(Envelope(
      wire.makeExecute(s._nextRequestId(), 'system/protocol/connect', 'hello', hello)));
  _requireOk(r1, 'hello');
  final remoteHello = wire.responseResult(r1!)!;
  s.remotePeerId = remoteHello.text('peer_id');
  final remoteNonce = remoteHello.bytes('nonce')!;

  // ── authenticate ──
  final auth = Entity.make(
      'system/protocol/connect/authenticate',
      cmap([
        'peer_id', local.peerId,
        'public_key', cbytes(local.publicKey()),
        'key_type', 'ed25519',
        'nonce', cbytes(remoteNonce),
      ]));
  final authSig = await local.sign(auth);
  final authInc = [
    Included(local.identityHash(), local.peerEntity),
    Included(authSig.hash(), authSig),
  ];
  final r2 = await s.send(Envelope(
      wire.makeExecute(
          s._nextRequestId(), 'system/protocol/connect', 'authenticate', auth),
      authInc));
  _requireOk(r2, 'authenticate');

  // parse the §4.4 initial capability grant
  final grant = wire.responseResult(r2!)!;
  final tokenH = grant.bytes('token')!;
  final token = r2.includedGet(tokenH);
  if (token == null) {
    throw wire.EntityTransportException(
        'authenticate grant omits the capability token');
  }
  final granterH = token.bytes('granter')!;
  final granterPeer = r2.includedGet(granterH);
  if (granterPeer == null) {
    throw wire.EntityTransportException(
        'authenticate grant omits the granter identity');
  }
  final capSig = _findSig(token.rawHash, r2.included);
  if (capSig == null) {
    throw wire.EntityTransportException(
        'authenticate grant omits the capability signature');
  }
  s.capability = token;
  s.granterPeer = granterPeer;
  s.capSignature = capSig;
}

Entity? _findSig(Uint8List target, List<Included> included) {
  for (final it in included) {
    final e = it.entity;
    if (e.type == 'system/signature' && octetsEqual(e.bytes('target'), target)) {
      return e;
    }
  }
  return null;
}

Uint8List _randomNonce() {
  final r = Random.secure();
  final b = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    b[i] = r.nextInt(256);
  }
  return b;
}

void _requireOk(Envelope? env, String step) {
  if (env == null) {
    throw wire.EntityTransportException('$step failed: no response');
  }
  final status = wire.responseStatus(env);
  if (status != 200) {
    final r = wire.responseResult(env);
    final code = r?.text('code');
    final msg = r?.text('message');
    throw wire.EntityTransportException(
        '$step failed: $status $code ${msg ?? ''}');
  }
}
