import 'entity.dart';
import 'envelope.dart';
import 'wire.dart' as wire;

/// Dispatch-layer value types: the handler [Outcome], the [Handler] interface,
/// the [HandlerContext], and per-connection [Conn] state.
///
/// **The idiom axis (exhaustive-switch verdicts + single-dispatch operation
/// `switch`).** A core system handler (§6.2) is a [Handler] whose [Handler.handle]
/// switches over the operation string — the mainstream `match op` ladder, with
/// the "unknown operation → 501" arm as the `default` branch. The §5.2/§5.10
/// verdicts are Dart `enum`s matched exhaustively at the dispatch site (the
/// static-rigor seam the profile's `pattern_matching` calls for). Failures are
/// VALUES ([Outcome] with a status) on the recoverable path — the sealed-result
/// error model, NOT thrown exceptions.

/// A handler outcome: a status, a result entity, and any protocol entities to
/// carry in the response envelope's `included` (§3.1) — caps, peer identities,
/// signatures.
final class Outcome {
  const Outcome(this.status, this.result, [this.included = const []]);

  final int status;
  final Entity result;
  final List<Included> included;

  static Outcome ok(Entity result, [List<Included> included = const []]) =>
      Outcome(200, result, included);

  static Outcome err(int status, String code, [String? message]) =>
      Outcome(status, wire.errorResult(code, message));
}

/// A core system handler (§6.2). The §6.6 backward tree-walk resolves a request
/// URI to a bootstrapped handler instance; [handle] then dispatches the
/// operation. `async` so a handler that originates an outbound EXECUTE
/// (§6.13(b)/§6.11 reentry) can `await` the response without blocking the event
/// loop — the Dart Future idiom (profile [async]).
abstract interface class Handler {
  Future<Outcome> handle(String operation, HandlerContext ctx);
}

/// The §6.6 HandlerContext: everything a handler needs to service one operation —
/// the EXECUTE entity, the per-connection state, the envelope's `included`, the
/// resolved caller capability (null for the unauthenticated connect path), and
/// the envelope.
final class HandlerContext {
  const HandlerContext(
      this.exec, this.conn, this.included, this.callerCap, this.env);

  final Entity exec;
  final Conn conn;
  final List<Included> included;
  final Entity? callerCap;
  final Envelope env;

  /// The EXECUTE's params entity, or null.
  Entity? params() => exec.entityField('params');
}

/// Per-connection state (§4.2 connection state is per-connection). Holds the §4.1
/// handshake progress (issued nonce, the initiator's claimed peer_id, established
/// flag) and the §6.13(b) handler-facing outbound seam.
///
/// The [outbound] seam sends an EXECUTE envelope over THIS connection and awaits
/// its correlated EXECUTE_RESPONSE (§6.11 reentry); the transport sets it. It is
/// null when the request did not arrive over a reentrant connection (e.g. an
/// in-process call). It is a `Future`-returning function (the async reentry
/// primitive — the Dart analogue of Kotlin's `suspend (Envelope) -> Envelope?`).
final class Conn {
  bool established = false;
  List<int>? issuedNonce; // nonce we issued in our hello response
  String? helloPeerId; // initiator's claimed peer_id from hello

  /// §6.13(b) reentry seam: send-and-await over this connection; null if
  /// unavailable.
  Future<Envelope?> Function(Envelope)? outbound;

  int _outCounter = 0;
  int nextOutCounter() => ++_outCounter;
}
