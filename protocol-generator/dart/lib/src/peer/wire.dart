import 'dart:typed_data';

import '../codec/ecf.dart';
import '../codec/ecf_value.dart';
import '../errors.dart';
import 'cbor.dart';
import 'entity.dart';
import 'envelope.dart';

/// §1.6 / §6.12 transport-layer failure: a malformed frame, a frame exceeding
/// the §1.6 / §4.10(a) bound, or a closed connection during a framed read/write.
/// Distinct from a protocol-status [Outcome] — a transport fault ends the
/// connection. Dart keeps an EXCEPTION for the unrecoverable I/O boundary (the
/// recoverable protocol path is the sealed-result/[Outcome] seam — profile
/// [error_model]; exceptions reserved for the I/O edge per Dart convention).
final class EntityTransportException implements Exception {
  EntityTransportException(this.message, [this.cause]);
  final String message;
  final Object? cause;
  @override
  String toString() => 'EntityTransportException: $message';
}

/// Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3
/// EXECUTE_RESPONSE).
///
/// Frame := `[4-byte BE length][CBOR payload]`; the payload is a CBOR-encoded
/// system/protocol/envelope (§3.1). Only EXECUTE and EXECUTE_RESPONSE are wire
/// message types (§3.3). hello / authenticate are OPERATIONS on
/// system/protocol/connect, not message types — any other root type is ignored
/// on the server side (the dispatcher returns no response).

/// §1.6 / §4.10(a) bound — 16 MiB max inbound payload.
const int maxFrame = 16 * 1024 * 1024;

// ── envelope <-> frame ─────────────────────────────────────────────────────────

Envelope envelopeOfFrame(Uint8List payload) {
  final r = Ecf.decode(payload);
  switch (r) {
    case Ok(:final value):
      if (value is! EcfMap) {
        throw EntityTransportException('frame: not a map');
      }
      return Envelope.ofCbor(value);
    case Err(:final error):
      throw EntityTransportException('frame decode: ${error.message}');
  }
}

Uint8List frameOfEnvelope(Envelope env) => Ecf.encodeOrThrow(env.toCbor());

// ── EXECUTE builder (§3.2) ───────────────────────────────────────────────────

/// Build an EXECUTE entity. [author]/[capability] are 33-byte hashes; [resource]
/// is a cbor-map (`{targets:[...]}`) or null.
Entity makeExecute(
  String requestId,
  String uri,
  String operation,
  Entity params, {
  Uint8List? author,
  Uint8List? capability,
  EcfMap? resource,
}) {
  final pairs = <EcfEntry>[
    EcfEntry(const EcfText('request_id'), EcfText(requestId)),
    EcfEntry(const EcfText('uri'), EcfText(uri)),
    EcfEntry(const EcfText('operation'), EcfText(operation)),
    EcfEntry(const EcfText('params'), params.toCbor()),
  ];
  if (author != null) {
    pairs.add(EcfEntry(const EcfText('author'), EcfBytes(author)));
  }
  if (capability != null) {
    pairs.add(EcfEntry(const EcfText('capability'), EcfBytes(capability)));
  }
  if (resource != null) {
    pairs.add(EcfEntry(const EcfText('resource'), resource));
  }
  return Entity.make('system/protocol/execute', EcfMap(pairs));
}

// ── EXECUTE_RESPONSE builder (§3.3) ───────────────────────────────────────────

Entity makeResponse(String requestId, int status, Entity result) => Entity.make(
      'system/protocol/execute/response',
      EcfMap.of({
        'request_id': EcfText(requestId),
        'status': EcfInt.of(status),
        'result': result.toCbor(),
      }),
    );

// ── error result + empty params + resource target ─────────────────────────────

Entity errorResult(String code, String? message) {
  final data = message != null
      ? EcfMap.of({'code': EcfText(code), 'message': EcfText(message)})
      : EcfMap.of({'code': EcfText(code)});
  return Entity.make('system/protocol/error', data);
}

/// Empty-params (§3.2): a primitive/any whose data is the canonical empty map.
Entity emptyParams() => Entity.make('primitive/any', emptyMap());

/// Build a resource cbor-map `{targets: [...]}`.
EcfMap resourceTarget(List<String> targets) =>
    EcfMap.of({'targets': textArray(targets)});

// ── response decode helpers (initiator side) ──────────────────────────────────

int responseStatus(Envelope env) => env.root.uint('status')?.toInt() ?? 0;

Entity? responseResult(Envelope env) {
  final m = env.root.mapField('result');
  return m == null ? null : Entity.ofCbor(m);
}
