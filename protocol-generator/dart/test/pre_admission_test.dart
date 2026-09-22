import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:entity_core_protocol/entity_core_peer.dart';
import 'package:entity_core_protocol/src/codec/ecf.dart';
import 'package:entity_core_protocol/src/codec/ecf_value.dart';
import 'package:entity_core_protocol/src/errors.dart';
import 'package:entity_core_protocol/src/peer/wire.dart' as wire;
import 'package:test/test.dart';

/// §4.11 pre-admission refusals (0.8.2.25) — classification AND emission.
///
/// §4.11's rule has two halves and they fail differently.
///
///   * "The frame obligation belongs to the class" is WIRE-VISIBLE, and the two
///     non-conformant behaviours it names are distinct: DROPPING the frame (no
///     response, no close — "the weaker of the two precisely because nothing surfaces
///     it") and CLOSING WITH NO CODED FRAME (indistinguishable from a network fault,
///     and on a multiplexed connection it destroys unrelated ADMITTED requests). This
///     peer had BOTH before 0.8.2.25: the un-salvageable decode arm and the
///     non-EXECUTE root dropped, the oversize arm and the mid-frame EOF closed bare.
///   * "The CODE belongs to the cause [MUST]" is a MAPPING, and a mapping is exactly
///     the thing that regresses silently when a new failure joins an existing branch.
///
/// Both halves are covered: the mapping at the unit level, and the emission over a
/// real socket, because a green mapping over a transport that never calls it is the
/// `check_path_permission` shape all over again.
///
/// THE PINNED CHECK SET (778) HAS NO VECTOR ON THIS SURFACE.
///
/// EVERY SOCKET CASE CARRIES A POSITIVE CONTROL. A probe fails in the direction of
/// the answer it is looking for: a malformed frame that is malformed in a SECOND way
/// answers the code under measurement for the wrong reason.
///
/// THE READ DEADLINE IS AN ASSERTION, NOT A CONVENIENCE. §4.11's non-conformant
/// behaviour is NO RESPONSE, so a socket read with no deadline HANGS on the defect
/// instead of failing on it — and a hung test is strictly worse than a red one: it
/// reports nothing and blocks everything behind it. Every read below is under
/// `.timeout(...)`, and the per-test `timeout` keeps a wedged socket from taking the
/// suite with it.
void main() {
  const readDeadline = Duration(seconds: 5);
  final caseTimeout = Timeout(const Duration(seconds: 20));

  Uint8List framed(Uint8List payload) {
    final out = Uint8List(payload.length + 4);
    final n = payload.length;
    out[0] = (n >> 24) & 0xff;
    out[1] = (n >> 16) & 0xff;
    out[2] = (n >> 8) & 0xff;
    out[3] = n & 0xff;
    out.setRange(4, 4 + n, payload);
    return out;
  }

  Uint8List enc(EcfValue v) => Ecf.encodeOrThrow(v);

  /// A well-formed EXECUTE the peer MUST answer 200 — the positive control.
  Future<Uint8List> helloFrame() async {
    final ident = await Identity.ofSeed(Uint8List(32)..fillRange(0, 32, 0x2a));
    final hello = Entity.make(
        'system/protocol/connect/hello',
        cmap([
          'peer_id', ident.peerId,
          'nonce', cbytes(Uint8List(32)..fillRange(0, 32, 0x01)),
          'protocols', textArray(['entity-core/1.0']),
          'timestamp', EcfInt.of(1),
          'hash_formats', textArray(['ecfv1-sha256']),
          'key_types', textArray(['ed25519']),
        ]));
    final env = Envelope(wire.makeExecute(
        'ctl-1', 'system/protocol/connect', 'hello', hello));
    return framed(wire.frameOfEnvelope(env));
  }

  /// A frame whose ONLY defect is a CBOR tag inside an entity's `data` map.
  ///
  /// Hand-spliced, because this peer's encoder cannot emit a tag by construction —
  /// AND THE SPLICE IS ASSERTED. A mutation that is not verified to have landed is
  /// not a mutation: an unverified splice leaves the frame perfectly well-formed, the
  /// peer answers something correct to a question this test is not asking, and that
  /// reads as a peer that does not implement the branch.
  Uint8List taggedExecutePayload() {
    final root = Entity.make(
        'system/protocol/execute',
        cmap([
          'request_id', 'tag-1',
          'uri', 'system/tree',
          'operation', 'get',
          'params', wire.emptyParams().toCbor(),
          'extra', EcfInt.of(0),
        ]));
    final payload = enc(EcfMap.of({'root': root.toCbor()}));
    // text(5) "extra", then uint 0.
    final marker = Uint8List.fromList(
        [0x65, 0x65, 0x78, 0x74, 0x72, 0x61, 0x00]);
    int indexOf(Uint8List hay, Uint8List needle, [int from = 0]) {
      outer:
      for (var i = from; i + needle.length <= hay.length; i++) {
        for (var j = 0; j < needle.length; j++) {
          if (hay[i + j] != needle[j]) continue outer;
        }
        return i;
      }
      return -1;
    }

    final at = indexOf(payload, marker);
    expect(at, isNot(-1),
        reason: 'the splice target moved; the mutation is not a mutation');
    expect(indexOf(payload, marker, at + 1), equals(-1),
        reason: 'the splice target is ambiguous');
    final out = Uint8List(payload.length + 1)
      ..setRange(0, at + marker.length - 1, payload)
      ..[at + marker.length - 1] = 0xc1 // tag 1, in front of the uint 0
      ..[at + marker.length] = 0x00
      ..setRange(at + marker.length + 1, payload.length + 1, payload,
          at + marker.length);
    // The splice is asserted to BE a tag rejection before any socket sees it.
    expect(Ecf.decode(out).errorOrNull, isA<TagRejected>());
    return out;
  }

  Future<T> withPeer<T>(Future<T> Function(int port) body) async {
    final peer =
        await Peer.create(Uint8List(32)..fillRange(0, 32, 0x7b));
    final listener = await startListener(peer, 0);
    try {
      return await body(listener.port);
    } finally {
      await listener.close();
    }
  }

  /// Read `expect` framed responses off `s`, each under the deadline.
  Future<List<(int, String, String)>> readN(
      Stream<Uint8List> stream, int want) async {
    final acc = <int>[];
    final out = <(int, String, String)>[];
    await for (final chunk in stream.timeout(readDeadline,
        onTimeout: (sink) => sink.addError(StateError(
            'no response: the frame was DROPPED (section 4.11)')))) {
      acc.addAll(chunk);
      while (acc.length >= 4) {
        final n = (acc[0] << 24) | (acc[1] << 16) | (acc[2] << 8) | acc[3];
        if (acc.length < 4 + n) break;
        final env = wire.envelopeOfFrame(
            Uint8List.fromList(acc.sublist(4, 4 + n)));
        acc.removeRange(0, 4 + n);
        final res = wire.responseResult(env);
        out.add((
          wire.responseStatus(env),
          res?.text('code') ?? '',
          env.root.text('request_id') ?? ''
        ));
      }
      if (out.length >= want) break;
    }
    return out;
  }

  /// Send `frames` on ONE connection and read `want` responses.
  Future<List<(int, String, String)>> drive(
      List<Uint8List> frames, int want, int port) async {
    final s = await Socket.connect('127.0.0.1', port);
    final bc = s.asBroadcastStream();
    try {
      for (final f in frames) {
        s.add(f);
      }
      await s.flush();
      return await readN(bc, want);
    } finally {
      s.destroy();
    }
  }

  group('section 4.11 — the CODE belongs to the CAUSE (0.8.2.25, section 5.2a)', () {
    // Before 0.8.2.24 this peer answered `400 non_canonical_ecf` for every one of
    // these, which is the code-under-the-wrong-reason defect §5.2a names: a mis-keyed
    // `included` entry carries NO TAG, its encoding is canonical, and *re-encode* is
    // not the caller's remedy.
    final rows = <(Object, int, String)>[
      // §4.10(a), mood raised SHOULD -> MUST at 0.8.2.25 (N14).
      (const PayloadTooLarge('x'), 413, 'payload_too_large'),
      // §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
      // non_canonical_ecf NON-CONFORMANT here.
      (const HashMismatch('x'), 400, 'hash_mismatch'),
      // ENTITY-CBOR-ENCODING §6.3 — the tag-policy arm keeps its own code.
      (const TagRejected('x'), 400, 'non_canonical_ecf'),
      // §4.7 / §4.11 framing arm: bytes that never become an Envelope.
      (const TruncatedInput('x'), 400, 'invalid_request'),
      // The row that makes the split load-bearing: a non-minimal head is
      // "non-canonical CBOR" BY NAME and is NOT the tag-policy arm.
      (const NonCanonicalEcf('x'), 400, 'invalid_request'),
      (const NonMinimalInt('x'), 400, 'invalid_request'),
      (const DuplicateKey('x'), 400, 'invalid_request'),
    ];

    test('maps each cause to its own status and code', () {
      expect(rows.length, equals(7)); // examined-N, not merely "no failures"
      for (final (cause, status, code) in rows) {
        // Wrapped AND bare: the decode path throws a DecodeRefusal carrying the
        // cause, while the transport's own arms pass the EntityError directly.
        for (final thrown in [cause, DecodeRefusal(cause as EntityError)]) {
          final r = wire.classifyPreAdmission(thrown);
          expect((r.status, r.code), equals((status, code)),
              reason: '${cause.runtimeType}');
          expect(r.message.codeUnits.every((c) => c < 128), isTrue,
              reason: 'a wire-visible message stays ASCII');
        }
      }
    });
  });

  group('section 4.11 — the decode boundary throws the CAUSE', () {
    final good = Entity.make('primitive/any', cmap(['x', 1]));

    test('a MIS-KEYED included entry throws HashMismatch', () {
      // The arc-probe B1/B2 input. The entry's ENCODING is canonical; what is false
      // is the claim the KEY makes.
      final payload = enc(EcfMap.of({
        'root': wire
            .makeExecute('t1', 'system/tree', 'get', wire.emptyParams())
            .toCbor(),
        'included': EcfMap([
          EcfEntry(cbytes(Uint8List(33)..fillRange(0, 33, 0x11)), good.toCbor())
        ]),
      }));
      Object? caught;
      try {
        wire.envelopeOfFrame(payload);
      } catch (e) {
        caught = e;
      }
      expect(caught, isA<DecodeRefusal>());
      expect((caught! as DecodeRefusal).cause, isA<HashMismatch>());
      final r = wire.classifyPreAdmission(caught);
      expect((r.status, r.code), equals((400, 'hash_mismatch')));
    });

    test('a non-binding carried content_hash throws HashMismatch', () {
      final m = EcfMap.of({
        'type': EcfText(good.type),
        'data': good.data(),
        'content_hash': cbytes(Uint8List(33)..fillRange(0, 33, 0x22)),
      });
      Object? caught;
      try {
        Entity.ofCbor(m);
      } catch (e) {
        caught = e;
      }
      expect(caught, isA<DecodeRefusal>());
      expect((caught! as DecodeRefusal).cause, isA<HashMismatch>());
    });

    test('a CBOR tag in a data-field position throws TagRejected', () {
      final payload = taggedExecutePayload();
      Object? caught;
      try {
        wire.envelopeOfFrame(payload);
      } catch (e) {
        caught = e;
      }
      expect(caught, isA<DecodeRefusal>());
      expect((caught! as DecodeRefusal).cause, isA<TagRejected>());
      final r = wire.classifyPreAdmission(caught);
      expect((r.status, r.code), equals((400, 'non_canonical_ecf')));
    });
  });

  group('section 4.11 — the frame obligation, over a real socket', () {
    test('the positive control answers 200 on its own', () async {
      // The control FIRST. If this ever fails, nothing below is a reading about the
      // peer — it is a reading about this file.
      await withPeer((port) async {
        expect(await drive([await helloFrame()], 1, port),
            equals([(200, '', 'ctl-1')]));
      });
    }, timeout: caseTimeout);

    test('a COMPLETE refused frame is answered, with the code of the cause, and the '
        'connection keeps serving', () async {
      final good = Entity.make('primitive/any', cmap(['x', 1]));
      final misKeyed = framed(enc(EcfMap.of({
        'root': wire
            .makeExecute('t1', 'system/tree', 'get', wire.emptyParams())
            .toCbor(),
        'included': EcfMap([
          EcfEntry(cbytes(Uint8List(33)..fillRange(0, 33, 0x11)), good.toCbor())
        ]),
      })));
      final tagged = framed(taggedExecutePayload());
      // A root that is neither EXECUTE nor EXECUTE_RESPONSE -> 400 invalid_request
      // (§3.3/§6.5 "Other type?", N12/N17). NOT a bare close, and NOT the silent drop
      // this peer used to answer it with.
      final otherRoot = framed(wire.frameOfEnvelope(Envelope(
          Entity.make('primitive/any', cmap(['request_id', 'x-1'])))));
      await withPeer((port) async {
        final got = await drive(
            [misKeyed, tagged, otherRoot, await helloFrame()], 4, port);
        expect(got[0], equals((400, 'hash_mismatch', 't1')));
        expect(got[1], equals((400, 'non_canonical_ecf', 'tag-1')));
        expect(got[2], equals((400, 'invalid_request', 'x-1')));
        expect(got[3], equals((200, '', 'ctl-1')),
            reason: 'still serving after three refusals');
      });
    }, timeout: caseTimeout);

    test('an UNCORRELATED refusal is a best-effort frame with an empty request_id',
        () async {
      // Where no `request_id` can be recovered, §4.11 prescribes "a best-effort coded
      // frame carrying no correlation" — an empty `request_id` IS that form. Guessing
      // one would correlate the refusal to somebody else's in-flight request.
      final notAnEnvelope = framed(enc(EcfMap.of({'nope': EcfInt.of(1)})));
      final garbage = framed(Uint8List.fromList([0xff, 0xff, 0xff, 0xff]));
      await withPeer((port) async {
        final got =
            await drive([notAnEnvelope, garbage, await helloFrame()], 3, port);
        expect(got[0], equals((400, 'invalid_request', '')));
        expect(got[1], equals((400, 'invalid_request', '')));
        expect(got[2], equals((200, '', 'ctl-1')));
      });
    }, timeout: caseTimeout);

    test('an OVERSIZE prefix is answered 413 BEFORE the close', () async {
      // §4.10(a) N14: SHOULD -> MUST. The over-size condition is detected at the
      // length prefix with the connection intact and nothing spent, so the 413 goes
      // out FIRST and the close comes after — the close is now IN ADDITION to the
      // frame, not instead of it. The peer's own listener is the control: it keeps
      // serving other connections.
      await withPeer((port) async {
        final s = await Socket.connect('127.0.0.1', port);
        final bc = s.asBroadcastStream();
        try {
          final big = wire.maxFrame + 1;
          s.add(Uint8List.fromList([
            (big >> 24) & 0xff,
            (big >> 16) & 0xff,
            (big >> 8) & 0xff,
            big & 0xff
          ])); // prefix only; no body ever sent
          await s.flush();
          final got = await readN(bc, 1);
          expect(got.length, equals(1));
          expect(got[0], equals((413, 'payload_too_large', '')),
              reason: 'no id was ever readable: the best-effort form');
        } finally {
          s.destroy();
        }
        expect(await drive([await helloFrame()], 1, port),
            equals([(200, '', 'ctl-1')]),
            reason: 'the listener survived the refusal');
      });
    }, timeout: caseTimeout);

    test('a TRUNCATED frame is answered', () async {
      // A declared body that never arrives — §4.11's framing arm names this input
      // outright. The write side is shut down so the peer sees EOF mid-frame rather
      // than an idle connection.
      //
      // THIS IS THE CASE THE MANAGED-RUNTIME WARNING IS ABOUT: the response can only
      // be written AFTER the client's FIN, so it fails on any runtime whose socket
      // layer closes the write side on a remote half-close. Node needed
      // `allowHalfOpen: true` and the BEAM needed `exit_on_close: false`; Dart's
      // `Socket` keeps its write side open until destroyed, which this case is what
      // MEASURES rather than assumes.
      await withPeer((port) async {
        final s = await Socket.connect('127.0.0.1', port);
        final bc = s.asBroadcastStream();
        try {
          s.add(Uint8List.fromList(
              [0x00, 0x00, 0x10, 0x00, 0xa1])); // declared 4096, sent 1
          await s.flush();
          await s.close(); // half-close: FIN, write side of OUR socket
          final got = await readN(bc, 1);
          expect(got.length, equals(1));
          expect(got[0], equals((400, 'invalid_request', '')));
        } finally {
          s.destroy();
        }
        expect(await drive([await helloFrame()], 1, port),
            equals([(200, '', 'ctl-1')]));
      });
    }, timeout: caseTimeout);

    test('a PARTIAL LENGTH PREFIX is answered', () async {
      // The arm the vanguard's first driver had no case for: its "truncated frame"
      // case sent a COMPLETE 4-byte prefix, so truncation was caught in the body read
      // and the prefix discrimination had nothing driving it.
      await withPeer((port) async {
        final s = await Socket.connect('127.0.0.1', port);
        final bc = s.asBroadcastStream();
        try {
          s.add(Uint8List.fromList([0x00, 0x00])); // two bytes of four
          await s.flush();
          await s.close();
          final got = await readN(bc, 1);
          expect(got.length, equals(1));
          expect(got[0], equals((400, 'invalid_request', '')));
        } finally {
          s.destroy();
        }
      });
    }, timeout: caseTimeout);

    test('a CLEAN close at a frame boundary is owed NOTHING', () async {
      // The differential for the two cases above, and the direction that would be
      // wrong in the expensive way: answering 400 to every peer that simply hangs up.
      // A complete request, its response read, then a clean half-close with an empty
      // reassembly window — the peer must send nothing further.
      await withPeer((port) async {
        final s = await Socket.connect('127.0.0.1', port);
        final bc = s.asBroadcastStream();
        final extra = <(int, String, String)>[];
        try {
          s.add(await helloFrame());
          await s.flush();
          expect(await readN(bc, 1), equals([(200, '', 'ctl-1')]));
          await s.close();
          // Anything arriving in the next second is a refusal that should not exist.
          final more = readN(bc, 1).then(extra.addAll).catchError((_) {});
          await Future.any(
              [more, Future<void>.delayed(const Duration(seconds: 1))]);
          expect(extra, isEmpty,
              reason: 'a clean EOF at a frame boundary is an ordinary close');
        } finally {
          s.destroy();
        }
      });
    }, timeout: caseTimeout);

    test('a pre-admission refusal is NEVER silence', () async {
      // The class obligation, stated once as its own assertion rather than inferred
      // from the rows above: EVERY pre-admission cause puts a frame on the wire.
      //
      // Dropping is §4.11's other non-conformant behaviour and is "the weaker of the
      // two precisely because nothing surfaces it" — a `continue` with no write looks
      // exactly like a peer that is merely slow, and the caller learns nothing until
      // its own §6.11(c) deadline. A deadline expiry here IS that failure.
      final causes = <Uint8List>[
        framed(enc(EcfMap.of({'nope': EcfInt.of(1)}))),
        framed(Uint8List.fromList([0xff, 0xff, 0xff, 0xff])),
        framed(Uint8List(0)),
        framed(wire.frameOfEnvelope(
            Envelope(Entity.make('primitive/any', emptyMap())))),
      ];
      expect(causes.length, equals(4));
      await withPeer((port) async {
        final got = await drive(causes, causes.length, port);
        expect(got.length, equals(4));
        for (final (status, code, _) in got) {
          expect(status, equals(400));
          expect(code, isNotEmpty,
              reason: 'every pre-admission refusal is coded, none is silence');
        }
      });
    }, timeout: caseTimeout);
  });
}
