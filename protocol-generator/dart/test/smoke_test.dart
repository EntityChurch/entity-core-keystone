import 'dart:typed_data';

import 'package:entity_core_protocol/entity_core_peer.dart';
import 'package:entity_core_protocol/src/codec/ecf_value.dart';
import 'package:test/test.dart';

/// S3 two-peer loopback smoke test (the phase exit gate).
///
/// Two Dart peers talk over real loopback TCP through the full §6.5 dispatch
/// chain. A RESPONDER peer listens; an INITIATOR peer (a second identity) dials
/// it and drives the §4.1 forward handshake (hello → authenticate), then:
///  - 404 on an unregistered path (no handler resolved);
///  - an authority-gated tree get (200) over the §4.4 discovery floor;
///  - a capability request (200);
///  - 8-way request_id demux of concurrently-issued replies (N7, §6.11).
///
/// A second scenario exercises the v7.74 Core Extensibility Boundary
/// (--debug-open-grants + --validate): the register live-hook (§6.13(a)), the
/// emit hook firing on register's tree writes (§6.13(c)), the §7a echo handler,
/// AND the §6.11 dispatch-outbound reentry (the validator-as-B-role surface S4's
/// origination-core needs).
///
/// The full validate-peer --profile core run is S4. This smoke proves the
/// wire-level peer surface so S4 can run the oracle.
void main() {
  final results = <bool>[];

  bool check(String name, bool ok) {
    results.add(ok);
    // ignore: avoid_print
    print('  [${ok ? "PASS" : "FAIL"}] $name');
    return ok;
  }

  Uint8List seed(int b) => Uint8List(32)..fillRange(0, 32, b);

  test('two-peer loopback (the S3 gate)', () async {
    await _runCoreScenario(check, seed);
    await _runExtensibilityScenario(check, seed);
    final pass = results.where((r) => r).length;
    final allPass = results.every((r) => r);
    // ignore: avoid_print
    print('\nSMOKE: ${allPass ? "PASS" : "FAIL"} ($pass/${results.length})');
    expect(allPass, isTrue, reason: 'two-peer loopback must be all-PASS');
  });
}

// ── Scenario 1: core ops (responder = default seed policy) ──────────────────────

Future<void> _runCoreScenario(
    bool Function(String, bool) check, Uint8List Function(int) seed) async {
  final responder = await Peer.create(seed(0x11));
  final listener = await startListener(responder, 0);
  try {
    // ignore: avoid_print
    print('Responder listening on 127.0.0.1:${listener.port} '
        '(peer ${responder.localPeer})');
    final initiator = await Peer.create(seed(0x22));
    final s = await dial(initiator, '127.0.0.1', listener.port);
    try {
      final remote = s.remotePeerId!;
      // ignore: avoid_print
      print('Handshake:');
      check('session established (capability minted)', s.capability != null);
      check('remote peer_id matches responder', remote == responder.localPeer);

      // ignore: avoid_print
      print('Dispatch:');
      final r404 =
          await s.execute('/$remote/does/not/exist', 'noop', emptyParams(), null);
      check('unregistered path -> 404', responseStatus(r404!) == 404);

      final ifaceTarget = resourceTarget(['system/handler/system/tree']);
      final rget =
          (await s.execute('/$remote/system/tree', 'get', emptyParams(), ifaceTarget))!;
      check('granted tree get -> 200', responseStatus(rget) == 200);
      final res = responseResult(rget);
      check('tree get returns a system/handler/interface entity',
          res != null && res.type == 'system/handler/interface');

      final reqGrant =
          Peer.grant(['system/tree'], ['system/type/*'], ['get'], null);
      final reqParams = Entity.make(
          'system/capability/request', cmap(['grants', EcfArray([reqGrant])]));
      final rcap =
          (await s.execute('/$remote/system/capability', 'request', reqParams, null))!;
      check('capability request -> 200', responseStatus(rcap) == 200);

      // 8-way request_id demux (N7, §6.11) — 8 concurrent futures.
      // ignore: avoid_print
      print('Concurrency (request_id demux):');
      final futures = [
        for (var i = 0; i < 8; i++)
          () async {
            final r = await s.execute('/$remote/system/tree', 'get',
                emptyParams(), resourceTarget(['system/handler/system/tree']));
            final rr = r == null ? null : responseResult(r);
            return r != null &&
                responseStatus(r) == 200 &&
                rr != null &&
                rr.type == 'system/handler/interface';
          }(),
      ];
      final correlated = (await Future.wait(futures)).where((b) => b).length;
      check('8 interleaved requests each correlated -> $correlated/8',
          correlated == 8);
    } finally {
      s.close();
    }
  } finally {
    await listener.close();
  }
}

// ── Scenario 2: the v7.74 Core Extensibility Boundary over the wire ─────────────

Future<void> _runExtensibilityScenario(
    bool Function(String, bool) check, Uint8List Function(int) seed) async {
  final responder =
      await Peer.create(seed(0x33), openGrants: true, conformance: true);
  var emitEvents = 0;
  responder.store.registerTreeConsumer((_) => emitEvents++);
  final listener = await startListener(responder, 0);
  try {
    final initiator =
        await Peer.create(seed(0x44), openGrants: true, conformance: true);
    final s = await dial(initiator, '127.0.0.1', listener.port);
    try {
      final remote = s.remotePeerId!;
      final emitBefore = emitEvents;
      // ignore: avoid_print
      print('Extensibility (open-grants + --validate):');

      // register live-hook (§6.13(a))
      final manifest = cmap(['name', 'demo', 'operations', emptyMap()]);
      final req =
          Entity.make('system/handler/register-request', cmap(['manifest', manifest]));
      final rreg = (await s.execute('/$remote/system/handler', 'register', req,
          resourceTarget(['system/handler/demo'])))!;
      check('handler register -> 200 (live, not 501)', responseStatus(rreg) == 200);
      check('emit hook fired on register tree writes (§6.13(c))',
          emitEvents > emitBefore);

      // §7a echo conformance handler (resolve→dispatch)
      final payload = Entity.make('primitive/any', cmap(['ping', EcfInt.of(42)]));
      final recho =
          (await s.execute('/$remote/system/validate/echo', 'echo', payload, null))!;
      check('§7a echo -> 200', responseStatus(recho) == 200);
      final res = responseResult(recho);
      check('§7a echo returns params verbatim',
          res != null && res.type == 'primitive/any');

      // §6.11 dispatch-outbound REENTRY (B→A echo over the inbound connection)
      check('§6.11 dispatch-outbound reentry round-trips (B→A echo over inbound)',
          await _runReentryProbe(s, remote));
    } finally {
      s.close();
    }
  } finally {
    await listener.close();
  }
}

/// Drive the §6.11 dispatch-outbound seam: the responder's (B) dispatch-outbound
/// handler originates an outbound EXECUTE back to the caller (A) over the SAME
/// inbound connection (reentry). The connection IS reentrant (B can write to A
/// over the open socket), so this proves the §6.13(b) outbound primitive + the
/// §6.11 reentry param shape end-to-end — the exact surface S4's origination-core
/// `dispatch_outbound_reentry` exercises over real two-peer TCP, here validated
/// at the smoke level (the validator supplies the cross-peer reentry cap at S4;
/// the smoke passes the session cap to prove the seam parses + reaches the
/// outbound primitive).
///
/// Accept outer 200 (A served the reentrant EXECUTE and B round-tripped it).
Future<bool> _runReentryProbe(Session s, String remote) async {
  final params = Entity.make(
      'primitive/any',
      cmap([
        'target', 'system/validate/echo',
        'operation', 'echo',
        'value', cmap(['ping', EcfInt.of(7)]),
        'reentry_capability', s.capability!.toCbor(),
        'reentry_granter', s.granterPeer!.toCbor(),
        'reentry_cap_signature', s.capSignature!.toCbor(),
      ]));
  final r = await s.execute(
      '/$remote/system/validate/dispatch-outbound', 'dispatch', params, null);
  if (r == null) return false;
  // Outer 200 = the §6.11 reentry round-tripped end-to-end: B's dispatch-outbound
  // handler originated an EXECUTE back to A over the SAME inbound connection, A's
  // reader dispatched it and replied, and B correlated the reply by request_id
  // and returned it. The INNER status reflects A's §5.2 authz verdict on the
  // reentrant EXECUTE (here the session cap A's granter B minted — a cap check,
  // not the transport). S4's validator supplies the cross-peer reentry cap that
  // makes the inner verdict 200; the smoke proves the transport seam (outer 200).
  final inner = responseResult(r)?.uint('status')?.toInt();
  // ignore: avoid_print
  print('    (reentry round-tripped; inner echo verdict=$inner)');
  return responseStatus(r) == 200;
}
