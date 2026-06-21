import 'dart:typed_data';

import 'package:entity_core_protocol/entity_core_peer.dart';
import 'package:test/test.dart';

/// §9.5 core type-registry smoke (the type-registry N/N gate).
///
/// A bootstrapped peer publishes the full §9.5 53-type core floor at
/// `/{peer}/system/type/{name}` (render-from-model — the content_hash of each is
/// computed by THIS peer's S2-green codec over `{type, data}`). This test
/// verifies, for every one of the 53 floor types:
///  - it is rendered + bound in the store (reachable at its tree path);
///  - its content_hash is a 33-byte ecfv1-sha256 hash (format byte 0x00 + digest);
///  - the render is DETERMINISTIC (a re-render yields the byte-identical hash).
///
/// The byte-for-byte diff against the canonical `type-registry-vectors-v1` is the
/// S4 `type_system` category; this S3 smoke proves the 53/53 floor renders +
/// binds + is stable, so the registry surface the oracle fetches exists.
void main() {
  test('§9.5 core type floor publishes 53/53 (rendered + bound + stable)',
      () async {
    final peer = await Peer.create(Uint8List(32)..fillRange(0, 32, 0x11));
    final local = peer.localPeer;
    final models = coreTypeModels();
    expect(models.length, 53, reason: 'the §9.5 core floor is exactly 53 types');

    var checked = 0;
    models.forEach((name, model) {
      final e = peer.store.getAt('/$local/system/type/$name');
      expect(e, isNotNull, reason: 'core type published at tree path: $name');
      expect(e!.type, 'system/type', reason: '$name is a system/type entity');
      final h = e.hash();
      expect(h.length, 33,
          reason: '$name content_hash is 33 bytes (format byte + digest)');
      expect(h[0], 0,
          reason: '$name content_hash format byte is 0x00 (ecfv1-sha256)');
      // determinism: a fresh render of the same model yields an identical hash.
      final rerendered = Entity.make('system/type', model);
      expect(octetsEqual(rerendered.hash(), h), isTrue,
          reason: '$name render is deterministic');
      checked++;
    });
    expect(checked, 53);
    // ignore: avoid_print
    print('TYPE-REGISTRY: PASS ($checked/${models.length} core types stable)');
  });
}
