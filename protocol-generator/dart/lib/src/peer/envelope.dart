import 'dart:typed_data';

import '../codec/ecf_value.dart';
import 'cbor.dart';
import 'entity.dart';

/// One included entry: a content_hash (33 bytes) and its entity. Identity is by
/// the entity's content_hash (the Uint8List is defensively held).
final class Included {
  Included(List<int> hash, this.entity) : hash = Uint8List.fromList(hash);
  final Uint8List hash;
  final Entity entity;
}

/// The protocol envelope (§3.1): a [root] entity plus an [included] list of
/// protocol entities keyed by content_hash. `included` is the §5.8 authority
/// carrier (caps, peer identities, signatures travel here).
///
/// Held as an insertion-ordered list of (hash, entity) pairs so a wire
/// round-trip is deterministic; lookup is by content_hash octets.
final class Envelope {
  Envelope(this.root, [List<Included> included = const []])
      : included = List.unmodifiable(included);

  final Entity root;
  final List<Included> included;

  /// Find an included entity by its content_hash, or null.
  Entity? includedGet(List<int> h) {
    for (final it in included) {
      if (octetsEqual(it.hash, h)) return it.entity;
    }
    return null;
  }

  // ── wire form ───────────────────────────────────────────────────────────────

  EcfMap toCbor() {
    // §3.1: `included` is a content_hash → entity MAP, so duplicate hashes
    // collapse to one entry. The peer/transport builders may list the same
    // entity twice (e.g. a cap whose granter IS the local identity —
    // granterPeer == peerEntity in the §6.11 reentry path), which would
    // otherwise emit a duplicate map key that the canonical codec rejects on
    // decode. Dedup by content_hash, preserving first-seen order, before
    // encoding. (Mirror of the Kotlin A-KT-010 fix.)
    final seen = <String>{};
    final inc = <EcfEntry>[];
    for (final it in included) {
      if (seen.add(hexEncode(it.hash))) {
        inc.add(EcfEntry(EcfBytes(it.hash), it.entity.toCbor()));
      }
    }
    return EcfMap.of({
      'root': root.toCbor(),
      'included': EcfMap(inc),
    });
  }

  static Envelope ofCbor(EcfMap m) {
    final rootV = m['root'];
    if (rootV is! EcfMap) throw ArgumentError('envelope: missing root');
    final root = Entity.ofCbor(rootV);
    final included = <Included>[];
    final incM = m['included'];
    if (incM is EcfMap) {
      // dedup by content_hash, preserving order (defensive — a well-formed
      // envelope has unique keys; the codec already rejects duplicate map keys).
      final seen = <String>{};
      for (final e in incM.entries) {
        final kb = e.key;
        final vm = e.value;
        if (kb is! EcfBytes) {
          throw ArgumentError('envelope: included key not bytes');
        }
        if (vm is! EcfMap) {
          throw ArgumentError('envelope: included value not a map');
        }
        final ent = Entity.ofCbor(vm);
        // §3.1: the included content_hash MUST equal the map key.
        if (!octetsEqual(kb.octets, ent.rawHash)) {
          throw ArgumentError('included key != content_hash');
        }
        if (seen.add(hexEncode(kb.octets))) {
          included.add(Included(kb.octets, ent));
        }
      }
    }
    return Envelope(root, included);
  }
}
