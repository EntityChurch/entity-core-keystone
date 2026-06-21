import 'dart:typed_data';

import 'cbor.dart';
import 'entity.dart';

/// A tree-change event (§6.10 Bind step).
final class TreeEvent {
  const TreeEvent(this.eventType, this.path, this.newHash, this.previousHash);
  final String eventType;
  final String path;
  final String? newHash;
  final String? previousHash;
}

/// A content-store event (§6.10 Store step).
final class ContentEvent {
  const ContentEvent(this.hash, this.entity);
  final Uint8List hash;
  final Entity entity;
}

/// One-level listing entry: a segment, its bound hash (or null), and whether the
/// segment has deeper descendants.
final class ListEntry {
  const ListEntry(this.segment, this.hashHex, this.hasChildren);
  final String segment;
  final String? hashHex;
  final bool hasChildren;
}

/// Storage (foundation, §1.7): the two layers.
///
/// ```
///   Content Store: hash → entity   (immutable, content-addressed, dedup)
///   Entity Tree:   path → hash     (mutable location index)
/// ```
///
/// In-memory minimal impl. Paths are the canonical absolute form
/// `/{peer_id}/rest` (§1.4); the peer canonicalizes before calling in. Path keys
/// are strings; the content store is keyed by the lowercase-hex content_hash (so
/// a byte hash works as a string map key).
///
/// **EMIT PATHWAY (§6.10 / v7.74 §6.13(c)) — the Core Extensibility Boundary.**
/// Tree/content writes produce events delivered to registered consumers. The hook
/// is LIVE even with ZERO consumers (events are produced and discarded) so a
/// future extension can register a consumer WITHOUT rebuilding the peer (the
/// §6.13(c) MUST). A core-only peer registers zero consumers, but the seam is
/// exercised on every bind.
///
/// **§4.8 store data-race safety (profile [async].store_safety =
/// event-loop-confinement).** Dart runs ONE event-loop isolate; there is NO
/// preemption, so a synchronous critical section over these maps is atomic BY
/// CONSTRUCTION (no data race possible without an `await` mid-section). Every
/// store method here is fully synchronous — read-modify-write of `_tree` /
/// `_content` never yields, so concurrent inbound dispatches (each its own
/// async task) interleave only at `await` points, never inside a store op. This
/// is the cleanest point in the §7b menu (akin to the actor-isolation peers),
/// the same reason A-C-009 (no-GC shared-entity race) is N/A: Dart is GC'd AND
/// single-threaded per isolate, so a shared entity is never concurrently mutated.
final class Store {
  final Map<String, Entity> _content = {}; // hash-hex → entity
  final Map<String, String> _tree = {}; // path → hash-hex
  final List<void Function(ContentEvent)> _contentConsumers = [];
  final List<void Function(TreeEvent)> _treeConsumers = [];

  // ── emit consumer registration (§6.10 consumer-registration primitive) ──────
  // Reachable any time, including post-bootstrap. Delivery is sync-inline (§9.4).

  void registerContentConsumer(void Function(ContentEvent) fn) =>
      _contentConsumers.add(fn);

  void registerTreeConsumer(void Function(TreeEvent) fn) =>
      _treeConsumers.add(fn);

  String _deriveEventType(String? previous, String? next) {
    if (previous == null) return 'created';
    if (next == null) return 'deleted';
    return 'modified';
  }

  // ── content store (§6.10 Store step: event only when the entity is new) ─────

  void putEntity(Entity e) {
    final k = hexEncode(e.rawHash);
    if (!_content.containsKey(k)) {
      _content[k] = e;
      final ev = ContentEvent(e.hash(), e);
      for (final fn in List.of(_contentConsumers)) {
        fn(ev);
      }
    }
  }

  Entity? getByHash(List<int> h) => _content[hexEncode(h)];

  // ── entity tree (§6.10 Bind step: event when the binding at the path changes) ─

  void bind(String path, Entity e) {
    putEntity(e);
    final next = hexEncode(e.rawHash);
    final prev = _tree[path];
    _tree[path] = next;
    if (next != prev) {
      final ev = TreeEvent(_deriveEventType(prev, next), path, next, prev);
      for (final fn in List.of(_treeConsumers)) {
        fn(ev);
      }
    }
  }

  void unbind(String path) {
    final prev = _tree.remove(path);
    if (prev != null) {
      final ev = TreeEvent('deleted', path, null, prev);
      for (final fn in List.of(_treeConsumers)) {
        fn(ev);
      }
    }
  }

  /// The hex content_hash bound at [path], or null.
  String? hashAt(String path) => _tree[path];

  Entity? getAt(String path) {
    final h = _tree[path];
    return h == null ? null : _content[h];
  }

  /// One-level listing under [prefix] (a path; a trailing slash is added if
  /// absent). Returns entries sorted by segment (§3.9).
  List<ListEntry> listing(String prefix) {
    final p = prefix.endsWith('/') ? prefix : '$prefix/';
    final plen = p.length;
    // segment → (hashOrNull, deeper).
    final acc = <String, _Cell>{};
    _tree.forEach((path, hash) {
      if (path.length > plen && path.startsWith(p)) {
        final rest = path.substring(plen);
        final slash = rest.indexOf('/');
        if (slash >= 0) {
          final seg = rest.substring(0, slash);
          final cur = acc[seg] ?? _Cell(null, false);
          acc[seg] = _Cell(cur.hash, true);
        } else {
          final cur = acc[rest] ?? _Cell(null, false);
          acc[rest] = _Cell(hash, cur.deeper);
        }
      }
    });
    final segs = acc.keys.toList()..sort();
    return [
      for (final seg in segs) ListEntry(seg, acc[seg]!.hash, acc[seg]!.deeper),
    ];
  }
}

final class _Cell {
  _Cell(this.hash, this.deeper);
  final String? hash;
  final bool deeper;
}
