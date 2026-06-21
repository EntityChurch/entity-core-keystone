import 'dart:typed_data';

import '../codec/ecf.dart';
import '../codec/ecf_value.dart';
import '../crypto/content_hash.dart';
import 'cbor.dart';

/// A materialized entity `{type, data, content_hash}` (§1.1, §3.4) on top of the
/// S2 codec value model.
///
/// The content_hash covers ONLY `{type, data}` (§1.1); the wire form ([toCbor])
/// carries content_hash as a third field so entities are self-describing across
/// serialization (§3.1). The two forms stay distinct: the hash is never computed
/// over a map that already contains the content_hash field.
///
/// The 33-byte [hash] (format byte 0x00 ‖ 32-byte SHA-256 digest) is a
/// [Uint8List]; it is defensively copied in/out (profile `no_byte_array_aliasing`
/// — Dart Uint8List is mutable + aliasable, and `final` makes the REFERENCE
/// immutable, not the CONTENTS). [rawData] is an arbitrary ECF value (§1.1) — a
/// map for protocol entities, a scalar for e.g. primitive/string payloads.
///
/// Content_hash IS sync: [ContentHash.compute] is a pure SHA-256 over the
/// S2-green encoder — no `Future`. Only signing/verifying (which touch Ed25519)
/// are async; entity construction stays synchronous, matching the codec surface.
///
/// Equality is content_hash-based (a Dart value-equality over the digest), so
/// `==` / `hashCode` are overridden by hand.
final class Entity {
  Entity._(this.type, this._rawData, this._hash);

  final String type;
  final EcfValue _rawData;
  final Uint8List _hash;

  /// Construct a materialized entity with a map `data` (the common protocol
  /// case), computing content_hash under the ecfv1-sha256 floor (format 0x00).
  factory Entity.make(String type, EcfMap data) => Entity.makeRaw(type, data);

  /// Construct a materialized entity with an ARBITRARY ECF `data` value (§1.1) —
  /// covers scalar-data entities like primitive/string.
  factory Entity.makeRaw(String type, EcfValue data) {
    final basis = EcfMap.of({'type': EcfText(type), 'data': data});
    final h = ContentHash.compute(basis);
    return Entity._(type, data, h);
  }

  /// Parse a wire entity cbor-map, recompute the hash from `{type, data}`, and
  /// validate it against the carried content_hash (§1.8 fidelity). We trust our
  /// recomputed hash, not the wire bytes (§5.2 validate-before-trust).
  factory Entity.ofCbor(EcfMap m) {
    final typeV = m['type'];
    final dataV = m['data'];
    if (typeV is! EcfText) {
      throw ArgumentError('entity: missing/invalid type');
    }
    if (dataV == null) {
      throw ArgumentError('entity: missing data');
    }
    final e = Entity.makeRaw(typeV.value, dataV);
    final carried = m['content_hash'];
    if (carried is EcfBytes && !octetsEqual(carried.octets, e._hash)) {
      throw ArgumentError('content_hash mismatch (§1.8 fidelity)');
    }
    return e;
  }

  /// The `data` as a map view: the map itself when data IS a map (every core
  /// protocol entity), or the canonical empty map when data is a scalar (so
  /// field reads on a scalar-data entity safely return null rather than throw).
  EcfMap data() {
    final d = _rawData;
    return d is EcfMap ? d : EcfMap(const []);
  }

  /// The raw `data` value (§1.1) — may be any ECF node, not just a map.
  EcfValue rawData() => _rawData;

  /// Defensive copy of the 33-byte content_hash.
  Uint8List hash() => Uint8List.fromList(_hash);

  /// Internal no-copy accessor (callers must not mutate).
  Uint8List get rawHash => _hash;

  // ── field reads off data ────────────────────────────────────────────────────

  String? text(String key) => mtext(data(), key);
  Uint8List? bytes(String key) => mbytes(data(), key);
  BigInt? uint(String key) => muint(data(), key);
  EcfValue? field(String key) => data()[key];
  EcfMap? mapField(String key) => asMap(data()[key]);

  /// Decode a nested entity carried at [key] (a wire cbor-map).
  Entity? entityField(String key) {
    final m = mapField(key);
    return m == null ? null : Entity.ofCbor(m);
  }

  // ── wire form ───────────────────────────────────────────────────────────────

  /// The wire cbor-map `{type, data, content_hash}`.
  EcfMap toCbor() => EcfMap.of({
        'type': EcfText(type),
        'data': _rawData,
        'content_hash': EcfBytes(_hash),
      });

  /// Encode the wire form to canonical ECF bytes.
  Uint8List wireBytes() => Ecf.encodeOrThrow(toCbor());

  @override
  bool operator ==(Object other) =>
      other is Entity && octetsEqual(_hash, other._hash);

  @override
  int get hashCode => Object.hashAll(_hash);

  @override
  String toString() => 'Entity($type, ${hexEncode(_hash)})';
}
