import 'dart:typed_data';

import '../codec/ecf_value.dart';

/// Small constructor + accessor helpers over the S2 [EcfValue] model, plus the
/// address-space hex convention. Keeps the peer code reading at the protocol
/// altitude (map/list builders, typed field reads) instead of restating the
/// codec value model inline. Dart-idiomatic: top-level functions in a library,
/// nullable returns via `T?` (no `Optional`), record-free positional builders.
///
/// **lowercase hex (A-CL-009 trap, applied proactively — profile [naming]
/// hex_case=lowercase).** [hexEncode] renders LOWERCASE — the §3.4/§3.5
/// tree-path convention. Tree paths are case-sensitive string keys
/// (`system/signature/{hash}`, the §5.1 revocation marker, the §6.9a policy
/// path); an uppercase default would be internally consistent but
/// cross-incompatible (the Common Lisp peer's lesson). Lowercase everywhere.

const _hexChars = '0123456789abcdef';

// ── builders ────────────────────────────────────────────────────────────────

/// Build a map from alternating `(key, value)` pairs. A `String` key becomes
/// [EcfText]; values are coerced via [coerce].
EcfMap cmap(List<Object?> kvs) {
  assert(kvs.length.isEven, 'odd kv count');
  final es = <EcfEntry>[];
  for (var i = 0; i < kvs.length; i += 2) {
    final k = kvs[i];
    final key = k is String ? EcfText(k) : k as EcfValue;
    es.add(EcfEntry(key, coerce(kvs[i + 1])));
  }
  return EcfMap(es);
}

/// The canonical empty map (a single 0xA0 byte).
EcfMap emptyMap() => EcfMap(const []);

/// Coerce a Dart value to its [EcfValue] node.
EcfValue coerce(Object? v) => switch (v) {
      EcfValue() => v,
      String() => EcfText(v),
      Uint8List() => EcfBytes(v),
      List<int>() => EcfBytes(v),
      bool() => v ? EcfBool.trueValue : EcfBool.falseValue,
      BigInt() => EcfInt(v),
      int() => EcfInt.of(v),
      null => EcfNull.instance,
      _ => throw ArgumentError('cannot coerce to EcfValue: ${v.runtimeType}'),
    };

EcfValue cbytes(List<int> b) => EcfBytes(b);

EcfArray textArray(List<String> ss) =>
    EcfArray(ss.map((s) => EcfText(s) as EcfValue).toList());

EcfArray cArray(List<EcfValue> items) => EcfArray(items);

EcfInt cint(int v) => EcfInt.of(v);

// ── typed field reads (over a map value, null-safe) ───────────────────────────

EcfMap? asMap(EcfValue? v) => v is EcfMap ? v : null;

String? mtext(EcfMap? m, String key) {
  final v = m?[key];
  return v is EcfText ? v.value : null;
}

Uint8List? mbytes(EcfMap? m, String key) {
  final v = m?[key];
  return v is EcfBytes ? v.octets : null;
}

BigInt? muint(EcfMap? m, String key) {
  final v = m?[key];
  return v is EcfInt ? v.value : null;
}

/// The text values of an array field (non-text items skipped), or null.
List<String>? textList(EcfMap? m, String key) {
  final v = m?[key];
  if (v is! EcfArray) return null;
  return v.items
      .whereType<EcfText>()
      .map((t) => t.value)
      .toList(growable: false);
}

/// The map values of an array field, or null.
List<EcfMap>? mapList(EcfMap? m, String key) {
  final v = m?[key];
  if (v is! EcfArray) return null;
  return v.items.whereType<EcfMap>().toList(growable: false);
}

bool ecfIsTrue(EcfValue? v) => v == EcfBool.trueValue;

// ── hex ───────────────────────────────────────────────────────────────────────

/// LOWERCASE hex (the §3.4/§3.5 address-space convention; A-CL-009).
String hexEncode(List<int> octets) {
  final out = StringBuffer();
  for (final b0 in octets) {
    final b = b0 & 0xff;
    out
      ..write(_hexChars[b >> 4])
      ..write(_hexChars[b & 0x0f]);
  }
  return out.toString();
}

Uint8List hexDecode(String s) {
  final n = s.length ~/ 2;
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Constant-shape octet equality (null-safe). Both null → false.
bool octetsEqual(List<int>? a, List<int>? b) {
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool isZeroHash(List<int> h) {
  for (final b in h) {
    if (b != 0) return false;
  }
  return true;
}
