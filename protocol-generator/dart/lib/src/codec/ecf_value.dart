import 'dart:typed_data';

/// The decoded-form value model for Entity Canonical Form (ECF).
///
/// A Dart-3 `sealed` hierarchy gives the codec/dispatch ladders an EXHAUSTIVE
/// `switch` EXPRESSION (the analyzer checks coverage over the closed set — no
/// `default` needed). This is the Dart static-exhaustiveness seam (the Kotlin
/// sealed-`when` analogue). See profile.toml [idiom].sealed_classes + A-DART-004.
///
/// Why an explicit model rather than reusing Dart stdlib types directly: ECF
/// requires `absent != null != false != 0` on the wire (V7 §1.3), and a CBOR
/// byte string (major 2) must stay distinct from a text string (major 3). So:
///  - booleans/null are explicit nodes ([EcfBool], [EcfNull]) — never erased to
///    a Dart `null`/`bool`;
///  - byte strings are [EcfBytes] (major 2), text is [EcfText] (major 3);
///  - integral-valued floats keep an explicit [EcfFloat] node so `1.0` encodes
///    as a float (the f16 ladder), never as integer 1;
///  - NaN/±Inf/-0.0 are carried as [EcfFloatSpecial] constants so a NaN/Inf
///    never has to round-trip through a Dart `double`.
///
/// Integers use [BigInt] ([EcfInt]) so the FULL uint64 / -2^64 head-form range
/// is representable — and, critically, web-safe: a bare Dart `int` is 64-bit on
/// the VM but 53-bit under dart2js/web, so a uint64-range head value near 2^63
/// would silently truncate. [BigInt] is arbitrary-precision on BOTH native and
/// web. The single most important codec-correctness decision (A-DART-006).
sealed class EcfValue {
  const EcfValue();
}

/// CBOR major-type 0/1 integer, carried as a [BigInt] (full uint64 / -2^64).
final class EcfInt extends EcfValue {
  const EcfInt(this.value);

  /// Construct from a (safe-range) Dart int.
  EcfInt.of(int v) : value = BigInt.from(v);

  final BigInt value;

  @override
  bool operator ==(Object other) => other is EcfInt && other.value == value;
  @override
  int get hashCode => value.hashCode;
  @override
  String toString() => 'EcfInt($value)';
}

/// A finite floating-point value (encoded via the shortest f16/f32/f64 ladder).
final class EcfFloat extends EcfValue {
  const EcfFloat(this.value);
  final double value;

  @override
  bool operator ==(Object other) =>
      other is EcfFloat && other.value.compareTo(value) == 0;
  @override
  int get hashCode => value.hashCode;
  @override
  String toString() => 'EcfFloat($value)';
}

/// The ECF Rule-4a special floats, carried as sentinels so the canonical wire
/// bytes are emitted directly and a NaN/Inf never materializes as a `double`.
enum EcfFloatSpecial implements EcfValue {
  nan,
  positiveInfinity,
  negativeInfinity,
  negativeZero,
}

/// CBOR byte string (major 2). The [Uint8List] is defensively copied in and out
/// — Dart `Uint8List` is mutable + aliasable (no_byte_array_aliasing); `final`
/// makes the REFERENCE immutable, not the contents, so the codec NEVER aliases
/// an internal buffer by reference.
final class EcfBytes extends EcfValue {
  EcfBytes(List<int> octets) : _data = Uint8List.fromList(octets);

  /// Internal: take ownership of an already-owned buffer without a copy (the
  /// codec hot path, which produced the buffer itself). Not for external use.
  EcfBytes.owned(this._data);

  final Uint8List _data;

  /// Defensive copy on read.
  Uint8List get octets => Uint8List.fromList(_data);

  /// Internal no-copy accessor for the codec hot path (caller must not mutate).
  Uint8List get rawUnsafe => _data;

  int get length => _data.length;

  @override
  bool operator ==(Object other) =>
      other is EcfBytes && _bytesEqual(_data, other._data);
  @override
  int get hashCode => Object.hashAll(_data);
  @override
  String toString() => 'EcfBytes(${_data.length}B)';
}

/// CBOR text string (major 3), held as a Dart [String] (UTF-8 on the wire).
final class EcfText extends EcfValue {
  const EcfText(this.value);
  final String value;

  @override
  bool operator ==(Object other) => other is EcfText && other.value == value;
  @override
  int get hashCode => value.hashCode;
  @override
  String toString() => 'EcfText($value)';
}

/// CBOR array (major 4), definite length. Holds a defensive-copy list.
final class EcfArray extends EcfValue {
  EcfArray(List<EcfValue> items) : items = List.unmodifiable(items);
  final List<EcfValue> items;

  @override
  bool operator ==(Object other) =>
      other is EcfArray && _listEqual(items, other.items);
  @override
  int get hashCode => Object.hashAll(items);
  @override
  String toString() => 'EcfArray(${items.length})';
}

/// A single map key/value pair (the key is [EcfText] or [EcfBytes] in canonical
/// ECF). Decode/construct order is preserved; the ENCODER re-sorts by encoded-key
/// length-then-lex (ECF Rule 2).
final class EcfEntry {
  const EcfEntry(this.key, this.value);
  final EcfValue key;
  final EcfValue value;

  @override
  bool operator ==(Object other) =>
      other is EcfEntry && other.key == key && other.value == value;
  @override
  int get hashCode => Object.hash(key, value);
}

/// CBOR map (major 5). Entries are held in construct/decode order as a list; the
/// encoder re-sorts. Keys are [EcfText] or [EcfBytes].
final class EcfMap extends EcfValue {
  EcfMap(List<EcfEntry> entries) : entries = List.unmodifiable(entries);

  final List<EcfEntry> entries;

  /// Build a map from a `{String|EcfValue : EcfValue}` literal (String keys are
  /// wrapped as [EcfText]). Insertion order preserved (the encoder re-sorts).
  factory EcfMap.of(Map<Object, EcfValue> kvs) {
    final es = <EcfEntry>[];
    kvs.forEach((k, v) {
      final key = k is String ? EcfText(k) : k as EcfValue;
      es.add(EcfEntry(key, v));
    });
    return EcfMap(es);
  }

  /// Fetch a value by text key; null if absent.
  EcfValue? operator [](String key) {
    for (final e in entries) {
      final k = e.key;
      if (k is EcfText && k.value == key) return e.value;
    }
    return null;
  }

  @override
  bool operator ==(Object other) =>
      other is EcfMap && _entriesEqual(entries, other.entries);
  @override
  int get hashCode => Object.hashAll(entries);
  @override
  String toString() => 'EcfMap(${entries.length})';
}

/// CBOR true/false (major 7). A node, never a bare Dart `bool`.
enum EcfBool implements EcfValue { trueValue, falseValue }

/// CBOR null (major 7, value 22). A singleton — distinct from a Dart null.
final class EcfNull extends EcfValue {
  const EcfNull._();
  static const EcfNull instance = EcfNull._();
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool _listEqual(List<EcfValue> a, List<EcfValue> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool _entriesEqual(List<EcfEntry> a, List<EcfEntry> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
