import 'dart:typed_data';

import '../errors.dart';

/// Multicodec-style unsigned LEB128 varints (V7 §1.5 / §7.3).
///
/// Invariant N1: every format-code / key-type / hash-type prefix is routed
/// through a REAL varint primitive, NOT a fixed byte. All currently-allocated
/// codes are < 0x80 (single byte), but a code >= 0x80 MUST extend correctly
/// (`128 -> 0x80 0x01`). The corpus exercises this with synthetic high codes
/// (content_hash.4 fc=128, peer_id.3 key_type=128).
///
/// The unsigned value carries through a [BigInt] so the full 64-bit range is
/// handled without a signed-shift footgun (and web-safe — same A-DART-006
/// reasoning as the integer head-form carrier).
class Varint {
  Varint._();

  /// Encode a non-negative [BigInt] as an unsigned LEB128 byte array.
  static Uint8List encodeBig(BigInt n) {
    if (n.isNegative) {
      throw ArgumentError('varint value must be non-negative: $n');
    }
    final out = <int>[];
    var v = n;
    final mask = BigInt.from(0x7f);
    do {
      var b = (v & mask).toInt();
      v = v >> 7;
      if (v != BigInt.zero) b |= 0x80;
      out.add(b);
    } while (v != BigInt.zero);
    return Uint8List.fromList(out);
  }

  /// Encode a non-negative Dart int as an unsigned LEB128 byte array.
  static Uint8List encode(int n) => encodeBig(BigInt.from(n));

  /// Decode an unsigned LEB128 varint from [buf] at [start].
  ///
  /// Throws an internal [EcfException] (carrying a sealed [EntityError]) on
  /// truncation or >64-bit overflow; the calling layer translates it to a
  /// result.
  static VarintDecoded decode(Uint8List buf, int start) {
    var value = BigInt.zero;
    var shift = 0;
    var i = start;
    while (true) {
      if (i >= buf.length) {
        throw const EcfException(TruncatedInput('varint: ran off end'));
      }
      if (shift >= 64) {
        throw const EcfException(NonCanonicalEcf('varint: exceeds 64 bits'));
      }
      final b = buf[i];
      i++;
      value |= BigInt.from(b & 0x7f) << shift;
      if (b & 0x80 == 0) return VarintDecoded(value, i);
      shift += 7;
    }
  }
}

/// A decoded varint: the value plus the index just past it.
class VarintDecoded {
  const VarintDecoded(this.value, this.next);
  final BigInt value;
  final int next;
}
