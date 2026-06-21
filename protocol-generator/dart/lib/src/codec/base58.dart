import 'dart:typed_data';

/// Base58 (Bitcoin alphabet) encode/decode, hand-rolled (dodges a pub dep + pin;
/// profile [codec].base58_library = "hand-rolled").
///
/// Used for peer-id formatting/parsing (V7 §1.2 / §7.3). Leading zero bytes map
/// to a leading `'1'` each, per the standard Base58 convention (leading-zero
/// preserving in both directions). The big-integer long-division uses [BigInt]
/// (web-safe arbitrary precision).
class Base58 {
  Base58._();

  static const String _alphabet =
      '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  static final BigInt _fiftyEight = BigInt.from(58);
  static final List<int> _index = _buildIndex();

  static List<int> _buildIndex() {
    final idx = List<int>.filled(128, -1);
    for (var i = 0; i < _alphabet.length; i++) {
      idx[_alphabet.codeUnitAt(i)] = i;
    }
    return idx;
  }

  /// Encode a byte array to a Base58 string.
  static String encode(List<int> octets) {
    var zeros = 0;
    while (zeros < octets.length && octets[zeros] == 0) {
      zeros++;
    }
    var n = _fromBytes(octets);
    final buf = StringBuffer();
    while (n > BigInt.zero) {
      final qr = n ~/ _fiftyEight;
      final rem = (n - qr * _fiftyEight).toInt();
      buf.writeCharCode(_alphabet.codeUnitAt(rem));
      n = qr;
    }
    final body = buf.toString().split('').reversed.join();
    return ('1' * zeros) + body;
  }

  /// Decode a Base58 string to a byte array (leading-zero preserving).
  static Uint8List decode(String s) {
    var ones = 0;
    while (ones < s.length && s.codeUnitAt(ones) == 0x31 /* '1' */) {
      ones++;
    }
    var n = BigInt.zero;
    for (var i = 0; i < s.length; i++) {
      final c = s.codeUnitAt(i);
      final d = c < 128 ? _index[c] : -1;
      if (d < 0) throw ArgumentError('invalid base58 char: ${s[i]}');
      n = n * _fiftyEight + BigInt.from(d);
    }
    final body = n == BigInt.zero ? Uint8List(0) : _toBytes(n);
    final out = Uint8List(ones + body.length);
    out.setRange(ones, out.length, body);
    return out;
  }

  /// Big-endian unsigned magnitude -> BigInt.
  static BigInt _fromBytes(List<int> b) {
    var n = BigInt.zero;
    for (final byte in b) {
      n = (n << 8) | BigInt.from(byte & 0xff);
    }
    return n;
  }

  /// BigInt -> big-endian unsigned magnitude (no sign byte).
  static Uint8List _toBytes(BigInt n) {
    final bytes = <int>[];
    var v = n;
    final mask = BigInt.from(0xff);
    while (v > BigInt.zero) {
      bytes.add((v & mask).toInt());
      v = v >> 8;
    }
    return Uint8List.fromList(bytes.reversed.toList());
  }
}
