// dart2js / web integer round-trip smoke (A-DART-006).
//
// Dart `int` is 64-bit on the native VM but maps to a JS number (53-bit integer
// precision) under `dart compile js` / dart2js / web. A uint64 head value near
// 2^63 would SILENTLY TRUNCATE on web if carried in a bare `int`. The codec
// carries the head-form range via `BigInt` (arbitrary precision on BOTH native
// and web), so this smoke — compiled to JS and run under node — MUST encode the
// [2^63, 2^64-1] band byte-identically to the native run, proving no truncation.
//
// Build + run:
//   dart compile js -o /tmp/web_int_smoke.js tool/web_int_smoke.dart
//   node /tmp/web_int_smoke.js
//
// Exits 0 + prints "WEB-INT SMOKE: PASS" iff every band value encodes to the
// expected canonical hex AND round-trips through decode.
import 'dart:typed_data';

import 'package:entity_core_protocol/entity_core_protocol.dart';

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  // value -> expected canonical hex (the [2^63, 2^64-1] band + -2^64).
  final cases = <String, String>{
    '9223372036854775808': '1b8000000000000000', // 2^63
    '18446744073709551615': '1bffffffffffffffff', // 2^64-1
    '12297829382473034410': '1baaaaaaaaaaaaaaaa', // 0xaaaa... mid-band
    '-18446744073709551616': '3bffffffffffffffff', // -2^64 (nint arg=2^64-1)
  };

  var failures = 0;
  cases.forEach((s, wantHex) {
    final v = EcfInt(BigInt.parse(s));
    final enc = Ecf.encode(v);
    if (enc is! Ok<Uint8List>) {
      print('FAIL $s: encode error ${(enc as Err).error}');
      failures++;
      return;
    }
    final gotHex = _hex(enc.value);
    if (gotHex != wantHex) {
      print('FAIL $s: want=$wantHex got=$gotHex (WEB TRUNCATION!)');
      failures++;
      return;
    }
    final back = Ecf.decode(enc.value);
    if (back is! Ok<EcfValue>) {
      print('FAIL $s: decode error');
      failures++;
      return;
    }
    final bv = back.value;
    if (bv is! EcfInt || bv.value != BigInt.parse(s)) {
      print('FAIL $s: round-trip mismatch got=$bv');
      failures++;
      return;
    }
  });

  if (failures == 0) {
    print('WEB-INT SMOKE: PASS (${cases.length} band values, no truncation)');
  } else {
    print('WEB-INT SMOKE: FAIL ($failures)');
    throw StateError('web int smoke failed');
  }
}
