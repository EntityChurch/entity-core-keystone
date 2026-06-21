import 'dart:typed_data';

import 'package:entity_core_protocol/entity_core_protocol.dart';
import 'package:test/test.dart';

/// Uncovered-range self-tests + Ed25519 RFC-8032 KAT.
///
/// The conformance corpus' `int` vectors top out at i64::MAX (int.10 =
/// 9223372036854775807 / 0x7fff...); the [2^63, 2^64-1] uint64 head-form band
/// and the -2^64 nint argument are NOT in the corpus. This is exactly the band a
/// signed-int (or a bare 53-bit web int) silently truncates — the F7 / A-DART-006
/// trap. We author the coverage ourselves (the codec-review-heuristic: map every
/// branch to a vector; author what the oracle can't see). The dart2js web smoke
/// (no truncation in that band) lives in a separate runnable, web_int_smoke.dart.
String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _enc(EcfValue v) => (Ecf.encode(v) as Ok<Uint8List>).value;

void main() {
  group('uint64 head-form band (BigInt carrier; beyond the corpus)', () {
    test('u64 max = 2^64-1', () {
      final v = EcfInt(BigInt.parse('18446744073709551615'));
      expect(_hex(_enc(v)), '1bffffffffffffffff');
    });
    test('2^63 (one past signed-i64 max — the critical F7 case)', () {
      final v = EcfInt(BigInt.parse('9223372036854775808'));
      expect(_hex(_enc(v)), '1b8000000000000000');
    });
    test('nint min = -2^64 (major 1, arg = 2^64-1)', () {
      final v = EcfInt(BigInt.parse('-18446744073709551616'));
      expect(_hex(_enc(v)), '3bffffffffffffffff');
    });
    test('round-trip across the band', () {
      for (final s in [
        '9223372036854775808', // 2^63
        '18446744073709551615', // 2^64-1
        '-18446744073709551616', // -2^64
        '-9223372036854775809', // one below -i64-min
      ]) {
        final v = EcfInt(BigInt.parse(s));
        final back = (Ecf.decode(_enc(v)) as Ok<EcfValue>).value;
        expect(back, v, reason: 'round-trip failed for $s');
      }
    });
  });

  group('float ladder boundaries beyond the corpus', () {
    test('f16 max 65504.0', () => expect(_hex(_enc(const EcfFloat(65504.0))), 'f97bff'));
    test('smallest f16 subnormal', () =>
        expect(_hex(_enc(const EcfFloat(5.960464477539063e-08))), 'f90001'));
    test('f32-not-f16 65503.0', () =>
        expect(_hex(_enc(const EcfFloat(65503.0))), 'fa477fdf00'));
    test('f64 1.1', () => expect(_hex(_enc(const EcfFloat(1.1))), 'fb3ff199999999999a'));
    test('NaN/Inf/-0.0 specials', () {
      expect(_hex(_enc(EcfFloatSpecial.nan)), 'f97e00');
      expect(_hex(_enc(EcfFloatSpecial.positiveInfinity)), 'f97c00');
      expect(_hex(_enc(EcfFloatSpecial.negativeInfinity)), 'f9fc00');
      expect(_hex(_enc(EcfFloatSpecial.negativeZero)), 'f98000');
    });
  });

  group('codec invariants N1-N3', () {
    test('N1: varint 128 -> 0x80 0x01', () {
      expect(_hex(Varint.encode(128)), '8001');
    });
    test('N2: bare tag 55799 (d9 d9 f7) rejects even at top level', () {
      final r = Ecf.decode(Uint8List.fromList([0xd9, 0xd9, 0xf7, 0xa0]));
      expect(r, isA<Err>());
      expect((r as Err).error, isA<TagRejected>());
    });
    test('N3: empty map = single byte 0xA0', () {
      expect(_hex(_enc(EcfMap(const []))), 'a0');
    });
  });

  group('base58 leading-zero preservation', () {
    test('round-trip with leading zeros', () {
      final raw = Uint8List.fromList([0x00, 0x00, 0x01, 0x02, 0xff]);
      final back = Base58.decode(Base58.encode(raw));
      expect(back, raw);
    });
  });

  group('peer_id §1.5 canonical form (A-DART-010)', () {
    test('Ed25519 32-byte pubkey -> (0x01, 0x00, raw pubkey)', () {
      final pk = Uint8List.fromList(List.generate(32, (i) => i));
      final pid = PeerId.fromPublicKey(pk, Curve.ed25519);
      final parts = PeerId.parse(pid);
      expect(parts.keyType, 0x01);
      expect(parts.hashType, 0x00);
      expect(parts.digest, pk);
    });
  });

  group('Ed25519 RFC-8032 KAT + sign/verify', () {
    test('all-zero seed -> known public key (RFC-8032 TEST 1)', () async {
      final seed = Uint8List(32);
      final pk = await Ed.rawPublicKeyFromSeed(seed, Curve.ed25519);
      expect(_hex(pk),
          '3b6a27bcceb6a42d62a3a8d02a6f0d7365321577 1de243a63ac048a18b59da29'
              .replaceAll(' ', ''));
    });
    test('sign/verify/tamper round-trip', () async {
      final seed = Uint8List.fromList(List.generate(32, (i) => i));
      final msg = Uint8List.fromList([1, 2, 3, 4, 5]);
      final pk = await Ed.rawPublicKeyFromSeed(seed, Curve.ed25519);
      final sig = await Ed.sign(seed, msg, Curve.ed25519);
      expect(await Ed.verify(pk, msg, sig, Curve.ed25519), isTrue);
      final tampered = Uint8List.fromList(sig)..[0] ^= 0xff;
      expect(await Ed.verify(pk, msg, tampered, Curve.ed25519), isFalse);
    });
  });
}
