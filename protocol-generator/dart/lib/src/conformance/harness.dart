import 'dart:io';
import 'dart:typed_data';

import '../codec/ecf.dart';
import '../codec/ecf_value.dart';
import '../crypto/content_hash.dart';
import '../crypto/ed.dart';
import '../crypto/peer_id.dart';
import '../errors.dart';

/// ECF wire-conformance harness (the codec gate).
///
/// The normative fixture `conformance-vectors-v1.cbor` is itself a canonical-ECF
/// array of vector maps, each carrying its own cross-blessed `canonical` bytes
/// (the Go `wire-conformance` oracle output, 3-way Go × Rust × Python
/// byte-locked). The harness decodes the fixture with THIS peer's OWN decoder (a
/// decoder bug is itself a conformance failure per ENTITY-CBOR-ENCODING.md §E.3),
/// runs each vector through the codec, and byte-compares against the embedded
/// `canonical`. Byte-identity to the fixture == oracle PASS.
///
/// Dispatch by `kind` + `id` category prefix:
///  - decode_reject -> the decoder MUST reject the canonical wire bytes
///  - encode_equal, category:
///      content_hash -> varint(format_code) ‖ SHA-2(ECF({type,data}))
///      peer_id      -> CBOR-text(Base58(varint(kt)‖varint(ht)‖digest))
///      signature    -> Ed25519_sign(seed, ECF({type,data}))  [raw 64 bytes]
///      else         -> plain ECF encode(input)
class ConformanceHarness {
  /// Resolve the fixture path: env `ECF_FIXTURE` or the vendored default.
  static String defaultFixture() {
    final env = Platform.environment['ECF_FIXTURE'];
    if (env != null && env.isNotEmpty) return env;
    return '../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor';
  }

  /// Run the corpus at [fixturePath]. Returns a [ConformanceResult].
  static Future<ConformanceResult> run(String fixturePath) async {
    final octets = await File(fixturePath).readAsBytes();
    final decoded = Ecf.decode(Uint8List.fromList(octets));
    if (decoded is! Ok<EcfValue>) {
      throw StateError(
          'fixture failed to decode with our own decoder: ${(decoded as Err).error}');
    }
    final top = decoded.value;
    if (top is! EcfArray) {
      throw StateError('fixture top-level is not an array');
    }

    var pass = 0;
    var fail = 0;
    var total = 0;
    final failures = <String>[];

    for (final v in top.items) {
      if (v is! EcfMap) continue; // meta / non-vector
      final kind = _text(v['kind']);
      if (kind == null) continue; // meta entry without a kind
      final id = _text(v['id']) ?? '?';
      total++;
      bool ok;
      String? detail;
      try {
        switch (kind) {
          case 'decode_reject':
            final wire = _bytes(v['canonical']);
            ok = Ecf.decode(wire) is Err;
            if (!ok) detail = 'decoder ACCEPTED a reject vector';
          case 'encode_equal':
            final want = _bytes(v['canonical']);
            final got = await _produce(id, v['input']!);
            ok = _bytesEqual(got, want);
            if (!ok) detail = 'want=${_hex(want)} got=${_hex(got)}';
          default:
            total--;
            continue;
        }
      } catch (e) {
        ok = false;
        detail = 'raised: $e';
      }
      if (ok) {
        pass++;
      } else {
        fail++;
        failures.add('FAIL $id: $detail');
      }
    }
    return ConformanceResult(pass, fail, total, failures);
  }

  static Future<Uint8List> _produce(String id, EcfValue input) async {
    switch (_category(id)) {
      case 'content_hash':
        final m = input as EcfMap;
        final codeVal = m['format_code'];
        final code = codeVal is EcfInt ? codeVal.value.toInt() : 0;
        final entity = EcfMap.of({'type': m['type']!, 'data': m['data']!});
        return ContentHash.compute(entity, formatCode: code);
      case 'peer_id':
        final m = input as EcfMap;
        final kt = (m['key_type']! as EcfInt).value.toInt();
        final ht = (m['hash_type']! as EcfInt).value.toInt();
        final digest = _bytes(m['digest']);
        final peerId = PeerId.format(kt, ht, digest);
        // canonical = the peer_id string encoded as a CBOR text string
        return Ecf.encodeOrThrow(EcfText(peerId));
      case 'signature':
        final m = input as EcfMap;
        final seed = _bytes(m['seed']);
        final entity = m['entity']! as EcfMap;
        final hashed =
            EcfMap.of({'type': entity['type']!, 'data': entity['data']!});
        final ecf = Ecf.encodeOrThrow(hashed);
        return Ed.sign(seed, ecf, Curve.ed25519);
      default:
        return Ecf.encodeOrThrow(input);
    }
  }

  static String _category(String id) {
    final dot = id.indexOf('.');
    return dot >= 0 ? id.substring(0, dot) : id;
  }

  static String? _text(EcfValue? v) => v is EcfText ? v.value : null;

  static Uint8List _bytes(EcfValue? v) {
    if (v is EcfBytes) return v.octets;
    throw StateError('expected bytes, got $v');
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}

/// The outcome of a conformance run.
class ConformanceResult {
  const ConformanceResult(this.pass, this.fail, this.total, this.failures);
  final int pass;
  final int fail;
  final int total;
  final List<String> failures;
}
