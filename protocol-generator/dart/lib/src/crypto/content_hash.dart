import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../codec/ecf.dart';
import '../codec/ecf_value.dart';
import '../codec/varint.dart';
import '../errors.dart';

/// content_hash construction (ENTITY-CBOR-ENCODING.md §4.2):
///
///   content_hash = varint(format_code) ‖ HASH(ECF({type, data}))
///
/// Format code 0x00 = ecfv1-sha256 (the required §9.1 floor); 0x01 =
/// ecfv1-sha384 (agility). The format_code is NOT part of the hashed entity —
/// only `{type, data}` is hashed. The varint prefix is multicodec-style LEB128
/// (invariant N1), so a code >= 0x80 extends to multiple bytes.
///
/// Asymmetry: the CONSTRUCT side serializes the caller-supplied format_code
/// verbatim (so content_hash.4 with code 128 passes); the RECEIVE/verify side
/// ([resolveFormat]) rejects any unallocated code.
///
/// SHA-256 = the first-party `package:crypto` (the §9.1 floor). SHA-384
/// (agility) is reachable but deferred with Ed448.
class ContentHash {
  ContentHash._();

  static const int formatSha256 = 0x00;
  static const int formatSha384 = 0x01;

  /// Compute the wire content_hash over an entity `{type, data}` map.
  /// Returns `varint(formatCode) ‖ digest(ECF({type, data}))`.
  static Uint8List compute(EcfMap entity, {int formatCode = formatSha256}) {
    final type = entity['type'];
    final data = entity['data'];
    if (type == null || data == null) {
      throw const EcfException(
          NonCanonicalEcf('content_hash input must have type and data'));
    }
    final hashed = EcfMap.of({'type': type, 'data': data});
    final ecf = Ecf.encodeOrThrow(hashed);
    final digest = _digest(formatCode, ecf);
    final prefix = Varint.encode(formatCode);
    final out = Uint8List(prefix.length + digest.length);
    out.setRange(0, prefix.length, prefix);
    out.setRange(prefix.length, out.length, digest);
    return out;
  }

  /// Construct-side digest selection: 0x01 -> SHA-384, else -> SHA-256. The
  /// corpus exercises only the varint prefix for synthetic high codes
  /// (content_hash.4); the peer layer (S3) rejects unallocated codes on receive.
  static List<int> _digest(int formatCode, Uint8List input) {
    if (formatCode == formatSha384) {
      return crypto.sha384.convert(input).bytes;
    }
    return crypto.sha256.convert(input).bytes;
  }

  /// Receive-side: resolve an integer format code to a digest name, or reject.
  static String resolveFormat(int code) {
    switch (code) {
      case formatSha256:
        return 'SHA-256';
      case formatSha384:
        return 'SHA-384';
      default:
        throw EcfException(UnsupportedContentHashFormat(
            'unsupported content_hash format code: $code'));
    }
  }
}
