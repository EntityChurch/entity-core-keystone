import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../codec/base58.dart';
import '../codec/varint.dart';
import 'ed.dart';

/// peer-id formatting/parsing + §1.5 canonical-form derivation.
///
///   peer_id = Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)
///
/// key_type and hash_type are multicodec-style LEB128 varints (invariant N1).
///
/// **A-DART-010 / P1.** The Ed25519 peer_id is derived from the §1.5 v7.65
/// CANONICAL-FORM TABLE (hash_type=0x00 identity-multihash, digest = RAW public
/// key, NO hash), NOT the stale §7.4 SHA-256 skeleton. The §1.5 size-cutoff: a
/// key <= 32 bytes is identity-multihash (hash_type=0x00, digest = key); a
/// larger key is SHA-256-form (hash_type=0x01, digest = SHA-256(key)). So
/// Ed25519 (32 B) -> (0x01, 0x00, pubkey) and Ed448 (57 B) -> (0x02, 0x01,
/// sha256(pubkey)).
///
/// The S2 conformance corpus uses OPAQUE digests (peer_id.* vectors supply
/// key_type/hash_type/digest explicitly), so a wrong CONSTRUCTION would still
/// pass S2 and only fail at the S4 handshake — hence the correct form is baked
/// in here proactively (verified by a local self-test).
class PeerId {
  PeerId._();

  static const int keyTypeEd25519 = 0x01;
  static const int keyTypeEd448 = 0x02;

  /// Format a peer-id string from its abstract components (the corpus path).
  static String format(int keyType, int hashType, List<int> digest) {
    final kt = Varint.encode(keyType);
    final ht = Varint.encode(hashType);
    final raw = Uint8List(kt.length + ht.length + digest.length);
    raw.setRange(0, kt.length, kt);
    raw.setRange(kt.length, kt.length + ht.length, ht);
    raw.setRange(kt.length + ht.length, raw.length, digest);
    return Base58.encode(raw);
  }

  /// Parse a peer-id string back to its components.
  static ParsedPeerId parse(String peerId) {
    final raw = Base58.decode(peerId);
    final kt = Varint.decode(raw, 0);
    final ht = Varint.decode(raw, kt.next);
    final digest = Uint8List.sublistView(raw, ht.next);
    return ParsedPeerId(
        kt.value.toInt(), ht.value.toInt(), Uint8List.fromList(digest));
  }

  /// Derive a peer-id from a RAW public key + curve, per the §1.5 canonical-form
  /// table + size-cutoff rule (A-DART-010). This is the construction the S4
  /// handshake binds against.
  static String fromPublicKey(Uint8List publicKey, Curve curve) {
    final keyType = curve == Curve.ed25519 ? keyTypeEd25519 : keyTypeEd448;
    final int hashType;
    final List<int> digest;
    if (publicKey.length <= 32) {
      hashType = 0x00; // identity-multihash: digest IS the public key
      digest = publicKey;
    } else {
      hashType = 0x01; // SHA-256-form for keys > 32 bytes
      digest = crypto.sha256.convert(publicKey).bytes;
    }
    return format(keyType, hashType, digest);
  }
}

/// Parsed peer-id components. `digest` is a fresh copy.
class ParsedPeerId {
  const ParsedPeerId(this.keyType, this.hashType, this.digest);
  final int keyType;
  final int hashType;
  final Uint8List digest;
}
