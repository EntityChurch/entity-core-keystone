import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';

import '../errors.dart';

/// The signature curves with allocated key_type codes (V7 §1.5).
enum Curve { ed25519, ed448 }

/// EdDSA sign / verify + raw public-key extraction via `cryptography_plus`
/// (pure-Dart Ed25519, RFC-8032 deterministic). Pure-Dart = self-contained on
/// every Flutter target (no native .so/.dylib) — the reach value (A-DART-002).
///
/// The S2 floor needs only Ed25519 sign over canonical-ECF entity bytes (the
/// `signature.*` corpus). Ed448 is a DEFERRED agility higher-bar (no maintained
/// pure-Dart Ed448; A-DART-003) — its methods throw [UnsupportedKeyType].
///
/// The `cryptography_plus` Ed25519 API is async (`Future`): `newKeyPairFromSeed`
/// / `sign` / `verify` / `extractPublicKey`. The peer surface is async anyway
/// (profile [async].default_surface), so this is idiomatic. The codec itself
/// stays synchronous; only the signature/peer-id-from-seed paths are async.
class Ed {
  Ed._();

  static final Ed25519 _ed25519 = Ed25519();

  static int seedLen(Curve curve) => curve == Curve.ed25519 ? 32 : 57;

  /// Sign [message] with a raw RFC-8032 seed. Returns the 64-byte Ed25519
  /// signature. Deterministic.
  static Future<Uint8List> sign(
      Uint8List seed, Uint8List message, Curve curve) async {
    if (curve != Curve.ed25519) {
      throw const EcfException(UnsupportedKeyType(
          'Ed448 sign is a deferred agility higher-bar (no pure-Dart Ed448)'));
    }
    if (seed.length != 32) {
      throw EcfException(
          BadSeed('Ed25519 seed must be 32 bytes, got ${seed.length}'));
    }
    final keyPair = await _ed25519.newKeyPairFromSeed(seed);
    final sig = await _ed25519.sign(message, keyPair: keyPair);
    return Uint8List.fromList(sig.bytes);
  }

  /// Derive the raw 32-byte RFC-8032 public key from a secret seed (S3 peer-id
  /// + system/peer construction).
  static Future<Uint8List> rawPublicKeyFromSeed(
      Uint8List seed, Curve curve) async {
    if (curve != Curve.ed25519) {
      throw const EcfException(UnsupportedKeyType(
          'Ed448 pubkey derivation is a deferred agility higher-bar'));
    }
    if (seed.length != 32) {
      throw EcfException(
          BadSeed('Ed25519 seed must be 32 bytes, got ${seed.length}'));
    }
    final keyPair = await _ed25519.newKeyPairFromSeed(seed);
    final pub = await keyPair.extractPublicKey();
    return Uint8List.fromList(pub.bytes);
  }

  /// Verify a signature against a RAW 32-byte public key.
  static Future<bool> verify(
      Uint8List rawPublicKey, Uint8List message, Uint8List signature,
      Curve curve) async {
    if (curve != Curve.ed25519) return false;
    final pub = SimplePublicKey(rawPublicKey, type: KeyPairType.ed25519);
    return _ed25519.verify(
      message,
      signature: Signature(signature, publicKey: pub),
    );
  }
}
