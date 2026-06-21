import 'dart:typed_data';

import '../crypto/ed.dart';
import '../crypto/peer_id.dart';
import 'cbor.dart';
import 'entity.dart';

/// A peer's identity (L1): an Ed25519 seed and everything derived from it (§1.5,
/// §3.5, §7.3).
///
/// ```
///   publicKey    = Ed25519 public key of seed                  (32 bytes)
///   peerId       = §1.5 canonical-form (identity-multihash)
///   peerEntity   = system/peer {public_key, key_type}          (§3.5; v7.65 — NO
///                  peer_id in the hashable basis)
///   identityHash = content_hash(peerEntity)                    (33 bytes)
/// ```
///
/// Signing is over the full 33-byte content_hash (format byte + digest, §7.3), so
/// a signature is bound to the hash format. peer_id is the §1.5
/// identity-multihash form ([PeerId.fromPublicKey], A-DART-010) — the §7.4
/// SHA-256 pseudocode is stale and would fail the handshake; §1.5 wins.
///
/// **Async:** [ofSeed]/[sign] are `Future`-returning because `cryptography_plus`
/// Ed25519 is async (profile [async]). The codec + entity construction stay
/// synchronous; only the crypto-touching paths await.
final class Identity {
  Identity._(
    this._seed,
    this._publicKey,
    this.peerId,
    this.peerEntity,
    this._identityHash,
  );

  final Uint8List _seed;
  final Uint8List _publicKey;
  final String peerId;
  final Entity peerEntity;
  final Uint8List _identityHash;

  Uint8List publicKey() => Uint8List.fromList(_publicKey);
  Uint8List identityHash() => Uint8List.fromList(_identityHash);
  Uint8List get rawIdentityHash => _identityHash;

  /// Construct an identity from a 32-byte Ed25519 seed.
  static Future<Identity> ofSeed(Uint8List seed) async {
    final s = Uint8List.fromList(seed);
    final pub = await Ed.rawPublicKeyFromSeed(s, Curve.ed25519);
    final peerEntity = peerEntityOfPublicKey(pub);
    final peerId = PeerId.fromPublicKey(pub, Curve.ed25519);
    return Identity._(s, pub, peerId, peerEntity, peerEntity.rawHash);
  }

  /// Sign a target entity's content_hash, producing a system/signature entity
  /// (§3.5): `target` = the signed entity's hash, `signer` = our identity hash.
  Future<Entity> sign(Entity target) async {
    final sig = await Ed.sign(_seed, target.rawHash, Curve.ed25519);
    return Entity.make(
      'system/signature',
      cmap([
        'target', cbytes(target.rawHash),
        'signer', cbytes(_identityHash),
        'algorithm', 'ed25519',
        'signature', cbytes(sig),
      ]),
    );
  }

  /// The system/peer entity for a raw public key (v7.65: no peer_id field).
  static Entity peerEntityOfPublicKey(Uint8List publicKey) => Entity.make(
        'system/peer',
        cmap(['public_key', cbytes(publicKey), 'key_type', 'ed25519']),
      );

  /// The §1.5 canonical (identity-multihash) peer_id for a raw Ed25519 pubkey.
  static String peerIdOfPublicKey(Uint8List publicKey) =>
      PeerId.fromPublicKey(publicKey, Curve.ed25519);

  /// Verify a system/signature entity against the signer's system/peer entity.
  /// Reads public_key from the peer entity; the §5.2 signer-hash binding is the
  /// caller's responsibility.
  static Future<bool> verifySignature(Entity signature, Entity signerPeer) async {
    final target = signature.bytes('target');
    final sig = signature.bytes('signature');
    final pub = signerPeer.bytes('public_key');
    if (target == null || sig == null || pub == null) return false;
    return Ed.verify(pub, target, sig, Curve.ed25519);
  }
}
