package org.entitycore.protocol.peer

import org.entitycore.protocol.crypto.Curve
import org.entitycore.protocol.crypto.Ed
import org.entitycore.protocol.crypto.PeerId

/**
 * A peer's identity (L1): an Ed25519 seed and everything derived from it (§1.5, §3.5,
 * §7.3).
 *
 * ```
 *   publicKey    = Ed25519 public key of seed                  (32 bytes)
 *   peerId       = §1.5 canonical-form (identity-multihash; A-KT-004)
 *   peerEntity   = system/peer {public_key, key_type}          (§3.5; v7.65 — NO
 *                  peer_id in the hashable basis)
 *   identityHash = content_hash(peerEntity)                    (33 bytes)
 * ```
 *
 * Signing is over the full 33-byte content_hash (format byte + digest, §7.3), so a
 * signature is bound to the hash format. peer_id is the §1.5 identity-multihash form
 * (A-KT-004) — the §7.4 SHA-256 pseudocode is stale and would fail the handshake; this
 * follows §1.5 (PeerId.fromPublicKey already encodes the rule). The raw public key comes
 * from [Ed.rawPublicKeyFromSeed] (net-new at S3 — A-KT-007).
 */
class Identity private constructor(
    private val seed: ByteArray,
    private val publicKeyOctets: ByteArray,
    val peerId: String,
    val peerEntity: Entity,
    private val identityHashOctets: ByteArray,
) {
    fun publicKey(): ByteArray = publicKeyOctets.copyOf()
    fun identityHash(): ByteArray = identityHashOctets.copyOf()
    internal fun rawIdentityHash(): ByteArray = identityHashOctets

    /**
     * Sign a target entity's content_hash, producing a system/signature entity (§3.5):
     * `target` = the signed entity's hash, `signer` = our identity hash.
     */
    fun sign(target: Entity): Entity {
        val sig = Ed.sign(seed, target.rawHash(), Curve.ED25519)
        return Entity.make(
            "system/signature",
            Cbor.map(
                "target", Cbor.bytes(target.rawHash()),
                "signer", Cbor.bytes(identityHashOctets),
                "algorithm", "ed25519",
                "signature", Cbor.bytes(sig),
            ),
        )
    }

    companion object {
        /** Construct an identity from a 32-byte Ed25519 seed. */
        fun ofSeed(seed: ByteArray): Identity {
            val s = seed.copyOf()
            val pub = Ed.rawPublicKeyFromSeed(s, Curve.ED25519)
            val peerEntity = peerEntityOfPublicKey(pub)
            val peerId = PeerId.fromPublicKey(pub, Curve.ED25519)
            return Identity(s, pub, peerId, peerEntity, peerEntity.rawHash())
        }

        /** The system/peer entity for a raw public key (v7.65: no peer_id field). */
        fun peerEntityOfPublicKey(publicKey: ByteArray): Entity = Entity.make(
            "system/peer",
            Cbor.map("public_key", Cbor.bytes(publicKey), "key_type", "ed25519"),
        )

        /** The §1.5 canonical (identity-multihash) peer_id for a raw Ed25519 public key. */
        fun peerIdOfPublicKey(publicKey: ByteArray): String =
            PeerId.fromPublicKey(publicKey, Curve.ED25519)

        /**
         * Verify a system/signature entity against the signer's system/peer entity. Reads
         * public_key from the peer entity; the §5.2 signer-hash binding is the caller's
         * responsibility.
         */
        fun verifySignature(signature: Entity, signerPeer: Entity): Boolean {
            val target = signature.bytes("target")
            val sig = signature.bytes("signature")
            val pub = signerPeer.bytes("public_key")
            if (target == null || sig == null || pub == null) return false
            return Ed.verify(pub, target, sig, Curve.ED25519)
        }

        fun octetsEqual(a: ByteArray?, b: ByteArray?): Boolean =
            a != null && b != null && a.contentEquals(b)
    }
}
