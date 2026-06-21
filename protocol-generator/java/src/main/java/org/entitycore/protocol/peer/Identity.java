package org.entitycore.protocol.peer;

import java.util.Arrays;

import org.entitycore.protocol.crypto.Ed;
import org.entitycore.protocol.crypto.EntityCryptoException;
import org.entitycore.protocol.crypto.PeerId;
import org.entitycore.protocol.crypto.PeerId.Curve;

/**
 * A peer's identity (L1): an Ed25519 seed and everything derived from it (§1.5, §3.5,
 * §7.3).
 *
 * <pre>
 *   publicKey    = Ed25519 public key of seed                  (32 bytes)
 *   peerId       = §1.5 canonical-form (identity-multihash; A-JAVA-004)
 *   peerEntity   = system/peer {public_key, key_type}          (§3.5; v7.65 — NO
 *                  peer_id in the hashable basis)
 *   identityHash = content_hash(peerEntity)                    (33 bytes)
 * </pre>
 *
 * <p>Signing is over the full 33-byte content_hash (format byte + digest, §7.3), so a
 * signature is bound to the hash format. peer_id is the §1.5 identity-multihash form
 * (A-JAVA-004) — the §7.4 SHA-256 pseudocode is stale and fails the handshake; this
 * follows §1.5.
 */
public final class Identity {
    private final byte[] seed;
    private final byte[] publicKey;
    private final String peerId;
    private final Entity peerEntity;
    private final byte[] identityHash;

    private Identity(byte[] seed, byte[] publicKey, String peerId,
                     Entity peerEntity, byte[] identityHash) {
        this.seed = seed;
        this.publicKey = publicKey;
        this.peerId = peerId;
        this.peerEntity = peerEntity;
        this.identityHash = identityHash;
    }

    /** Construct an identity from a 32-byte Ed25519 seed. */
    public static Identity ofSeed(byte[] seed) throws EntityCryptoException {
        byte[] s = seed.clone();
        byte[] pub = Ed.rawPublicKeyFromSeed(s, Curve.ED25519);
        Entity peerEntity = peerEntityOfPublicKey(pub);
        String peerId = PeerId.fromPublicKey(pub, Curve.ED25519);
        return new Identity(s, pub, peerId, peerEntity, peerEntity.rawHash());
    }

    /** The system/peer entity for a raw public key (v7.65: no peer_id field). */
    public static Entity peerEntityOfPublicKey(byte[] publicKey) {
        return Entity.make("system/peer",
                Cbor.map("public_key", Cbor.bytes(publicKey), "key_type", "ed25519"));
    }

    /** The §1.5 canonical (identity-multihash) peer_id for a raw Ed25519 public key. */
    public static String peerIdOfPublicKey(byte[] publicKey) {
        return PeerId.fromPublicKey(publicKey, Curve.ED25519);
    }

    public byte[] publicKey() {
        return publicKey.clone();
    }

    public String peerId() {
        return peerId;
    }

    public Entity peerEntity() {
        return peerEntity;
    }

    public byte[] identityHash() {
        return identityHash.clone();
    }

    byte[] rawIdentityHash() {
        return identityHash;
    }

    /**
     * Sign a target entity's content_hash, producing a system/signature entity (§3.5):
     * {@code target} = the signed entity's hash, {@code signer} = our identity hash.
     */
    public Entity sign(Entity target) throws EntityCryptoException {
        byte[] sig = Ed.sign(seed, target.rawHash(), Curve.ED25519);
        return Entity.make("system/signature",
                Cbor.map(
                        "target", Cbor.bytes(target.rawHash()),
                        "signer", Cbor.bytes(identityHash),
                        "algorithm", "ed25519",
                        "signature", Cbor.bytes(sig)));
    }

    /**
     * Verify a system/signature entity against the signer's system/peer entity. Reads
     * public_key from the peer entity; the §5.2 signer-hash binding is the caller's
     * responsibility.
     */
    public static boolean verifySignature(Entity signature, Entity signerPeer) {
        byte[] target = signature.bytes("target");
        byte[] sig = signature.bytes("signature");
        byte[] pub = signerPeer.bytes("public_key");
        if (target == null || sig == null || pub == null) {
            return false;
        }
        try {
            return Ed.verify(pub, target, sig, Curve.ED25519);
        } catch (EntityCryptoException e) {
            return false;
        }
    }

    static boolean octetsEqual(byte[] a, byte[] b) {
        return a != null && b != null && Arrays.equals(a, b);
    }
}
