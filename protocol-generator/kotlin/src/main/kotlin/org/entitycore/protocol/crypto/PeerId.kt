package org.entitycore.protocol.crypto

import org.entitycore.protocol.codec.Base58
import org.entitycore.protocol.codec.Varint
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * peer-id formatting/parsing + §1.5 canonical-form derivation.
 *
 *   peer_id = Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)
 *
 * key_type and hash_type are multicodec-style LEB128 varints (invariant N1).
 *
 * **A-KT-004 (corroborates A-JAVA-004 / A-ZIG-001 / A-OC-007 / A-CL-002).** The Ed25519
 * peer_id is derived from the §1.5 v7.65 CANONICAL-FORM TABLE (hash_type=0x00
 * identity-multihash, digest = RAW public key, NO hash), NOT the stale §7.4 SHA-256
 * skeleton. The §1.5 size-cutoff: a key <= 32 bytes is identity-multihash
 * (hash_type=0x00, digest = key); a larger key is SHA-256-form (hash_type=0x01,
 * digest = SHA-256(key)). So Ed25519 (32 B) -> (0x01, 0x00, pubkey) and Ed448 (57 B)
 * -> (0x02, 0x01, sha256(pubkey)). On v7.75 this is corroboration-only (the §7.4-vs-§1.5
 * contradiction the spec-first peers surfaced is already reconciled by v7.73 erratum E1).
 *
 * The S2 conformance corpus uses OPAQUE digests (peer_id.* vectors supply
 * key_type/hash_type/digest explicitly), so a wrong CONSTRUCTION would still pass S2 and
 * only fail at the S4 handshake — hence the correct form is baked in here proactively.
 */
object PeerId {
    const val KEY_TYPE_ED25519 = 0x01
    const val KEY_TYPE_ED448 = 0x02

    /** Format a peer-id string from its abstract components (the corpus path). */
    fun format(keyType: Int, hashType: Int, digest: ByteArray): String {
        val raw = ByteArrayOutputStream()
        val kt = Varint.encode(keyType.toLong())
        val ht = Varint.encode(hashType.toLong())
        raw.write(kt, 0, kt.size)
        raw.write(ht, 0, ht.size)
        raw.write(digest, 0, digest.size)
        return Base58.encode(raw.toByteArray())
    }

    /** Parsed peer-id components. `digest` is a fresh copy. */
    data class Parsed(val keyType: Int, val hashType: Int, val digest: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Parsed && keyType == other.keyType && hashType == other.hashType &&
                digest.contentEquals(other.digest)
        override fun hashCode(): Int =
            (keyType * 31 + hashType) * 31 + digest.contentHashCode()
    }

    /** Parse a peer-id string back to its components. */
    fun parse(peerId: String): Parsed {
        val raw = Base58.decode(peerId)
        val kt = Varint.decode(raw, 0)
        val ht = Varint.decode(raw, kt.next)
        val dlen = (raw.size - ht.next).coerceAtLeast(0)
        val digest = ByteArray(dlen)
        if (dlen > 0) raw.copyInto(digest, 0, ht.next, ht.next + dlen)
        return Parsed(kt.value.toInt(), ht.value.toInt(), digest)
    }

    /**
     * Derive a peer-id from a RAW public key and curve, per the §1.5 canonical-form
     * table + size-cutoff rule (A-KT-004). This is the construction the S4 handshake
     * binds against.
     */
    fun fromPublicKey(publicKey: ByteArray, curve: Curve): String {
        val keyType = if (curve == Curve.ED25519) KEY_TYPE_ED25519 else KEY_TYPE_ED448
        val hashType: Int
        val digest: ByteArray
        if (publicKey.size <= 32) {
            hashType = 0x00 // identity-multihash: digest IS the public key
            digest = publicKey.copyOf()
        } else {
            hashType = 0x01 // SHA-256-form for keys > 32 bytes
            digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
        }
        return format(keyType, hashType, digest)
    }
}
