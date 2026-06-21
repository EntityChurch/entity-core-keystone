package org.entitycore.protocol.crypto

import org.entitycore.protocol.EcfException
import org.entitycore.protocol.EntityError
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.EdECPublicKey
import java.security.spec.EdECPoint
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec
import java.math.BigInteger

/** The signature curves with allocated key_type codes (V7 §1.5). */
enum class Curve { ED25519, ED448 }

/**
 * EdDSA sign / verify via the JDK SunEC provider (JEP 339: Ed25519 + Ed448), and raw
 * public-key extraction. Zero runtime dependency; RFC-8032 deterministic. Called
 * directly from Kotlin (Kotlin/JVM has zero-overhead Java interop — `java.security`
 * is just a Kotlin import). Profile [codec].ed25519_library = jdk-sunec.
 *
 * The S2 floor needs only Ed25519 sign over canonical-ECF entity bytes (the
 * `signature.*` corpus); SunEC runs the RFC-8032 seed expansion internally, so a raw
 * 32-byte seed → deterministic 64-byte signature needs no third-party crypto. Ed448 +
 * the raw-key-from-point seam are wired for the (deferred, higher-bar) agility corpus.
 */
object Ed {

    private fun spec(curve: Curve): NamedParameterSpec =
        if (curve == Curve.ED25519) NamedParameterSpec.ED25519 else NamedParameterSpec.ED448

    private fun algo(curve: Curve): String = if (curve == Curve.ED25519) "Ed25519" else "Ed448"

    private fun seedLen(curve: Curve): Int = if (curve == Curve.ED25519) 32 else 57

    /** Build a [PrivateKey] from a raw RFC-8032 seed (32 B Ed25519 / 57 B Ed448).
     *  SunEC runs the RFC-8032 expansion internally. */
    fun privateKeyFromSeed(seed: ByteArray, curve: Curve): PrivateKey {
        if (seed.size != seedLen(curve)) {
            throw EcfException(EntityError.CryptoError.BadSeed(
                "$curve seed must be ${seedLen(curve)} bytes, got ${seed.size}"))
        }
        return KeyFactory.getInstance(algo(curve))
            .generatePrivate(EdECPrivateKeySpec(spec(curve), seed.copyOf()))
    }

    /** Sign [message] with the seed-derived key. RFC-8032 signature (64 B Ed25519,
     *  114 B Ed448). Deterministic. */
    fun sign(seed: ByteArray, message: ByteArray, curve: Curve): ByteArray {
        try {
            val priv = privateKeyFromSeed(seed, curve)
            val sig = Signature.getInstance(algo(curve))
            sig.initSign(priv)
            sig.update(message)
            return sig.sign()
        } catch (e: java.security.GeneralSecurityException) {
            throw EcfException(EntityError.CryptoError.SignFailed("sign failed: $curve: ${e.message}"))
        }
    }

    /**
     * Derive the raw RFC-8032 public-key bytes from a secret seed (S3 peer-id +
     * system/peer construction). SunEC has no seed→public-point API, so Ed25519 is
     * derived in [EdKeyDerivation] (A-KT-007). Only Ed25519 (the §9.1 floor curve) is
     * wired; Ed448 raw-key derivation is a deferred agility higher-bar.
     */
    fun rawPublicKeyFromSeed(seed: ByteArray, curve: Curve): ByteArray = when (curve) {
        Curve.ED25519 -> EdKeyDerivation.rawPublicKeyEd25519(seed)
        Curve.ED448 -> throw EcfException(EntityError.CryptoError.UnsupportedKeyType(
            "Ed448 seed→pubkey derivation is a deferred agility higher-bar"))
    }

    /** Verify a signature against a RAW public key. */
    fun verify(rawPublicKey: ByteArray, message: ByteArray, signature: ByteArray, curve: Curve): Boolean =
        try {
            val pub = publicKeyFromRaw(rawPublicKey, curve)
            val sig = Signature.getInstance(algo(curve))
            sig.initVerify(pub)
            sig.update(message)
            sig.verify(signature)
        } catch (e: java.security.GeneralSecurityException) {
            false
        }

    /** Extract the raw RFC-8032 public-key bytes from a SunEC [PublicKey]
     *  ([EdECPoint] → little-endian y with the x sign bit in the final byte). */
    fun rawPublicKey(pub: PublicKey, curve: Curve): ByteArray {
        val ed = pub as? EdECPublicKey
            ?: throw EcfException(EntityError.CryptoError.UnsupportedKeyType("not an EdEC public key: ${pub.javaClass}"))
        val point = ed.point
        val len = seedLen(curve)
        val out = ByteArray(len)
        val y = point.y.toByteArray() // big-endian magnitude
        for (i in y.indices) {
            val idx = y.size - 1 - i // least-significant first
            if (i < len) out[i] = y[idx]
        }
        if (point.isXOdd) out[len - 1] = (out[len - 1].toInt() or 0x80).toByte()
        return out
    }

    /** Rebuild a SunEC [PublicKey] from RAW RFC-8032 bytes (inverse of [rawPublicKey]). */
    fun publicKeyFromRaw(raw: ByteArray, curve: Curve): PublicKey {
        val le = raw.copyOf()
        val last = le.size - 1
        val xOdd = (le[last].toInt() and 0x80) != 0
        le[last] = (le[last].toInt() and 0x7f).toByte()
        val be = ByteArray(le.size) { le[le.size - 1 - it] }
        val y = BigInteger(1, be)
        val point = EdECPoint(xOdd, y)
        return KeyFactory.getInstance(algo(curve))
            .generatePublic(EdECPublicKeySpec(spec(curve), point))
    }
}
