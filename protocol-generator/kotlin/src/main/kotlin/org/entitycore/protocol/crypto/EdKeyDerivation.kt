package org.entitycore.protocol.crypto

import org.entitycore.protocol.EcfException
import org.entitycore.protocol.EntityError
import java.math.BigInteger
import java.security.MessageDigest

/**
 * RFC-8032 raw public-key derivation from a secret seed (Ed25519) — fully JDK-native
 * (zero third-party dependency).
 *
 * **Why this exists (A-KT-009, corroborates the Java A-JAVA-002 seam).** SunEC
 * signs/verifies but exposes a public key only as an `EdECPoint` (y-coordinate +
 * x-sign-bit) and has NO seed→public-point API. The S3 peer needs the RAW 32-byte
 * public key to build the §1.5 identity-multihash peer_id and the wire `system/peer`
 * entity (the S2 codec corpus only ever supplied OPAQUE peer_id digests, so this path
 * is net-new at S3 — exactly the A-KT-004 note). So the public key is derived here:
 * SHA-512 (JDK) expand → clamp → Curve25519 (twisted Edwards a=-1) base-point scalar
 * multiply → little-endian point encode. The result is independently cross-checked by
 * feeding it to SunEC's verifier ([Ed.verify]) on a self-signed message.
 *
 * Ported byte-for-byte from the proven Java peer derivation (same JDK substrate); only
 * Ed25519 is wired here (the S3 floor curve). Ed448 derivation stays a deferred agility
 * higher-bar (profile: floor first).
 */
internal object EdKeyDerivation {

    private val P25519: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
    private val D25519: BigInteger =
        BigInteger.valueOf(-121665)
            .multiply(BigInteger.valueOf(121666).modInverse(P25519)).mod(P25519)
    private val BY25519: BigInteger =
        BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P25519)).mod(P25519)

    /** Derive the raw RFC-8032 Ed25519 public-key bytes (32) from a 32-byte seed. */
    fun rawPublicKeyEd25519(seed: ByteArray): ByteArray {
        if (seed.size != 32) {
            throw EcfException(EntityError.CryptoError.BadSeed(
                "Ed25519 seed must be 32 bytes, got ${seed.size}"))
        }
        val h = sha512(seed)
        val s = h.copyOfRange(0, 32)
        s[0] = (s[0].toInt() and 248).toByte()
        s[31] = (s[31].toInt() and 127).toByte()
        s[31] = (s[31].toInt() or 64).toByte()
        val scalar = leToBig(s)
        val bx = recoverX25519(BY25519, false)
        val r = scalarMul(scalar, arrayOf(bx, BY25519), P25519, D25519)
        return encodePoint(r, P25519, 32)
    }

    // twisted-Edwards (a = -1) addition for Ed25519.
    private fun add(p1: Array<BigInteger>, q1: Array<BigInteger>, p: BigInteger, d: BigInteger):
        Array<BigInteger> {
        val x1 = p1[0]; val y1 = p1[1]; val x2 = q1[0]; val y2 = q1[1]
        val dxy = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(p)
        val x3 = x1.multiply(y2).add(x2.multiply(y1))
            .multiply(BigInteger.ONE.add(dxy).modInverse(p)).mod(p)
        val y3 = y1.multiply(y2).add(x1.multiply(x2))
            .multiply(BigInteger.ONE.subtract(dxy).modInverse(p)).mod(p)
        return arrayOf(x3, y3)
    }

    private fun scalarMul(e: BigInteger, point: Array<BigInteger>, p: BigInteger, d: BigInteger):
        Array<BigInteger> {
        var q = arrayOf(BigInteger.ZERO, BigInteger.ONE) // identity
        for (i in e.bitLength() - 1 downTo 0) {
            q = add(q, q, p, d)
            if (e.testBit(i)) q = add(q, point, p, d)
        }
        return q
    }

    private fun recoverX25519(y: BigInteger, xOdd: Boolean): BigInteger {
        val p = P25519; val d = D25519
        val y2 = y.multiply(y).mod(p)
        val u = y2.subtract(BigInteger.ONE).mod(p)
        val v = d.multiply(y2).add(BigInteger.ONE).mod(p)
        val xx = u.multiply(v.modInverse(p)).mod(p)
        var x = xx.modPow(p.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), p)
        if (x.multiply(x).mod(p) != xx) {
            val i2 = BigInteger.TWO.modPow(
                p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), p)
            x = x.multiply(i2).mod(p)
        }
        if (x.testBit(0) != xOdd) x = p.subtract(x)
        return x
    }

    private fun encodePoint(point: Array<BigInteger>, p: BigInteger, len: Int): ByteArray {
        val x = point[0]
        val y = point[1].mod(p)
        val le = ByteArray(len)
        val be = y.toByteArray() // big-endian magnitude (may carry a leading sign byte)
        for (i in be.indices) {
            val idx = be.size - 1 - i // walk from least-significant
            if (i < len) le[i] = be[idx]
        }
        if (x.testBit(0)) le[len - 1] = (le[len - 1].toInt() or 0x80).toByte()
        return le
    }

    private fun leToBig(le: ByteArray): BigInteger {
        val be = ByteArray(le.size) { le[le.size - 1 - it] }
        return BigInteger(1, be)
    }

    private fun sha512(input: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-512").digest(input)
}
