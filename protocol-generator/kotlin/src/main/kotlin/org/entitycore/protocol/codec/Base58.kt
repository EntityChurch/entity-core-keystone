package org.entitycore.protocol.codec

import java.math.BigInteger

/**
 * Base58 (Bitcoin alphabet) encode/decode, hand-rolled (dodges a Gradle dep + pin;
 * profile [codec].base58_library = "hand-rolled").
 *
 * Used for peer-id formatting/parsing (V7 §1.2 / §7.3). Leading zero bytes map to a
 * leading `'1'` each, per the standard Base58 convention (leading-zero preserving in
 * both directions).
 */
object Base58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val FIFTY_EIGHT = BigInteger.valueOf(58)
    private val INDEX = IntArray(128) { -1 }.also {
        for (i in ALPHABET.indices) it[ALPHABET[i].code] = i
    }

    /** Encode a byte array to a Base58 string. */
    fun encode(octets: ByteArray): String {
        var zeros = 0
        while (zeros < octets.size && octets[zeros].toInt() == 0) zeros++
        var n = BigInteger(1, octets) // big-endian unsigned magnitude
        val sb = StringBuilder()
        while (n.signum() > 0) {
            val qr = n.divideAndRemainder(FIFTY_EIGHT)
            sb.append(ALPHABET[qr[1].toInt()])
            n = qr[0]
        }
        sb.reverse()
        return buildString {
            repeat(zeros) { append('1') }
            append(sb)
        }
    }

    /** Decode a Base58 string to a byte array (leading-zero preserving). */
    fun decode(s: String): ByteArray {
        var ones = 0
        while (ones < s.length && s[ones] == '1') ones++
        var n = BigInteger.ZERO
        for (c in s) {
            val d = if (c.code < 128) INDEX[c.code] else -1
            require(d >= 0) { "invalid base58 char: $c" }
            n = n.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(d.toLong()))
        }
        val body = if (n.signum() == 0) ByteArray(0) else stripSignByte(n.toByteArray())
        val out = ByteArray(ones + body.size)
        body.copyInto(out, ones)
        return out
    }

    /** BigInteger.toByteArray may prepend a 0x00 sign byte; strip it for magnitude. */
    private fun stripSignByte(b: ByteArray): ByteArray =
        if (b.size > 1 && b[0].toInt() == 0) b.copyOfRange(1, b.size) else b
}
