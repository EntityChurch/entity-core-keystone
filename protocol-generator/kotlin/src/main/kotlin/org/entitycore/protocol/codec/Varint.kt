package org.entitycore.protocol.codec

import org.entitycore.protocol.EcfException
import org.entitycore.protocol.EntityError
import java.io.ByteArrayOutputStream

/**
 * Multicodec-style unsigned LEB128 varints (V7 §1.5 / §7.3).
 *
 * Invariant N1: every format-code / key-type / hash-type prefix is routed through a
 * REAL varint primitive, NOT fixed bytes. All currently-allocated codes are < 0x80
 * (single byte), but a code >= 0x80 MUST extend correctly (`128 -> 0x80 0x01`). The
 * corpus exercises this with synthetic high codes (content_hash.4 fc=128, peer_id.3
 * key_type=128).
 *
 * The unsigned value carries through a Kotlin `ULong` (profile [idiom] unsigned_types),
 * so the full 64-bit range is handled with no signed-shift footgun.
 */
object Varint {

    /** Encode a non-negative value as an unsigned LEB128 byte array. */
    fun encode(n: Long): ByteArray {
        require(n >= 0) { "varint value must be non-negative: $n" }
        val out = ByteArrayOutputStream(2)
        var v: ULong = n.toULong()
        do {
            var b = (v and 0x7fuL).toInt()
            v = v shr 7
            if (v != 0uL) b = b or 0x80
            out.write(b)
        } while (v != 0uL)
        return out.toByteArray()
    }

    /** Decode result: the value plus the index just past the varint. */
    data class Decoded(val value: Long, val next: Int)

    /**
     * Decode an unsigned LEB128 varint from [buf] at [start].
     *
     * Throws an internal [EcfException] (carrying a sealed [EntityError]) on truncation
     * or >64-bit overflow; the calling layer translates it to an [org.entitycore.protocol.EcfResult].
     */
    fun decode(buf: ByteArray, start: Int): Decoded {
        var value: ULong = 0uL
        var shift = 0
        var i = start
        while (true) {
            if (i >= buf.size) {
                throw EcfException(EntityError.CodecError.TruncatedInput("varint: ran off end at $i"))
            }
            if (shift >= 64) {
                throw EcfException(EntityError.CodecError.NonCanonicalEcf("varint: exceeds 64 bits"))
            }
            val b = buf[i].toInt() and 0xff
            i++
            value = value or ((b and 0x7f).toULong() shl shift)
            if (b and 0x80 == 0) return Decoded(value.toLong(), i)
            shift += 7
        }
    }
}
