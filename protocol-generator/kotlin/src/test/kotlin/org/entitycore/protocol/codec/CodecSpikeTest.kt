package org.entitycore.protocol.codec

import org.entitycore.protocol.EcfResult
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A-KT-001 mandated spike: push the load-bearing canonical risks through the
 * hand-rolled encoder BEFORE trusting the full build — the length-then-lex map-key
 * ordering and the shortest-float (incl. f16) ladder. These assert the exact corpus
 * bytes for the map_keys.* and float.* vectors directly (independent of the fixture
 * loader), so a spike regression is caught here in isolation.
 *
 * Plus the F7 beyond-corpus regression (codec-review-heuristic): the int corpus tops
 * out at i64::MAX, so uints in [2^63, 2^64-1] are UNTESTED by the oracle — exactly
 * where a signed decode silently overflows. We exercise them here with a local
 * round-trip past i64::MAX.
 */
class CodecSpikeTest {

    private fun enc(v: EcfValue): ByteArray = CanonicalCbor.encodeOrThrow(v)
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun spikeFloatLadder() {
        // f16 / f32 / f64 boundaries + specials, exact corpus bytes (float.1..14).
        assertEquals("f90000", hex(enc(EcfValue.Float64(0.0))))
        assertEquals("f98000", hex(enc(EcfValue.FloatSpecial.NEGATIVE_ZERO)))
        assertEquals("f93c00", hex(enc(EcfValue.Float64(1.0))))
        assertEquals("f93e00", hex(enc(EcfValue.Float64(1.5))))
        assertEquals("f97c00", hex(enc(EcfValue.FloatSpecial.POSITIVE_INFINITY)))
        assertEquals("f9fc00", hex(enc(EcfValue.FloatSpecial.NEGATIVE_INFINITY)))
        assertEquals("f97e00", hex(enc(EcfValue.FloatSpecial.NAN)))
        assertEquals("f97800", hex(enc(EcfValue.Float64(32768.0))))
        assertEquals("f97bfe", hex(enc(EcfValue.Float64(65472.0))))
        assertEquals("f97bff", hex(enc(EcfValue.Float64(65504.0))))      // max normal f16
        assertEquals("f9fbff", hex(enc(EcfValue.Float64(-65504.0))))
        assertEquals("fa477fdf00", hex(enc(EcfValue.Float64(65503.0))))  // MUST be f32 not f16
        assertEquals("fa47c35000", hex(enc(EcfValue.Float64(100000.0)))) // f32
        assertEquals("fb3ff199999999999a", hex(enc(EcfValue.Float64(1.1)))) // f64
    }

    @Test
    fun spikeMapKeyOrdering() {
        // length-FIRST then byte-lexicographic (map_keys.2/.3/.5/.6).
        // 'z' (len1) before 'aa' (len2):
        val m2 = EcfValue.MapVal.of("aa", EcfValue.IntVal.of(2), "z", EcfValue.IntVal.of(1))
        assertEquals("a2617a0162616102", hex(enc(m2)))
        // same-length lexicographic: 'a' before 'b':
        val m3 = EcfValue.MapVal.of("b", EcfValue.IntVal.of(2), "a", EcfValue.IntVal.of(1))
        assertEquals("a2616101616202", hex(enc(m3)))
        // byte-string key sorts before text key (0x43.. < 0x68..):
        val m5 = EcfValue.MapVal(listOf(
            EcfValue.Entry(EcfValue.Bytes(byteArrayOf(0x6b, 0x65, 0x79)), EcfValue.IntVal.of(2)),
            EcfValue.Entry(EcfValue.Text("text_key"), EcfValue.IntVal.of(1)),
        ))
        assertEquals("a2436b65790268746578745f6b657901", hex(enc(m5)))
        // 'aa' (len2) before 'aaa' (len3) — length, then lex:
        val m6 = EcfValue.MapVal.of("aaa", EcfValue.IntVal.of(2), "aa", EcfValue.IntVal.of(1))
        assertEquals("a2626161016361616102", hex(enc(m6)))
    }

    @Test
    fun beyondCorpusUint64PastI64Max() {
        // F7: 2^63 .. 2^64-1 — past signed i64::MAX, untested by the oracle corpus.
        val twoPow63 = BigInteger.ONE.shiftLeft(63)                       // 0x1b8000000000000000
        assertEquals("1b8000000000000000", hex(enc(EcfValue.IntVal(twoPow63))))
        val maxU64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE) // 0x1bffffffffffffffff
        assertEquals("1bffffffffffffffff", hex(enc(EcfValue.IntVal(maxU64))))
        // -2^64 is the largest nint argument (major 1, arg = 2^64-1).
        val minNint = BigInteger.ONE.shiftLeft(64).negate()
        assertEquals("3bffffffffffffffff", hex(enc(EcfValue.IntVal(minNint))))

        // round-trip each back through our own decoder.
        for (v in listOf(twoPow63, maxU64, minNint)) {
            val bytes = enc(EcfValue.IntVal(v))
            val back = CanonicalCbor.decode(bytes)
            assertTrue(back is EcfResult.Ok)
            assertEquals(EcfValue.IntVal(v), back.value)
        }
    }
}
