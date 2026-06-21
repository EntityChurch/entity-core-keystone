package org.entitycore.protocol.codec

import org.entitycore.protocol.EcfException
import org.entitycore.protocol.EcfResult
import org.entitycore.protocol.EntityError
import java.io.ByteArrayOutputStream
import java.math.BigInteger

/**
 * Entity Canonical Form (ECF) — hand-rolled canonical CBOR encoder + decoder.
 *
 * Per ENTITY-CBOR-ENCODING.md v1.5 (spec-data v7.71/v7.75). No JVM CBOR library gives
 * ECF's guarantees (length-FIRST then byte-lexicographic map-key ordering; the f16
 * shortest-float ladder; recursive major-type-6 tag rejection; raw-byte fidelity), so
 * the canonical layer is owned here. Authored as an INDEPENDENT Kotlin reading of V7,
 * not a port of the Java peer (A-KT-001):
 *  - minimal integer encoding (Rule 1) — full uint64 / -2^64 range via [BigInteger];
 *  - map keys sorted by ENCODED LENGTH then byte-lexicographic (Rule 2 / §3.5);
 *  - definite lengths only (Rule 3) — no 0x5f/0x7f/0x9f/0xbf;
 *  - shortest float preserving value incl. f16 (Rule 4) + Rule-4a special bytes;
 *  - recursive major-type-6 (tag) rejection on decode (invariant N2; §6.3);
 *  - empty map = the single byte 0xA0 (invariant N3 — falls out of the generic map
 *    encoder, not special-cased).
 *
 * Public surface: [encode]/[decode] return an [EcfResult] (the Kotlin-idiomatic
 * sealed-result error seam). The recursive hot path throws an internal [EcfException]
 * carrying the sealed [EntityError]; the public wrappers translate it back into an
 * [EcfResult.Err] — so the THROW never escapes the codec, and callers match `when`.
 */
object CanonicalCbor {

    /** ECF §10.2 nesting depth limit. */
    const val MAX_DEPTH = 64

    private val MAX_U64: BigInteger = BigInteger.ONE.shiftLeft(64) // exclusive
    private val U64_MASK_FF: BigInteger = BigInteger.valueOf(0xff)

    // ───────────────────────────────────────────────────────────────────────────
    // Encode
    // ───────────────────────────────────────────────────────────────────────────

    /** Encode [value] to canonical ECF bytes (result-returning public surface). */
    fun encode(value: EcfValue): EcfResult<ByteArray> = guard {
        val out = ByteArrayOutputStream(64)
        enc(value, out)
        out.toByteArray()
    }

    /** Encode and unwrap — for internal callers that treat encode failures as bugs. */
    internal fun encodeOrThrow(value: EcfValue): ByteArray {
        val out = ByteArrayOutputStream(64)
        enc(value, out)
        return out.toByteArray()
    }

    private fun enc(value: EcfValue, out: ByteArrayOutputStream) {
        when (value) {
            is EcfValue.FloatSpecial -> when (value) {
                EcfValue.FloatSpecial.NAN -> writeBytes(out, 0xf9, 0x7e, 0x00)
                EcfValue.FloatSpecial.POSITIVE_INFINITY -> writeBytes(out, 0xf9, 0x7c, 0x00)
                EcfValue.FloatSpecial.NEGATIVE_INFINITY -> writeBytes(out, 0xf9, 0xfc, 0x00)
                EcfValue.FloatSpecial.NEGATIVE_ZERO -> writeBytes(out, 0xf9, 0x80, 0x00)
            }
            is EcfValue.Bool -> out.write(if (value == EcfValue.Bool.TRUE) 0xf5 else 0xf4)
            EcfValue.Null -> out.write(0xf6)
            is EcfValue.IntVal -> encInt(value.value, out)
            is EcfValue.Float64 -> encFloat(value.value, out)
            is EcfValue.Bytes -> {
                val o = value.raw()
                encHead(2, o.size.toLong(), out)
                out.write(o, 0, o.size)
            }
            is EcfValue.Text -> {
                val o = value.value.toByteArray(Charsets.UTF_8)
                encHead(3, o.size.toLong(), out)
                out.write(o, 0, o.size)
            }
            is EcfValue.Arr -> {
                encHead(4, value.items.size.toLong(), out)
                for (item in value.items) enc(item, out)
            }
            is EcfValue.MapVal -> encMap(value, out)
        }
    }

    private fun encInt(v: BigInteger, out: ByteArrayOutputStream) {
        if (v.signum() >= 0) {
            encHeadBig(0, v, out)
        } else {
            // major 1, argument = -1 - v
            encHeadBig(1, v.negate().subtract(BigInteger.ONE), out)
        }
    }

    private fun encHead(major: Int, arg: Long, out: ByteArrayOutputStream) =
        encHeadBig(major, BigInteger.valueOf(arg), out)

    /**
     * Emit a CBOR initial byte for [major] with the SHORTEST argument for the given
     * non-negative [arg] (RFC 8949 §4.2.1 Rule 1). The head form switches on a Kotlin
     * `ULong` for arguments below 2^63, exercising the profile's unsigned-types idiom
     * (no `Long.compareUnsigned` dance); the >= 2^63 case stays on [BigInteger] since
     * the corpus reaches 2^64-1 (max uint64) and -2^64 (max nint argument).
     */
    private fun encHeadBig(major: Int, arg: BigInteger, out: ByteArrayOutputStream) {
        val m = major shl 5
        if (arg.signum() < 0 || arg >= MAX_U64) {
            throw EcfException(EntityError.CodecError.NonCanonicalEcf("argument out of uint64 range: $arg"))
        }
        val ge2p63 = arg.bitLength() > 63
        if (!ge2p63) {
            val a: ULong = arg.toLong().toULong() // fits in [0, 2^63)
            when {
                a < 24uL -> out.write(m or a.toInt())
                a < 0x100uL -> { out.write(m or 24); out.write((a and 0xffuL).toInt()) }
                a < 0x10000uL -> {
                    out.write(m or 25)
                    out.write(((a shr 8) and 0xffuL).toInt())
                    out.write((a and 0xffuL).toInt())
                }
                a < 0x100000000uL -> {
                    out.write(m or 26)
                    for (i in 3 downTo 0) out.write(((a shr (8 * i)) and 0xffuL).toInt())
                }
                else -> {
                    out.write(m or 27)
                    for (i in 7 downTo 0) out.write(((a shr (8 * i)) and 0xffuL).toInt())
                }
            }
        } else {
            // 8-byte argument covering [2^63, 2^64-1].
            out.write(m or 27)
            for (i in 7 downTo 0) out.write(arg.shiftRight(8 * i).and(U64_MASK_FF).toInt())
        }
    }

    private fun encMap(m: EcfValue.MapVal, out: ByteArrayOutputStream) {
        // Encode each key + value, then sort entries by encoded-KEY bytes
        // (length-then-lex, ECF Rule 2). Duplicate keys in a canonical map are illegal,
        // so there are no ties on the key bytes.
        val encoded = m.entries.map { EncodedEntry(encodeOrThrow(it.key), encodeOrThrow(it.value)) }
            .sortedWith(KEY_ORDER)
        encHead(5, encoded.size.toLong(), out)
        for (e in encoded) {
            out.write(e.key, 0, e.key.size)
            out.write(e.value, 0, e.value.size)
        }
    }

    private class EncodedEntry(val key: ByteArray, val value: ByteArray)

    /** Length-then-byte-lexicographic order on encoded-key octets (ECF Rule 2). Because
     *  CBOR head-encoding puts the length in the low bits of the initial byte, this is
     *  byte-wise lexicographic on the FULL encoded key — the same order the Go oracle's
     *  `bytes.Compare(keyBytes)` produces. */
    private val KEY_ORDER = Comparator<EncodedEntry> { a, b ->
        if (a.key.size != b.key.size) return@Comparator a.key.size.compareTo(b.key.size)
        for (i in a.key.indices) {
            val x = a.key[i].toInt() and 0xff
            val y = b.key[i].toInt() and 0xff
            if (x != y) return@Comparator x.compareTo(y)
        }
        0
    }

    // ── float ladder: f16 ⊂ f32 ⊂ f64, shortest that round-trips exactly ────────

    private fun encFloat(f: Double, out: ByteArrayOutputStream) {
        // -0.0 is canonical f16 (Rule 4a). (+0.0 falls through to the f16 path.)
        if (f == 0.0 && java.lang.Double.doubleToRawLongBits(f) != 0L) {
            writeBytes(out, 0xf9, 0x80, 0x00)
            return
        }
        val h = doubleToF16(f)
        if (h != null && f16ToDouble(h) == f) {
            out.write(0xf9)
            out.write((h shr 8) and 0xff)
            out.write(h and 0xff)
            return
        }
        val sf = f.toFloat()
        if (sf.toDouble() == f && !sf.isInfinite()) {
            val bits = java.lang.Float.floatToRawIntBits(sf)
            out.write(0xfa)
            for (i in 3 downTo 0) out.write((bits shr (8 * i)) and 0xff)
            return
        }
        val bits = java.lang.Double.doubleToRawLongBits(f)
        out.write(0xfb)
        for (i in 7 downTo 0) out.write(((bits shr (8 * i)) and 0xff).toInt())
    }

    /** Convert a finite double to a 16-bit IEEE half, or null if not exactly
     *  representable as a finite f16 (caller falls back to f32/f64). */
    internal fun doubleToF16(f: Double): Int? {
        val bits = java.lang.Double.doubleToRawLongBits(f)
        val sign = ((bits ushr 63) and 0x1L).toInt()
        val exp = ((bits ushr 52) and 0x7ffL).toInt()
        val mant = bits and 0xfffffffffffffL
        if (exp == 0x7ff) return null // inf/nan handled as specials, not here
        if (exp == 0 && mant == 0L) return if (sign == 1) 0x8000 else 0x0000
        val unbiased: Int
        val fullMant: Long
        if (exp == 0) {
            // subnormal double — normalize
            val lead = java.lang.Long.numberOfLeadingZeros(mant) - (63 - 52)
            unbiased = -1022 - lead
            fullMant = ((mant shl (lead + 1)) and 0x1fffffffffffffL) or 0x10000000000000L
        } else {
            unbiased = exp - 1023
            fullMant = mant or 0x10000000000000L
        }
        val he = unbiased + 15 // half biased exponent
        if (he > 30) return null // too large for finite f16
        if (he >= 1) {
            // normalized f16: low 42 mantissa bits must be zero (10-bit fraction)
            if ((mant and 0x3ffffffffffL) != 0L) return null
            val hmant = (mant shr 42).toInt()
            return (sign shl 15) or (he shl 10) or hmant
        }
        // subnormal f16 (he <= 0): value = significand * 2^(unbiased-52); representable
        // iff value * 2^24 is an integer in [1,1023].
        val scaledExp = (unbiased - 52) + 24
        if (scaledExp >= 0) {
            val scaled = BigInteger.valueOf(fullMant).shiftLeft(scaledExp)
            if (scaled.bitLength() <= 10 && scaled.signum() > 0 &&
                scaled <= BigInteger.valueOf(1023)
            ) {
                val s = scaled.toInt()
                if (s >= 1) return (sign shl 15) or s
            }
            return null
        }
        val shift = -scaledExp
        if ((fullMant and ((1L shl shift) - 1)) != 0L) return null
        val q = fullMant shr shift
        if (q in 1..1023) return (sign shl 15) or q.toInt()
        return null
    }

    /** Convert a 16-bit IEEE half to a double (finite values only on this path). */
    internal fun f16ToDouble(h: Int): Double {
        val sign = (h ushr 15) and 0x1
        val exp = (h ushr 10) and 0x1f
        val mant = h and 0x3ff
        val s = if (sign == 1) -1.0 else 1.0
        if (exp == 0) {
            if (mant == 0) return s * 0.0
            return s * mant * Math.pow(2.0, -24.0) // subnormal
        }
        if (exp == 0x1f) {
            return if (mant == 0) s * Double.POSITIVE_INFINITY else Double.NaN
        }
        return s * (1024 + mant) * Math.pow(2.0, (exp - 25).toDouble()) // (1.m) * 2^(exp-15)
    }

    private fun writeBytes(out: ByteArrayOutputStream, vararg bs: Int) {
        for (b in bs) out.write(b and 0xff)
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Decode
    // ───────────────────────────────────────────────────────────────────────────

    /** Decode canonical ECF bytes to a value; rejects trailing bytes. Result-returning. */
    fun decode(octets: ByteArray): EcfResult<EcfValue> = guard {
        val c = Cursor(octets, 0)
        val v = dec(c, 0)
        if (c.i < octets.size) {
            throw EcfException(EntityError.CodecError.NonCanonicalEcf("trailing bytes: ${octets.size - c.i}"))
        }
        v
    }

    private class Cursor(val o: ByteArray, var i: Int)

    private fun dec(c: Cursor, depth: Int): EcfValue {
        if (depth > MAX_DEPTH) throw EcfException(EntityError.CodecError.NonCanonicalEcf("max depth exceeded"))
        if (c.i >= c.o.size) throw EcfException(EntityError.CodecError.TruncatedInput("item: ran off end"))
        val ib = c.o[c.i].toInt() and 0xff
        val major = ib ushr 5
        val info = ib and 0x1f
        c.i++
        return when (major) {
            0 -> EcfValue.IntVal(decArg(c, info))
            1 -> EcfValue.IntVal(decArg(c, info).negate().subtract(BigInteger.ONE))
            2 -> {
                val len = decLen(c, info)
                need(c, len)
                val b = c.o.copyOfRange(c.i, c.i + len)
                c.i += len
                EcfValue.Bytes(b)
            }
            3 -> {
                val len = decLen(c, info)
                need(c, len)
                val s = String(c.o, c.i, len, Charsets.UTF_8)
                c.i += len
                EcfValue.Text(s)
            }
            4 -> {
                val len = decLen(c, info)
                val items = ArrayList<EcfValue>(minOf(len, 64))
                repeat(len) { items.add(dec(c, depth + 1)) }
                EcfValue.Arr(items)
            }
            5 -> {
                val len = decLen(c, info)
                val entries = ArrayList<EcfValue.Entry>(minOf(len, 64))
                val seen = HashSet<Any>()
                repeat(len) {
                    val key = dec(c, depth + 1)
                    val value = dec(c, depth + 1)
                    if (!seen.add(keySurrogate(key))) {
                        throw EcfException(EntityError.CodecError.DuplicateKey("duplicate map key"))
                    }
                    entries.add(EcfValue.Entry(key, value))
                }
                EcfValue.MapVal(entries)
            }
            6 -> throw EcfException(EntityError.CodecError.TagRejected("major-type-6 tag rejected at ${c.i - 1}"))
            7 -> decSimple(c, info)
            else -> throw EcfException(EntityError.CodecError.NonCanonicalEcf("bad major type $major"))
        }
    }

    /** Decode the argument for majors 0/1 (full uint64 range -> BigInteger). */
    private fun decArg(c: Cursor, info: Int): BigInteger = when {
        info < 24 -> BigInteger.valueOf(info.toLong())
        info == 24 -> { need(c, 1); val v = c.o[c.i].toInt() and 0xff; c.i += 1; BigInteger.valueOf(v.toLong()) }
        info == 25 -> {
            need(c, 2)
            val v = ((c.o[c.i].toInt() and 0xff) shl 8) or (c.o[c.i + 1].toInt() and 0xff)
            c.i += 2; BigInteger.valueOf(v.toLong())
        }
        info == 26 -> {
            need(c, 4)
            var v = 0L
            for (k in 0 until 4) v = (v shl 8) or (c.o[c.i + k].toLong() and 0xff)
            c.i += 4; BigInteger.valueOf(v)
        }
        info == 27 -> {
            need(c, 8)
            var v = BigInteger.ZERO
            for (k in 0 until 8) v = v.shiftLeft(8).or(BigInteger.valueOf(c.o[c.i + k].toLong() and 0xff))
            c.i += 8; v
        }
        else -> throw EcfException(EntityError.CodecError.NonCanonicalEcf("reserved/indefinite argument: $info"))
    }

    /** Decode a length argument (majors 2-5); must fit in an Int. */
    private fun decLen(c: Cursor, info: Int): Int {
        val v = decArg(c, info)
        if (v.bitLength() > 31) throw EcfException(EntityError.CodecError.NonCanonicalEcf("length too large: $v"))
        return v.toInt()
    }

    private fun decSimple(c: Cursor, info: Int): EcfValue = when (info) {
        20 -> EcfValue.Bool.FALSE
        21 -> EcfValue.Bool.TRUE
        22 -> EcfValue.Null
        25 -> {
            need(c, 2)
            val b0 = c.o[c.i].toInt() and 0xff; val b1 = c.o[c.i + 1].toInt() and 0xff; c.i += 2
            decodeF16(b0, b1)
        }
        26 -> {
            need(c, 4)
            var bits = 0
            for (k in 0 until 4) bits = (bits shl 8) or (c.o[c.i + k].toInt() and 0xff)
            c.i += 4; decodeF32(bits)
        }
        27 -> {
            need(c, 8)
            var bits = 0L
            for (k in 0 until 8) bits = (bits shl 8) or (c.o[c.i + k].toLong() and 0xff)
            c.i += 8; decodeF64(bits)
        }
        else -> throw EcfException(EntityError.CodecError.NonCanonicalEcf("bad simple value: $info"))
    }

    private fun decodeF16(b0: Int, b1: Int): EcfValue {
        val h = (b0 shl 8) or b1
        val s = (h ushr 15) and 1; val e = (h ushr 10) and 0x1f; val m = h and 0x3ff
        if (e == 0x1f) {
            return if (m == 0) (if (s == 1) EcfValue.FloatSpecial.NEGATIVE_INFINITY else EcfValue.FloatSpecial.POSITIVE_INFINITY)
            else EcfValue.FloatSpecial.NAN
        }
        if (e == 0 && m == 0) return if (s == 1) EcfValue.FloatSpecial.NEGATIVE_ZERO else EcfValue.Float64(0.0)
        return EcfValue.Float64(f16ToDouble(h))
    }

    private fun decodeF32(bits: Int): EcfValue {
        val s = (bits ushr 31) and 1; val e = (bits ushr 23) and 0xff; val m = bits and 0x7fffff
        if (e == 0xff) {
            return if (m == 0) (if (s == 1) EcfValue.FloatSpecial.NEGATIVE_INFINITY else EcfValue.FloatSpecial.POSITIVE_INFINITY)
            else EcfValue.FloatSpecial.NAN
        }
        if (e == 0 && m == 0) return if (s == 1) EcfValue.FloatSpecial.NEGATIVE_ZERO else EcfValue.Float64(0.0)
        return EcfValue.Float64(java.lang.Float.intBitsToFloat(bits).toDouble())
    }

    private fun decodeF64(bits: Long): EcfValue {
        val s = ((bits ushr 63) and 1L).toInt()
        val e = ((bits ushr 52) and 0x7ffL).toInt()
        val m = bits and 0xfffffffffffffL
        if (e == 0x7ff) {
            return if (m == 0L) (if (s == 1) EcfValue.FloatSpecial.NEGATIVE_INFINITY else EcfValue.FloatSpecial.POSITIVE_INFINITY)
            else EcfValue.FloatSpecial.NAN
        }
        if (e == 0 && m == 0L) return if (s == 1) EcfValue.FloatSpecial.NEGATIVE_ZERO else EcfValue.Float64(0.0)
        return EcfValue.Float64(java.lang.Double.longBitsToDouble(bits))
    }

    private fun need(c: Cursor, len: Int) {
        if (len < 0 || c.i + len > c.o.size) {
            throw EcfException(EntityError.CodecError.TruncatedInput("need $len at ${c.i}"))
        }
    }

    private fun keySurrogate(key: EcfValue): Any = when (key) {
        is EcfValue.Text -> "s:${key.value}"
        is EcfValue.Bytes -> "b:${key.octets().joinToString(",")}"
        is EcfValue.IntVal -> "i:${key.value}"
        // ECF map keys are text or bytes; anything else is non-canonical.
        else -> throw EcfException(EntityError.CodecError.NonCanonicalEcf("non-canonical map key type"))
    }

    /** Run [block], translating an internal [EcfException] into an [EcfResult.Err] so the
     *  sealed [EntityError] is the value-level error surface (the throw never escapes). */
    private inline fun <T> guard(block: () -> T): EcfResult<T> =
        try {
            EcfResult.Ok(block())
        } catch (e: EcfException) {
            EcfResult.Err(e.error)
        }
}
