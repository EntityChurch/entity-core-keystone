package org.entitycore.protocol.peer

import org.entitycore.protocol.codec.EcfValue
import java.math.BigInteger

/**
 * Small constructor + accessor helpers over the S2 [EcfValue] model, plus the
 * address-space hex convention. Keeps the peer code reading at the protocol altitude
 * (map/list builders, typed field reads) instead of restating the codec value model
 * inline. Kotlin-idiomatic: file-level functions in a package object, nullable returns
 * via `T?` (no `Optional`), `vararg` builders.
 *
 * **lowercase hex (A-CL-009 trap).** [hex] renders LOWERCASE — the §3.4/§3.5 tree-path
 * convention. Tree paths are case-sensitive string keys (`system/signature/{hash}`, the
 * §5.1 revocation marker, the §6.9a policy path); the Common Lisp peer's uppercase
 * default produced an internally-consistent but cross-incompatible address space. We are
 * lowercase everywhere (the codec already is; the peer-layer paths are too).
 */
internal object Cbor {

    private val HEXC = "0123456789abcdef".toCharArray()

    // ── builders ──────────────────────────────────────────────────────────────

    /** Build a map from alternating key, value pairs. A String key becomes Text; values
     *  are coerced via [coerce] (raw EcfValue passes through; String→Text; ByteArray→Bytes;
     *  Boolean→Bool; Long/Int/BigInteger→IntVal). */
    fun map(vararg kvs: Any?): EcfValue.MapVal {
        require(kvs.size % 2 == 0) { "odd kv count" }
        val es = ArrayList<EcfValue.Entry>(kvs.size / 2)
        var i = 0
        while (i < kvs.size) {
            val k = kvs[i]
            val key = if (k is String) EcfValue.Text(k) else k as EcfValue
            es.add(EcfValue.Entry(key, coerce(kvs[i + 1])))
            i += 2
        }
        return EcfValue.MapVal(es)
    }

    /** The canonical empty map (a single 0xA0 byte). */
    fun emptyMap(): EcfValue.MapVal = EcfValue.MapVal(emptyList())

    /** Coerce a Kotlin value to its EcfValue node. */
    fun coerce(v: Any?): EcfValue = when (v) {
        is EcfValue -> v
        is String -> EcfValue.Text(v)
        is ByteArray -> EcfValue.Bytes(v)
        is Boolean -> if (v) EcfValue.Bool.TRUE else EcfValue.Bool.FALSE
        is BigInteger -> EcfValue.IntVal(v)
        is Long -> EcfValue.IntVal.of(v)
        is Int -> EcfValue.IntVal.of(v.toLong())
        null -> EcfValue.Null
        else -> throw IllegalArgumentException("cannot coerce to EcfValue: ${v::class}")
    }

    fun bytes(b: ByteArray): EcfValue = EcfValue.Bytes(b)

    fun textArray(vararg ss: String): EcfValue.Arr =
        EcfValue.Arr(ss.map { EcfValue.Text(it) })

    fun textArray(ss: List<String>): EcfValue.Arr =
        EcfValue.Arr(ss.map { EcfValue.Text(it) })

    fun array(items: List<EcfValue>): EcfValue.Arr = EcfValue.Arr(items)

    // ── typed field reads (over a map value, null-safe) ─────────────────────────

    fun asMap(v: EcfValue?): EcfValue.MapVal? = v as? EcfValue.MapVal

    fun text(m: EcfValue.MapVal?, key: String): String? =
        (m?.get(key) as? EcfValue.Text)?.value

    fun bytes(m: EcfValue.MapVal?, key: String): ByteArray? =
        (m?.get(key) as? EcfValue.Bytes)?.octets()

    fun uint(m: EcfValue.MapVal?, key: String): BigInteger? =
        (m?.get(key) as? EcfValue.IntVal)?.value

    /** The text values of an array field (non-text items skipped), or null. */
    fun textList(m: EcfValue.MapVal?, key: String): List<String>? {
        val a = m?.get(key) as? EcfValue.Arr ?: return null
        return a.items.mapNotNull { (it as? EcfValue.Text)?.value }
    }

    /** The map values of an array field, or null. */
    fun mapList(m: EcfValue.MapVal?, key: String): List<EcfValue.MapVal>? {
        val a = m?.get(key) as? EcfValue.Arr ?: return null
        return a.items.mapNotNull { it as? EcfValue.MapVal }
    }

    fun isTrue(v: EcfValue?): Boolean = v === EcfValue.Bool.TRUE

    // ── hex ─────────────────────────────────────────────────────────────────────

    /** LOWERCASE hex (the §3.4/§3.5 address-space convention; A-CL-009). */
    fun hex(octets: ByteArray): String {
        val out = CharArray(octets.size * 2)
        for (i in octets.indices) {
            val b = octets[i].toInt() and 0xff
            out[i * 2] = HEXC[b ushr 4]
            out[i * 2 + 1] = HEXC[b and 0x0f]
        }
        return String(out)
    }

    fun unhex(s: String): ByteArray {
        val n = s.length / 2
        val out = ByteArray(n)
        for (i in 0 until n) {
            out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }
}
