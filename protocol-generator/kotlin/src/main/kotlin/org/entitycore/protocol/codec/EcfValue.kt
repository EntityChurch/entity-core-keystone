package org.entitycore.protocol.codec

import java.math.BigInteger

/**
 * The decoded-form value model for Entity Canonical Form (ECF).
 *
 * A `sealed interface` hierarchy gives the codec/dispatch ladders an EXHAUSTIVE `when`
 * (the compiler checks coverage over the closed set — no `else` needed). This is the
 * Kotlin static-exhaustiveness seam. A sealed *interface* (not class) is used so the
 * value-less variants ([Bool], [FloatSpecial], [Null]) can be Kotlin `enum`/`object`
 * singletons and still be first-class `EcfValue`s in the `when` (Kotlin enums/objects
 * implement interfaces; this is the idiomatic closed-hierarchy shape here).
 *
 * Why an explicit model rather than reusing `kotlin` stdlib types directly: ECF
 * requires `absent != null != false != 0` on the wire (V7 §1.3), and a CBOR byte string
 * (major 2) must stay distinct from a text string (major 3). So:
 *  - booleans/null are explicit nodes ([Bool], [Null]) — never erased to a Kotlin
 *    `null`/`Boolean`;
 *  - byte strings are [Bytes] (major 2), text is [Text] (major 3) — never conflated;
 *  - integral-valued floats keep an explicit [Float64] node so `1.0` encodes as a
 *    float (the `f90000` ladder), never as integer 1;
 *  - the float specials NaN/±Inf/-0.0 are carried as [FloatSpecial] constants so a
 *    NaN/Inf never has to round-trip through a Kotlin `Double`.
 *
 * Integers use [BigInteger] ([IntVal]) so the full uint64 / -2^64 head-form range is
 * representable. Kotlin's `ULong` (profile [idiom] unsigned_types) carries the unsigned
 * uint64 head-form natively without the signedness-comparison footgun — the win shows up
 * in the head-FORM emitter (see [CanonicalCbor], which switches argument length on a
 * `ULong`), while the value NODE keeps `BigInteger` because the nint side reaches -2^64
 * (one past `ULong`).
 */
sealed interface EcfValue {

    /** CBOR major-type 0/1 integer, as a [BigInteger] (full uint64 / -2^64 range). */
    data class IntVal(val value: BigInteger) : EcfValue {
        companion object {
            fun of(v: Long): IntVal = IntVal(BigInteger.valueOf(v))
        }
    }

    /** A finite floating-point value (encoded via the shortest f16/f32/f64 ladder). */
    data class Float64(val value: Double) : EcfValue

    /** The ECF Rule-4a special floats. Carried as sentinels so the canonical wire bytes
     *  are emitted directly and a NaN/Inf never materializes as a `Double`. */
    enum class FloatSpecial : EcfValue {
        NAN, POSITIVE_INFINITY, NEGATIVE_INFINITY, NEGATIVE_ZERO
    }

    /** CBOR byte string (major 2). The [ByteArray] is defensively copied in and out —
     *  JVM `ByteArray` is mutable + aliasable (profile no_byte_array_aliasing); a `val`
     *  does NOT make the contents immutable, so the codec NEVER aliases an internal
     *  buffer by reference. */
    class Bytes(octets: ByteArray) : EcfValue {
        private val data: ByteArray = octets.copyOf()
        /** Defensive copy on read. */
        fun octets(): ByteArray = data.copyOf()
        /** Internal no-copy accessor for the codec hot path (caller must not mutate). */
        internal fun raw(): ByteArray = data
        override fun equals(other: Any?): Boolean =
            other is Bytes && data.contentEquals(other.data)
        override fun hashCode(): Int = data.contentHashCode()
        override fun toString(): String = "Bytes(${data.size}B)"
    }

    /** CBOR text string (major 3), held as a Kotlin [String] (UTF-8 on the wire). */
    data class Text(val value: String) : EcfValue

    /** CBOR array (major 4), definite length. Read-only view on a defensive copy. */
    class Arr(items: List<EcfValue>) : EcfValue {
        val items: List<EcfValue> = items.toList()
        override fun equals(other: Any?): Boolean = other is Arr && items == other.items
        override fun hashCode(): Int = items.hashCode()
        companion object {
            fun of(vararg items: EcfValue): Arr = Arr(items.toList())
        }
    }

    /** A single map key/value pair (key is [Text] or [Bytes]). */
    data class Entry(val key: EcfValue, val value: EcfValue)

    /** CBOR map (major 5). Decode/construct order is preserved as a list of [Entry];
     *  the ENCODER re-sorts by encoded-key length-then-lex (ECF Rule 2). Keys are
     *  [Text] or [Bytes]. */
    class MapVal(entries: List<Entry>) : EcfValue {
        val entries: List<Entry> = entries.toList()

        /** Fetch a value by Text key; null if absent. */
        operator fun get(key: String): EcfValue? =
            entries.firstOrNull { (it.key as? Text)?.value == key }?.value

        override fun equals(other: Any?): Boolean = other is MapVal && entries == other.entries
        override fun hashCode(): Int = entries.hashCode()

        companion object {
            /** Build a map from alternating key, value... (a String key is wrapped as Text). */
            fun of(vararg kvs: Any?): MapVal {
                require(kvs.size % 2 == 0) { "odd kv count" }
                val es = ArrayList<Entry>(kvs.size / 2)
                var i = 0
                while (i < kvs.size) {
                    val k = kvs[i]
                    val key = if (k is String) Text(k) else k as EcfValue
                    es.add(Entry(key, kvs[i + 1] as EcfValue))
                    i += 2
                }
                return MapVal(es)
            }
        }
    }

    /** CBOR true/false (major 7). */
    enum class Bool : EcfValue { TRUE, FALSE }

    /** CBOR null (major 7, value 22). A singleton — distinct from a Kotlin null. */
    object Null : EcfValue
}
