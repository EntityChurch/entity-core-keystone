package org.entitycore.protocol.peer

import org.entitycore.protocol.codec.CanonicalCbor
import org.entitycore.protocol.codec.EcfValue
import org.entitycore.protocol.crypto.ContentHash
import java.math.BigInteger

/**
 * A materialized entity `{type, data, content_hash}` (§1.1, §3.4) on top of the S2
 * codec value model.
 *
 * The content_hash covers ONLY `{type, data}` (§1.1); the wire form ([toCbor]) carries
 * content_hash as a third field so entities are self-describing across serialization
 * (§3.1). The two forms stay distinct: the hash is never computed over a map that
 * already contains the content_hash field.
 *
 * The 33-byte [hash] (format byte 0x00 ‖ 32-byte SHA-256 digest) is held as a
 * [ByteArray]; it is defensively copied in/out (profile `no_byte_array_aliasing` — JVM
 * ByteArray is mutable + aliasable, and Kotlin `val` does NOT make the CONTENTS
 * immutable). [data] is an arbitrary ECF value (§1.1) — a map for protocol entities, a
 * scalar for e.g. primitive/string payloads.
 *
 * Not a `data class`: equality/identity is content_hash-based (a `data class` over a
 * `ByteArray` field gives reference equality), so we override equals/hashCode by hand.
 */
class Entity private constructor(
    val type: String,
    private val rawData: EcfValue,
    private val hashOctets: ByteArray,
) {
    /** The `data` as a map view: the map itself when data IS a map (every core protocol
     *  entity), or the canonical empty map when data is a scalar (so field reads on a
     *  scalar-data entity safely return null rather than throw). */
    fun data(): EcfValue.MapVal =
        rawData as? EcfValue.MapVal ?: EcfValue.MapVal(emptyList())

    /** The raw `data` value (§1.1) — may be any ECF node, not just a map. */
    fun rawData(): EcfValue = rawData

    /** Defensive copy of the 33-byte content_hash. */
    fun hash(): ByteArray = hashOctets.copyOf()

    /** Internal no-copy accessor (callers must not mutate). */
    internal fun rawHash(): ByteArray = hashOctets

    // ── field reads off data ────────────────────────────────────────────────────

    fun text(key: String): String? = Cbor.text(data(), key)
    fun bytes(key: String): ByteArray? = Cbor.bytes(data(), key)
    fun uint(key: String): BigInteger? = Cbor.uint(data(), key)
    fun field(key: String): EcfValue? = data()[key]
    fun mapField(key: String): EcfValue.MapVal? = Cbor.asMap(data()[key])

    /** Decode a nested entity carried at [key] (a wire cbor-map). */
    fun entityField(key: String): Entity? = mapField(key)?.let { ofCbor(it) }

    // ── wire form ───────────────────────────────────────────────────────────────

    /** The wire cbor-map `{type, data, content_hash}`. */
    fun toCbor(): EcfValue.MapVal = EcfValue.MapVal.of(
        "type", EcfValue.Text(type),
        "data", rawData,
        "content_hash", EcfValue.Bytes(hashOctets),
    )

    /** Encode the wire form to canonical ECF bytes. */
    fun wireBytes(): ByteArray = CanonicalCbor.encodeOrThrow(toCbor())

    override fun equals(other: Any?): Boolean =
        other is Entity && hashOctets.contentEquals(other.hashOctets)

    override fun hashCode(): Int = hashOctets.contentHashCode()

    override fun toString(): String = "Entity($type, ${Cbor.hex(hashOctets)})"

    companion object {
        /** Construct a materialized entity with a map `data` (the common protocol case),
         *  computing content_hash under the ecfv1-sha256 floor (format_code 0x00). */
        fun make(type: String, data: EcfValue.MapVal): Entity = makeRaw(type, data)

        /** Construct a materialized entity with an ARBITRARY ECF `data` value (§1.1) —
         *  covers scalar-data entities like primitive/string. */
        fun makeRaw(type: String, data: EcfValue): Entity {
            val basis = EcfValue.MapVal.of("type", EcfValue.Text(type), "data", data)
            val h = ContentHash.compute(basis, ContentHash.FORMAT_SHA256)
            return Entity(type, data, h)
        }

        /**
         * Parse a wire entity cbor-map, recompute the hash from `{type, data}`, and
         * validate it against the carried content_hash (§1.8 fidelity). We trust our
         * recomputed hash, not the wire bytes (§5.2 validate-before-trust).
         */
        fun ofCbor(m: EcfValue.MapVal): Entity {
            val typeV = m["type"]
            val dataV = m["data"]
            require(typeV is EcfValue.Text) { "entity: missing/invalid type" }
            requireNotNull(dataV) { "entity: missing data" }
            // §1.1: data is an arbitrary ECF value (map for protocol entities, scalar for
            // e.g. primitive/string). Accept any non-null node, not just maps.
            val e = makeRaw(typeV.value, dataV)
            val carried = m["content_hash"]
            if (carried is EcfValue.Bytes && !carried.octets().contentEquals(e.hashOctets)) {
                throw IllegalArgumentException("content_hash mismatch (§1.8 fidelity)")
            }
            return e
        }
    }
}
