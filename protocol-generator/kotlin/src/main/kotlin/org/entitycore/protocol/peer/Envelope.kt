package org.entitycore.protocol.peer

import org.entitycore.protocol.codec.EcfValue

/**
 * The protocol envelope (§3.1): a [root] entity plus an [included] list of protocol
 * entities keyed by content_hash. `included` is the §5.8 authority carrier (caps, peer
 * identities, signatures travel here).
 *
 * Held as an insertion-ordered list of (hash, entity) pairs so a wire round-trip is
 * deterministic; lookup is by content_hash octets.
 */
class Envelope(val root: Entity, included: List<Included> = emptyList()) {

    /** One included entry: a content_hash (33 bytes) and its entity. Not a `data class`
     *  (the ByteArray field would give reference equality); identity is by the entity. */
    class Included(val hash: ByteArray, val entity: Entity)

    val included: List<Included> = included.toList()

    /** Find an included entity by its content_hash, or null. */
    fun includedGet(h: ByteArray): Entity? =
        included.firstOrNull { it.hash.contentEquals(h) }?.entity

    // ── wire form ───────────────────────────────────────────────────────────────

    fun toCbor(): EcfValue.MapVal {
        // §3.1: `included` is a content_hash → entity MAP, so duplicate hashes collapse
        // to one entry. The peer/transport builders may list the same entity twice (e.g.
        // a cap whose granter IS the local identity — granterPeer == peerEntity in the
        // §6.11 reentry path), which would otherwise emit a duplicate map key that the
        // canonical codec rejects on decode. Dedup by content_hash, preserving first-seen
        // order, before encoding.
        val seen = HashSet<String>()
        val inc = ArrayList<EcfValue.Entry>(included.size)
        for (it in included) {
            if (seen.add(Cbor.hex(it.hash))) {
                inc.add(EcfValue.Entry(EcfValue.Bytes(it.hash), it.entity.toCbor()))
            }
        }
        return EcfValue.MapVal.of(
            "root", root.toCbor(),
            "included", EcfValue.MapVal(inc),
        )
    }

    companion object {
        fun ofCbor(m: EcfValue.MapVal): Envelope {
            val rootV = m["root"]
            require(rootV is EcfValue.MapVal) { "envelope: missing root" }
            val root = Entity.ofCbor(rootV)
            val included = ArrayList<Included>()
            val incM = m["included"] as? EcfValue.MapVal
            if (incM != null) {
                // dedup by content_hash, preserving order (defensive — a well-formed
                // envelope has unique keys; the codec already rejects duplicate map keys).
                val seen = HashSet<String>()
                for (e in incM.entries) {
                    val kb = e.key as? EcfValue.Bytes
                        ?: throw IllegalArgumentException("envelope: included key not bytes")
                    val vm = e.value as? EcfValue.MapVal
                        ?: throw IllegalArgumentException("envelope: included value not a map")
                    val ent = Entity.ofCbor(vm)
                    // §3.1: the included content_hash MUST equal the map key.
                    if (!kb.octets().contentEquals(ent.rawHash())) {
                        throw IllegalArgumentException("included key != content_hash")
                    }
                    if (seen.add(Cbor.hex(kb.octets()))) {
                        included.add(Included(kb.octets(), ent))
                    }
                }
            }
            return Envelope(root, included)
        }
    }
}
