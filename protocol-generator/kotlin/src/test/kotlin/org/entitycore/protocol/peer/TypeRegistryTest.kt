package org.entitycore.protocol.peer

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * §9.5 core type-registry smoke (the type-registry N/N gate).
 *
 * A bootstrapped peer publishes the full §9.5 53-type core floor at
 * `/{peer}/system/type/{name}` (render-from-model — the content_hash of each is computed
 * by THIS peer's S2-green codec over `{type, data}`). This test verifies, for every one
 * of the 53 floor types:
 *  - it is rendered + bound in the store (reachable at its tree path);
 *  - its content_hash is a 33-byte ecfv1-sha256 hash (format byte 0x00 + 32-byte digest);
 *  - the render is DETERMINISTIC (a re-render yields the byte-identical hash) — the
 *    convergence the S4 type_system byte-diff against the canonical vectors depends on.
 *
 * The byte-for-byte diff against the canonical `type-registry-vectors-v1` is the S4
 * `type_system` category; this S3 smoke proves the 53/53 floor renders + binds + is
 * stable, so the registry surface the oracle fetches exists.
 */
class TypeRegistryTest {

    @Test
    fun coreTypeFloorPublishes() {
        val peer = Peer.create(ByteArray(32) { 0x11 })
        val local = peer.localPeer
        val models = CoreTypeDefs.models()
        assertEquals(53, models.size, "the §9.5 core floor is exactly 53 types")

        var checked = 0
        for ((name, _) in models) {
            val e = peer.store.getAt("/$local/system/type/$name")
            assertTrue(e != null, "core type published at tree path: $name")
            assertEquals("system/type", e.type, "$name is a system/type entity")
            val h = e.hash()
            assertEquals(33, h.size, "$name content_hash is 33 bytes (format byte + digest)")
            assertEquals(0, h[0].toInt(), "$name content_hash format byte is 0x00 (ecfv1-sha256)")
            // determinism: a fresh render of the same model yields the byte-identical hash.
            val rerendered = Entity.make("system/type", models.getValue(name))
            assertTrue(rerendered.hash().contentEquals(h), "$name render is deterministic")
            checked++
        }
        println("TYPE-REGISTRY: PASS ($checked/${models.size} core types rendered + bound + stable)")
        assertEquals(53, checked)
    }
}
