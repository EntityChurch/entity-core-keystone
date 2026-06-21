package org.entitycore.protocol.peer

import org.entitycore.protocol.codec.EcfValue
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * §3.6 M3 multi-signature K-of-N — ACCEPT path.
 *
 * The validate-peer `multisig` category is 100% rejection tests (malformed-quorum → 403),
 * which a fail-closed peer passes vacuously. The Go oracle's one accept-path check
 * (`valid_2of3_peer_signed_accepted`) env-skips for the ephemeral run-s4 peer. This unit
 * test covers the direction the oracle omits: a real 2-of-3 multi-sig root (one signer =
 * the local peer, two valid signatures over the cap content_hash) → ALLOW, plus the deny
 * flips (below-threshold M4, local-not-in-signers M6, degenerate-threshold M3,
 * duplicate-signers M3, off-root M3) and the single-sig superset (a single-sig root still
 * verifies, unregressed).
 *
 * Direct against [Capability.verifyCapabilityChain] — the Layer-1 verdict core (§5.10
 * determinism) — with the chain materialized in the envelope's `included` list, exactly
 * as a dispatch request carries it (§5.5).
 */
class MultiSigCapabilityTest {

    private fun seed(b: Int): ByteArray = ByteArray(32) { b.toByte() }

    /** A multi-sig root capability: granter = {signers, threshold}, with a grantee. */
    private fun multiSigCap(signers: List<ByteArray>, threshold: Long, grantee: ByteArray): Entity {
        val granter = Cbor.map(
            "signers", EcfValue.Arr(signers.map { Cbor.bytes(it) }),
            "threshold", EcfValue.IntVal.of(threshold),
        )
        return Entity.make("system/capability/token",
            Cbor.map(
                "granter", granter,
                "grantee", Cbor.bytes(grantee),
                "grants", EcfValue.Arr(listOf(
                    Peer.grant(listOf("system/tree"), listOf("system/type/*"), listOf("get"), null))),
            ))
    }

    private fun included(vararg entities: Entity): List<Envelope.Included> =
        entities.map { Envelope.Included(it.hash(), it) }

    /** Run the chain verdict for [cap] given [inc], against an empty store. */
    private fun allows(local: String, cap: Entity, inc: List<Envelope.Included>): Boolean =
        try {
            Capability.verifyCapabilityChain(local, Store(), cap, inc) == Capability.Verdict.ALLOW
        } catch (e: Capability.UnresolvableGrantee) {
            false
        }

    @Test
    fun multiSigKofN() {
        // Three signer identities; id1 is the LOCAL peer (M6).
        val id1 = Identity.ofSeed(seed(0x11))
        val id2 = Identity.ofSeed(seed(0x22))
        val id3 = Identity.ofSeed(seed(0x33))
        val local = id1.peerId

        // The grantee is the local peer too (so the §5.5 root grantee resolves).
        val grantee = id1.identityHash()
        val signers = listOf(id1.identityHash(), id2.identityHash(), id3.identityHash())

        val p1 = id1.peerEntity
        val p2 = id2.peerEntity
        val p3 = id3.peerEntity

        // ── ACCEPT: valid 2-of-3, local in quorum, 2 valid sigs over the cap hash ──
        val cap = multiSigCap(signers, 2, grantee)
        val s1 = id1.sign(cap)
        val s2 = id2.sign(cap)
        assertTrue(allows(local, cap, included(p1, p2, p3, s1, s2)),
            "2-of-3 valid quorum (local in signers) -> ALLOW (M3/M4/M6)")

        // M4: only 1 valid sig (< threshold) -> DENY.
        assertFalse(allows(local, cap, included(p1, p2, p3, s1)),
            "1-of-3 below threshold -> DENY (M4 k-of-n)")

        // M4: a DUPLICATE signature from one signer does NOT inflate the count.
        val s1dup = id1.sign(cap)
        assertFalse(allows(local, cap, included(p1, p2, p3, s1, s1dup)),
            "duplicate signature from one signer does not reach threshold -> DENY (M4)")

        // M6: the local peer is NOT among the signers -> DENY (even with a valid quorum).
        val capNoLocal = multiSigCap(listOf(id2.identityHash(), id3.identityHash()), 2, grantee)
        val s2b = id2.sign(capNoLocal)
        val s3b = id3.sign(capNoLocal)
        assertFalse(allows(local, capNoLocal, included(p2, p3, s2b, s3b)),
            "local peer not in signers -> DENY (M6)")

        // M3: threshold = 1 (degenerate single disguised as quorum) -> DENY by structure.
        val capT1 = multiSigCap(signers, 1, grantee)
        val s1t = id1.sign(capT1)
        val s2t = id2.sign(capT1)
        assertFalse(allows(local, capT1, included(p1, p2, p3, s1t, s2t)),
            "threshold=1 -> DENY (M3 structure precedence)")

        // M3: duplicate signers in the descriptor -> DENY by structure.
        val capDup = multiSigCap(listOf(id1.identityHash(), id1.identityHash()), 2, grantee)
        val s1d = id1.sign(capDup)
        assertFalse(allows(local, capDup, included(p1, s1d)),
            "duplicate signers in descriptor -> DENY (M3 distinct)")

        // M3 root-only: a multi-sig token WITH a parent (off-root) -> DENY.
        val multiWithParent = Entity.make("system/capability/token",
            Cbor.map(
                "granter", Cbor.map(
                    "signers", EcfValue.Arr(listOf(Cbor.bytes(id1.identityHash()), Cbor.bytes(id2.identityHash()))),
                    "threshold", EcfValue.IntVal.of(2L)),
                "grantee", Cbor.bytes(grantee),
                "parent", Cbor.bytes(p1.hash())))
        assertFalse(allows(local, multiWithParent, included(p1, p2)),
            "multi-sig token with a parent (off-root) -> DENY (M3 root-only)")

        // ── single-sig superset: a normal single-sig root still verifies (unregressed).
        val singleRoot = Entity.make("system/capability/token",
            Cbor.map(
                "granter", Cbor.bytes(id1.identityHash()),
                "grantee", Cbor.bytes(id1.identityHash()),
                "grants", EcfValue.Arr(listOf(
                    Peer.grant(listOf("system/tree"), listOf("system/type/*"), listOf("get"), null)))))
        val singleSig = id1.sign(singleRoot)
        assertTrue(allows(local, singleRoot, included(p1, singleSig)),
            "single-sig root rooted at local still verifies (strict superset)")
    }
}
