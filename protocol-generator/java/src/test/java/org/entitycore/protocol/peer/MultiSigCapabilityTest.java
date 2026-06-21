package org.entitycore.protocol.peer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.entitycore.protocol.codec.EcfValue;
import org.junit.jupiter.api.Test;

/**
 * §3.6 M3 multi-signature K-of-N — ACCEPT path.
 *
 * <p>The validate-peer {@code multisig} category is 100% rejection tests
 * (malformed-quorum → 403), which a fail-closed peer passes vacuously. The Go oracle's
 * one accept-path check ({@code valid_2of3_peer_signed_accepted}) env-skips for the
 * ephemeral run-s4 peer (keys not on disk). This unit test covers the direction the
 * oracle omits: a real 2-of-3 multi-sig root (one signer = the local peer, two valid
 * signatures over the cap content_hash) → ALLOW, plus the deny flips (below-threshold
 * M4, local-not-in-signers M6, degenerate-threshold M3, duplicate-signers M3) and the
 * single-sig superset (a single-sig root still verifies, unregressed).
 *
 * <p>Direct against {@link Capability#verifyCapabilityChain} — the Layer-1 verdict core
 * (§5.10 determinism) — with the chain materialized in the envelope's {@code included}
 * map, exactly as a dispatch request carries it (§5.5).
 */
final class MultiSigCapabilityTest {

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) b);
        return s;
    }

    /** A multi-sig root capability: granter = {signers, threshold}, with a grantee. */
    private static Entity multiSigCap(List<byte[]> signers, long threshold, byte[] grantee) {
        List<EcfValue> sigArr = new ArrayList<>(signers.size());
        for (byte[] s : signers) {
            sigArr.add(Cbor.bytes(s));
        }
        EcfValue.Map granter = Cbor.map(
                "signers", new EcfValue.Array(sigArr),
                "threshold", EcfValue.Int.of(threshold));
        return Entity.make("system/capability/token",
                Cbor.map(
                        "granter", granter,
                        "grantee", Cbor.bytes(grantee),
                        "grants", new EcfValue.Array(List.of(
                                Peer.grant(List.of("system/tree"), List.of("system/type/*"),
                                        List.of("get"), null)))));
    }

    private static List<Envelope.Included> included(Entity... entities) {
        List<Envelope.Included> inc = new ArrayList<>();
        for (Entity e : entities) {
            inc.add(new Envelope.Included(e.rawHash(), e));
        }
        return inc;
    }

    /** Run the chain verdict for {@code cap} given {@code inc}, against an empty store. */
    private static boolean allows(String local, Entity cap, List<Envelope.Included> inc) {
        try {
            return Capability.verifyCapabilityChain(local, new Store(), cap, inc)
                    == Capability.Verdict.ALLOW;
        } catch (Capability.UnresolvableGrantee e) {
            return false;
        }
    }

    @Test
    void multiSigKofN() throws Exception {
        // Three signer identities; id1 is the LOCAL peer (M6).
        Identity id1 = Identity.ofSeed(seed(0x11));
        Identity id2 = Identity.ofSeed(seed(0x22));
        Identity id3 = Identity.ofSeed(seed(0x33));
        String local = id1.peerId();

        // The grantee is the local peer too (so the §5.5 root grantee resolves).
        byte[] grantee = id1.identityHash();
        List<byte[]> signers = List.of(
                id1.identityHash(), id2.identityHash(), id3.identityHash());

        // The three signer peer entities + grantee resolve from `included`.
        Entity p1 = id1.peerEntity();
        Entity p2 = id2.peerEntity();
        Entity p3 = id3.peerEntity();

        // ── ACCEPT: valid 2-of-3, local in quorum, 2 valid sigs over the cap hash ──
        Entity cap = multiSigCap(signers, 2, grantee);
        Entity s1 = id1.sign(cap);
        Entity s2 = id2.sign(cap);
        assertTrue(
                allows(local, cap, included(p1, p2, p3, s1, s2)),
                "2-of-3 valid quorum (local in signers) -> ALLOW (M3/M4/M6)");

        // M4: only 1 valid sig (< threshold) -> DENY.
        assertFalse(
                allows(local, cap, included(p1, p2, p3, s1)),
                "1-of-3 below threshold -> DENY (M4 k-of-n)");

        // M4: a DUPLICATE signature from one signer does NOT inflate the count.
        // Two copies of id1's sig + nothing from id2/id3 = 1 distinct valid signer < 2.
        Entity s1dup = id1.sign(cap);
        assertFalse(
                allows(local, cap, included(p1, p2, p3, s1, s1dup)),
                "duplicate signature from one signer does not reach threshold -> DENY (M4)");

        // M6: the local peer is NOT among the signers -> DENY (even with a valid quorum).
        Entity capNoLocal = multiSigCap(
                List.of(id2.identityHash(), id3.identityHash()), 2, grantee);
        Entity s2b = id2.sign(capNoLocal);
        Entity s3b = id3.sign(capNoLocal);
        assertFalse(
                allows(local, capNoLocal, included(p2, p3, s2b, s3b)),
                "local peer not in signers -> DENY (M6)");

        // M3: threshold = 1 (degenerate single-sig disguised as quorum) -> DENY by
        // structure, even with valid signatures (precedence: M3 before M4).
        Entity capT1 = multiSigCap(signers, 1, grantee);
        Entity s1t = id1.sign(capT1);
        Entity s2t = id2.sign(capT1);
        assertFalse(
                allows(local, capT1, included(p1, p2, p3, s1t, s2t)),
                "threshold=1 -> DENY (M3 structure precedence)");

        // M3: duplicate signers in the descriptor -> DENY by structure.
        Entity capDup = multiSigCap(
                List.of(id1.identityHash(), id1.identityHash()), 2, grantee);
        Entity s1d = id1.sign(capDup);
        assertFalse(
                allows(local, capDup, included(p1, s1d)),
                "duplicate signers in descriptor -> DENY (M3 distinct)");

        // M3: a multi-sig token OFF the chain root -> DENY (root-only).
        // Build a single-sig child whose parent is the multi-sig root; the multi-sig
        // token appearing as a non-root link is rejected.
        Entity childOfMulti = Entity.make("system/capability/token",
                Cbor.map(
                        "granter", Cbor.bytes(grantee),
                        "grantee", Cbor.bytes(grantee),
                        "parent", Cbor.bytes(cap.rawHash())));
        // (cap here is the multi-sig root reachable as parent.) The off-root multi-sig
        // would only arise if a multi-sig token had a parent; covered by M3 parent!=null
        // inside verifyMultiSigRoot and the root-only guard in the chain walk. We assert
        // the structural guard directly: a multi-sig token WITH a parent denies.
        Entity multiWithParent = Entity.make("system/capability/token",
                Cbor.map(
                        "granter", Cbor.map(
                                "signers", new EcfValue.Array(List.of(
                                        Cbor.bytes(id1.identityHash()),
                                        Cbor.bytes(id2.identityHash()))),
                                "threshold", EcfValue.Int.of(2)),
                        "grantee", Cbor.bytes(grantee),
                        "parent", Cbor.bytes(p1.rawHash())));
        assertFalse(
                allows(local, multiWithParent, included(p1, p2)),
                "multi-sig token with a parent (off-root) -> DENY (M3 root-only)");

        // ── single-sig superset: a normal single-sig root still verifies (unregressed).
        // Root granter = local identity; self-signed; grantee = local.
        Entity singleRoot = Entity.make("system/capability/token",
                Cbor.map(
                        "granter", Cbor.bytes(id1.identityHash()),
                        "grantee", Cbor.bytes(id1.identityHash()),
                        "grants", new EcfValue.Array(List.of(
                                Peer.grant(List.of("system/tree"),
                                        List.of("system/type/*"), List.of("get"), null)))));
        Entity singleSig = id1.sign(singleRoot);
        assertTrue(
                allows(local, singleRoot, included(p1, singleSig)),
                "single-sig root rooted at local still verifies (strict superset)");
    }
}
