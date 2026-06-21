package org.entitycore.protocol.conformance;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;

import org.entitycore.protocol.codec.Base58;
import org.entitycore.protocol.codec.CanonicalCbor;
import org.entitycore.protocol.codec.EcfValue;
import org.entitycore.protocol.codec.TagRejectedException;
import org.entitycore.protocol.codec.Varint;
import org.entitycore.protocol.crypto.Ed;
import org.entitycore.protocol.crypto.PeerId;
import org.entitycore.protocol.crypto.Shake256;
import org.junit.jupiter.api.Test;

/**
 * Uncovered-range probes + the Ed448 RFC-8032 KAT gate (codec-review heuristic: a
 * green corpus proves the math vs the corpus, not the ranges it does not cover).
 */
final class SelfTest {

    private static byte[] hex(String h) { return HexFormat.of().parseHex(h); }
    private static EcfValue rt(EcfValue v) throws Exception { return CanonicalCbor.decode(CanonicalCbor.encode(v)); }
    private static EcfValue.Int bigInt(String dec) { return new EcfValue.Int(new BigInteger(dec)); }

    @Test
    void uint64AboveSignedRange() throws Exception {
        // 2^63 (above signed-i64 max — Java long has no native unsigned; BigInteger sidesteps)
        EcfValue.Int p63 = new EcfValue.Int(BigInteger.ONE.shiftLeft(63));
        assertEquals(p63, rt(p63));
        // 2^64-1
        EcfValue.Int max = new EcfValue.Int(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE));
        assertArrayEquals(hex("1bffffffffffffffff"), CanonicalCbor.encode(max));
        assertEquals(max, rt(max));
        // -2^64
        EcfValue.Int nmin = new EcfValue.Int(BigInteger.ONE.shiftLeft(64).negate());
        assertArrayEquals(hex("3bffffffffffffffff"), CanonicalCbor.encode(nmin));
        assertEquals(nmin, rt(nmin));
    }

    @Test
    void floatLadderAndSpecials() throws Exception {
        assertEquals(EcfValue.FloatSpecial.NAN, rt(EcfValue.FloatSpecial.NAN));
        assertEquals(EcfValue.FloatSpecial.POSITIVE_INFINITY, rt(EcfValue.FloatSpecial.POSITIVE_INFINITY));
        assertEquals(EcfValue.FloatSpecial.NEGATIVE_INFINITY, rt(EcfValue.FloatSpecial.NEGATIVE_INFINITY));
        assertEquals(EcfValue.FloatSpecial.NEGATIVE_ZERO, rt(EcfValue.FloatSpecial.NEGATIVE_ZERO));
        assertEquals(3, CanonicalCbor.encode(new EcfValue.Float64(1.5)).length);   // f16
        assertEquals(9, CanonicalCbor.encode(new EcfValue.Float64(1.1)).length);   // f64
        assertEquals(5, CanonicalCbor.encode(new EcfValue.Float64(65503.0)).length); // f32
        assertEquals(new EcfValue.Float64(65504.0), rt(new EcfValue.Float64(65504.0)));
    }

    @Test
    void peerIdFormatParseRoundTrip() throws Exception {
        byte[] digest = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        PeerId.Parsed p1 = PeerId.parse(PeerId.format(1, 0, digest));
        assertEquals(1, p1.keyType());
        assertEquals(0, p1.hashType());
        assertArrayEquals(digest, p1.digest());
        // multi-byte key_type (128)
        PeerId.Parsed p2 = PeerId.parse(PeerId.format(128, 1, digest));
        assertEquals(128, p2.keyType());
        assertEquals(1, p2.hashType());
        assertArrayEquals(digest, p2.digest());
    }

    @Test
    void base58LeadingZeroPreserved() {
        byte[] b = hex("0000deadbeef");
        assertArrayEquals(b, Base58.decode(Base58.encode(b)));
    }

    @Test
    void varintMultibyte() throws Exception {
        assertArrayEquals(hex("8001"), Varint.encode(128));
        Varint.Decoded d = Varint.decode(hex("8001"), 0);
        assertEquals(128, d.value());
        assertEquals(2, d.next());
    }

    @Test
    void ed25519SignVerifyTamper() throws Exception {
        byte[] seed = new byte[32];
        byte[] msg = "selftest".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] sig = Ed.sign(seed, msg, PeerId.Curve.ED25519);
        byte[] pub = Ed.rawPublicKeyFromSeed(seed, PeerId.Curve.ED25519);
        assertEquals(64, sig.length);
        assertTrue(Ed.verify(pub, msg, sig, PeerId.Curve.ED25519));
        assertFalse(Ed.verify(pub, "selftesu".getBytes(), sig, PeerId.Curve.ED25519));
    }

    @Test
    void ed25519PubkeyRfc8032Test1() throws Exception {
        // RFC 8032 §7.1 TEST 1: all-zero seed.
        byte[] pub = Ed.rawPublicKeyFromSeed(new byte[32], PeerId.Curve.ED25519);
        assertArrayEquals(
                hex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"),
                pub);
        // cross-check: native-derived raw pubkey is accepted by the SunEC verifier.
        byte[] msg = "x".getBytes();
        byte[] sig = Ed.sign(new byte[32], msg, PeerId.Curve.ED25519);
        assertTrue(Ed.verify(pub, msg, sig, PeerId.Curve.ED25519));
    }

    @Test
    void shake256KnownAnswer() {
        // NIST: SHAKE256("") first 32 bytes.
        assertArrayEquals(
                hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
                Shake256.digest(new byte[0], 32));
    }

    @Test
    void bareTagRejected() {
        assertThrows(TagRejectedException.class,
                () -> CanonicalCbor.decode(hex("d9d9f7a0")));
    }

    /**
     * A-JAVA-002 GATE: native Ed448 RFC-8032 byte-equality KAT. Pins from v7.71
     * agility-SEEDS.md §1.1 (KEY-TYPE-ED448-1, seed 0x42×57).
     */
    @Test
    void ed448Kat() throws Exception {
        byte[] seed = new byte[57];
        Arrays.fill(seed, (byte) 0x42);
        byte[] msg = hex("76372e3637205068617365203120636f686f72742063726f73732d696d706c2045643434382066697874757265");
        byte[] wantPub = hex("2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00");
        byte[] wantSig = hex("0aff7a36b2b5e7502f9a133bc9ed39316284f0be738e2485546b33fda60966b19ac0e3424ed549072af7ac5caa6d695c3e1e6412207cecaf8085444fbf062cb5271ea6d127c6c87327e1e20793f2b10341d04bd4bed32e220eca1b2255cc8aa4d2a0c8304d67e6f20e814b90411049b33400");
        String wantPeerId = "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4";

        byte[] pub = Ed.rawPublicKeyFromSeed(seed, PeerId.Curve.ED448);
        assertArrayEquals(wantPub, pub, "Ed448 KAT pubkey (57 B, byte-equal)");

        byte[] sig = Ed.sign(seed, msg, PeerId.Curve.ED448);
        assertArrayEquals(wantSig, sig, "Ed448 KAT signature (114 B, byte-equal RFC-8032)");

        assertTrue(Ed.verify(pub, msg, sig, PeerId.Curve.ED448), "Ed448 KAT verify");

        String peerId = PeerId.fromPublicKey(pub, PeerId.Curve.ED448);
        assertEquals(wantPeerId, peerId, "Ed448 KAT peer_id (§1.5 SHA-256-form)");
    }

    private static void assertThrows(Class<? extends Throwable> type,
                                     org.junit.jupiter.api.function.Executable e) {
        org.junit.jupiter.api.Assertions.assertThrows(type, e);
    }
}
