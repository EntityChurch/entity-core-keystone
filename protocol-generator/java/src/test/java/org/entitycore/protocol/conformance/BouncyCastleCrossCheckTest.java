package org.entitycore.protocol.conformance;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HexFormat;

import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.entitycore.protocol.crypto.Ed;
import org.entitycore.protocol.crypto.PeerId;
import org.junit.jupiter.api.Test;

/**
 * OPT-IN agility cross-check (A-JAVA-002): an INDEPENDENT managed crypto source
 * (BouncyCastle, the C# A-009 precedent) confirms the JDK SunEC Ed448 signature and
 * our native ({@link org.entitycore.protocol.crypto.EdKeyDerivation}) raw-public-key
 * derivation. This is TEST scope only ({@code provided} dependency) — the CORE build
 * is BouncyCastle-free; SunEC + the hand-rolled SHAKE256/curve math cover the floor
 * and the agility bar with zero runtime dependency. This test exists to *decide*
 * SunEC-vs-BC for the agility corpus by proving they agree byte-for-byte.
 */
final class BouncyCastleCrossCheckTest {

    private static byte[] hex(String h) { return HexFormat.of().parseHex(h); }

    @Test
    void ed448SunEcAndNativeAgreeWithBouncyCastle() throws Exception {
        byte[] seed = new byte[57];
        Arrays.fill(seed, (byte) 0x42);
        byte[] msg = hex("76372e3637205068617365203120636f686f72742063726f73732d696d706c2045643434382066697874757265");

        // BouncyCastle: derive pubkey from seed (RFC-8032), sign deterministically.
        Ed448PrivateKeyParameters bcPriv = new Ed448PrivateKeyParameters(seed, 0);
        Ed448PublicKeyParameters bcPub = bcPriv.generatePublicKey();
        byte[] bcPubBytes = bcPub.getEncoded();
        Ed448Signer bcSigner = new Ed448Signer(new byte[0]); // Ed448 (no context)
        bcSigner.init(true, bcPriv);
        bcSigner.update(msg, 0, msg.length);
        byte[] bcSig = bcSigner.generateSignature();

        // Our native raw pubkey == BouncyCastle pubkey.
        byte[] nativePub = Ed.rawPublicKeyFromSeed(seed, PeerId.Curve.ED448);
        assertArrayEquals(bcPubBytes, nativePub, "native Ed448 pubkey == BouncyCastle");

        // SunEC signature == BouncyCastle signature (both RFC-8032 deterministic).
        byte[] sunEcSig = Ed.sign(seed, msg, PeerId.Curve.ED448);
        assertArrayEquals(bcSig, sunEcSig, "SunEC Ed448 signature == BouncyCastle");

        // BouncyCastle verifies the SunEC signature against the native pubkey.
        Ed448Signer verifier = new Ed448Signer(new byte[0]);
        verifier.init(false, new Ed448PublicKeyParameters(nativePub, 0));
        verifier.update(msg, 0, msg.length);
        assertTrue(verifier.verifySignature(sunEcSig),
                "BouncyCastle verifies the SunEC signature + native pubkey");
    }
}
