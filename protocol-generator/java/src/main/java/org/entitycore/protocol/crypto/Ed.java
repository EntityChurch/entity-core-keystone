package org.entitycore.protocol.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;

import org.entitycore.protocol.crypto.PeerId.Curve;

/**
 * EdDSA sign / verify via the JDK SunEC provider (JEP 339: Ed25519 + Ed448), and raw
 * public-key extraction. Zero runtime dependency; RFC-8032 deterministic.
 *
 * <p><b>Crypto sourcing decision (A-JAVA-002).</b> SIGN/VERIFY use SunEC for both
 * curves — the JDK closes the agility SIGNATURE bar natively, with no BouncyCastle
 * (the CORE build is BC-free; BC stays an opt-in cross-check only). RAW PUBLIC-KEY
 * derivation uses {@link EdKeyDerivation} (native RFC-8032 scalar multiply), because
 * SunEC exposes a public key only as an {@link EdECPoint} and has no seed→public API
 * — and the JDK ships no SHAKE256, which the Ed448 expansion needs. So the public-key
 * derivation is hand-rolled (SHA-512 / hand-rolled SHAKE256 + BigInteger curve math),
 * keeping the whole core dependency-free.
 */
public final class Ed {
    private Ed() { }

    private static NamedParameterSpec spec(Curve curve) {
        return (curve == Curve.ED25519) ? NamedParameterSpec.ED25519 : NamedParameterSpec.ED448;
    }

    private static String algo(Curve curve) {
        return (curve == Curve.ED25519) ? "Ed25519" : "Ed448";
    }

    private static int seedLen(Curve curve) {
        return (curve == Curve.ED25519) ? 32 : 57;
    }

    /** Build a {@link PrivateKey} from a raw RFC-8032 seed (32 B Ed25519 / 57 B Ed448).
     *  SunEC runs the RFC-8032 expansion internally. */
    public static PrivateKey privateKeyFromSeed(byte[] seed, Curve curve)
            throws EntityCryptoException {
        if (seed.length != seedLen(curve)) {
            throw new BadSeedException(curve + " seed must be " + seedLen(curve)
                    + " bytes, got " + seed.length);
        }
        try {
            KeyFactory kf = KeyFactory.getInstance(algo(curve));
            return kf.generatePrivate(new EdECPrivateKeySpec(spec(curve), seed.clone()));
        } catch (GeneralSecurityException e) {
            throw new EntityCryptoException("private key from seed failed: " + curve, e);
        }
    }

    /** Derive the RAW (RFC-8032 byte-string) public key from a seed — native, via
     *  {@link EdKeyDerivation}. */
    public static byte[] rawPublicKeyFromSeed(byte[] seed, Curve curve)
            throws EntityCryptoException {
        return EdKeyDerivation.rawPublicKey(seed, curve);
    }

    /** Extract the raw RFC-8032 public-key bytes from a SunEC {@link PublicKey}
     *  ({@link EdECPoint} → little-endian y with the x sign bit in the final byte). */
    public static byte[] rawPublicKey(PublicKey pub, Curve curve) throws EntityCryptoException {
        if (!(pub instanceof EdECPublicKey ed)) {
            throw new EntityCryptoException("not an EdEC public key: " + pub.getClass());
        }
        EdECPoint point = ed.getPoint();
        int len = seedLen(curve);
        byte[] out = new byte[len];
        byte[] y = point.getY().toByteArray(); // big-endian magnitude
        for (int i = 0; i < y.length; i++) {
            int idx = y.length - 1 - i;        // least-significant first
            if (i < len) {
                out[i] = y[idx];
            }
        }
        if (point.isXOdd()) {
            out[len - 1] |= (byte) 0x80;
        }
        return out;
    }

    /** Sign {@code message} with the seed-derived key. RFC-8032 signature (64 B
     *  Ed25519, 114 B Ed448). */
    public static byte[] sign(byte[] seed, byte[] message, Curve curve)
            throws EntityCryptoException {
        try {
            PrivateKey priv = privateKeyFromSeed(seed, curve);
            Signature sig = Signature.getInstance(algo(curve));
            sig.initSign(priv);
            sig.update(message);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new EntityCryptoException("sign failed: " + curve, e);
        }
    }

    /** Verify a signature against a RAW public key. */
    public static boolean verify(byte[] rawPublicKey, byte[] message, byte[] signature,
                                 Curve curve) throws EntityCryptoException {
        try {
            PublicKey pub = publicKeyFromRaw(rawPublicKey, curve);
            Signature sig = Signature.getInstance(algo(curve));
            sig.initVerify(pub);
            sig.update(message);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** Rebuild a SunEC {@link PublicKey} from RAW RFC-8032 bytes (inverse of
     *  {@link #rawPublicKey}). */
    public static PublicKey publicKeyFromRaw(byte[] raw, Curve curve)
            throws EntityCryptoException {
        try {
            byte[] le = raw.clone();
            int last = le.length - 1;
            boolean xOdd = (le[last] & 0x80) != 0;
            le[last] &= 0x7f;
            byte[] be = new byte[le.length];
            for (int i = 0; i < le.length; i++) {
                be[i] = le[le.length - 1 - i];
            }
            BigInteger y = new BigInteger(1, be);
            EdECPoint point = new EdECPoint(xOdd, y);
            KeyFactory kf = KeyFactory.getInstance(algo(curve));
            return kf.generatePublic(new EdECPublicKeySpec(spec(curve), point));
        } catch (GeneralSecurityException e) {
            throw new EntityCryptoException("public key from raw failed: " + curve, e);
        }
    }
}
