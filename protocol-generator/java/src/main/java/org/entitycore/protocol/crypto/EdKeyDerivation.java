package org.entitycore.protocol.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.entitycore.protocol.crypto.PeerId.Curve;

/**
 * RFC-8032 raw public-key derivation from a secret seed, for Ed25519 and Ed448 —
 * fully JDK-native (zero third-party dependency).
 *
 * <p><b>Why this exists (A-JAVA-002, the headline Java crypto-axis seam).</b> SunEC
 * signs/verifies both curves but exposes a public key only as an {@code EdECPoint}
 * (y-coordinate + x-sign-bit), and has NO seed→public-point API. So to build the
 * §1.5 identity-multihash peer_id and the wire {@code system/peer} entity (both need
 * the RAW 32-/57-byte public key), the public key is derived here:
 * <ul>
 *   <li><b>Ed25519:</b> SHA-512 (JDK) expand → clamp → Curve25519 (twisted Edwards)
 *       base-point scalar multiply → little-endian point encode.</li>
 *   <li><b>Ed448:</b> SHAKE256 ({@link Shake256}, hand-rolled — the JDK ships no
 *       SHAKE) expand → clamp → Edwards448 base-point scalar multiply → encode.</li>
 * </ul>
 * Both are verified against RFC-8032 / agility-corpus known-answer pubkeys, and the
 * result is independently cross-checked by feeding it to SunEC's verifier
 * ({@link Ed#verify}) on a self-signed message.
 */
public final class EdKeyDerivation {
    private EdKeyDerivation() { }

    // ── Ed25519 (Curve25519, twisted Edwards a=-1) ──────────────────────────────
    private static final BigInteger P25519 =
            BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger D25519 =
            BigInteger.valueOf(-121665)
                    .multiply(BigInteger.valueOf(121666).modInverse(P25519)).mod(P25519);
    private static final BigInteger BY25519 =
            BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P25519)).mod(P25519);

    // ── Ed448 (Edwards448 "Goldilocks", untwisted a=1, d=-39081) ────────────────
    private static final BigInteger P448 =
            BigInteger.TWO.pow(448).subtract(BigInteger.TWO.pow(224)).subtract(BigInteger.ONE);
    private static final BigInteger D448 = BigInteger.valueOf(-39081).mod(P448);
    private static final BigInteger BX448 = new BigInteger(
            "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a464"
          + "12ae1af72ab66511433b80e18b00938e2626a82bc70cc05e", 16);
    private static final BigInteger BY448 = new BigInteger(
            "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d7"
          + "3ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14", 16);

    /** Derive the raw RFC-8032 public-key bytes (32 Ed25519 / 57 Ed448) from a seed. */
    public static byte[] rawPublicKey(byte[] seed, Curve curve) throws EntityCryptoException {
        return curve == Curve.ED25519 ? ed25519(seed) : ed448(seed);
    }

    private static byte[] ed25519(byte[] seed) throws EntityCryptoException {
        if (seed.length != 32) {
            throw new BadSeedException("Ed25519 seed must be 32 bytes, got " + seed.length);
        }
        byte[] h = sha512(seed);
        byte[] s = java.util.Arrays.copyOfRange(h, 0, 32);
        s[0] &= (byte) 248;
        s[31] &= (byte) 127;
        s[31] |= (byte) 64;
        BigInteger scalar = leToBig(s);
        BigInteger bx = recoverX25519(BY25519, false);
        BigInteger[] r = scalarMul(scalar, new BigInteger[]{bx, BY25519}, P25519, D25519);
        return encodePoint(r, P25519, 32);
    }

    private static byte[] ed448(byte[] seed) throws EntityCryptoException {
        if (seed.length != 57) {
            throw new BadSeedException("Ed448 seed must be 57 bytes, got " + seed.length);
        }
        byte[] h = Shake256.digest(seed, 114);
        byte[] s = java.util.Arrays.copyOfRange(h, 0, 57);
        s[0] &= (byte) 0xFC;
        s[55] |= (byte) 0x80;
        s[56] = 0;
        BigInteger scalar = leToBig(s);
        BigInteger[] r = scalarMul(scalar, new BigInteger[]{BX448.mod(P448), BY448.mod(P448)},
                P448, D448);
        return encodePoint(r, P448, 57);
    }

    // ── twisted-Edwards (a=-1) addition for Ed25519 ─────────────────────────────
    // ── untwisted-Edwards (a=1) addition for Ed448 ──────────────────────────────
    // The two differ only in the y3 sign term; select by curve modulus.
    private static BigInteger[] add(BigInteger[] p1, BigInteger[] q1, BigInteger p, BigInteger d) {
        BigInteger x1 = p1[0], y1 = p1[1], x2 = q1[0], y2 = q1[1];
        BigInteger dxy = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(p);
        BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1))
                .multiply(BigInteger.ONE.add(dxy).modInverse(p)).mod(p);
        BigInteger y3;
        if (p.equals(P25519)) {
            // twisted (a = -1): y3 = (y1*y2 + x1*x2) / (1 - d x1 x2 y1 y2)
            y3 = y1.multiply(y2).add(x1.multiply(x2))
                    .multiply(BigInteger.ONE.subtract(dxy).modInverse(p)).mod(p);
        } else {
            // untwisted (a = 1): y3 = (y1*y2 - x1*x2) / (1 - d x1 x2 y1 y2)
            y3 = y1.multiply(y2).subtract(x1.multiply(x2))
                    .multiply(BigInteger.ONE.subtract(dxy).modInverse(p)).mod(p);
        }
        return new BigInteger[]{x3, y3};
    }

    private static BigInteger[] scalarMul(BigInteger e, BigInteger[] point,
                                          BigInteger p, BigInteger d) {
        BigInteger[] q = {BigInteger.ZERO, BigInteger.ONE}; // identity
        for (int i = e.bitLength() - 1; i >= 0; i--) {
            q = add(q, q, p, d);
            if (e.testBit(i)) {
                q = add(q, point, p, d);
            }
        }
        return q;
    }

    private static BigInteger recoverX25519(BigInteger y, boolean xOdd) {
        BigInteger p = P25519, d = D25519;
        BigInteger y2 = y.multiply(y).mod(p);
        BigInteger u = y2.subtract(BigInteger.ONE).mod(p);
        BigInteger v = d.multiply(y2).add(BigInteger.ONE).mod(p);
        BigInteger xx = u.multiply(v.modInverse(p)).mod(p);
        BigInteger x = xx.modPow(p.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), p);
        if (!x.multiply(x).mod(p).equals(xx)) {
            BigInteger i2 = BigInteger.TWO.modPow(
                    p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
            x = x.multiply(i2).mod(p);
        }
        if (x.testBit(0) != xOdd) {
            x = p.subtract(x);
        }
        return x;
    }

    private static byte[] encodePoint(BigInteger[] point, BigInteger p, int len) {
        BigInteger x = point[0];
        BigInteger y = point[1].mod(p);
        byte[] le = new byte[len];
        byte[] be = y.toByteArray(); // big-endian magnitude (may have a leading sign byte)
        for (int i = 0; i < be.length; i++) {
            int idx = be.length - 1 - i; // walk from least-significant
            if (i < len) {
                le[i] = be[idx];
            }
        }
        if (x.testBit(0)) {
            le[len - 1] |= (byte) 0x80;
        }
        return le;
    }

    private static BigInteger leToBig(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    private static byte[] sha512(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(in);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("missing JDK SHA-512", e);
        }
    }
}
