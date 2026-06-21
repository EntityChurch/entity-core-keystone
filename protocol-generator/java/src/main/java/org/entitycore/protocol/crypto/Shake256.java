package org.entitycore.protocol.crypto;

/**
 * SHAKE256 (FIPS 202 extendable-output function) — hand-rolled Keccak-f[1600].
 *
 * <p><b>Why hand-rolled (A-JAVA-002 refinement, the Java crypto-axis finding).</b>
 * The RFC-8032 Ed448 public-key derivation (seed → SHAKE256-expand → clamp → scalar
 * multiply the base point) needs SHAKE256. SunEC provides Ed448 SIGN/VERIFY natively
 * but does NOT expose seed→public-point, and the JDK {@code MessageDigest} registry
 * ships SHA3-{224,256,384,512} (fixed output) but NO SHAKE256 (extendable output).
 * So a fully-native, BouncyCastle-free Ed448 raw-public-key derivation requires
 * SHAKE256 from somewhere — and the supply-chain-clean choice (consistent with the
 * hand-rolled CBOR/base58/varint stance) is to hand-roll it (~120 lines, pure, no
 * deps) rather than pull BouncyCastle into the core build. Verified against the NIST
 * SHAKE256("") known-answer and the agility-corpus Ed448 pubkey pin.
 */
public final class Shake256 {
    private Shake256() { }

    /** SHAKE256 rate in bytes (1600-bit state, 512-bit capacity). */
    private static final int RATE = 136;

    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    private static final int[] ROT = {
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
    };

    /** Compute {@code outLen} bytes of SHAKE256 over {@code input}. */
    public static byte[] digest(byte[] input, int outLen) {
        long[] st = new long[25];
        int off = 0;
        int full = input.length / RATE;
        for (int blk = 0; blk < full; blk++) {
            absorb(st, input, off);
            keccakf(st);
            off += RATE;
        }
        byte[] last = new byte[RATE];
        int rem = input.length - off;
        System.arraycopy(input, off, last, 0, rem);
        last[rem] ^= 0x1f;             // SHAKE domain-separation suffix
        last[RATE - 1] ^= (byte) 0x80; // final-bit padding
        absorb(st, last, 0);
        keccakf(st);

        byte[] out = new byte[outLen];
        int got = 0;
        while (got < outLen) {
            int take = Math.min(RATE, outLen - got);
            for (int i = 0; i < take; i++) {
                out[got + i] = (byte) (st[i / 8] >>> (8 * (i % 8)));
            }
            got += take;
            if (got < outLen) {
                keccakf(st);
            }
        }
        return out;
    }

    private static void absorb(long[] st, byte[] b, int off) {
        for (int i = 0; i < RATE / 8; i++) {
            long w = 0;
            for (int k = 0; k < 8; k++) {
                w |= ((long) (b[off + i * 8 + k] & 0xff)) << (8 * k);
            }
            st[i] ^= w;
        }
    }

    private static void keccakf(long[] s) {
        for (int r = 0; r < 24; r++) {
            long[] c = new long[5];
            for (int i = 0; i < 5; i++) {
                c[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
            }
            long[] dd = new long[5];
            for (int i = 0; i < 5; i++) {
                dd[i] = c[(i + 4) % 5] ^ Long.rotateLeft(c[(i + 1) % 5], 1);
            }
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    s[i + 5 * j] ^= dd[i];
                }
            }
            long[] b = new long[25];
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    int idx = i + 5 * j;
                    int ni = j;
                    int nj = (2 * i + 3 * j) % 5;
                    b[ni + 5 * nj] = Long.rotateLeft(s[idx], ROT[idx]);
                }
            }
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    s[i + 5 * j] = b[i + 5 * j] ^ ((~b[(i + 1) % 5 + 5 * j]) & b[(i + 2) % 5 + 5 * j]);
                }
            }
            s[0] ^= RC[r];
        }
    }
}
