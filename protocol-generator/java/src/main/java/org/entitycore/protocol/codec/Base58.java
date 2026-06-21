package org.entitycore.protocol.codec;

import java.math.BigInteger;

/**
 * Base58 (Bitcoin alphabet) encode/decode, hand-rolled (dodges a Maven dep + pin).
 *
 * <p>Used for peer-id formatting/parsing (V7 §1.2 / §7.3). Leading zero bytes map to
 * a leading {@code '1'} each, per the standard Base58 convention (leading-zero
 * preserving in both directions).
 */
public final class Base58 {
    private Base58() { }

    private static final String ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger FIFTY_EIGHT = BigInteger.valueOf(58);
    private static final int[] INDEX = new int[128];
    static {
        java.util.Arrays.fill(INDEX, -1);
        for (int i = 0; i < ALPHABET.length(); i++) {
            INDEX[ALPHABET.charAt(i)] = i;
        }
    }

    /** Encode a byte array to a Base58 string. */
    public static String encode(byte[] octets) {
        int zeros = 0;
        while (zeros < octets.length && octets[zeros] == 0) {
            zeros++;
        }
        // Big-endian unsigned magnitude.
        BigInteger n = new BigInteger(1, octets);
        StringBuilder sb = new StringBuilder();
        while (n.signum() > 0) {
            BigInteger[] qr = n.divideAndRemainder(FIFTY_EIGHT);
            sb.append(ALPHABET.charAt(qr[1].intValue()));
            n = qr[0];
        }
        sb.reverse();
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < zeros; i++) {
            out.append('1');
        }
        out.append(sb);
        return out.toString();
    }

    /** Decode a Base58 string to a byte array (leading-zero preserving). */
    public static byte[] decode(String s) {
        int ones = 0;
        while (ones < s.length() && s.charAt(ones) == '1') {
            ones++;
        }
        BigInteger n = BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int d = (c < 128) ? INDEX[c] : -1;
            if (d < 0) {
                throw new IllegalArgumentException("invalid base58 char: " + c);
            }
            n = n.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(d));
        }
        byte[] body = n.signum() == 0 ? new byte[0] : stripSignByte(n.toByteArray());
        byte[] out = new byte[ones + body.length];
        // leading zeros already 0; copy body after them
        System.arraycopy(body, 0, out, ones, body.length);
        return out;
    }

    /** BigInteger.toByteArray may prepend a 0x00 sign byte; strip it for magnitude. */
    private static byte[] stripSignByte(byte[] b) {
        if (b.length > 1 && b[0] == 0) {
            byte[] r = new byte[b.length - 1];
            System.arraycopy(b, 1, r, 0, r.length);
            return r;
        }
        return b;
    }
}
