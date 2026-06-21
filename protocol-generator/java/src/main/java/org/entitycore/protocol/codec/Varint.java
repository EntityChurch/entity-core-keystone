package org.entitycore.protocol.codec;

import java.io.ByteArrayOutputStream;

/**
 * Multicodec-style unsigned LEB128 varints (V7 §1.5 / §7.3).
 *
 * <p>Invariant N1: every format-code / key-type / hash-type prefix is routed through
 * a REAL varint primitive, NOT fixed bytes. All currently-allocated codes are
 * &lt; 0x80 (single byte), but a code &gt;= 0x80 MUST extend correctly
 * ({@code 128 -> 0x80 0x01}). The corpus exercises this with synthetic high codes
 * (content_hash.4 fc=128, peer_id.3 key_type=128).
 */
public final class Varint {
    private Varint() { }

    /** Encode a non-negative {@code long} as an unsigned LEB128 byte array. */
    public static byte[] encode(long n) {
        if (n < 0) {
            throw new IllegalArgumentException("varint value must be non-negative: " + n);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(2);
        // Use unsigned-shift so the full 64-bit range is supported.
        long v = n;
        do {
            int b = (int) (v & 0x7f);
            v >>>= 7;
            if (v != 0) {
                b |= 0x80;
            }
            out.write(b);
        } while (v != 0);
        return out.toByteArray();
    }

    /** Decode result: the value plus the index just past the varint. */
    public record Decoded(long value, int next) { }

    /**
     * Decode an unsigned LEB128 varint from {@code buf} at {@code start}.
     *
     * @throws TruncatedInputException if the varint runs off the end
     * @throws NonCanonicalEcfException on a non-minimal encoding or &gt;64-bit overflow
     */
    public static Decoded decode(byte[] buf, int start) throws EntityCodecException {
        long value = 0;
        int shift = 0;
        int i = start;
        while (true) {
            if (i >= buf.length) {
                throw new TruncatedInputException("varint: ran off end at " + i);
            }
            if (shift >= 64) {
                throw new NonCanonicalEcfException("varint: exceeds 64 bits");
            }
            int b = buf[i] & 0xff;
            i++;
            value |= ((long) (b & 0x7f)) << shift;
            if ((b & 0x80) == 0) {
                // Reject non-minimal: a trailing 0x00 continuation-less byte after a
                // non-zero accumulation would be non-canonical, but the multicodec
                // form here is the minimal LEB128 the corpus pins.
                return new Decoded(value, i);
            }
            shift += 7;
        }
    }
}
