package org.entitycore.protocol.codec;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Entity Canonical Form (ECF) — hand-rolled canonical CBOR encoder + decoder.
 *
 * <p>Per ENTITY-CBOR-ENCODING.md v1.5 (spec-data v7.71/v7.72). No JVM CBOR library
 * gives ECF's guarantees (RFC-7049 length-FIRST then lexicographic map-key ordering
 * differs from RFC-8949 §4.2 bytewise; plus the f16 shortest-float ladder, recursive
 * tag rejection, raw-byte fidelity), so the canonical layer is owned here:
 * <ul>
 *   <li>minimal integer encoding (Rule 1) — full uint64 / -2^64 range via
 *       {@link BigInteger}, no native-unsigned trap;</li>
 *   <li>map keys sorted by ENCODED LENGTH then byte-lexicographic (Rule 2 / §3.5);</li>
 *   <li>definite lengths only (Rule 3) — no 0x5f/0x7f/0x9f/0xbf;</li>
 *   <li>shortest float preserving value incl. f16 (Rule 4) + Rule-4a special bytes;</li>
 *   <li>recursive major-type-6 (tag) rejection on decode (invariant N2; §6.3);</li>
 *   <li>empty map = the single byte {@code 0xA0} (invariant N3 — falls out of the
 *       generic map encoder, not special-cased).</li>
 * </ul>
 */
public final class CanonicalCbor {
    private CanonicalCbor() { }

    /** ECF §10.2 nesting depth limit. */
    public static final int MAX_DEPTH = 64;

    private static final BigInteger MAX_U64 = BigInteger.ONE.shiftLeft(64); // exclusive

    // ───────────────────────────────────────────────────────────────────────────
    // Encode
    // ───────────────────────────────────────────────────────────────────────────

    /** Encode {@code value} to canonical ECF bytes. */
    public static byte[] encode(EcfValue value) throws EntityCodecException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        enc(value, out);
        return out.toByteArray();
    }

    private static void enc(EcfValue value, ByteArrayOutputStream out) throws EntityCodecException {
        switch (value) {
            case EcfValue.FloatSpecial s -> {
                switch (s) {
                    case NAN -> writeBytes(out, 0xf9, 0x7e, 0x00);
                    case POSITIVE_INFINITY -> writeBytes(out, 0xf9, 0x7c, 0x00);
                    case NEGATIVE_INFINITY -> writeBytes(out, 0xf9, 0xfc, 0x00);
                    case NEGATIVE_ZERO -> writeBytes(out, 0xf9, 0x80, 0x00);
                }
            }
            case EcfValue.Bool b -> out.write(b == EcfValue.Bool.TRUE ? 0xf5 : 0xf4);
            case EcfValue.Null n -> out.write(0xf6);
            case EcfValue.Int i -> encInt(i.value(), out);
            case EcfValue.Float64 f -> encFloat(f.value(), out);
            case EcfValue.Bytes bs -> {
                byte[] o = bs.raw();
                encHead(2, o.length, out);
                out.write(o, 0, o.length);
            }
            case EcfValue.Text t -> {
                byte[] o = t.value().getBytes(StandardCharsets.UTF_8);
                encHead(3, o.length, out);
                out.write(o, 0, o.length);
            }
            case EcfValue.Array a -> {
                encHead(4, a.items().size(), out);
                for (EcfValue item : a.items()) {
                    enc(item, out);
                }
            }
            case EcfValue.Map m -> encMap(m, out);
        }
    }

    private static void encInt(BigInteger v, ByteArrayOutputStream out) throws EntityCodecException {
        if (v.signum() >= 0) {
            encHeadBig(0, v, out);
        } else {
            // major 1, argument = -1 - v
            encHeadBig(1, v.negate().subtract(BigInteger.ONE), out);
        }
    }

    /** Emit a CBOR initial byte for {@code major} with the shortest argument for the
     *  given non-negative {@code arg} (int fast path). */
    private static void encHead(int major, int arg, ByteArrayOutputStream out)
            throws EntityCodecException {
        encHeadBig(major, BigInteger.valueOf(arg), out);
    }

    private static void encHeadBig(int major, BigInteger arg, ByteArrayOutputStream out)
            throws EntityCodecException {
        int m = major << 5;
        if (arg.signum() < 0 || arg.compareTo(MAX_U64) >= 0) {
            throw new NonCanonicalEcfException("argument out of uint64 range: " + arg);
        }
        long a = arg.bitLength() <= 63 ? arg.longValueExact() : -1L; // -1 sentinel: >=2^63
        boolean ge2p63 = arg.bitLength() > 63;
        if (!ge2p63 && a < 24) {
            out.write(m | (int) a);
        } else if (!ge2p63 && a < 0x100L) {
            out.write(m | 24);
            out.write((int) (a & 0xff));
        } else if (!ge2p63 && a < 0x10000L) {
            out.write(m | 25);
            out.write((int) ((a >> 8) & 0xff));
            out.write((int) (a & 0xff));
        } else if (!ge2p63 && a < 0x100000000L) {
            out.write(m | 26);
            for (int i = 3; i >= 0; i--) {
                out.write((int) ((a >> (8 * i)) & 0xff));
            }
        } else {
            // 8-byte argument: covers up to 2^64-1 (use BigInteger for >=2^63).
            out.write(m | 27);
            for (int i = 7; i >= 0; i--) {
                out.write(arg.shiftRight(8 * i).and(BigInteger.valueOf(0xff)).intValue());
            }
        }
    }

    private static void encMap(EcfValue.Map m, ByteArrayOutputStream out) throws EntityCodecException {
        // Encode each key + value, then sort entries by encoded-KEY bytes
        // (length-then-lex, ECF Rule 2). stable to preserve input order on ties
        // (there should be no ties in a canonical map — duplicate keys are illegal).
        List<EncodedEntry> encoded = new ArrayList<>(m.entries().size());
        for (EcfValue.Map.Entry e : m.entries()) {
            encoded.add(new EncodedEntry(encode(e.key()), encode(e.value())));
        }
        encoded.sort(KEY_ORDER);
        encHead(5, encoded.size(), out);
        for (EncodedEntry e : encoded) {
            out.write(e.key, 0, e.key.length);
            out.write(e.val, 0, e.val.length);
        }
    }

    private record EncodedEntry(byte[] key, byte[] val) { }

    /** Length-then-byte-lexicographic order on encoded-key octets (ECF Rule 2). */
    private static final Comparator<EncodedEntry> KEY_ORDER = (a, b) -> {
        if (a.key.length != b.key.length) {
            return Integer.compare(a.key.length, b.key.length);
        }
        for (int i = 0; i < a.key.length; i++) {
            int x = a.key[i] & 0xff;
            int y = b.key[i] & 0xff;
            if (x != y) {
                return Integer.compare(x, y);
            }
        }
        return 0;
    };

    // ── float ladder: f16 ⊂ f32 ⊂ f64, shortest that round-trips exactly ────────

    private static void encFloat(double f, ByteArrayOutputStream out) {
        // -0.0 is canonical f16 (Rule 4a). (+0.0 falls through to the f16 path.)
        if (f == 0.0 && (Double.doubleToRawLongBits(f) != 0L)) { // negative zero
            writeBytes(out, 0xf9, 0x80, 0x00);
            return;
        }
        Integer h = doubleToF16(f);
        if (h != null && f16ToDouble(h) == f) {
            out.write(0xf9);
            out.write((h >> 8) & 0xff);
            out.write(h & 0xff);
            return;
        }
        float sf = (float) f;
        if ((double) sf == f && !Float.isInfinite(sf)) {
            int bits = Float.floatToRawIntBits(sf);
            out.write(0xfa);
            for (int i = 3; i >= 0; i--) {
                out.write((bits >> (8 * i)) & 0xff);
            }
            return;
        }
        long bits = Double.doubleToRawLongBits(f);
        out.write(0xfb);
        for (int i = 7; i >= 0; i--) {
            out.write((int) ((bits >> (8 * i)) & 0xff));
        }
    }

    /** Convert a finite double to a 16-bit IEEE half, or null if not exactly
     *  representable as a finite f16 (caller falls back to f32/f64). */
    static Integer doubleToF16(double f) {
        long bits = Double.doubleToRawLongBits(f);
        int sign = (int) ((bits >>> 63) & 0x1);
        int exp = (int) ((bits >>> 52) & 0x7ff);
        long mant = bits & 0xfffffffffffffL;
        if (exp == 0x7ff) {
            return null; // inf/nan handled as specials, not here
        }
        if (exp == 0 && mant == 0) {
            return sign == 1 ? 0x8000 : 0x0000;
        }
        int unbiased;
        long fullMant; // 53-bit significand including implicit leading 1 (for normals)
        if (exp == 0) {
            // subnormal double — normalize
            int lead = Long.numberOfLeadingZeros(mant) - (63 - 52);
            unbiased = -1022 - lead;
            fullMant = (mant << (lead + 1)) & 0x1fffffffffffffL; // implicit 1 now at bit 52
            fullMant |= 0x10000000000000L;
        } else {
            unbiased = exp - 1023;
            fullMant = mant | 0x10000000000000L; // 53-bit with implicit leading 1
        }
        int he = unbiased + 15; // half biased exponent
        if (he > 30) {
            return null; // too large for finite f16
        }
        if (he >= 1) {
            // normalized f16: need the low 42 mantissa bits to be zero (10-bit fraction)
            if ((mant & 0x3ffffffffffL) != 0) {
                return null;
            }
            int hmant = (int) (mant >> 42);
            return (sign << 15) | (he << 10) | hmant;
        }
        // subnormal f16 (he <= 0): value = significand * 2^(unbiased-52); representable
        // iff value * 2^24 is an integer in [1,1023].
        // scaledExp = (unbiased - 52) + 24
        int scaledExp = (unbiased - 52) + 24;
        if (scaledExp >= 0) {
            // would multiply; only stays <=1023 for tiny mantissas — check via shift
            // fullMant << scaledExp must be in [1,1023] AND lose no bits (it can't, it's
            // a left shift), but realistically scaledExp>0 here means value too large.
            // Guard: result must fit.
            BigInteger scaled = BigInteger.valueOf(fullMant).shiftLeft(scaledExp);
            if (scaled.bitLength() <= 10 && scaled.signum() > 0
                    && scaled.compareTo(BigInteger.valueOf(1023)) <= 0) {
                int s = scaled.intValue();
                if (s >= 1) {
                    return (sign << 15) | s;
                }
            }
            return null;
        }
        int shift = -scaledExp;
        // need fullMant divisible by 2^shift (no fraction lost) and quotient in [1,1023]
        if ((fullMant & ((1L << shift) - 1)) != 0) {
            return null;
        }
        long q = fullMant >> shift;
        if (q >= 1 && q <= 1023) {
            return (sign << 15) | (int) q;
        }
        return null;
    }

    /** Convert a 16-bit IEEE half to a double (finite values only on this path). */
    static double f16ToDouble(int h) {
        int sign = (h >>> 15) & 0x1;
        int exp = (h >>> 10) & 0x1f;
        int mant = h & 0x3ff;
        double s = (sign == 1) ? -1.0 : 1.0;
        if (exp == 0) {
            if (mant == 0) {
                return s * 0.0;
            }
            return s * mant * Math.pow(2, -24); // subnormal
        }
        if (exp == 0x1f) {
            return mant == 0 ? s * Double.POSITIVE_INFINITY : Double.NaN;
        }
        return s * (1024 + mant) * Math.pow(2, exp - 25); // (1.m) * 2^(exp-15)
    }

    private static void writeBytes(ByteArrayOutputStream out, int... bs) {
        for (int b : bs) {
            out.write(b & 0xff);
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Decode
    // ───────────────────────────────────────────────────────────────────────────

    /** Decode canonical ECF bytes to a value; rejects trailing bytes. */
    public static EcfValue decode(byte[] octets) throws EntityCodecException {
        Cursor c = new Cursor(octets, 0);
        EcfValue v = dec(c, 0);
        if (c.i < octets.length) {
            throw new NonCanonicalEcfException("trailing bytes: " + (octets.length - c.i));
        }
        return v;
    }

    private static final class Cursor {
        final byte[] o;
        int i;
        Cursor(byte[] o, int i) { this.o = o; this.i = i; }
    }

    private static EcfValue dec(Cursor c, int depth) throws EntityCodecException {
        if (depth > MAX_DEPTH) {
            throw new NonCanonicalEcfException("max depth exceeded");
        }
        if (c.i >= c.o.length) {
            throw new TruncatedInputException("item: ran off end");
        }
        int ib = c.o[c.i] & 0xff;
        int major = ib >>> 5;
        int info = ib & 0x1f;
        c.i++;
        switch (major) {
            case 0: {
                BigInteger arg = decArg(c, info);
                return new EcfValue.Int(arg);
            }
            case 1: {
                BigInteger arg = decArg(c, info);
                return new EcfValue.Int(arg.negate().subtract(BigInteger.ONE));
            }
            case 2: {
                int len = decLen(c, info);
                need(c, len);
                byte[] b = new byte[len];
                System.arraycopy(c.o, c.i, b, 0, len);
                c.i += len;
                return new EcfValue.Bytes(b);
            }
            case 3: {
                int len = decLen(c, info);
                need(c, len);
                String s = new String(c.o, c.i, len, StandardCharsets.UTF_8);
                c.i += len;
                return new EcfValue.Text(s);
            }
            case 4: {
                int len = decLen(c, info);
                List<EcfValue> items = new ArrayList<>(Math.min(len, 64));
                for (int k = 0; k < len; k++) {
                    items.add(dec(c, depth + 1));
                }
                return new EcfValue.Array(items);
            }
            case 5: {
                int len = decLen(c, info);
                List<EcfValue.Map.Entry> entries = new ArrayList<>(Math.min(len, 64));
                Set<Object> seen = new HashSet<>();
                for (int k = 0; k < len; k++) {
                    EcfValue key = dec(c, depth + 1);
                    EcfValue val = dec(c, depth + 1);
                    if (!seen.add(keySurrogate(key))) {
                        throw new DuplicateKeyException("duplicate map key");
                    }
                    entries.add(new EcfValue.Map.Entry(key, val));
                }
                return new EcfValue.Map(entries);
            }
            case 6:
                throw new TagRejectedException("major-type-6 tag rejected at " + (c.i - 1));
            case 7:
                return decSimple(c, info);
            default:
                throw new NonCanonicalEcfException("bad major type " + major);
        }
    }

    /** Decode the argument for majors 0/1 (full uint64 range -> BigInteger). */
    private static BigInteger decArg(Cursor c, int info) throws EntityCodecException {
        if (info < 24) {
            return BigInteger.valueOf(info);
        }
        switch (info) {
            case 24: need(c, 1); { int v = c.o[c.i] & 0xff; c.i += 1; return BigInteger.valueOf(v); }
            case 25: need(c, 2); {
                int v = ((c.o[c.i] & 0xff) << 8) | (c.o[c.i + 1] & 0xff);
                c.i += 2; return BigInteger.valueOf(v);
            }
            case 26: need(c, 4); {
                long v = 0;
                for (int k = 0; k < 4; k++) { v = (v << 8) | (c.o[c.i + k] & 0xff); }
                c.i += 4; return BigInteger.valueOf(v);
            }
            case 27: need(c, 8); {
                BigInteger v = BigInteger.ZERO;
                for (int k = 0; k < 8; k++) {
                    v = v.shiftLeft(8).or(BigInteger.valueOf(c.o[c.i + k] & 0xff));
                }
                c.i += 8; return v;
            }
            default:
                throw new NonCanonicalEcfException("reserved/indefinite argument: " + info);
        }
    }

    /** Decode a length argument (for majors 2-5); must fit in an int. */
    private static int decLen(Cursor c, int info) throws EntityCodecException {
        BigInteger v = decArg(c, info);
        if (v.bitLength() > 31) {
            throw new NonCanonicalEcfException("length too large: " + v);
        }
        return v.intValue();
    }

    private static EcfValue decSimple(Cursor c, int info) throws EntityCodecException {
        switch (info) {
            case 20: return EcfValue.Bool.FALSE;
            case 21: return EcfValue.Bool.TRUE;
            case 22: return EcfValue.Null.NULL;
            case 25: need(c, 2); {
                int b0 = c.o[c.i] & 0xff, b1 = c.o[c.i + 1] & 0xff; c.i += 2;
                return decodeF16(b0, b1);
            }
            case 26: need(c, 4); {
                int bits = 0;
                for (int k = 0; k < 4; k++) { bits = (bits << 8) | (c.o[c.i + k] & 0xff); }
                c.i += 4; return decodeF32(bits);
            }
            case 27: need(c, 8); {
                long bits = 0;
                for (int k = 0; k < 8; k++) { bits = (bits << 8) | (c.o[c.i + k] & 0xff); }
                c.i += 8; return decodeF64(bits);
            }
            default:
                throw new NonCanonicalEcfException("bad simple value: " + info);
        }
    }

    private static EcfValue decodeF16(int b0, int b1) {
        int h = (b0 << 8) | b1;
        int s = (h >>> 15) & 1, e = (h >>> 10) & 0x1f, m = h & 0x3ff;
        if (e == 0x1f) {
            return m == 0 ? (s == 1 ? EcfValue.FloatSpecial.NEGATIVE_INFINITY
                                    : EcfValue.FloatSpecial.POSITIVE_INFINITY)
                          : EcfValue.FloatSpecial.NAN;
        }
        if (e == 0 && m == 0) {
            return s == 1 ? EcfValue.FloatSpecial.NEGATIVE_ZERO : new EcfValue.Float64(0.0);
        }
        return new EcfValue.Float64(f16ToDouble(h));
    }

    private static EcfValue decodeF32(int bits) {
        int s = (bits >>> 31) & 1, e = (bits >>> 23) & 0xff, m = bits & 0x7fffff;
        if (e == 0xff) {
            return m == 0 ? (s == 1 ? EcfValue.FloatSpecial.NEGATIVE_INFINITY
                                    : EcfValue.FloatSpecial.POSITIVE_INFINITY)
                          : EcfValue.FloatSpecial.NAN;
        }
        if (e == 0 && m == 0) {
            return s == 1 ? EcfValue.FloatSpecial.NEGATIVE_ZERO : new EcfValue.Float64(0.0);
        }
        return new EcfValue.Float64((double) Float.intBitsToFloat(bits));
    }

    private static EcfValue decodeF64(long bits) {
        int s = (int) ((bits >>> 63) & 1);
        int e = (int) ((bits >>> 52) & 0x7ff);
        long m = bits & 0xfffffffffffffL;
        if (e == 0x7ff) {
            return m == 0 ? (s == 1 ? EcfValue.FloatSpecial.NEGATIVE_INFINITY
                                    : EcfValue.FloatSpecial.POSITIVE_INFINITY)
                          : EcfValue.FloatSpecial.NAN;
        }
        if (e == 0 && m == 0) {
            return s == 1 ? EcfValue.FloatSpecial.NEGATIVE_ZERO : new EcfValue.Float64(0.0);
        }
        return new EcfValue.Float64(Double.longBitsToDouble(bits));
    }

    private static void need(Cursor c, int len) throws EntityCodecException {
        if (len < 0 || c.i + len > c.o.length) {
            throw new TruncatedInputException("need " + len + " at " + c.i);
        }
    }

    private static Object keySurrogate(EcfValue key) throws EntityCodecException {
        if (key instanceof EcfValue.Text t) {
            return "s:" + t.value();
        }
        if (key instanceof EcfValue.Bytes b) {
            return "b:" + java.util.Arrays.toString(b.raw());
        }
        if (key instanceof EcfValue.Int i) {
            return "i:" + i.value();
        }
        // ECF map keys are text or bytes; anything else is non-canonical.
        throw new NonCanonicalEcfException("non-canonical map key type");
    }
}
