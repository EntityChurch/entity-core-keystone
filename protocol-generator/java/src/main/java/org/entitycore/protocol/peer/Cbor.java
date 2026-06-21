package org.entitycore.protocol.peer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.entitycore.protocol.codec.EcfValue;

/**
 * Small constructor + accessor helpers over the S2 {@link EcfValue} model, plus the
 * address-space hex convention. Keeps the peer code reading at the protocol altitude
 * (map/list builders, typed field reads) instead of restating the codec value model
 * inline.
 *
 * <p><b>lowercase hex (A-CL-009 trap).</b> {@link #hex} renders LOWERCASE — the
 * §3.4/§3.5 tree-path convention. Tree paths are case-sensitive string keys
 * ({@code system/signature/{hash}}, the §5.1 revocation marker, the §6.9a policy
 * path), so the Common Lisp peer's uppercase default produced an internally-consistent
 * but cross-incompatible address space. We are lowercase everywhere (the codec already
 * is; the peer-layer paths are too).
 */
final class Cbor {
    private Cbor() { }

    private static final char[] HEXC = "0123456789abcdef".toCharArray();

    // ── builders ──────────────────────────────────────────────────────────────

    /** Build a map from alternating key, value pairs. String keys become Text; a raw
     *  {@link EcfValue} value passes through, a {@link String} value becomes Text, a
     *  {@code long}/{@link BigInteger} becomes Int, a {@link Boolean} becomes Bool. */
    static EcfValue.Map map(Object... kvs) {
        if ((kvs.length & 1) != 0) {
            throw new IllegalArgumentException("odd kv count");
        }
        List<EcfValue.Map.Entry> es = new ArrayList<>(kvs.length / 2);
        for (int i = 0; i < kvs.length; i += 2) {
            EcfValue k = (kvs[i] instanceof String s) ? new EcfValue.Text(s) : (EcfValue) kvs[i];
            es.add(new EcfValue.Map.Entry(k, val(kvs[i + 1])));
        }
        return new EcfValue.Map(es);
    }

    /** The canonical empty map (a single 0xA0 byte). */
    static EcfValue.Map emptyMap() {
        return new EcfValue.Map(List.of());
    }

    /** Coerce a Java value to its EcfValue node. */
    static EcfValue val(Object v) {
        if (v instanceof EcfValue e) {
            return e;
        }
        if (v instanceof String s) {
            return new EcfValue.Text(s);
        }
        if (v instanceof byte[] b) {
            return new EcfValue.Bytes(b);
        }
        if (v instanceof Boolean bo) {
            return bo ? EcfValue.Bool.TRUE : EcfValue.Bool.FALSE;
        }
        if (v instanceof BigInteger bi) {
            return new EcfValue.Int(bi);
        }
        if (v instanceof Long l) {
            return EcfValue.Int.of(l);
        }
        if (v instanceof Integer in) {
            return EcfValue.Int.of(in);
        }
        if (v == null) {
            return EcfValue.Null.NULL;
        }
        throw new IllegalArgumentException("cannot coerce to EcfValue: " + v.getClass());
    }

    /** A byte-string node. */
    static EcfValue bytes(byte[] b) {
        return new EcfValue.Bytes(b);
    }

    /** A text-array node from strings. */
    static EcfValue.Array textArray(String... ss) {
        List<EcfValue> items = new ArrayList<>(ss.length);
        for (String s : ss) {
            items.add(new EcfValue.Text(s));
        }
        return new EcfValue.Array(items);
    }

    /** An array node from EcfValues. */
    static EcfValue.Array array(List<EcfValue> items) {
        return new EcfValue.Array(items);
    }

    // ── typed field reads (over a map value, null-safe) ─────────────────────────

    static EcfValue.Map asMap(EcfValue v) {
        return (v instanceof EcfValue.Map m) ? m : null;
    }

    static String text(EcfValue.Map m, String key) {
        if (m == null) {
            return null;
        }
        EcfValue v = m.get(key);
        return (v instanceof EcfValue.Text t) ? t.value() : null;
    }

    static byte[] bytes(EcfValue.Map m, String key) {
        if (m == null) {
            return null;
        }
        EcfValue v = m.get(key);
        return (v instanceof EcfValue.Bytes b) ? b.octets() : null;
    }

    static BigInteger uint(EcfValue.Map m, String key) {
        if (m == null) {
            return null;
        }
        EcfValue v = m.get(key);
        return (v instanceof EcfValue.Int i) ? i.value() : null;
    }

    /** A list of the text values in an array field (skips non-text), or null. */
    static List<String> textList(EcfValue.Map m, String key) {
        if (m == null) {
            return null;
        }
        EcfValue v = m.get(key);
        if (!(v instanceof EcfValue.Array a)) {
            return null;
        }
        List<String> out = new ArrayList<>(a.items().size());
        for (EcfValue item : a.items()) {
            if (item instanceof EcfValue.Text t) {
                out.add(t.value());
            }
        }
        return out;
    }

    /** A list of the map values in an array field, or null. */
    static List<EcfValue.Map> mapList(EcfValue.Map m, String key) {
        if (m == null) {
            return null;
        }
        EcfValue v = m.get(key);
        if (!(v instanceof EcfValue.Array a)) {
            return null;
        }
        List<EcfValue.Map> out = new ArrayList<>(a.items().size());
        for (EcfValue item : a.items()) {
            if (item instanceof EcfValue.Map mm) {
                out.add(mm);
            }
        }
        return out;
    }

    static boolean isTrue(EcfValue v) {
        return v == EcfValue.Bool.TRUE;
    }

    // ── hex ─────────────────────────────────────────────────────────────────────

    /** LOWERCASE hex (the §3.4/§3.5 address-space convention; A-CL-009). */
    static String hex(byte[] octets) {
        char[] out = new char[octets.length * 2];
        for (int i = 0; i < octets.length; i++) {
            int b = octets[i] & 0xff;
            out[i * 2] = HEXC[b >>> 4];
            out[i * 2 + 1] = HEXC[b & 0x0f];
        }
        return new String(out);
    }

    static byte[] unhex(String s) {
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
