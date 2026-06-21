package org.entitycore.protocol.codec;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * The decoded-form value model for Entity Canonical Form (ECF).
 *
 * <p>A {@code sealed interface} + nested records gives the codec/dispatch ladders an
 * EXHAUSTIVE pattern-matching switch (JDK 21 JEP 441) over a closed type set — the
 * static-OO analogue of the OCaml variant / Zig tagged union / CL sentinel approach.
 *
 * <p>Why an explicit model rather than reusing {@code java.lang} types directly:
 * ECF requires {@code absent != null != false != 0} on the wire (V7 §1.3), and a
 * CBOR byte string (major 2) must stay distinct from a text string (major 3). So:
 * <ul>
 *   <li>booleans/null are explicit nodes ({@link Bool}, {@link Null}) — never erased
 *       to a Java {@code null}/{@code boolean};</li>
 *   <li>byte strings are {@link Bytes} (major 2), text is {@link Text} (major 3) —
 *       never conflated;</li>
 *   <li>integral-valued floats keep an explicit {@link Float64} node so {@code 1.0}
 *       encodes as a float ({@code f90000} ladder), never as integer 1 (the
 *       value-erasure trap TS hit with cborg);</li>
 *   <li>the float specials NaN/±Inf/-0.0 are carried as {@link FloatSpecial}
 *       constants so a NaN/Inf never has to round-trip through a Java {@code double}.</li>
 * </ul>
 *
 * <p>Integers use {@code java.math.BigInteger} ({@link Int}) so the full uint64 /
 * -2^64 head-form range is representable with NO native-unsigned trap (Java
 * {@code long} has no native unsigned; this side-steps it entirely).
 */
public sealed interface EcfValue
        permits EcfValue.Int, EcfValue.Float64, EcfValue.FloatSpecial,
                EcfValue.Bytes, EcfValue.Text, EcfValue.Array, EcfValue.Map,
                EcfValue.Bool, EcfValue.Null {

    /** CBOR major-type 0/1 integer, as a {@link java.math.BigInteger} (full range). */
    record Int(java.math.BigInteger value) implements EcfValue {
        public Int {
            Objects.requireNonNull(value, "value");
        }
        public static Int of(long v) { return new Int(java.math.BigInteger.valueOf(v)); }
    }

    /** A finite floating-point value (encoded via the shortest f16/f32/f64 ladder). */
    record Float64(double value) implements EcfValue { }

    /** The ECF Rule-4a special floats. Carried as sentinels so the canonical wire
     *  bytes are emitted directly and a NaN/Inf never materializes as a {@code double}. */
    enum FloatSpecial implements EcfValue {
        NAN, POSITIVE_INFINITY, NEGATIVE_INFINITY, NEGATIVE_ZERO
    }

    /** CBOR byte string (major 2). The {@code byte[]} is defensively copied in and
     *  out — Java arrays are mutable, so the codec NEVER aliases an internal buffer
     *  (profile {@code no_byte_array_aliasing}). */
    record Bytes(byte[] octets) implements EcfValue {
        public Bytes(byte[] octets) {
            this.octets = octets.clone();
        }
        /** Defensive copy on read. */
        @Override public byte[] octets() { return octets.clone(); }
        /** Internal, no-copy accessor for the codec hot path (caller must not mutate). */
        byte[] raw() { return octets; }
        @Override public boolean equals(Object o) {
            return o instanceof Bytes b && Arrays.equals(octets, b.octets);
        }
        @Override public int hashCode() { return Arrays.hashCode(octets); }
        @Override public String toString() { return "Bytes(" + octets.length + "B)"; }
    }

    /** CBOR text string (major 3), held as a Java {@link String} (UTF-8 on the wire). */
    record Text(String value) implements EcfValue {
        public Text {
            Objects.requireNonNull(value, "value");
        }
    }

    /** CBOR array (major 4), definite length. Order-preserving, immutable view. */
    record Array(List<EcfValue> items) implements EcfValue {
        public Array(List<EcfValue> items) {
            this.items = Collections.unmodifiableList(new ArrayList<>(items));
        }
        public static Array of(EcfValue... items) { return new Array(Arrays.asList(items)); }
    }

    /** CBOR map (major 5). Order is whatever was constructed/decoded; the ENCODER
     *  re-sorts by encoded-key length-then-lex (ECF Rule 2). Keys are {@link Text}
     *  or {@link Bytes}. Held as an ordered list of {@link Entry} so decode order is
     *  preserved and duplicate detection is the decoder's job (not a Map collision). */
    record Map(List<Entry> entries) implements EcfValue {
        public Map(List<Entry> entries) {
            this.entries = Collections.unmodifiableList(new ArrayList<>(entries));
        }
        /** A single map key/value pair (key is Text or Bytes). */
        public record Entry(EcfValue key, EcfValue value) { }

        /** Build a map from alternating key, value, key, value... (Text keys via String). */
        public static Map of(Object... kvs) {
            if ((kvs.length & 1) != 0) {
                throw new IllegalArgumentException("odd kv count");
            }
            List<Entry> es = new ArrayList<>(kvs.length / 2);
            for (int i = 0; i < kvs.length; i += 2) {
                EcfValue k = (kvs[i] instanceof String s) ? new Text(s) : (EcfValue) kvs[i];
                es.add(new Entry(k, (EcfValue) kvs[i + 1]));
            }
            return new Map(es);
        }

        /** Fetch a value by Text key; null if absent. */
        public EcfValue get(String key) {
            for (Entry e : entries) {
                if (e.key() instanceof Text t && t.value().equals(key)) {
                    return e.value();
                }
            }
            return null;
        }
    }

    /** CBOR true/false (major 7). */
    enum Bool implements EcfValue { TRUE, FALSE }

    /** CBOR null (major 7, value 22). A singleton — distinct from a Java null. */
    enum Null implements EcfValue { NULL }
}
