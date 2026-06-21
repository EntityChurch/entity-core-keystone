package org.entitycore.protocol.peer;

import java.util.Arrays;

import org.entitycore.protocol.codec.CanonicalCbor;
import org.entitycore.protocol.codec.EcfValue;
import org.entitycore.protocol.codec.EntityCodecException;
import org.entitycore.protocol.crypto.ContentHash;

/**
 * A materialized entity {@code {type, data, content_hash}} (§1.1, §3.4) on top of the
 * S2 codec value model.
 *
 * <p>The content_hash covers ONLY {@code {type, data}} (§1.1); the wire form
 * ({@link #toCbor}) carries content_hash as a third field so entities are
 * self-describing across serialization (§3.1). The two forms stay distinct: the hash
 * is never computed over a map that already contains the content_hash field.
 *
 * <p>The 33-byte {@code hash} (format byte 0x00 ‖ 32-byte SHA-256 digest) is held as a
 * {@code byte[]}; it is defensively copied in and out (profile
 * {@code no_byte_array_aliasing} — Java arrays are mutable).
 */
public final class Entity {
    private final String type;
    // §1.1: an entity's `data` is an ARBITRARY ECF value, not necessarily a map.
    // Core protocol entities happen to be maps, but a primitive/string entity (e.g. a
    // tree-stored payload, or the concurrency gate's staged entities) has scalar data.
    // We hold the raw value and expose a null-safe map view for the protocol paths.
    private final EcfValue rawData;
    private final byte[] hash;

    private Entity(String type, EcfValue rawData, byte[] hash) {
        this.type = type;
        this.rawData = rawData;
        this.hash = hash;
    }

    /** Construct a materialized entity with a map `data` (the common protocol case),
     *  computing content_hash under the ecfv1-sha256 floor (format_code 0x00). */
    public static Entity make(String type, EcfValue.Map data) {
        return makeRaw(type, data);
    }

    /** Construct a materialized entity with an ARBITRARY ECF `data` value (§1.1) —
     *  covers scalar-data entities like primitive/string. */
    public static Entity makeRaw(String type, EcfValue data) {
        try {
            EcfValue.Map basis = EcfValue.Map.of("type", new EcfValue.Text(type), "data", data);
            byte[] h = ContentHash.compute(basis, ContentHash.FORMAT_SHA256);
            return new Entity(type, data, h);
        } catch (EntityCodecException e) {
            // {type,data} always encodes; an exception here is a programmer error.
            throw new IllegalStateException("content_hash of well-formed entity failed", e);
        }
    }

    public String type() {
        return type;
    }

    /** The `data` as a map view: the map itself when data IS a map (every core protocol
     *  entity), or the canonical empty map when data is a scalar (so field reads on a
     *  scalar-data entity safely return null rather than NPE). */
    public EcfValue.Map data() {
        return (rawData instanceof EcfValue.Map m) ? m : new EcfValue.Map(java.util.List.of());
    }

    /** The raw `data` value (§1.1) — may be any ECF node, not just a map. */
    public EcfValue rawData() {
        return rawData;
    }

    /** Defensive copy of the 33-byte content_hash. */
    public byte[] hash() {
        return hash.clone();
    }

    /** Internal no-copy accessor (callers must not mutate). */
    byte[] rawHash() {
        return hash;
    }

    // ── field reads off data ────────────────────────────────────────────────────

    public String text(String key) {
        return Cbor.text(data(), key);
    }

    public byte[] bytes(String key) {
        return Cbor.bytes(data(), key);
    }

    public java.math.BigInteger uint(String key) {
        return Cbor.uint(data(), key);
    }

    public EcfValue field(String key) {
        return data().get(key);
    }

    public EcfValue.Map mapField(String key) {
        return Cbor.asMap(data().get(key));
    }

    /** Decode a nested entity carried at {@code key} (a wire cbor-map). */
    public Entity entityField(String key) {
        EcfValue.Map m = mapField(key);
        return (m != null) ? ofCbor(m) : null;
    }

    // ── wire form ───────────────────────────────────────────────────────────────

    /** The wire cbor-map {@code {type, data, content_hash}}. */
    public EcfValue.Map toCbor() {
        return EcfValue.Map.of(
                "type", new EcfValue.Text(type),
                "data", rawData,
                "content_hash", new EcfValue.Bytes(hash));
    }

    /**
     * Parse a wire entity cbor-map, recompute the hash from {@code {type, data}}, and
     * validate it against the carried content_hash (§1.8 fidelity). We trust our
     * recomputed hash, not the wire bytes (§5.2 validate-before-trust).
     */
    public static Entity ofCbor(EcfValue.Map m) {
        EcfValue typeV = m.get("type");
        EcfValue dataV = m.get("data");
        if (!(typeV instanceof EcfValue.Text t)) {
            throw new IllegalArgumentException("entity: missing/invalid type");
        }
        if (dataV == null) {
            throw new IllegalArgumentException("entity: missing data");
        }
        // §1.1: data is an arbitrary ECF value (map for protocol entities, scalar for
        // e.g. primitive/string). Accept any non-null node, not just maps.
        Entity e = makeRaw(t.value(), dataV);
        EcfValue carried = m.get("content_hash");
        if (carried instanceof EcfValue.Bytes b
                && !Arrays.equals(b.octets(), e.hash)) {
            throw new IllegalArgumentException("content_hash mismatch (§1.8 fidelity)");
        }
        return e;
    }

    /** Encode the wire form to canonical ECF bytes. */
    public byte[] wireBytes() throws EntityCodecException {
        return CanonicalCbor.encode(toCbor());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Entity e && Arrays.equals(hash, e.hash);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash);
    }

    @Override
    public String toString() {
        return "Entity(" + type + ", " + Cbor.hex(hash) + ")";
    }
}
