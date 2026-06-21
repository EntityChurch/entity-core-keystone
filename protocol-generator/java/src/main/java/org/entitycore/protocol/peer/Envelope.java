package org.entitycore.protocol.peer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.entitycore.protocol.codec.EcfValue;

/**
 * The protocol envelope (§3.1): a {@code root} entity plus an {@code included} map of
 * protocol entities keyed by content_hash. {@code included} is the §5.8 authority
 * carrier (caps, peer identities, signatures travel here).
 *
 * <p>Held as an insertion-ordered list of (hash, entity) pairs so a wire round-trip is
 * deterministic; lookup is by content_hash octets.
 */
public final class Envelope {
    /** One included entry: a content_hash (33 bytes) and its entity. */
    public record Included(byte[] hash, Entity entity) { }

    private final Entity root;
    private final List<Included> included;

    public Envelope(Entity root, List<Included> included) {
        this.root = root;
        this.included = (included == null) ? List.of() : List.copyOf(included);
    }

    public Envelope(Entity root) {
        this(root, List.of());
    }

    public Entity root() {
        return root;
    }

    public List<Included> included() {
        return included;
    }

    /** Find an included entity by its content_hash, or null. */
    public Entity includedGet(byte[] h) {
        for (Included in : included) {
            if (Arrays.equals(in.hash(), h)) {
                return in.entity();
            }
        }
        return null;
    }

    // ── wire form ───────────────────────────────────────────────────────────────

    public EcfValue.Map toCbor() {
        List<EcfValue.Map.Entry> inc = new ArrayList<>(included.size());
        for (Included in : included) {
            inc.add(new EcfValue.Map.Entry(
                    new EcfValue.Bytes(in.hash()), in.entity().toCbor()));
        }
        return EcfValue.Map.of(
                "root", root.toCbor(),
                "included", new EcfValue.Map(inc));
    }

    public static Envelope ofCbor(EcfValue.Map m) {
        EcfValue rootV = m.get("root");
        if (!(rootV instanceof EcfValue.Map rm)) {
            throw new IllegalArgumentException("envelope: missing root");
        }
        Entity root = Entity.ofCbor(rm);
        List<Included> included = new ArrayList<>();
        if (m.get("included") instanceof EcfValue.Map incM) {
            // dedup by content_hash, preserving order (defensive — a well-formed
            // envelope has unique keys, the codec already rejects duplicate map keys).
            Map<String, Boolean> seen = new LinkedHashMap<>();
            for (EcfValue.Map.Entry e : incM.entries()) {
                if (!(e.key() instanceof EcfValue.Bytes kb)) {
                    throw new IllegalArgumentException("envelope: included key not bytes");
                }
                if (!(e.value() instanceof EcfValue.Map vm)) {
                    throw new IllegalArgumentException("envelope: included value not a map");
                }
                Entity ent = Entity.ofCbor(vm);
                // §3.1: the included content_hash MUST equal the map key.
                if (!Arrays.equals(kb.octets(), ent.rawHash())) {
                    throw new IllegalArgumentException("included key != content_hash");
                }
                if (seen.putIfAbsent(Cbor.hex(kb.octets()), Boolean.TRUE) == null) {
                    included.add(new Included(kb.octets(), ent));
                }
            }
        }
        return new Envelope(root, included);
    }
}
