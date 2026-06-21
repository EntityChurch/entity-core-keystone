package org.entitycore.protocol.peer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Storage (foundation, §1.7): the two layers.
 *
 * <pre>
 *   Content Store: hash → entity   (immutable, content-addressed, dedup)
 *   Entity Tree:   path → hash     (mutable location index)
 * </pre>
 *
 * <p>In-memory minimal impl. Paths are the canonical absolute form
 * {@code /{peer_id}/rest} (§1.4); the peer canonicalizes before calling in. Path keys
 * are strings; the content store is keyed by the lowercase-hex content_hash (so a
 * byte[] works as a string map key).
 *
 * <p><b>EMIT PATHWAY (§6.10 / v7.74 §6.13(c)) — the Core Extensibility Boundary.</b>
 * Tree/content writes produce events delivered to registered consumers. The hook is
 * LIVE even with ZERO consumers (events are produced and discarded) so a future
 * extension can register a consumer WITHOUT rebuilding the peer — the §6.13(c) MUST. A
 * core-only peer registers zero consumers, but the seam is exercised on every bind.
 *
 * <p>Thread-safe (the transport dispatches concurrent inbound EXECUTEs that read/write
 * the store): the maps are {@link ConcurrentHashMap}, consumer lists are
 * copy-on-write. Bind reads-then-writes are not globally atomic, which is acceptable
 * for the §1.7 minimal impl + the loopback / --profile core surface (no concurrent
 * writer contention on the same path in the conformance flows).
 */
public final class Store {

    /** A tree-change event (§6.10 Bind step). */
    public record TreeEvent(String eventType, String path, String newHash, String previousHash) { }

    /** A content-store event (§6.10 Store step). */
    public record ContentEvent(byte[] hash, Entity entity) { }

    private final Map<String, Entity> content = new ConcurrentHashMap<>();   // hash-hex → entity
    private final Map<String, String> tree = new ConcurrentHashMap<>();      // path → hash-hex
    private final List<Consumer<ContentEvent>> contentConsumers = new CopyOnWriteArrayList<>();
    private final List<Consumer<TreeEvent>> treeConsumers = new CopyOnWriteArrayList<>();

    // ── emit consumer registration (§6.10 consumer-registration primitive) ──────
    // Reachable any time, including post-bootstrap. Delivery is sync-inline (§9.4).

    public void registerContentConsumer(Consumer<ContentEvent> fn) {
        contentConsumers.add(fn);
    }

    public void registerTreeConsumer(Consumer<TreeEvent> fn) {
        treeConsumers.add(fn);
    }

    private static String deriveEventType(String previous, String next) {
        if (previous == null) {
            return "created";
        }
        if (next == null) {
            return "deleted";
        }
        return "modified";
    }

    // ── content store ───────────────────────────────────────────────────────────
    // §6.10 Store step: a content-store event fires only when the entity is new.

    public void putEntity(Entity e) {
        String k = Cbor.hex(e.rawHash());
        if (content.putIfAbsent(k, e) == null) {
            ContentEvent ev = new ContentEvent(e.hash(), e);
            for (Consumer<ContentEvent> fn : contentConsumers) {
                fn.accept(ev);
            }
        }
    }

    public Entity getByHash(byte[] h) {
        return content.get(Cbor.hex(h));
    }

    // ── entity tree (location index) ────────────────────────────────────────────
    // §6.10 Bind step: a tree-change event fires when the binding at the path changes.

    public void bind(String path, Entity e) {
        putEntity(e);
        String next = Cbor.hex(e.rawHash());
        String prev = tree.put(path, next);
        boolean changed = !next.equals(prev);
        if (changed) {
            TreeEvent ev = new TreeEvent(deriveEventType(prev, next), path, next, prev);
            for (Consumer<TreeEvent> fn : treeConsumers) {
                fn.accept(ev);
            }
        }
    }

    public void unbind(String path) {
        String prev = tree.remove(path);
        if (prev != null) {
            TreeEvent ev = new TreeEvent("deleted", path, null, prev);
            for (Consumer<TreeEvent> fn : treeConsumers) {
                fn.accept(ev);
            }
        }
    }

    /** The hex content_hash bound at {@code path}, or null. */
    public String hashAt(String path) {
        return tree.get(path);
    }

    public Entity getAt(String path) {
        String h = tree.get(path);
        return (h != null) ? content.get(h) : null;
    }

    /** One-level listing entry: a segment, its bound hash (or null), and whether the
     *  segment has deeper descendants. */
    public record ListEntry(String segment, String hashHex, boolean hasChildren) { }

    /**
     * One-level listing under {@code prefix} (a path; a trailing slash is added if
     * absent). Returns entries sorted by segment (§3.9).
     */
    public List<ListEntry> listing(String prefix) {
        String p = prefix.endsWith("/") ? prefix : prefix + "/";
        int plen = p.length();
        // segment → [hashOrNull, deeper]
        Map<String, Object[]> acc = new TreeMap<>();
        for (Map.Entry<String, String> e : tree.entrySet()) {
            String path = e.getKey();
            if (path.length() > plen && path.startsWith(p)) {
                String rest = path.substring(plen);
                int slash = rest.indexOf('/');
                if (slash >= 0) {
                    String seg = rest.substring(0, slash);
                    Object[] cell = acc.computeIfAbsent(seg, k -> new Object[] {null, Boolean.FALSE});
                    cell[1] = Boolean.TRUE;
                } else {
                    Object[] cell = acc.computeIfAbsent(rest, k -> new Object[] {null, Boolean.FALSE});
                    cell[0] = e.getValue();
                }
            }
        }
        List<ListEntry> out = new ArrayList<>(acc.size());
        for (Map.Entry<String, Object[]> e : acc.entrySet()) {
            out.add(new ListEntry(e.getKey(), (String) e.getValue()[0], (Boolean) e.getValue()[1]));
        }
        return out;
    }
}
