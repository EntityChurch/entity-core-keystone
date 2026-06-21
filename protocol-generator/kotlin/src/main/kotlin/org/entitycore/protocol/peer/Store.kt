package org.entitycore.protocol.peer

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Storage (foundation, §1.7): the two layers.
 *
 * ```
 *   Content Store: hash → entity   (immutable, content-addressed, dedup)
 *   Entity Tree:   path → hash     (mutable location index)
 * ```
 *
 * In-memory minimal impl. Paths are the canonical absolute form `/{peer_id}/rest`
 * (§1.4); the peer canonicalizes before calling in. Path keys are strings; the content
 * store is keyed by the lowercase-hex content_hash (so a ByteArray works as a string
 * map key).
 *
 * **EMIT PATHWAY (§6.10 / v7.74 §6.13(c)) — the Core Extensibility Boundary.** Tree/
 * content writes produce events delivered to registered consumers. The hook is LIVE
 * even with ZERO consumers (events are produced and discarded) so a future extension
 * can register a consumer WITHOUT rebuilding the peer (the §6.13(c) MUST). A core-only
 * peer registers zero consumers, but the seam is exercised on every bind.
 *
 * **§4.8 store data-race safety under concurrent dispatch.** The transport dispatches
 * concurrent inbound EXECUTEs (each on its own coroutine) that read/write the store, so
 * the maps are [ConcurrentHashMap] and consumer lists are copy-on-write — the structural
 * (lock-free read, atomic-per-key write) discipline. `putIfAbsent`/`put` are atomic, so
 * the §6.10 emit-on-change decision reads the atomic return value (no read-then-write
 * race on the change flag). This is the §7b "manual-but-structured" store-safety route
 * the profile names (the coroutine alternative — a single-writer store dispatcher /
 * `Mutex` — is unnecessary here because the concurrent-collection ops are already atomic
 * at the granularity the conformance flows need).
 */
class Store {

    /** A tree-change event (§6.10 Bind step). */
    data class TreeEvent(
        val eventType: String,
        val path: String,
        val newHash: String?,
        val previousHash: String?,
    )

    /** A content-store event (§6.10 Store step). */
    data class ContentEvent(val hash: ByteArray, val entity: Entity)

    private val content = ConcurrentHashMap<String, Entity>()  // hash-hex → entity
    private val tree = ConcurrentHashMap<String, String>()     // path → hash-hex
    private val contentConsumers = CopyOnWriteArrayList<(ContentEvent) -> Unit>()
    private val treeConsumers = CopyOnWriteArrayList<(TreeEvent) -> Unit>()

    // ── emit consumer registration (§6.10 consumer-registration primitive) ──────
    // Reachable any time, including post-bootstrap. Delivery is sync-inline (§9.4).

    fun registerContentConsumer(fn: (ContentEvent) -> Unit) {
        contentConsumers.add(fn)
    }

    fun registerTreeConsumer(fn: (TreeEvent) -> Unit) {
        treeConsumers.add(fn)
    }

    private fun deriveEventType(previous: String?, next: String?): String = when {
        previous == null -> "created"
        next == null -> "deleted"
        else -> "modified"
    }

    // ── content store (§6.10 Store step: event only when the entity is new) ─────

    fun putEntity(e: Entity) {
        val k = Cbor.hex(e.rawHash())
        if (content.putIfAbsent(k, e) == null) {
            val ev = ContentEvent(e.hash(), e)
            contentConsumers.forEach { it(ev) }
        }
    }

    fun getByHash(h: ByteArray): Entity? = content[Cbor.hex(h)]

    // ── entity tree (§6.10 Bind step: event when the binding at the path changes) ─

    fun bind(path: String, e: Entity) {
        putEntity(e)
        val next = Cbor.hex(e.rawHash())
        val prev = tree.put(path, next)
        if (next != prev) {
            val ev = TreeEvent(deriveEventType(prev, next), path, next, prev)
            treeConsumers.forEach { it(ev) }
        }
    }

    fun unbind(path: String) {
        val prev = tree.remove(path)
        if (prev != null) {
            val ev = TreeEvent("deleted", path, null, prev)
            treeConsumers.forEach { it(ev) }
        }
    }

    /** The hex content_hash bound at [path], or null. */
    fun hashAt(path: String): String? = tree[path]

    fun getAt(path: String): Entity? = tree[path]?.let { content[it] }

    /** One-level listing entry: a segment, its bound hash (or null), and whether the
     *  segment has deeper descendants. */
    data class ListEntry(val segment: String, val hashHex: String?, val hasChildren: Boolean)

    /**
     * One-level listing under [prefix] (a path; a trailing slash is added if absent).
     * Returns entries sorted by segment (§3.9).
     */
    fun listing(prefix: String): List<ListEntry> {
        val p = if (prefix.endsWith("/")) prefix else "$prefix/"
        val plen = p.length
        // segment → (hashOrNull, deeper); a sorted map gives §3.9 segment ordering.
        val acc = sortedMapOf<String, Pair<String?, Boolean>>()
        for ((path, hash) in tree) {
            if (path.length > plen && path.startsWith(p)) {
                val rest = path.substring(plen)
                val slash = rest.indexOf('/')
                if (slash >= 0) {
                    val seg = rest.substring(0, slash)
                    val cur = acc[seg] ?: (null to false)
                    acc[seg] = cur.first to true
                } else {
                    val cur = acc[rest] ?: (null to false)
                    acc[rest] = hash to cur.second
                }
            }
        }
        return acc.map { (seg, cell) -> ListEntry(seg, cell.first, cell.second) }
    }
}
