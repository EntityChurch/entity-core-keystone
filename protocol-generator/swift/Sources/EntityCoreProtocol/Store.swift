// Store.swift — content store + entity tree + emit pathway (foundation, §1.7/§6.10).
//
// THE SWIFT CONCURRENCY ADVANTAGE (§7b). The store is an `actor`: all mutable
// state (content map, tree map, consumer lists) is actor-isolated, so concurrent
// per-request dispatch CANNOT race it — the compiler enforces serialized access
// via Swift 6 strict concurrency. The store-race that bit Zig (HashMap double-free)
// and Common Lisp (gethash 500s) under §7b's T2.1/T2.2 is *structurally impossible*
// here: there is no path to touch the maps except `await`-ing an actor method,
// which the runtime serializes onto the actor's executor. No mutex, no lock — the
// type system is the proof. (PROPOSAL-V7-V7.75 made store data-race-safety a §4.8
// floor MUST; an actor is the cleanest conformant shape.)
//
// Two layers of §1.7:
//   Content Store:  hash → entity   (immutable, content-addressed, dedup)
//   Entity Tree:    path → hash      (mutable location index)
// A path may be both bound to an entity AND a prefix for child paths (§1.7);
// listing (§3.9) reports the two dimensions independently. Paths are canonical
// absolute "/{peer_id}/rest" (§1.4) — the peer canonicalizes before calling in.

/// Content-store event (§6.10 Store step): carries `(hash, entity)` ONLY — no
/// execution context (that is a tree-change-event concept).
public struct ContentStoreEvent: Sendable {
    public let hash: [UInt8]
    public let entity: Entity
    /// MAY field: first-store-of-hash. Impl-private; informational.
    public let isNew: Bool
}

/// Tree-change event (§6.10 Bind step / v7.74 §6.13(c) field inventory). `context`
/// is impl-defined (§6.8a) and inert on a core peer; omitted here.
public struct TreeChangeEvent: Sendable {
    /// "created" | "modified" | "deleted" — derived per the null-hash rule below.
    public let eventType: String
    public let path: String
    /// nil ⇒ operational unbind (delete).
    public let newHash: [UInt8]?
    /// nil ⇒ path was previously unbound.
    public let previousHash: [UInt8]?
}

/// `event_type` derivation (§6.10, normative): created if no previous, deleted if
/// no new (operational unbind), modified otherwise. A bind to a
/// `system/deletion-marker` entity fires "modified" — classification keys ONLY on
/// a null `new_hash` (a bind always has a new_hash), NEVER on entity type.
func deriveEventType(previous: [UInt8]?, new: [UInt8]?) -> String {
    if previous == nil { return "created" }
    if new == nil { return "deleted" }
    return "modified"
}

public actor Store {
    private var content: [HashKey: Entity] = [:]
    private var tree: [String: [UInt8]] = [:]
    // Emit consumers (§6.10 consumer-registration primitive). The hook is LIVE even
    // with zero consumers — events are produced and discarded — so a future
    // extension can register without the peer being rebuilt (§6.13(c) MUST). A
    // core-only peer registers zero. Consumers are `@Sendable` closures.
    private var contentConsumers: [@Sendable (ContentStoreEvent) -> Void] = []
    private var treeConsumers: [@Sendable (TreeChangeEvent) -> Void] = []

    public init() {}

    // MARK: emit registration (§6.10) — reachable any time, incl. post-bootstrap.

    public func registerContentConsumer(_ f: @escaping @Sendable (ContentStoreEvent) -> Void) {
        contentConsumers.append(f)
    }
    public func registerTreeConsumer(_ f: @escaping @Sendable (TreeChangeEvent) -> Void) {
        treeConsumers.append(f)
    }

    // MARK: content store (§6.10 Store step)

    /// Store an entity. Fires a content-store event only when the entity is new to
    /// the store (a re-put of an existing hash fires nothing). A direct put runs
    /// only the Store step.
    public func putEntity(_ e: Entity) {
        guard let h = e.contentHash else { return }
        let key = HashKey(h)
        let isNew = content[key] == nil
        content[key] = e
        if isNew {
            let ev = ContentStoreEvent(hash: h, entity: e, isNew: true)
            for f in contentConsumers { f(ev) }
        }
    }

    public func getByHash(_ h: [UInt8]) -> Entity? { content[HashKey(h)] }

    // MARK: entity tree (location index, §6.10 Bind step)

    /// Bind `path → entity` (runs Store then Bind). A tree-change event fires when
    /// the binding at the path changes; no event on a re-bind to the current hash.
    public func bind(path: String, _ e: Entity) {
        putEntity(e)
        guard let h = e.contentHash else { return }
        let previous = tree[path]
        let changed = previous.map { !$0.elementsEqual(h) } ?? true
        tree[path] = h
        if changed {
            let ev = TreeChangeEvent(
                eventType: deriveEventType(previous: previous, new: h),
                path: path, newHash: h, previousHash: previous)
            for f in treeConsumers { f(ev) }
        }
    }

    /// Operational unbind (§6.10 deleted). Fires a "deleted" tree-change event.
    public func unbind(path: String) {
        let previous = tree[path]
        tree.removeValue(forKey: path)
        if previous != nil {
            let ev = TreeChangeEvent(eventType: "deleted", path: path, newHash: nil, previousHash: previous)
            for f in treeConsumers { f(ev) }
        }
    }

    public func hashAt(path: String) -> [UInt8]? { tree[path] }

    public func getAt(path: String) -> Entity? {
        guard let h = tree[path] else { return nil }
        return content[HashKey(h)]
    }

    public func isBound(path: String) -> Bool { tree[path] != nil }

    // MARK: listing (§3.9) — one level under a prefix path

    /// One-level listing under `prefix` (a path ending in "/"). Returns
    /// `(segment, hash?, hasChildren)` per `system/tree/listing-entry` (§3.9). A
    /// bound direct child contributes a hash; a path that is also a prefix of
    /// deeper paths contributes hasChildren.
    public func listing(prefix rawPrefix: String) -> [(segment: String, hash: [UInt8]?, hasChildren: Bool)] {
        let prefix = rawPrefix.hasSuffix("/") ? rawPrefix : rawPrefix + "/"
        var acc: [String: (hash: [UInt8]?, deeper: Bool)] = [:]
        for (path, hash) in tree where path.hasPrefix(prefix) && path.count > prefix.count {
            let rest = String(path.dropFirst(prefix.count))
            if let slash = rest.firstIndex(of: "/") {
                let seg = String(rest[rest.startIndex..<slash])
                var e = acc[seg] ?? (hash: nil, deeper: false)
                e.deeper = true
                acc[seg] = e
            } else {
                var e = acc[rest] ?? (hash: nil, deeper: false)
                e.hash = hash
                acc[rest] = e
            }
        }
        return acc.map { (segment: $0.key, hash: $0.value.hash, hasChildren: $0.value.deeper) }
            .sorted { $0.segment < $1.segment }
    }
}

/// A `[UInt8]` content-hash usable as a `Dictionary` key. `[UInt8]` is not
/// `Hashable` as a key in a way that's stable for our use without this wrapper
/// being explicit about byte-wise identity. `Sendable` value type.
public struct HashKey: Hashable, Sendable {
    public let bytes: [UInt8]
    public init(_ bytes: [UInt8]) { self.bytes = bytes }
    public static func == (l: HashKey, r: HashKey) -> Bool { l.bytes == r.bytes }
    public func hash(into h: inout Hasher) { h.combine(bytes) }
}
