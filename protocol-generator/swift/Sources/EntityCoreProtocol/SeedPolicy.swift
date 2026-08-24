// SeedPolicy.swift — §6.9a Peer Authority Bootstrap (the keystone convention).
//
// Implements `shared/seed-policy/` (the language-agnostic cross-peer convention)
// in Swift idiom. A seed policy is a declared mapping `grantee_identity →
// (scope, bounds)`, materialized into the tree at L0 under
// `system/capability/policy/{key}` and consulted at §4.6 authenticate. It
// REPLACES the hardcoded initialGrants()/openGrants() fork (§6.9a: non-conformant).
//
// Two entries are always present (§6.9a.0 minimum):
//   - `self`    — the peer-owner capability (root cap, full scope over /{peer}/*),
//                 self-signed, detached-signature shape (§6.9a.0 shape 1; the
//                 keystone S8 uniformity decision — all self-issued caps use it).
//   - `default` — the fallback scope for unnamed identities; default = §4.4 floor.
//
// Builder API (per the §5 convention): seedPolicy parameter on the Peer init;
// SeedPolicy.standard() | .debugOpen() | .of(entries:). Authenticate-time
// derivation UNIONs the matched policy scope with the §4.4 discovery floor (v7.62
// §8), via the v7.64 dual-form lookup (hex → Base58 → default).

/// A grant-entry in a seed policy (the §3.6 grant-entry shape, as plain Swift).
public struct SeedGrant: Sendable {
    public let handlers: [String]
    public let resources: [String]
    public let operations: [String]
    /// §3.6 `peers` dimension. `nil` OMITS the key, which is NOT the same as
    /// universal: an absent `peers` is resolved per-link against the GRANTER's own
    /// frame (§5.5a), so a grant without it can only ever authorize the granter's
    /// own peer. A seed intended to be universal must say so explicitly.
    public let peers: [String]?
    public init(handlers: [String], resources: [String], operations: [String],
                peers: [String]? = nil) {
        self.handlers = handlers; self.resources = resources; self.operations = operations
        self.peers = peers
    }
    /// Render to the CBOR grant-entry map shape.
    public func toValue() -> CBORValue {
        var fields: [(String, CBORValue)] = [
            ("handlers", .textMap([("include", .array(handlers.map { .text($0) }))])),
            ("resources", .textMap([("include", .array(resources.map { .text($0) }))])),
            ("operations", .textMap([("include", .array(operations.map { .text($0) }))])),
        ]
        if let peers {
            fields.append(("peers", .textMap([("include", .array(peers.map { .text($0) }))])))
        }
        // §3.6 key order is fixed by ECF's canonical map sort at encode time, so
        // appending is safe regardless of position.
        return .textMap(fields)
    }
}

/// One policy entry: a grantee key + its grants.
public struct SeedEntry: Sendable {
    /// "self" | "default" | <identity_hash_hex> | <base58_peer_id>.
    public let grantee: String
    public let grants: [SeedGrant]
    public init(grantee: String, grants: [SeedGrant]) {
        self.grantee = grantee; self.grants = grants
    }
}

/// A parsed seed policy. `self` is materialized regardless of whether it appears
/// in `entries` (the peer always owns its namespace).
public struct SeedPolicy: Sendable {
    public let entries: [SeedEntry]
    public init(entries: [SeedEntry]) { self.entries = entries }

    /// The §4.4 discovery floor — the SHOULD initial scope every authenticated
    /// identity receives (read system/type/* + system/handler/*; request caps).
    public static var discoveryFloor: [SeedGrant] {
        [
            SeedGrant(handlers: ["system/tree"], resources: ["system/type/*", "system/handler/*"], operations: ["get"]),
            SeedGrant(handlers: ["system/capability"], resources: [], operations: ["request"]),
        ]
    }

    /// The conformant default policy: `default` → discovery floor.
    public static func standard() -> SeedPolicy {
        SeedPolicy(entries: [SeedEntry(grantee: "default", grants: discoveryFloor)])
    }

    /// The degenerate `default → *` policy — the retired `--debug-open-grants`.
    /// DEPRECATED (v7.74; removed v7.75). Routes through the real §6.9a mechanism
    /// (not a hardcoded fork). Use only to drive the full grant-gated validate-peer
    /// surface from a single connector.
    public static func debugOpen() -> SeedPolicy {
        // Every dimension must be EXPLICITLY universal, and two of them were not:
        //
        //  * `peers` was omitted. An absent peers scope resolves per-link against
        //    the granter's own frame (§5.5a), so the connection cap authorized only
        //    THIS peer. Any delegated child cap — whose granter is the CALLER, hence
        //    a different frame — then failed §5.6 attenuation, and every request
        //    presenting one came back 403 scope_exceeds_authority. That is a single
        //    seed defect, but it reads as three unrelated capability failures
        //    (CAP-5, CAP-6, and CAP-6a's control losing its teeth).
        //
        //  * `resources` carried only "/*/*". §5.5a's bare-star is granter-LOCAL,
        //    never universal, so the absolute all-peers form is needed alongside it
        //    to cover foreign namespaces (the A-PD-017 sibling trap, same shape).
        //
        // This now matches the go/ocaml/haskell/lean seeds exactly.
        SeedPolicy(entries: [SeedEntry(grantee: "default",
            grants: [SeedGrant(handlers: ["*"], resources: ["*", "/*/*"],
                               operations: ["*"], peers: ["*"])])])
    }

    /// Custom entries (the `.of(...)` builder).
    public static func of(_ entries: [SeedEntry]) -> SeedPolicy { SeedPolicy(entries: entries) }

    /// The matched policy grant-entries for an authenticated identity, by the
    /// v7.64 dual-form lookup (hex → Base58 → default). Returns [] if no match
    /// and no default. (The discovery floor is UNION'd by the caller per v7.62 §8.)
    public func grantsFor(identityHashHex: String, peerIDBase58: String) -> [SeedGrant] {
        if let e = entries.first(where: { $0.grantee == identityHashHex }) { return e.grants }
        if let e = entries.first(where: { $0.grantee == peerIDBase58 }) { return e.grants }
        if let e = entries.first(where: { $0.grantee == "default" }) { return e.grants }
        return []
    }
}
