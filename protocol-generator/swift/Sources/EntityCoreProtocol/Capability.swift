// Capability.swift — L3 capability system (§5). CONFORMANCE algorithms (§7):
// different logic is fine, identical ALLOW/DENY is required (N8 verdict
// determinism). Derived spec-first from the §5.2/§5.4/§5.5/§5.6/§5.7 pseudocode.
//
// The verdict shape encodes the §5.2a auth(401)/authz(403) boundary explicitly:
//   .allow                       → proceed
//   .authDeny                    → 401 authentication_failed (envelope unauthenticated)
//   .authzDeny(code)             → 403 <code> (authenticated but unauthorized)
//   .unresolvableGrantee         → 401 unresolvable_grantee (PR-3 carve-out)
// MANY peers found §5.2's flat "DENY→403" under-specifies this; §5.2a now
// enumerates it — we build to the enumeration (corroborates OCaml A-OC-008,
// Zig A-ZIG-006, arch F20).

/// A request-time verification verdict mapped to (status, code) by the dispatcher.
public enum Verdict: Sendable, Equatable {
    case allow
    case authDeny                       // 401 authentication_failed
    case authzDeny(code: String)        // 403 <code>
    case unresolvableGrantee            // 401 unresolvable_grantee
    case chainTooDeep                   // 400 chain_depth_exceeded (§4.10b)

    public var capabilityDenied: Verdict { .authzDeny(code: "capability_denied") }
}

public enum Capability {

    // MARK: §1.4 / §5.4 pattern matching

    /// §5.4 canonicalize: resolve peer-relative paths to absolute. Reject
    /// directory-relative and bare peer-wildcard forms. NOTE the granter frame:
    /// cap resource patterns canonicalize against the *granter's* peer_id (§5.5a),
    /// request paths against local (§5.4); the caller supplies the right frame.
    public static func canonicalize(_ path: String, frame peerID: String) -> String {
        let path = normalizeURI(path)                                    // strip entity:// scheme (§1.4)
        if path.hasPrefix("./") || path.hasPrefix("../") { return path } // reserved; pass through (rejected upstream)
        if path.hasPrefix("*/") { return path }                          // ambiguous; pass through
        if path.hasPrefix("/") { return path }                           // already absolute
        return "/" + peerID + "/" + path                                 // peer-relative incl. bare "*"
    }

    /// §1.4 universal address space: an `entity://{peer_id}/rest` URI is the
    /// scheme-qualified form of the absolute path `/{peer_id}/rest`. The validator
    /// addresses every EXECUTE `uri` and resource target in this form. Strip the
    /// scheme to the bare absolute path (mirrors OCaml `normalize_uri`).
    public static func normalizeURI(_ uri: String) -> String {
        if uri.hasPrefix("entity://") { return "/" + String(uri.dropFirst("entity://".count)) }
        return uri
    }

    /// §5.4 matches_pattern. Both inputs MUST already be canonical (absolute).
    public static func matchesPattern(_ path: String, _ pattern: String) -> Bool {
        if pattern == "*" { return true }
        // Peer wildcard /*/rest — match any peer's subtree.
        if pattern.hasPrefix("/*/") {
            let remainder = String(pattern.dropFirst(3))
            // path is /{peer}/rest — strip the peer segment.
            let afterLead = path.dropFirst() // drop leading "/"
            guard let slash = afterLead.firstIndex(of: "/") else { return false }
            let pathRest = String(afterLead[afterLead.index(after: slash)...])
            return matchesPattern(pathRest, remainder)
        }
        // Subtree pattern/* — prefix match.
        if pattern.hasSuffix("/*") {
            let prefix = String(pattern.dropLast(1)) // keep trailing "/"
            return path.hasPrefix(prefix)
        }
        return path == pattern
    }

    static func isPattern(_ path: String) -> Bool { path.contains("*") }

    /// §5.4 is_peer_id: Base58, ≥46 chars (the informative floor).
    static func isPeerID(_ segment: String) -> Bool {
        guard segment.count >= 46 else { return false }
        return segment.utf8.allSatisfy { Base58.alphabetContains($0) }
    }

    /// §5.4 validate_absolute_path: first segment after "/" must be a peer_id.
    /// Called on concrete (non-pattern) targets only.
    static func validateAbsolutePath(_ path: String) -> Bool {
        guard path.hasPrefix("/") else { return false }
        let segs = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard let first = segs.first else { return false }
        return isPeerID(String(first))
    }

    // MARK: §5.2 matches_scope (uniform over path-scope & id-scope)

    /// A grant scope `{include, exclude?}`.
    public struct Scope: Sendable {
        public let include: [String]
        public let exclude: [String]
        public init(include: [String], exclude: [String] = []) {
            self.include = include; self.exclude = exclude
        }
        /// Read a scope off a CBORValue map `{include:[...], exclude?:[...]}`.
        public static func from(_ v: CBORValue?) -> Scope {
            guard let v else { return Scope(include: []) }
            let inc = (v.arrayAt("include") ?? []).compactMap { $0.textValue }
            let exc = (v.arrayAt("exclude") ?? []).compactMap { $0.textValue }
            return Scope(include: inc, exclude: exc)
        }
    }

    /// §5.2 matches_scope: value is included and not excluded. `frame` is the
    /// canonicalization peer_id for BOTH value and patterns at this call site.
    public static func matchesScope(_ value: String, _ scope: Scope, frame: String) -> Bool {
        let cv = canonicalize(value, frame: frame)
        var matched = false
        for p in scope.include where matchesPattern(cv, canonicalize(p, frame: frame)) { matched = true; break }
        guard matched else { return false }
        for p in scope.exclude where matchesPattern(cv, canonicalize(p, frame: frame)) { return false }
        return true
    }

    // MARK: §3.6 grant-entry model

    /// A grant-entry (§3.6): the four scope dimensions + opaque constraints/allowances.
    public struct GrantEntry: Sendable {
        public let handlers: Scope
        public let resources: Scope
        public let operations: Scope
        public let peers: Scope?               // absent ⇒ local peer only
        public let constraints: [(key: CBORValue, value: CBORValue)]
        public let allowances: [(key: CBORValue, value: CBORValue)]

        public static func from(_ v: CBORValue) -> GrantEntry {
            GrantEntry(
                handlers: Scope.from(v.mapValue("handlers")),
                resources: Scope.from(v.mapValue("resources")),
                operations: Scope.from(v.mapValue("operations")),
                peers: v.mapValue("peers").map { Scope.from($0) },
                constraints: v.mapValue("constraints")?.mapPairs ?? [],
                allowances: v.mapValue("allowances")?.mapPairs ?? [])
        }
    }

    /// All grant-entries on a `system/capability/token` entity.
    public static func grants(of cap: Entity) -> [GrantEntry] {
        (cap.data.arrayAt("grants") ?? []).map { GrantEntry.from($0) }
    }

    /// §5.2 check_permission. Called AFTER handler resolution. Checks handler +
    /// operation + peer + (when present) resource — all four from ONE grant entry.
    /// `frame` is local_peer_id for the *check* (request paths canonicalize local);
    /// cap resource patterns within `check_resource_scope` canonicalize against the
    /// granter (§5.5a) — supplied via `granterFrame`.
    public static func checkPermission(
        operation: String, handlerPattern: String, targetPeer: String,
        resourceTarget: ResourceTarget?, grants: [GrantEntry],
        localPeerID: String, granterFrame: String
    ) -> Bool {
        for g in grants {
            if !matchesScope(operation, g.operations, frame: localPeerID) { continue }
            if !matchesScope(handlerPattern, g.handlers, frame: localPeerID) { continue }
            let peersScope = g.peers ?? Scope(include: [localPeerID])
            if !matchesScope(targetPeer, peersScope, frame: localPeerID) { continue }
            if let rt = resourceTarget {
                if !checkResourceScope(rt, g.resources, localPeerID: localPeerID, granterFrame: granterFrame) { continue }
            }
            return true
        }
        return false
    }

    /// §3.2 resource-target `{targets, exclude?}`.
    public struct ResourceTarget: Sendable {
        public let targets: [String]
        public let exclude: [String]
        public static func from(_ v: CBORValue?) -> ResourceTarget? {
            guard let v, let t = v.arrayAt("targets") else { return nil }
            return ResourceTarget(
                targets: t.compactMap { $0.textValue },
                exclude: (v.arrayAt("exclude") ?? []).compactMap { $0.textValue })
        }
    }

    /// §5.2 check_resource_scope. The effective target scope (targets minus caller
    /// excludes) must be within the effective grant scope (includes minus grant
    /// excludes). Request targets canonicalize against `localPeerID`; the grant's
    /// resource patterns canonicalize against `granterFrame` (§5.5a granter frame).
    public static func checkResourceScope(
        _ rt: ResourceTarget, _ grantResources: Scope, localPeerID: String, granterFrame: String
    ) -> Bool {
        let callerExclude = rt.exclude
        for target in rt.targets {
            let ct = canonicalize(target, frame: localPeerID)
            if !isPattern(ct) && !validateAbsolutePath(ct) { return false }
            if isCoveredBy(ct, callerExclude, frame: localPeerID) { continue }
            // grant include/exclude canonicalize against the GRANTER (§5.5a).
            if !isCoveredBy(ct, grantResources.include, frame: granterFrame) { return false }
            if isPattern(ct) {
                for ge in grantResources.exclude {
                    let cge = canonicalize(ge, frame: granterFrame)
                    if !patternsOverlap(ct, cge) { continue }
                    if !isCoveredBy(cge, callerExclude, frame: localPeerID) { return false }
                }
            } else {
                for ge in grantResources.exclude {
                    let cge = canonicalize(ge, frame: granterFrame)
                    if matchesPattern(ct, cge) { return false }
                }
            }
        }
        return true
    }

    static func isCoveredBy(_ pathOrPattern: String, _ patternSet: [String], frame: String) -> Bool {
        for p in patternSet where matchesPattern(pathOrPattern, canonicalize(p, frame: frame)) { return true }
        return false
    }

    static func stripWildcard(_ pattern: String) -> String {
        if pattern.hasSuffix("/*") { return String(pattern.dropLast(2)) }
        if pattern == "*" { return "" }
        return pattern
    }

    static func patternsOverlap(_ a: String, _ b: String) -> Bool {
        let pa = stripWildcard(a), pb = stripWildcard(b)
        return pa.hasPrefix(pb) || pb.hasPrefix(pa)
    }

    /// §5.2 extract_peer: first segment if a peer_id, else local.
    public static func extractPeer(_ uri: String, localPeerID: String) -> String {
        let trimmed = uri.hasPrefix("/") ? String(uri.dropFirst()) : uri
        let first = String(trimmed.split(separator: "/", omittingEmptySubsequences: false).first ?? "")
        return isPeerID(first) ? first : localPeerID
    }

    // MARK: §3.6 multi-signature granter (K-of-N quorum root)

    /// A multi-signature granter descriptor (§3.6). The `granter` field of a
    /// `system/capability/token` is a UNION: a single `system/hash` (bytes) for the
    /// single-sig path, or this `{signers: [system/hash], threshold: uint}` map for
    /// a K-of-N quorum root. Multi-sig is ROOT-ONLY (M3).
    public struct MultiSigGranter: Sendable {
        public let signers: [[UInt8]]
        public let threshold: UInt64
    }

    /// Parse the `granter` field as a multi-sig descriptor. Returns nil when the
    /// granter is a single `system/hash` (bytes) or absent — i.e. when this is the
    /// single-sig path. Recognition is purely structural: granter is a `.map` ⇒
    /// multi-sig (signers array + threshold uint).
    public static func multiGranter(of cap: Entity) -> MultiSigGranter? {
        guard let g = cap.data.mapValue("granter"), case .map = g else { return nil }
        let signers = (g.arrayAt("signers") ?? []).compactMap { $0.bytesValue }
        let threshold = g.uintAt("threshold") ?? 0
        return MultiSigGranter(signers: signers, threshold: threshold)
    }

    /// True iff this cap's `granter` is a multi-sig descriptor (a map, not bytes).
    public static func isMultiSig(_ cap: Entity) -> Bool { multiGranter(of: cap) != nil }

    /// True iff `signers` contains a duplicate hash (byte-wise).
    static func hasDuplicateSigners(_ signers: [[UInt8]]) -> Bool {
        var seen = Set<HashKey>()
        for s in signers where !seen.insert(HashKey(s)).inserted { return true }
        return false
    }

    /// All `system/signature` entities in `included` whose `target` == `targetHash`.
    static func signaturesTargeting(_ targetHash: [UInt8], in included: [HashKey: Entity]) -> [Entity] {
        included.values.filter {
            $0.type == "system/signature" && ($0.data.bytesAt("target")?.elementsEqual(targetHash) ?? false)
        }
    }

    /// §3.6 M3 / §5.5 M4·M6 — validate a multi-signature ROOT capability. Returns
    /// true (ALLOW) only if the structure is well-formed AND a quorum of distinct
    /// signers signed the cap's content hash. Structural validation (M3) precedes
    /// signature counting (§3.6 precedence 25): a malformed quorum is denied on its
    /// structure, not on its signatures. Every failure path returns false → the
    /// dispatcher maps it to 403 capability_denied (never a throw, never a hang).
    /// `signerPeerID` derives a resolved signer entity's peer_id (§1.5).
    public static func verifyMultiSigRoot(
        _ cap: Entity, granter mg: MultiSigGranter, included: [HashKey: Entity],
        localPeerID: String, now: UInt64, resolve: Resolver, signerPeerID: (Entity) -> String?
    ) -> Bool {
        // §3.6 M3 structure — root-only; a real quorum (n ≥ 2); a usable threshold
        // (2 ≤ threshold ≤ n, so neither degenerate-single nor unsatisfiable);
        // distinct signers. Checked BEFORE any signature work (precedence 25).
        if cap.data.bytesAt("parent") != nil { return false }
        let n = mg.signers.count
        if n < 2 { return false }
        if mg.threshold < 2 || mg.threshold > UInt64(n) { return false }
        if hasDuplicateSigners(mg.signers) { return false }

        // §5.5 M6 root-at-local: the local peer MUST be one of the quorum signers.
        let localInSigners = mg.signers.contains { s in
            guard let p = resolve(s) else { return false }
            return signerPeerID(p) == localPeerID
        }
        if !localInSigners { return false }

        // Temporal validity + grantee resolution (as for any root).
        if let nb = cap.data.uintAt("not_before"), now < nb { return false }
        if let ea = cap.data.uintAt("expires_at"), ea < now { return false }
        guard let granteeHash = cap.data.bytesAt("grantee"), resolve(granteeHash) != nil else { return false }

        // §5.5 M4 k-of-n: count DISTINCT quorum members that produced a valid
        // signature over the cap's content hash; a duplicate signature from the same
        // signer does NOT inflate the count.
        guard let target = cap.contentHash else { return false }
        let sigs = signaturesTargeting(target, in: included)
        var validSigners = Set<HashKey>()
        for signerHash in mg.signers {
            if validSigners.contains(HashKey(signerHash)) { continue }
            guard let signerPeer = resolve(signerHash) else { continue }
            let signed = sigs.contains { sig in
                (sig.data.bytesAt("signer")?.elementsEqual(signerHash) ?? false) && verifySignature(sig, by: signerPeer)
            }
            if signed { validSigners.insert(HashKey(signerHash)) }
        }
        return UInt64(validSigners.count) >= mg.threshold
    }

    // MARK: §5.5 chain walk

    /// resolve_fn lookups go through `included` first, then the content store
    /// (caller supplies the merged resolver).
    public typealias Resolver = (_ hash: [UInt8]) -> Entity?

    /// §5.5 collect_authority_chain: cap → root (parent == null). Returns the
    /// ordered chain, or nil on unreachable / too-deep (both fail closed).
    public static func collectChain(_ cap: Entity, resolve: Resolver, maxDepth: Int = 64) -> [Entity]? {
        var chain: [Entity] = []
        var current: Entity? = cap
        var depth = 0
        while let c = current {
            if depth > maxDepth { return nil }
            chain.append(c)
            guard let parentHash = c.data.bytesAt("parent") else { return chain } // root reached
            current = resolve(parentHash)
            if current == nil { return nil }                                       // unreachable
            depth += 1
        }
        return chain
    }

    /// §4.10(b) structural-bound pre-check: true if the authority chain rooted at
    /// `cap` exceeds `maxDepth` links. Walks parent pointers without verifying
    /// signatures — depth is a purely structural property, gated BEFORE the per-link
    /// authz walk so an over-deep chain is reported as 400 chain_depth_exceeded
    /// (structural excess), distinct from a 403 capability_denied authz failure (arch
    /// ruling, v7.75 §4.10(b)). An unreachable parent is NOT a depth problem — it
    /// returns false here and is left for `verifyChain` to deny (403).
    public static func chainExceedsDepth(_ cap: Entity, resolve: Resolver, maxDepth: Int = 64) -> Bool {
        var current: Entity? = cap
        var depth = 0
        while let c = current {
            if depth > maxDepth { return true }
            guard let parentHash = c.data.bytesAt("parent") else { return false } // root within bound
            current = resolve(parentHash)
            if current == nil { return false }                                     // unreachable — not depth
            depth += 1
        }
        return false
    }

    /// §5.5 verify_capability_chain (single-sig path — the core floor; multi-sig
    /// M3/M4/M6 root-only is in §5.5 but exercised by the multisig category at S4).
    /// `granterFrameFor` maps a cap to its granter's peer_id (§5.5a per-link frame).
    public static func verifyChain(
        _ cap: Entity, included: [HashKey: Entity], localPeerID: String, now: UInt64,
        resolve: Resolver, granterPeerID: (Entity) -> String?
    ) -> Verdict {
        guard let chain = collectChain(cap, resolve: resolve) else { return .authzDeny(code: "capability_denied") }

        // Root check (§5.5): a single-sig root's granter must resolve to a present
        // peer entity AND its peer_id must equal the local peer (sole root authority);
        // a §3.6 M3 multi-sig root (root-only) instead passes K-of-N quorum
        // verification (M3 structure → M6 root-at-local → temporal/grantee → M4).
        guard let root = chain.last else { return .authzDeny(code: "capability_denied") }
        if let mg = multiGranter(of: root) {
            guard verifyMultiSigRoot(root, granter: mg, included: included,
                                     localPeerID: localPeerID, now: now, resolve: resolve,
                                     signerPeerID: peerIDOf) else {
                return .authzDeny(code: "capability_denied")
            }
        } else {
            guard let rootGranter = root.data.bytesAt("granter"), resolve(rootGranter) != nil,
                  granterPeerID(root) == localPeerID else {
                return .authzDeny(code: "capability_denied")
            }
        }

        for i in 0..<chain.count {
            let current = chain[i]
            // §3.6 M3 multi-sig is ROOT-ONLY and is fully verified above (structure,
            // quorum signatures, temporal, grantee). A multi-sig token at the root is
            // skipped here; one anywhere but the chain root is rejected.
            if isMultiSig(current) {
                if i == chain.count - 1 { continue }
                return .authzDeny(code: "capability_denied")
            }
            // Signature (single-sig): find by target, verify signer == granter.
            guard let granterHash = current.data.bytesAt("granter"),
                  let sig = Wire.findSignature(target: current.contentHash ?? [], in: included),
                  let granter = resolve(granterHash) else { return .authzDeny(code: "capability_denied") }
            guard let sigSigner = sig.data.bytesAt("signer"), sigSigner.elementsEqual(granterHash) else {
                return .authzDeny(code: "capability_denied")
            }
            guard verifySignature(sig, by: granter) else { return .authzDeny(code: "capability_denied") }

            // Grantee resolution (PR-3): per-link, MUST resolve to a present peer.
            guard let granteeHash = current.data.bytesAt("grantee"), resolve(granteeHash) != nil else {
                return .unresolvableGrantee
            }

            // Temporal validity.
            if let nb = current.data.uintAt("not_before"), now < nb { return .authzDeny(code: "capability_denied") }
            if let ea = current.data.uintAt("expires_at"), ea < now { return .authzDeny(code: "capability_denied") }

            // Delegation (not for root).
            if i < chain.count - 1 {
                let parent = chain[i + 1]
                guard let parentGrantee = parent.data.bytesAt("grantee"),
                      parentGrantee.elementsEqual(granterHash) else { return .authzDeny(code: "capability_denied") }
                if !isAttenuated(child: current, parent: parent,
                                 childFrame: granterPeerID(current) ?? localPeerID,
                                 parentFrame: granterPeerID(parent) ?? localPeerID) {
                    return .authzDeny(code: "capability_denied")
                }
                if !checkDelegationCaveats(parent: parent, child: current, depth: i) {
                    return .authzDeny(code: "capability_denied")
                }
            }
        }
        return .allow
    }

    // MARK: §5.6 attenuation (per-side granter frame, §5.5a Amendment 1)

    public static func isAttenuated(child: Entity, parent: Entity, childFrame: String, parentFrame: String) -> Bool {
        let childGrants = grants(of: child), parentGrants = grants(of: parent)
        for cg in childGrants {
            if !grantCoveredBy(cg, parentGrants, childFrame: childFrame, parentFrame: parentFrame) { return false }
        }
        // Expiration nil-vs-finite (§5.6 normative): finite parent + null child = escalation.
        if let pe = parent.data.uintAt("expires_at") {
            guard let ce = child.data.uintAt("expires_at") else { return false }
            if ce > pe { return false }
        }
        return true
    }

    static func grantCoveredBy(_ child: GrantEntry, _ parents: [GrantEntry], childFrame: String, parentFrame: String) -> Bool {
        for p in parents where grantSubset(child, p, childFrame: childFrame, parentFrame: parentFrame) { return true }
        return false
    }

    static func grantSubset(_ child: GrantEntry, _ parent: GrantEntry, childFrame: String, parentFrame: String) -> Bool {
        if !scopeSubset(child.handlers, parent.handlers, childFrame: childFrame, parentFrame: parentFrame) { return false }
        if !scopeSubset(child.operations, parent.operations, childFrame: childFrame, parentFrame: parentFrame) { return false }
        if !scopeSubset(child.resources, parent.resources, childFrame: childFrame, parentFrame: parentFrame) { return false }
        let cp = child.peers ?? Scope(include: [childFrame])
        let pp = parent.peers ?? Scope(include: [parentFrame])
        if !scopeSubset(cp, pp, childFrame: childFrame, parentFrame: parentFrame) { return false }
        // Constraint key retention + byte equality.
        for (k, v) in parent.constraints {
            guard let cv = child.constraints.first(where: { cborEqual($0.key, k) })?.value, cborEqual(cv, v) else { return false }
        }
        // Allowance key containment + byte equality.
        for (k, v) in child.allowances {
            guard let pv = parent.allowances.first(where: { cborEqual($0.key, k) })?.value, cborEqual(pv, v) else { return false }
        }
        return true
    }

    /// §5.6 scope_subset: each child include covered by some parent include (each
    /// side canonicalized against ITS OWN granter frame, §5.5a); child inherits all
    /// parent excludes.
    static func scopeSubset(_ child: Scope, _ parent: Scope, childFrame: String, parentFrame: String) -> Bool {
        for cp in child.include {
            let cc = canonicalize(cp, frame: childFrame)
            if !parent.include.contains(where: { matchesPattern(cc, canonicalize($0, frame: parentFrame)) }) { return false }
        }
        for pe in parent.exclude {
            let cpe = canonicalize(pe, frame: parentFrame)
            let inherited = child.exclude.contains { matchesPattern(cpe, canonicalize($0, frame: childFrame)) }
            if !inherited { return false }
        }
        return true
    }

    // MARK: §5.7 delegation caveats

    static func checkDelegationCaveats(parent: Entity, child: Entity, depth: Int) -> Bool {
        guard let caveats = parent.data.mapValue("delegation_caveats") else { return true }
        if case .some(true) = caveats.mapValue("no_delegation").flatMap(boolValue) { return false }
        if let maxDepth = caveats.uintAt("max_delegation_depth"), UInt64(depth) >= maxDepth { return false }
        if let maxTTL = caveats.uintAt("max_delegation_ttl") {
            guard let ea = child.data.uintAt("expires_at"), let ca = child.data.uintAt("created_at") else { return false }
            if ea - ca > maxTTL { return false }
        }
        return true
    }

    // MARK: signature verification

    /// Derive a resolved `system/peer` entity's peer_id from its `public_key`
    /// (§1.5 identity-multihash for Ed25519). Returns nil when the entity has no
    /// usable key → the caller denies (never a silent fallback).
    public static func peerIDOf(_ peer: Entity) -> String? {
        guard let pk = peer.data.bytesAt("public_key") else { return nil }
        return try? PeerID.fromEd25519(publicKey: pk).format()
    }

    /// Verify a `system/signature` entity against the signer's `system/peer` entity.
    public static func verifySignature(_ sig: Entity, by peer: Entity) -> Bool {
        guard let target = sig.data.bytesAt("target"),
              let signature = sig.data.bytesAt("signature"),
              let pubkey = peer.data.bytesAt("public_key") else { return false }
        return Signing.verify(publicKey: pubkey, message: target, signature: signature)
    }

    // MARK: helpers

    static func boolValue(_ v: CBORValue) -> Bool? { if case let .bool(b) = v { return b } else { return nil } }

    /// Byte-equality of two CBOR values via canonical re-encode (§5.6 bytes_equal).
    static func cborEqual(_ a: CBORValue, _ b: CBORValue) -> Bool {
        guard let ea = try? CBOR.encode(a), let eb = try? CBOR.encode(b) else { return a == b }
        return ea.elementsEqual(eb)
    }
}
