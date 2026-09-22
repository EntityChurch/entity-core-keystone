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

    // ── §5.6 temporal ceiling (CAP-5 / CAP-6) ───────────────────────────────

    /// Convert a DURATION term to an absolute timestamp; `nil` when the term
    /// contributes no ceiling.
    ///
    /// §5.6 rule 3: an overflowing conversion is treated as ABSENT exactly as a
    /// null term is -- never wrapped, never saturated (saturating manufactures
    /// `expires_at == 2^64-1`, a finite bound indistinguishable from a deliberate
    /// one). `addingReportingOverflow` makes the drop explicit; a bare `+` traps.
    ///
    /// `ttl == 0` is deliberately NOT special-cased: §5.6 rule 2 makes it DEFINED
    /// and equal to `created_at` (expire immediately), and letting it fall out of
    /// the arithmetic is what keeps it from collapsing into the "no bound" spelling.
    public static func addTTL(_ createdAt: UInt64, _ ttl: UInt64?) -> UInt64? {
        guard let ttl else { return nil }
        let (sum, overflow) = createdAt.addingReportingOverflow(ttl)
        return overflow ? nil : sum
    }

    /// §5.6 MIN_DEFINED: minimum over the DEFINED terms only; `nil` when none is
    /// defined. Absolute terms enter directly; durations go through `addTTL` first.
    public static func minDefined(_ terms: [UInt64?]) -> UInt64? {
        terms.compactMap { $0 }.min()
    }

    // ── §6.2 CAP-6a: unrepresentable temporal fields on INGEST ──────────────

    /// True when every CAP-6a temporal field on a RECEIVED token is ABSENT (legal)
    /// or a representable uint.
    ///
    /// `uintAt` returns nil for BOTH an absent field and a present non-uint one, so
    /// a token carrying `expires_at: -1` slips past the range checks and is honored.
    /// §6.2 CAP-6a: such a token "is malformed. A verifier MUST refuse it and MUST
    /// NOT treat the unrepresentable field as absent."
    public static func temporalFieldsRepresentable(_ tok: Entity) -> Bool {
        for key in ["expires_at", "not_before", "created_at"] {
            guard let v = tok.data.mapValue(key) else { continue }
            if case .uint = v { continue }
            return false
        }
        return true
    }



    // MARK: §1.4 / §5.4 pattern matching

    /// §5.4 canonicalize: resolve peer-relative paths to absolute. Reject
    /// directory-relative and bare peer-wildcard forms. NOTE the granter frame:
    /// cap resource patterns canonicalize against the *granter's* peer_id (§5.5a),
    /// request paths against local (§5.4); the caller supplies the right frame.
    /// The unmatchable value (0.8.2.20). Unreachable as a canonical path by
    /// CONSTRUCTION: its first segment cannot be a peer_id, since a peer_id needs
    /// >= 46 Base58 characters and `-` is outside the Base58 alphabet.
    public static let neverMatch = "/never-match"

    public static func canonicalize(_ path: String, frame peerID: String) -> String {
        let path = normalizeURI(path)                                    // strip entity:// scheme (§1.4)
        // TOTAL (0.8.2.20): the return domain is "a canonical path OR neverMatch".
        // These two arms used to PASS THE INPUT THROUGH under a comment saying it was
        // rejected upstream. A pass-through matched nothing, which is the desired
        // outcome in an INCLUDE and the opposite of it in an EXCLUDE: a grant exclude
        // carrying "../x" carved out nothing and the grant was silently wider than its
        // author wrote (measured on the wire 2026-09-14).
        if path.hasPrefix("./") || path.hasPrefix("../") { return neverMatch }
        if path.hasPrefix("*/") { return neverMatch }                    // use /*/rest
        if path.hasPrefix("/") { return path }                           // already absolute
        return "/" + peerID + "/" + path                                 // peer-relative incl. bare "*"
    }

    /// AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
    /// fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
    /// fail-OPEN in an exclude (carves out nothing), so the reading is chosen where the
    /// POSITION is known and `matchesPattern` stays uniform over its operands.
    ///
    /// EVERY CALL SITE MUST GUARD IT ON PATH-SCOPE (0.8.2.24, N2/N3). This used to be
    /// asked of every dimension, transcribing §5.2's loop before that loop grew its type
    /// dispatch. `neverMatch` is a §5.4 PATH-canonicalization sentinel and has no meaning
    /// on an id-scope dimension, whose patterns are literal identifiers that §5.2's own
    /// id-scope arm forbids putting through the §5.4 transforms. Asking it outside the
    /// type dispatch ran an id pattern through those transforms purely to classify it and
    /// then DENIED THE WHOLE DIMENSION on a property unrelated to whether the exclude
    /// carves anything out: an `operations` exclude of `*/apply` — an ordinary namespaced
    /// operation name, a literal matching nothing under the id-scope grammar —
    /// canonicalized to the sentinel and denied every operation. Over-denial, and
    /// invisible on any well-formed grant.
    static func excludeIsUnmatchable(_ excl: [String], frame: String) -> Bool {
        for p in excl where canonicalize(p, frame: frame) == neverMatch { return true }
        return false
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
        // neverMatch never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
        // rule rather than a property of the string: the line below returns true for a
        // bare "*", so safety must not rest on a value merely looking unmatchable.
        if path == neverMatch || pattern == neverMatch { return false }
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

    // MARK: §5.2 matches_scope (typed by scope kind — 0.8.1, F40)

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

    /// Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at
    /// every call site — no default — so a new one cannot inherit the wrong matcher
    /// silently, which is exactly the F40 defect.
    public enum ScopeKind: Sendable {
        /// `operations`, `peers` — `system/capability/id-scope`.
        case id
        /// `handlers`, `resources` — `system/capability/path-scope`.
        case path
    }

    /// §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard
    /// forms — bare `*` and a trailing slash-star segment-prefix. None of the §5.4 path
    /// transforms apply, so a pattern carrying path syntax is matched as a literal
    /// string: a non-match, never a fault.
    public static func matchesIDPattern(_ value: String, _ pattern: String) -> Bool {
        if pattern == "*" { return true }
        if pattern.count >= 2, pattern.hasSuffix("/*") {
            return value.hasPrefix(String(pattern.dropLast()))
        }
        return value == pattern
    }

    /// §5.2 matches_scope: value is included and not excluded. `kind` selects the
    /// matcher by scope type — `.path` canonicalizes both sides against `frame`, `.id`
    /// compares literally. The two MUST NOT be interchanged.
    public static func matchesScope(_ value: String, _ scope: Scope, frame: String, kind: ScopeKind) -> Bool {
        // SCOPED TO PATH-SCOPE (0.8.2.24). §5.2's exclude loop tests the sentinel INSIDE
        // `if dimension_type == "system/capability/path-scope"`, and §5.4's rule is
        // likewise "a capability carrying an unmatchable PATH-SCOPE pattern is INVALID
        // ... It does NOT reach `operations` or `peers` [MUST]". The two id-scope
        // dimensions reach the literal arm below unguarded, which is correct: under the
        // id-scope grammar every non-`*` pattern is a literal and a literal is never
        // structurally unmatchable, so there is nothing here for the sentinel to detect.
        // (§5.4 says so outright and leaves the id-scope form of the carves-out-nothing
        // hazard deliberately open rather than minting a second sentinel for it — so this
        // is a scope boundary, not an omission.)
        if kind == .path && excludeIsUnmatchable(scope.exclude, frame: frame) { return false }  // 0.8.2.21
        if kind == .id {
            var matchedID = false
            for p in scope.include where matchesIDPattern(value, p) { matchedID = true; break }
            guard matchedID else { return false }
            for p in scope.exclude where matchesIDPattern(value, p) { return false }
            return true
        }
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
            if !matchesScope(operation, g.operations, frame: localPeerID, kind: .id) { continue }
            if !matchesScope(handlerPattern, g.handlers, frame: localPeerID, kind: .path) { continue }
            let peersScope = g.peers ?? Scope(include: [localPeerID])
            if !matchesScope(targetPeer, peersScope, frame: localPeerID, kind: .id) { continue }
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
        // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before
        // any target: the coverage tests below are correct in isolation and are simply
        // never reached on a sentinel, because matchesPattern answers false.
        //
        // UNGUARDED ON PURPOSE, unlike `matchesScope`'s (0.8.2.24): `grantResources` is
        // always the RESOURCES dimension, which §5.2 fixes as path-scope, so the type
        // test this call site would perform is a constant. Naming the dimension in the
        // signature is what makes that checkable — a frame argument on an id-scope call
        // site is the defect. Do NOT "fix" this by copying the `kind == .path` guard
        // across.
        if excludeIsUnmatchable(grantResources.exclude, frame: granterFrame) { return false }
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

    // MARK: §5.2 effective targets and §6.3 check_path_permission

    /// §5.2's effective target list (0.8.2.20): the caller's OWN `resource.exclude`
    /// removes entries from the request BEFORE anything else looks at it.
    ///
    /// The survivors come back in the caller's OWN SPELLING, not canonicalized —
    /// 0.8.2.21 is explicit that `effective_targets` yields raw survivors, and the
    /// distinction is load-bearing here because the value flows on to `store.getAt`,
    /// which canonicalizes for itself.
    ///
    /// `nil` means the EXECUTE carries NO `resource` at all, which is a different input
    /// from "a resource whose every target was excluded" — and for a resource-OPTIONAL
    /// operation 0.8.2.24 (N7) makes them DIFFERENT REQUESTS with different answers, not
    /// merely different inputs to one disposition.
    ///
    /// `nil`-vs-`[]` IS THE NON-LOSSY PROJECTION §3.3 REQUIRES `[MUST]` (0.8.2.25, N11):
    /// *"where an implementation projects `resource.targets` onto the effective set ahead
    /// of the handler, that projection MUST NOT be lossy about its own emptiness — narrow
    /// when narrowing leaves something, and retain the raw pair when narrowing would
    /// empty it."*  A function returning only a list cannot satisfy that: collapsing
    /// `[qA] exclude [qA]` to `[]` deletes the two-empties discriminator before any
    /// handler can read it, and the handler's refusal arm becomes dead code that only a
    /// WIRE drive can detect. Swift carries the discriminator as the `?`, which is the
    /// same property spelled the way this substrate spells "absent".
    ///
    /// This peer has exactly ONE narrowing seam — this function, called by the tree
    /// handler — and §6.5's dispatch chain does not project: `dispatchInner` passes the
    /// EXECUTE through untouched and `checkPermission` reads `resource` for itself. So
    /// there is no second door to keep in step, and adding a projection at dispatch would
    /// create one.
    ///
    /// PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT** and only the KEY's absence is
    /// absent — the cell the two vanguards disagreed on until 0.8.2.25, corrected toward
    /// `go`. Reading `{"targets": 42}` as absent serves a PRESENT resource the wider
    /// absent-case answer §3.3 forbids: N11's own defect one field over.
    ///
    /// OPEN, AND ALL THREE PEERS ANSWER IT THE SAME WAY WITH NO TEXT BEHIND THEM: a
    /// `resource` map carrying no `targets` KEY at all is reported absent, so `get` serves
    /// it the root listing. §3.2 says *"`targets` — Array of paths or patterns this
    /// operation accesses. MUST contain at least one entry"*, which makes that shape a
    /// MALFORMED resource rather than an absent one. Left as shipped rather than decided
    /// in a sweep (the F86 precedent): the disposition a malformed `resource` earns is not
    /// pinned anywhere and nothing in the 778-check set drives the shape.
    public static func effectiveTargets(_ execute: Entity, localPeerID: String) -> [String]? {
        guard let r = execute.data.mapValue("resource"), case .map = r else { return nil }
        guard let targetsValue = r.mapValue("targets") else { return nil }
        let targets = (targetsValue.arrayValue ?? []).compactMap { $0.textValue }
        let callerExclude = (r.arrayAt("exclude") ?? []).compactMap { $0.textValue }
        return targets.filter { t in
            let ct = canonicalize(t, frame: localPeerID)
            // The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4's table
            // rules it separately from the grant arm): `canonicalize` answers `neverMatch`
            // and `matchesPattern` then answers false, so the target simply survives. That
            // asymmetry is 0.8.2.21's whole point and it is INHERITED here, not restated.
            return !callerExclude.contains { matchesPattern(ct, canonicalize($0, frame: localPeerID)) }
        }
    }

    /// §6.3's handler-level path check.
    ///
    /// IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the enforcement wherever the
    /// subject is derived after dispatch, and the dispatch-level check can be made
    /// VACUOUS by caller-controlled input: a caller who excludes the one target its
    /// capability does not cover removes that target from `checkPermission`'s view
    /// entirely, and a handler that then acts on it has authorized nothing.
    ///
    /// THREE DIMENSIONS, NOT FOUR. `peers` is not consulted here — the path is local by
    /// construction at this point (§1.4's inbound rule refuses a foreign namespace at
    /// §6.5 step 3, before any handler runs), and §6.3's signature names only handlers,
    /// operations and resources.
    ///
    /// THE FRAME IS `localPeerID`, NOT THE GRANTER, AND THAT IS THE SPEC'S OWN SIGNATURE
    /// RATHER THAN A CHOICE. §6.3's block reads
    /// `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)` —
    /// there is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the
    /// subject is a pattern being compared against a parent's pattern; this call site
    /// compares a CONCRETE LOCAL PATH the handler is about to touch. The first `go` cut
    /// threaded the per-link granter frame in by analogy with §5.5a and was wrong.
    ///
    /// There is no caller-exclude set here: the subject is a single concrete path, and the
    /// caller's exclusions have already been applied in deriving it. Every grant exclude
    /// covering the subject therefore denies — which `matchesScope` already implements,
    /// including 0.8.2.21's sentinel rule, so this is three calls to it and nothing else.
    ///
    /// An empty `resources.include` is a legal grant shape (§5.2: handlers that touch no
    /// tree paths) and DENIES every path here, which is what that note says it should. And
    /// a malformed path canonicalizes to `neverMatch`, which matches no grant (§5.4), so
    /// it falls through to DENY rather than being matched against anything.
    public static func checkPathPermission(
        operation: String, path: String, handlerPattern: String,
        grants: [GrantEntry], localPeerID: String
    ) -> Bool {
        let canonicalPath = canonicalize(path, frame: localPeerID)
        for g in grants {
            if !matchesScope(handlerPattern, g.handlers, frame: localPeerID, kind: .path) { continue }
            if !matchesScope(operation, g.operations, frame: localPeerID, kind: .id) { continue }
            if !matchesScope(canonicalPath, g.resources, frame: localPeerID, kind: .path) { continue }
            return true
        }
        return false
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
        if !temporalFieldsRepresentable(cap) { return false }   // CAP-6a
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

            // Temporal validity. CAP-6a FIRST — the range checks use `uintAt`,
            // which cannot tell "absent" from "present but not a uint"; that
            // ambiguity is exactly the fail-open.
            if !temporalFieldsRepresentable(current) { return .authzDeny(code: "capability_denied") }
            if let nb = current.data.uintAt("not_before"), now < nb { return .authzDeny(code: "capability_denied") }
            if let ea = current.data.uintAt("expires_at"), ea < now { return .authzDeny(code: "capability_denied") }

            // Delegation (not for root).
            if i < chain.count - 1 {
                let parent = chain[i + 1]
                guard let parentGrantee = parent.data.bytesAt("grantee"),
                      parentGrantee.elementsEqual(granterHash) else { return .authzDeny(code: "capability_denied") }
                if !isAttenuated(child: current, parent: parent,
                                 childFrame: granterPeerID(current) ?? localPeerID,
                                 parentFrame: granterPeerID(parent) ?? localPeerID,
                                 localPeerID: localPeerID) {
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

    public static func isAttenuated(child: Entity, parent: Entity, childFrame: String, parentFrame: String, localPeerID: String) -> Bool {
        let childGrants = grants(of: child), parentGrants = grants(of: parent)
        for cg in childGrants {
            if !grantCoveredBy(cg, parentGrants, childFrame: childFrame, parentFrame: parentFrame, localPeerID: localPeerID) { return false }
        }
        // Expiration nil-vs-finite (§5.6 normative): finite parent + null child = escalation.
        if let pe = parent.data.uintAt("expires_at") {
            guard let ce = child.data.uintAt("expires_at") else { return false }
            if ce > pe { return false }
        }
        return true
    }

    static func grantCoveredBy(_ child: GrantEntry, _ parents: [GrantEntry], childFrame: String, parentFrame: String, localPeerID: String) -> Bool {
        for p in parents where grantSubset(child, p, childFrame: childFrame, parentFrame: parentFrame, localPeerID: localPeerID) { return true }
        return false
    }

    /// §5.6 grant subset.
    ///
    /// §5.5a Amendment 1's per-link granter frames (`childFrame` / `parentFrame`)
    /// scope the **resource dimension ONLY**. handlers, operations and peers are
    /// compared in the LOCAL frame on both sides.
    ///
    /// Getting that wrong is invisible until the frames differ. This used to pass
    /// the granter frames to all four dimensions and default `peers` to them, which
    /// is identical behaviour whenever child and parent share a granter — every
    /// self-issued path — and wrong for exactly one case: a DELEGATED child cap,
    /// whose granter is the caller rather than this peer. There, a parent handler
    /// scope of `["*"]` canonicalized to `/<thisPeer>/*` while the child's
    /// `["system/capability"]` canonicalized to `/<callerPeer>/system/capability`,
    /// so a universal parent grant could not cover ANY child grant and every
    /// request presenting a delegated cap came back 403. It surfaced as three
    /// unrelated-looking capability failures (CAP-5, CAP-6, and CAP-6a's control
    /// losing its teeth), none of which is where the defect was.
    static func grantSubset(_ child: GrantEntry, _ parent: GrantEntry, childFrame: String, parentFrame: String, localPeerID: String) -> Bool {
        // `kind` follows §5.2's dimension table, not the frame: handlers/resources are
        // path-scope, operations/peers id-scope (F50, 0.8.2.16).
        if !scopeSubset(child.handlers, parent.handlers, childFrame: localPeerID, parentFrame: localPeerID, kind: .path) { return false }
        if !scopeSubset(child.operations, parent.operations, childFrame: localPeerID, parentFrame: localPeerID, kind: .id) { return false }
        if !scopeSubset(child.resources, parent.resources, childFrame: childFrame, parentFrame: parentFrame, kind: .path) { return false }
        let cp = child.peers ?? Scope(include: [localPeerID])
        let pp = parent.peers ?? Scope(include: [localPeerID])
        if !scopeSubset(cp, pp, childFrame: localPeerID, parentFrame: localPeerID, kind: .id) { return false }
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

    /// §5.6 scope_subset: each child include covered by some parent include; child
    /// inherits all parent excludes.
    ///
    /// TYPED BY SCOPE KIND, EXACTLY AS ITS SIBLING `matchesScope` IS (F50, ruled
    /// 0.8.2.16). §3.6's grammar binds the SCOPE TYPE, not one function: *"an
    /// implementation on the canonicalizing reading is non-conformant and MUST adopt the
    /// literal matcher."* F40 fixed `matchesScope` and left this one behind, and the two
    /// readings AGREE on every well-formed grant — which is why no hand-tried example
    /// found it. `entity-core-formalization` measured the disagreement on `lean`: 2 of 64
    /// include pairs and 2 of 64 exclude pairs, fail-CLOSED (`/tree/get` vs `*`,
    /// `*/apply` vs `*`), against 0 over a 16-pair control alphabet. Fail-closed here
    /// means an over-narrow delegation refusal rather than an over-grant — but the
    /// direction is not the point, the matcher is.
    ///
    /// `kind` is passed at EVERY call site with no default, because a default is how the
    /// next dimension inherits the wrong matcher silently, which is the original F40
    /// defect.
    ///
    /// On the PATH arm each side canonicalizes against ITS OWN granter frame (§5.5a). The
    /// ID arm takes no frame at all: an id pattern is a literal, and there is nothing to
    /// canonicalize it against.
    static func scopeSubset(_ child: Scope, _ parent: Scope, childFrame: String, parentFrame: String, kind: ScopeKind) -> Bool {
        if kind == .id {
            for cp in child.include {
                if !parent.include.contains(where: { matchesIDPattern(cp, $0) }) { return false }
            }
            for pe in parent.exclude {
                if !child.exclude.contains(where: { matchesIDPattern(pe, $0) }) { return false }
            }
            return true
        }
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
