// ScopeAlgebraTests.swift — the 0.8.2.20/.21/.24/.25 surface: §5.2 effective
// targets, §6.3 `check_path_permission`, §5.4's path-scope-only sentinel, F50's
// typing of `scope_subset`, and §4.11/§5.2a's code-belongs-to-the-cause split.
//
// The oracle carries no vector on most of this — the 778-check set is indifferent
// to every function below — so the accept direction is the peer's own to cover.
// Each mutation control that must redden a named case here lives in
// output/scratch/plant-swift.sh and is EXECUTED, not described.

import XCTest
@testable import EntityCoreProtocol

final class ScopeAlgebraTests: XCTestCase {

    // A syntactically valid peer_id (>= 46 Base58 chars) so `canonicalize` and
    // `isPeerID` behave as they do on the wire.
    let local = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA"

    func scope(_ include: [String], exclude: [String] = []) -> Capability.Scope {
        Capability.Scope(include: include, exclude: exclude)
    }

    func grant(handlers: [String], operations: [String],
               resources: [String], resourcesExclude: [String] = []) -> CBORValue {
        func sc(_ incl: [String], _ excl: [String]) -> CBORValue {
            var f: [(String, CBORValue)] = [("include", .array(incl.map { .text($0) }))]
            if !excl.isEmpty { f.append(("exclude", .array(excl.map { .text($0) }))) }
            return .textMap(f)
        }
        return .textMap([
            ("handlers", sc(handlers, [])),
            ("operations", sc(operations, [])),
            ("resources", sc(resources, resourcesExclude)),
        ])
    }

    func token(_ grants: [CBORValue]) -> Entity {
        Entity(type: "system/capability/token", data: .textMap([("grants", .array(grants))]))
    }

    func execute(targets: [String]? = nil, exclude: [String]? = nil,
                 targetsRaw: CBORValue? = nil, resourceOmitsTargets: Bool = false) -> Entity {
        var fields: [(String, CBORValue)] = [("operation", .text("get"))]
        if resourceOmitsTargets {
            fields.append(("resource", .textMap([("exclude", .array([]))])))
        } else if let targetsRaw {
            fields.append(("resource", .textMap([("targets", targetsRaw)])))
        } else if let targets {
            var r: [(String, CBORValue)] = [("targets", .array(targets.map { .text($0) }))]
            if let exclude { r.append(("exclude", .array(exclude.map { .text($0) }))) }
            fields.append(("resource", .textMap(r)))
        }
        return Entity(type: "system/protocol/execute", data: .textMap(fields))
    }

    // MARK: §5.2 effective targets (0.8.2.20/.21, N11)

    /// The caller's own exclude removes entries BEFORE anything else looks at the
    /// request, and survivors keep the caller's RAW spelling (0.8.2.21) rather than a
    /// canonical form.
    func testCallerExcludeRemovesItsOwnTarget() {
        XCTAssertEqual(Capability.effectiveTargets(execute(targets: ["qA", "qB"], exclude: ["qB"]),
                                                   localPeerID: local) ?? [], ["qA"])
    }

    func testSurvivorsAreRawNotCanonicalized() {
        XCTAssertEqual(Capability.effectiveTargets(execute(targets: ["qA"]), localPeerID: local) ?? [], ["qA"])
    }

    /// N11's NON-LOSSY PROJECTION `[MUST]`: the two empties are DIFFERENT REQUESTS and a
    /// function returning only a list cannot tell them apart. A resource-OPTIONAL
    /// operation answers them differently (N7/N10 + EXTENSION-TREE §2.2a: absent → root
    /// listing, self-excluded → 400 path_required), so collapsing them here would delete
    /// the discriminator before any handler could read it.
    func testAbsentResourceIsNil() {
        XCTAssertNil(Capability.effectiveTargets(execute(), localPeerID: local))
    }

    func testSelfExcludedResourceIsEmptyButPresent() {
        let eff = Capability.effectiveTargets(execute(targets: ["qA"], exclude: ["qA"]), localPeerID: local)
        XCTAssertNotNil(eff, "a PRESENT resource whose every target was excluded must not read as absent")
        XCTAssertEqual(eff ?? ["unset"], [])
    }

    /// PRESENT-BUT-ILL-TYPED `targets` IS PRESENT — the cell the two vanguards disagreed
    /// on until 0.8.2.25, corrected toward `go`. Reading it as ABSENT would serve a
    /// present resource the wider absent-case answer §3.3 forbids (on `get`, the root
    /// listing instead of 400 path_required). The KEY's presence is the discriminator,
    /// not the value's type.
    func testIllTypedTargetsIsPresentWithAnEmptyEffectiveList() {
        let eff = Capability.effectiveTargets(execute(targetsRaw: .text("qA")), localPeerID: local)
        XCTAssertNotNil(eff, "an ill-typed `targets` is PRESENT, not absent")
        XCTAssertEqual(eff ?? ["unset"], [])
    }

    func testResourceWithNoTargetsKeyIsAbsent() {
        XCTAssertNil(Capability.effectiveTargets(execute(resourceOmitsTargets: true), localPeerID: local))
    }

    /// §5.4's caller-exclude arm is fail-OPEN on an unmatchable pattern (the GRANT arm is
    /// fail-CLOSED): `canonicalize` answers the sentinel, `matchesPattern` then answers
    /// false, and the target simply SURVIVES.
    func testUnmatchableCallerExcludeCarvesOutNothing() {
        XCTAssertEqual(Capability.effectiveTargets(execute(targets: ["qA"], exclude: ["../nope"]),
                                                   localPeerID: local) ?? [], ["qA"])
    }

    // MARK: §6.3 check_path_permission

    func cpp(_ tok: Entity, _ path: String, op: String = "get", pattern: String = "system/tree") -> Bool {
        Capability.checkPathPermission(operation: op, path: path, handlerPattern: pattern,
                                       grants: Capability.grants(of: tok), localPeerID: local)
    }

    var okToken: Entity {
        token([grant(handlers: ["system/tree"], operations: ["get"], resources: ["q/*"])])
    }

    /// THE ACCEPT CASE IS WHAT VALIDATES THE FIXTURE. A predicate test built only from
    /// deny cases is indistinguishable from one asserting `false == false`, and a broken
    /// fixture makes every deny pass for free.
    func testAcceptValidatesTheFixture() {
        XCTAssertTrue(cpp(okToken, "q/a"))
    }

    /// One deny per DIMENSION: a single deny cannot separate "it checks the dimension I
    /// care about" from "it denies".
    func testDenyOnResourcesDimension() { XCTAssertFalse(cpp(okToken, "other/a")) }
    func testDenyOnOperationsDimension() { XCTAssertFalse(cpp(okToken, "q/a", op: "put")) }
    func testDenyOnHandlersDimension() { XCTAssertFalse(cpp(okToken, "q/a", pattern: "system/other")) }

    /// §5.2's note: an empty `resources.include` is a legal grant shape (a handler that
    /// touches no tree paths) and DENIES every path here.
    func testEmptyResourcesIncludeDeniesEveryPath() {
        XCTAssertFalse(cpp(token([grant(handlers: ["system/tree"], operations: ["get"], resources: [])]), "q/a"))
    }

    /// A malformed path canonicalizes to the sentinel, which matches no grant (§5.4), so
    /// it falls through to DENY rather than being matched at all.
    func testMalformedPathDenies() { XCTAssertFalse(cpp(okToken, "../nope")) }

    /// A grant exclude covering the subject denies: the caller's exclusions were already
    /// applied in deriving this concrete path, so nothing carves it back.
    func testGrantExcludeCoveringThePathDenies() {
        XCTAssertFalse(cpp(token([grant(handlers: ["system/tree"], operations: ["get"],
                                        resources: ["q/*"], resourcesExclude: ["q/a"])]), "q/a"))
    }

    // MARK: §5.4's sentinel is PATH-SCOPE only (0.8.2.24, N2/N3)

    /// The discriminating pair, and the id case cannot be passed by accident: `*/apply`
    /// is an ordinary namespaced operation name that PATH-canonicalizes to the sentinel,
    /// so on the pre-.24 unscoped reading it denied the WHOLE dimension and `get`
    /// included by a bare `*` came back false.
    func testSentinelDoesNotReachIDScopeOperations() {
        XCTAssertTrue(Capability.matchesScope("get", scope(["*"], exclude: ["*/apply"]),
                                              frame: local, kind: .id))
    }

    func testSentinelDoesNotReachIDScopePeers() {
        XCTAssertTrue(Capability.matchesScope(local, scope(["*"], exclude: ["../nope"]),
                                              frame: local, kind: .id))
    }

    /// The other half, and it proves this is a scope SPLIT rather than a removal: on a
    /// path-scope dimension an unmatchable exclude still denies (0.8.2.21), because there
    /// it would otherwise carve out nothing and leave the grant silently wider than its
    /// author wrote.
    func testSentinelStillDeniesOnPathScope() {
        XCTAssertFalse(Capability.matchesScope("system/tree", scope(["*"], exclude: ["../nope"]),
                                               frame: local, kind: .path))
    }

    func testOrdinaryPathScopeExcludeCarvesOutOnlyItsTarget() {
        XCTAssertTrue(Capability.matchesScope("system/tree", scope(["*"], exclude: ["system/secret"]),
                                              frame: local, kind: .path))
    }

    // MARK: F50 — scope_subset is typed by scope kind (ruled 0.8.2.16)

    func ssub(_ child: Capability.Scope, _ parent: Capability.Scope, _ kind: Capability.ScopeKind) -> Bool {
        Capability.scopeSubset(child, parent, childFrame: local, parentFrame: local, kind: kind)
    }

    /// The two pairs `entity-core-formalization` measured as disagreeing on `lean`, both
    /// fail-CLOSED under the canonicalizing reading. On the id matcher a literal child
    /// include is covered by a bare `*` parent.
    func testScopeSubsetIDCoversPathShapedLiteral() {
        XCTAssertTrue(ssub(scope(["/tree/get"]), scope(["*"]), .id))
    }

    func testScopeSubsetIDCoversStarSlashApply() {
        XCTAssertTrue(ssub(scope(["*/apply"]), scope(["*"]), .id))
    }

    /// The id matcher must still REFUSE a genuine widening, or "typed" would just mean
    /// "always true".
    func testScopeSubsetIDRefusesWidening() {
        XCTAssertFalse(ssub(scope(["*"]), scope(["get"]), .id))
    }

    /// And the path arm is UNCHANGED — this is a split, not a replacement.
    func testScopeSubsetPathStillCovers() {
        XCTAssertTrue(ssub(scope(["q/a"]), scope(["*"]), .path))
    }

    func testScopeSubsetPathRefusesUncovered() {
        XCTAssertFalse(ssub(scope(["q/a"]), scope(["r/*"]), .path))
    }

    // MARK: §5.2a / §4.11 — the code belongs to the cause (0.8.2.24 N4/N5, 0.8.2.25)

    /// A mis-keyed `included` entry is a RESOLUTION-INTEGRITY failure, not a CBOR
    /// tag-policy violation — its encoding is canonical, and what is false is the claim
    /// the KEY makes — so it MUST answer 400 `hash_mismatch` and `non_canonical_ecf` is
    /// explicitly non-conformant there.
    func testMisKeyedIncludedThrowsHashMismatch() throws {
        let inner = try Model.make(type: "primitive/any", fields: [("v", .text("x"))])
        let envelope = CBORValue.textMap([
            ("root", try CBOR.decode(Model.make(type: Wire.executeType, data: .map([])).bytes)),
            ("included", .map([(key: .bytes([UInt8](repeating: 0, count: 33)),
                                value: try CBOR.decode(inner.bytes))])),
        ])
        let bytes = try CBOR.encode(envelope)
        XCTAssertThrowsError(try Wire.decodeEnvelope(bytes)) { err in
            // Named rather than left to `XCTAssertThrowsError`'s bare "something threw":
            // the pre-0.8.2.24 spelling was `.malformed`, which would still satisfy an
            // unqualified assertion.
            guard case .hashMismatch = (err as? CodecError) ?? .badSeed else {
                return XCTFail("expected .hashMismatch, got \(err)")
            }
        }
    }

    func testPreAdmissionMisKeyedIsHashMismatch() {
        let r = Wire.preAdmissionRefusal(.hashMismatch("x"))
        XCTAssertEqual(r.status, 400); XCTAssertEqual(r.code, "hash_mismatch")
    }

    func testPreAdmissionTagKeepsNonCanonicalECF() {
        let r = Wire.preAdmissionRefusal(.tagRejected)
        XCTAssertEqual(r.status, 400); XCTAssertEqual(r.code, "non_canonical_ecf")
    }

    func testPreAdmissionStructuralIsInvalidRequest() {
        let r = Wire.preAdmissionRefusal(.malformed("x"))
        XCTAssertEqual(r.status, 400); XCTAssertEqual(r.code, "invalid_request")
    }

    func testPreAdmissionOversizeIs413() {
        let r = Wire.preAdmissionRefusal(.frameTooLarge)
        XCTAssertEqual(r.status, 413); XCTAssertEqual(r.code, "payload_too_large")
    }

    /// §4.11's framing arm is owed a coded frame; an ordinary close is NOT a refusal of
    /// anything and there is nobody left to answer.
    func testFramingRefusalClassification() {
        XCTAssertTrue(Wire.isFramingRefusal(.frameTooLarge))
        XCTAssertTrue(Wire.isFramingRefusal(.truncatedFrame))
        XCTAssertFalse(Wire.isFramingRefusal(.malformed("x")))
    }

    // MARK: the classification has to happen AT THE READ

    /// The three checks above are pure functions of an error VALUE: they stay green while
    /// `readFrame` reports the WRONG one. §4.11's distinction — "a clean close at a frame
    /// BOUNDARY is an ordinary hangup and is owed nothing; a stream that ends mid-frame
    /// is a REFUSAL and is owed a coded frame" — can only be made where the frame
    /// boundary is known, so it is driven here over a real socketpair. A test that never
    /// executes the site it is about is the never-executed-guard class wearing a green
    /// tick.
    func readAfter(_ sent: [UInt8]) -> Socket.FrameRead {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds), 0)
        let a = Socket(fd: fds[0]), b = Socket(fd: fds[1])
        if !sent.isEmpty { _ = sent.withUnsafeBytes { write(fds[1], $0.baseAddress!, sent.count) } }
        shutdown(fds[1], Int32(SHUT_WR))
        let r = a.readFrame()
        a.close(); b.close()
        return r
    }

    func testCleanCloseAtABoundaryIsNotARefusal() {
        guard case .closed = readAfter([]) else { return XCTFail("expected .closed") }
    }

    func testPartialLengthPrefixIsTruncated() {
        guard case .refused(.truncatedFrame) = readAfter([0, 0]) else {
            return XCTFail("expected .refused(.truncatedFrame)")
        }
    }

    func testPrefixDeclaringMoreThanArrivesIsTruncated() {
        guard case .refused(.truncatedFrame) = readAfter([0, 0, 0, 0x64, 0x61, 0x62]) else {
            return XCTFail("expected .refused(.truncatedFrame)")
        }
    }

    /// The body arm is the one an "off == 0" inference gets wrong: the prefix has been
    /// consumed, so ZERO body bytes is still a truncation and not a boundary.
    func testPrefixWithNoBodyAtAllIsStillTruncated() {
        guard case .refused(.truncatedFrame) = readAfter([0, 0, 0, 0x64]) else {
            return XCTFail("expected .refused(.truncatedFrame)")
        }
    }

    func testOverMaxLengthPrefixIsFrameTooLarge() {
        guard case .refused(.frameTooLarge) = readAfter([0xff, 0xff, 0xff, 0xff]) else {
            return XCTFail("expected .refused(.frameTooLarge)")
        }
    }
}
