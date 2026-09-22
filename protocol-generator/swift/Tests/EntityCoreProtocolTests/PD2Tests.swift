// PD2Tests.swift — §1.4 PD-2 outbound sub-dispatch, and THE ONE RULE THE WIRE
// CANNOT MEASURE.
//
// The oracle's `dispatch_outbound_multisig_root_refused` check is GREEN on a peer
// that has never implemented §1.4's multi-signature clause. Measured by planting the
// guard out on both vanguards: the oracle's K-of-2 root is co-signed by the target
// and a third party and NOT by the local peer, so §5.5's M6 (the local peer MUST be a
// validated quorum member) refuses it first, for a reason that has nothing to do with
// §1.4. The discriminating input is a quorum THE LOCAL PEER IS A MEMBER OF, minted at
// the target, and nothing on the wire drives it.
//
// So the green row is not evidence for that rule and this file is. The ANTECEDENT
// test is the load-bearing part: it pins that the very same quorum DOES verify in the
// local frame, so a refusal in the foreign frame is attributable to §1.4 and not to a
// fixture M6 was rejecting anyway. Without it the control is INERT — which is how the
// first `go` version shipped, and only planting caught it.

import XCTest
import Foundation
@testable import EntityCoreProtocol

final class PD2Tests: XCTestCase {

    let local = try! Identity(seed: Array(repeating: 0x01, count: 32))
    let target = try! Identity(seed: Array(repeating: 0x02, count: 32))
    let third = try! Identity(seed: Array(repeating: 0x03, count: 32))

    var localPeer: String { local.peerID }
    var targetPeer: String { target.peerID }

    /// A single-signature token.
    func mkCap(granter: Identity, grantee: Identity, grants: [CBORValue]) -> BuiltEntity {
        try! Model.make(type: "system/capability/token", fields: [
            ("granter", .bytes(granter.identityHash)),
            ("grantee", .bytes(grantee.identityHash)),
            ("grants", .array(grants)),
        ])
    }

    /// A §3.6 K-of-N quorum-rooted token. `grants` is NON-EMPTY on purpose: an empty
    /// list makes `targetMintedPeersRelaxation` answer nil BEFORE it reaches the §1.4
    /// clause, so a "relaxes nothing" assertion would hold for an adjacent reason and
    /// a plant removing the §1.4 refusal would leave it green.
    func mkMultiCap(signers: [Identity], threshold: UInt64, grantee: Identity) -> BuiltEntity {
        try! Model.make(type: "system/capability/token", fields: [
            ("granter", .textMap([
                ("signers", .array(signers.map { .bytes($0.identityHash) })),
                ("threshold", .uint(threshold)),
            ])),
            ("grantee", .bytes(grantee.identityHash)),
            ("grants", .array([.map([])])),
        ])
    }

    func included(peers: [Identity], sigs: [BuiltEntity], caps: [BuiltEntity] = []) -> [HashKey: Entity] {
        var d: [HashKey: Entity] = [:]
        for p in peers { d[HashKey(p.identityHash)] = p.peerEntity.entity }
        for s in sigs { d[HashKey(s.hash)] = s.entity }
        for c in caps { d[HashKey(c.hash)] = c.entity }
        return d
    }

    func granterPeerID(_ inc: [HashKey: Entity]) -> (Entity) -> String? {
        { c in
            guard let gh = c.data.bytesAt("granter") else { return nil }
            return inc[HashKey(gh)].flatMap { Capability.peerIDOf($0) }
        }
    }

    /// The narrow scaffold grant GUIDE-CONFORMANCE §7a.1 requires of
    /// `dispatch-outbound`: it is the NARROWNESS that lets the confused-deputy
    /// discriminator fire at all.
    var narrowGrant: BuiltEntity {
        mkCap(granter: local, grantee: local, grants: Peer.ownGrants(for: "system/validate/dispatch-outbound"))
    }

    var echoResource: Capability.ResourceTarget {
        Capability.ResourceTarget(targets: ["system/handler/system/validate/echo"], exclude: [])
    }

    // MARK: - §1.4: a MULTI-SIGNATURE root never relaxes Dimension 4

    func testQuorumVerifiesLocallyButIsRefusedInTheTargetFrame() throws {
        // The quorum the local peer IS a member of — the input the oracle cannot build.
        let cap = mkMultiCap(signers: [local, target], threshold: 2, grantee: local)
        let s1 = try local.signatureEntity(target: cap.hash)
        let s2 = try target.signatureEntity(target: cap.hash)
        let inc = included(peers: [local, target], sigs: [s1, s2])
        let resolve: Capability.Resolver = { h in inc[HashKey(h)] }

        // ANTECEDENT. If this ever fails the refusal below proves nothing: M6 would be
        // rejecting the fixture and the §1.4 clause would never be reached.
        XCTAssertEqual(
            Capability.verifyChain(cap.entity, included: inc, localPeerID: localPeer, now: 0,
                                   resolve: resolve, granterPeerID: granterPeerID(inc)),
            .allow, "ANTECEDENT: the quorum must verify in the LOCAL frame")

        // THE RULE (E3/F66).
        XCTAssertEqual(
            Capability.verifyChain(cap.entity, included: inc, localPeerID: localPeer, now: 0,
                                   resolve: resolve, granterPeerID: granterPeerID(inc),
                                   rootPeerID: targetPeer),
            .authzDeny(code: "capability_denied"),
            "a multi-signature root is only ever valid LOCALLY")

        XCTAssertNil(
            Capability.targetMintedPeersRelaxation(
                cap.entity, included: inc, localPeerID: localPeer, targetPeerID: targetPeer,
                now: 0, resolve: resolve, granterPeerID: granterPeerID(inc), isRevoked: { _ in false }),
            "and so it relaxes nothing")
    }

    func testSingleSigTargetMintedCredentialDoesRelax() throws {
        // CONTRAST: the granter FORM is the only variable against the test above, which
        // is what says the refusal is about the quorum and not about foreign rooting.
        let cap = mkCap(granter: target, grantee: local, grants: [.map([])])
        let sig = try target.signatureEntity(target: cap.hash)
        let inc = included(peers: [local, target], sigs: [sig])
        let resolve: Capability.Resolver = { h in inc[HashKey(h)] }
        let relax = Capability.targetMintedPeersRelaxation(
            cap.entity, included: inc, localPeerID: localPeer, targetPeerID: targetPeer,
            now: 0, resolve: resolve, granterPeerID: granterPeerID(inc), isRevoked: { _ in false })
        XCTAssertEqual(relax?.include, [targetPeer])
    }

    // MARK: - one gate and one exemption (§6.8 confused-deputy)

    func gate(cred: Entity?, operation: String) throws -> Bool {
        let cap = mkCap(granter: target, grantee: local, grants: [.map([])])
        let sig = try target.signatureEntity(target: cap.hash)
        let inc = included(peers: [local, target], sigs: [sig])
        let resolve: Capability.Resolver = { h in inc[HashKey(h)] }
        return Capability.checkOutboundSubDispatch(
            localPeerID: localPeer, targetPeerID: targetPeer,
            handlerPattern: "system/validate/echo", operation: operation,
            handlerGrant: narrowGrant.entity, resource: echoResource,
            cred: cred ?? nil, included: inc, now: 0, resolve: resolve,
            granterPeerID: granterPeerID(inc), isRevoked: { _ in false })
    }

    func testComposeAllowsWhenTheHandlerGrantCovers() throws {
        let cap = mkCap(granter: target, grantee: local, grants: [.map([])])
        XCTAssertTrue(try gate(cred: cap.entity, operation: "echo"))
    }

    func testBypassRefusesAnOperationTheHandlerGrantDoesNotCover() throws {
        // The ONLY input that separates the two readings: both obvious vectors agree
        // under either one (sources agree -> allow, no source -> refuse).
        let cap = mkCap(granter: target, grantee: local, grants: [.map([])])
        XCTAssertFalse(try gate(cred: cap.entity, operation: "put"),
                       "a credential is not a grant — it may not supply Dimensions 1-3")
    }

    func testAmbientArmRefusesAForeignTarget() throws {
        // §5.2's default for an absent `peers` scope is {include: [local_peer_id]}.
        XCTAssertFalse(try gate(cred: nil, operation: "echo"))
    }

    // MARK: - §1.4's three spellings onto the one form a grant can match

    func testPeerRelativeOf() {
        XCTAssertEqual(Capability.peerRelativeOf("system/validate/echo"), "system/validate/echo")
        XCTAssertEqual(Capability.peerRelativeOf("/" + localPeer + "/system/validate/echo"),
                       "system/validate/echo")
        XCTAssertEqual(Capability.peerRelativeOf("entity://" + localPeer + "/system/validate/echo"),
                       "system/validate/echo")
        // The standing smalltalk/forth defect: an unconditional strip turns
        // system/protocol/connect into protocol/connect and every self-minted grant
        // becomes unusable while the handshake stays green.
        XCTAssertEqual(Capability.peerRelativeOf("/system/protocol/connect"),
                       "system/protocol/connect")
    }

    func testGrantPathToleratesEitherSpelling() {
        XCTAssertEqual(
            Capability.grantPath(localPeerID: localPeer, pattern: "/" + localPeer + "/system/validate/echo"),
            Capability.grantPath(localPeerID: localPeer, pattern: "system/validate/echo"))
    }
}
