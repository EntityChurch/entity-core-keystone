// MultiSigTests.swift — §3.6 K-of-N multi-signature capability roots, ACCEPT path.
//
// The validate-peer `multisig` category is 100% REJECTION tests: each builds a
// MALFORMED quorum and asserts 403. A fail-closed peer passes 10/10 WITHOUT genuine
// k-of-n — so the oracle CANNOT exercise the ALLOW direction. These tests do: a real
// 2-of-3 root (one signer = local peer) with a threshold of valid signatures over the
// cap's content hash MUST be ALLOWed, and each M3/M4/M6 invariant flip MUST deny.
// Mirrors the OCaml selftest accept-path block.

import XCTest
import Foundation
@testable import EntityCoreProtocol

final class MultiSigTests: XCTestCase {

    // Three distinct identities; id1 is the local peer (a quorum member).
    let id1 = try! Identity(seed: Array(repeating: 0x01, count: 32))
    let id2 = try! Identity(seed: Array(repeating: 0x02, count: 32))
    let id3 = try! Identity(seed: Array(repeating: 0x03, count: 32))

    var local: String { id1.peerID }

    /// Build a multi-sig `system/capability/token` with the given signers/threshold.
    func mkMultiSigCap(signers: [Identity], threshold: UInt64, parent: [UInt8]? = nil) -> BuiltEntity {
        let granter = CBORValue.textMap([
            ("signers", .array(signers.map { .bytes($0.identityHash) })),
            ("threshold", .uint(threshold)),
        ])
        var fields: [(String, CBORValue)] = [
            ("granter", granter),
            ("grantee", .bytes(id1.identityHash)),
            ("grants", .array([])),
        ]
        if let p = parent { fields.append(("parent", .bytes(p))) }
        return try! Model.make(type: "system/capability/token", fields: fields)
    }

    /// Build an `included` resolver dict keyed by content hash: peers + signatures.
    func included(peers: [Identity], sigs: [BuiltEntity]) -> [HashKey: Entity] {
        var dict: [HashKey: Entity] = [:]
        for p in peers { dict[HashKey(p.identityHash)] = p.peerEntity.entity }
        for s in sigs { dict[HashKey(s.hash)] = s.entity }
        return dict
    }

    /// Run the chain verifier the way the peer does (resolve via `included`, granter
    /// peer_id derived from the resolved peer's public_key, §1.5).
    func allows(_ cap: BuiltEntity, _ inc: [HashKey: Entity]) -> Bool {
        let resolve: Capability.Resolver = { h in inc[HashKey(h)] }
        let granterPeerID: (Entity) -> String? = { c in
            guard let gh = c.data.bytesAt("granter") else { return nil }
            if gh.elementsEqual(self.id1.identityHash) { return self.id1.peerID }
            return resolve(gh).flatMap { Capability.peerIDOf($0) }
        }
        let verdict = Capability.verifyChain(
            cap.entity, included: inc, localPeerID: local, now: 0,
            resolve: resolve, granterPeerID: granterPeerID)
        return verdict == .allow
    }

    // MARK: - ACCEPT path (the direction the oracle omits)

    func testValid2of3QuorumAllows() throws {
        // 2-of-3, local (id1) in quorum, two valid signatures over the cap hash → ALLOW.
        let cap = mkMultiSigCap(signers: [id1, id2, id3], threshold: 2)
        let s1 = try id1.signatureEntity(target: cap.hash)
        let s2 = try id2.signatureEntity(target: cap.hash)
        let inc = included(peers: [id1, id2, id3], sigs: [s1, s2])
        XCTAssertTrue(allows(cap, inc), "2-of-3 valid quorum must be ALLOWed")
    }

    // MARK: - DENY flips

    func testBelowThresholdDenies() throws {
        // Only one valid signature with threshold 2 → M4 quorum unmet → DENY.
        let cap = mkMultiSigCap(signers: [id1, id2, id3], threshold: 2)
        let s1 = try id1.signatureEntity(target: cap.hash)
        let inc = included(peers: [id1, id2, id3], sigs: [s1])
        XCTAssertFalse(allows(cap, inc), "below-threshold (1 of 2) must DENY")
    }

    func testLocalNotInSignersDenies() throws {
        // local peer (id1) absent from signers → M6 fails → DENY (even with quorum sigs).
        let cap = mkMultiSigCap(signers: [id2, id3], threshold: 2)
        let s2 = try id2.signatureEntity(target: cap.hash)
        let s3 = try id3.signatureEntity(target: cap.hash)
        let inc = included(peers: [id2, id3], sigs: [s2, s3])
        XCTAssertFalse(allows(cap, inc), "local-not-in-signers must DENY (M6)")
    }

    func testThresholdOneDenies() throws {
        // threshold=1 violates M3 structure (2 ≤ threshold) → DENY before sig counting.
        let cap = mkMultiSigCap(signers: [id1, id2, id3], threshold: 1)
        let s1 = try id1.signatureEntity(target: cap.hash)
        let s2 = try id2.signatureEntity(target: cap.hash)
        let inc = included(peers: [id1, id2, id3], sigs: [s1, s2])
        XCTAssertFalse(allows(cap, inc), "threshold=1 must DENY (M3 precedence)")
    }

    func testDuplicateSignersDenies() throws {
        // duplicate signer hashes violate M3 distinctness → DENY.
        let cap = mkMultiSigCap(signers: [id1, id1], threshold: 2)
        let s1 = try id1.signatureEntity(target: cap.hash)
        let inc = included(peers: [id1], sigs: [s1])
        XCTAssertFalse(allows(cap, inc), "duplicate signers must DENY (M3)")
    }

    func testDuplicateSignatureDoesNotInflateCount() throws {
        // Two signatures from the SAME signer (id1) cannot satisfy a 2-of-3 quorum:
        // M4 counts DISTINCT signers, so this stays below threshold → DENY.
        let cap = mkMultiSigCap(signers: [id1, id2, id3], threshold: 2)
        let s1 = try id1.signatureEntity(target: cap.hash)
        // A second signature still from id1 (re-signing the same target) — duplicate signer.
        let s1b = try id1.signatureEntity(target: cap.hash)
        var inc = included(peers: [id1, id2, id3], sigs: [s1])
        // Inject a second id1 signature under a distinct key so both are present.
        inc[HashKey(Array(s1b.hash.reversed()))] = s1b.entity
        XCTAssertFalse(allows(cap, inc), "duplicate signer signatures must NOT inflate the quorum count")
    }

    func testMultiSigOffRootDenies() throws {
        // A multi-sig token is ROOT-ONLY: one that is NOT the root (has a parent) → DENY.
        // Build a single-sig root, then a multi-sig child pointing at it.
        let root = try Model.make(type: "system/capability/token", fields: [
            ("granter", .bytes(id1.identityHash)),
            ("grantee", .bytes(id1.identityHash)),
            ("grants", .array([])),
        ])
        let rootSig = try id1.signatureEntity(target: root.hash)
        let child = mkMultiSigCap(signers: [id1, id2, id3], threshold: 2, parent: root.hash)
        let cs1 = try id1.signatureEntity(target: child.hash)
        let cs2 = try id2.signatureEntity(target: child.hash)
        var inc = included(peers: [id1, id2, id3], sigs: [rootSig, cs1, cs2])
        inc[HashKey(root.hash)] = root.entity
        XCTAssertFalse(allows(child, inc), "a multi-sig token off the chain root must DENY")
    }

    // MARK: - Single-sig strict superset (no regression)

    func testSingleSigRootStillVerifies() throws {
        // A normal single-sig root must still ALLOW identically (strict superset).
        let cap = try Model.make(type: "system/capability/token", fields: [
            ("granter", .bytes(id1.identityHash)),
            ("grantee", .bytes(id1.identityHash)),
            ("grants", .array([])),
        ])
        let sig = try id1.signatureEntity(target: cap.hash)
        let inc = included(peers: [id1], sigs: [sig])
        XCTAssertTrue(allows(cap, inc), "single-sig root must still verify (strict superset)")
    }
}
