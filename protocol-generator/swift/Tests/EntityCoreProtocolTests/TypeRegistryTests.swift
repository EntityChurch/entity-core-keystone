// TypeRegistryTests.swift — A-SW-009 byte-diff gate.
//
// Every §9.5 core type's content_hash must be byte-identical to the Go-rendered
// `type-registry-vectors-v1.cbor` set (the S8 drift target). This is the offline
// gate that de-risks the live `type_system` conformance category: the codec is
// byte-green at S2, so the only remaining risk is the field-shape DATA, which the
// per-type digest diff catches exactly. Mirrors Zig A-ZIG-008 / TS type-registry.

import XCTest
import Foundation
@testable import EntityCoreProtocol

final class TypeRegistryTests: XCTestCase {

    static let vectorPath: String = {
        let here = URL(fileURLWithPath: #filePath)
        let swiftDir = here
            .deletingLastPathComponent()  // EntityCoreProtocolTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // swift
        return swiftDir
            .deletingLastPathComponent()  // protocol-generator
            .appendingPathComponent("shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor")
            .path
    }()

    /// name -> 64-char digest hex (after the "ecf-sha256:" prefix).
    func loadWant() throws -> [String: String] {
        let data = try Data(contentsOf: URL(fileURLWithPath: Self.vectorPath))
        let decoded = try CBOR.decode([UInt8](data))
        guard case let .array(vectors) = decoded else {
            XCTFail("vector file is not a CBOR array"); return [:]
        }
        var want: [String: String] = [:]
        let prefix = "ecf-sha256:"
        for v in vectors {
            guard let name = v.textAt("name"), let ch = v.textAt("content_hash"),
                  ch.hasPrefix(prefix) else { continue }
            want[name] = String(ch.dropFirst(prefix.count))
        }
        return want
    }

    func testCoreTypeFloorRendersByteIdentical() throws {
        let want = try loadWant()
        XCTAssertEqual(TypeRegistry.coreTypeCount, 53, "core floor must be exactly 53 types")

        var matched = 0
        var mismatches: [String] = []
        for (name, digest) in try TypeRegistry.renderedDigests() {
            let got = Hex.encode(digest)
            guard let expect = want[name] else {
                mismatches.append("MISSING from vectors: \(name)")
                continue
            }
            if got == expect { matched += 1 }
            else { mismatches.append("MISMATCH \(name)\n    want \(expect)\n    got  \(got)") }
        }
        if !mismatches.isEmpty {
            XCTFail("type-registry byte-diff: \(matched)/53 identical\n" + mismatches.joined(separator: "\n"))
        }
        XCTAssertEqual(matched, 53)
    }
}
