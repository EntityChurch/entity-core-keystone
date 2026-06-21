// ConformanceTests.swift — the S2 wire-conformance gate.
//
// Loads the normative ECF corpus (conformance-vectors-v1.cbor) via OUR decoder
// (per Appendix E §E.3: a decoder bug here is itself a conformance failure), then
// for each vector:
//   encode_equal — encode `input` canonically, assert byte-equal to `canonical`.
//   decode_reject — feed `canonical` to the decoder, assert it rejects.
// Reports 69/69 (64 encode + 5 reject). The fixture carries its own cross-blessed
// bytes — no running Go oracle needed at S2.
//
// Category dispatch mirrors the language-agnostic harness shape: content_hash /
// peer_id / signature build via their specialized constructors; every other
// category round-trips the decoded `input` through the canonical encoder.

import XCTest
import Foundation
@testable import EntityCoreProtocol

final class ConformanceTests: XCTestCase {

    // Absolute path to the shared corpus (outside the package tree). The keystone
    // repo root is fixed under the mounted /work in-container; resolve relative to
    // this source file so it works both in-container and on a dev host.
    static let corpusPath: String = {
        // Tests/EntityCoreProtocolTests/ConformanceTests.swift → up 3 → swift/ →
        // up 2 → protocol-generator/ → shared/test-vectors/...
        let here = URL(fileURLWithPath: #filePath)
        let swiftDir = here
            .deletingLastPathComponent()  // EntityCoreProtocolTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // swift
        return swiftDir
            .deletingLastPathComponent()  // protocol-generator
            .appendingPathComponent("shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor")
            .path
    }()

    static let expectedSHA256 = "41d68d2d717f84e195d46ec002fce6b8729742026256e72dc7a3a8b6c0c6a052"

    func loadVectors() throws -> [CBORValue] {
        let data = try Data(contentsOf: URL(fileURLWithPath: Self.corpusPath))
        let bytes = [UInt8](data)
        // Verify the corpus SHA-256 before trusting it (decode it, don't assume).
        let digest = Hex.encode(ContentHash.sha256(bytes))
        XCTAssertEqual(digest, Self.expectedSHA256, "corpus SHA-256 mismatch — refusing to trust fixture")
        let decoded = try CBOR.decode(bytes)
        guard case let .array(vectors) = decoded else {
            XCTFail("fixture is not a CBOR array"); return []
        }
        return vectors
    }

    func category(_ id: String) -> String {
        if let dot = id.firstIndex(of: ".") { return String(id[id.startIndex..<dot]) }
        return id
    }

    /// Produce the bytes a vector's category requires.
    func produce(category cat: String, input: CBORValue) throws -> [UInt8] {
        switch cat {
        case "content_hash":
            guard let typeVal = input.mapValue("type"), case let .text(type) = typeVal,
                  let data = input.mapValue("data") else {
                throw CodecError.malformed("content_hash input shape")
            }
            let fc = input.mapValue("format_code")?.uintValue ?? 0
            return try ContentHash.contentHash(formatCode: fc, type: type, data: data)

        case "peer_id":
            guard let kt = input.mapValue("key_type")?.uintValue,
                  let ht = input.mapValue("hash_type")?.uintValue,
                  let digest = input.mapValue("digest")?.bytesValue else {
                throw CodecError.malformed("peer_id input shape")
            }
            let pid = PeerID(keyType: kt, hashType: ht, digest: digest).format()
            // Canonical bytes are the ECF encoding of the peer-id text string.
            return try CBOR.encode(.text(pid))

        case "signature":
            guard let seed = input.mapValue("seed")?.bytesValue,
                  let entity = input.mapValue("entity"),
                  let typeVal = entity.mapValue("type"), case let .text(type) = typeVal,
                  let data = entity.mapValue("data") else {
                throw CodecError.malformed("signature input shape")
            }
            // ESTABLISHED CONVENTION (not a new finding): the `signature` corpus
            // vectors sign over the raw ECF bytes of {type, data} — the content_hash
            // PREIMAGE — NOT over the 33-byte content_hash that §7.3 NORMATIVE names
            // ("message = entity.content_hash"). This is the cross-peer convention
            // the FFI rust/c impls + Go/Rust/Py oracles locked at corpus-v1 (see
            // research SESSION-NOTE-2026-06-07-FFI-RUST-FIRST-PASS #3). The §7.3-vs-
            // corpus tension is ledgered as A-SW-007 (corroboration). The fixture is
            // the conformance ground truth (S5); the harness follows the corpus.
            let message = try ContentHash.ecfOfEntity(type: type, data: data)
            return try Signing.sign(seed: seed, message: message)

        default:
            // float / int / map_keys / length / primitive / nested / envelope:
            // re-encode the decoded input canonically.
            return try CBOR.encode(input)
        }
    }

    func testConformanceCorpus() throws {
        let vectors = try loadVectors()
        XCTAssertEqual(vectors.count, 69, "expected 69 vectors in the v1 corpus")

        var pass = 0
        var fail = 0
        var byCategory: [String: (pass: Int, total: Int)] = [:]
        var failures: [String] = []

        for v in vectors {
            guard let id = v.mapValue("id")?.textValue,
                  let kind = v.mapValue("kind")?.textValue,
                  let canon = v.mapValue("canonical")?.bytesValue else {
                XCTFail("malformed vector record"); continue
            }
            let cat = category(id)
            var tally = byCategory[cat] ?? (0, 0)
            tally.total += 1

            var ok = false
            if kind == "decode_reject" {
                // The decoder MUST reject these wire bytes.
                do {
                    _ = try CBOR.decode(canon)
                    failures.append("\(id): decoder ACCEPTED a reject vector")
                } catch {
                    ok = true
                }
            } else {
                guard let input = v.mapValue("input") else {
                    failures.append("\(id): encode_equal vector missing input"); continue
                }
                do {
                    let produced = try produce(category: cat, input: input)
                    if produced == canon {
                        ok = true
                    } else {
                        failures.append("\(id): want \(Hex.encode(canon)) got \(Hex.encode(produced))")
                    }
                } catch {
                    failures.append("\(id): threw \(error)")
                }
            }

            if ok { pass += 1; tally.pass += 1 } else { fail += 1 }
            byCategory[cat] = tally
        }

        // Print a category breakdown for the report.
        print("\n-- conformance by category --")
        for cat in byCategory.keys.sorted() {
            let t = byCategory[cat]!
            print("  \(cat.padding(toLength: 14, withPad: " ", startingAt: 0)) \(t.pass)/\(t.total)")
        }
        print("TOTAL: \(pass) passed, \(fail) failed (of \(pass + fail))")
        if !failures.isEmpty { print("FAILURES:\n  " + failures.joined(separator: "\n  ")) }

        XCTAssertEqual(fail, 0, "conformance failures:\n" + failures.joined(separator: "\n"))
        XCTAssertEqual(pass, 69)
    }
}
