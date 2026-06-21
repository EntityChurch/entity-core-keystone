// CodecSelftests.swift — uncovered-range selftests (codec-review heuristic).
//
// Conformance-green ≠ bug-free. The 69-vector corpus does not exercise: the full
// unsigned-64-bit range above Int64.max (the integer-width trap), the nint min
// (-2^64), base58 leading-zero preservation, Ed25519 determinism/tamper-reject,
// tag rejection NESTED at depth, duplicate-key rejection, and decode∘encode
// identity over the whole corpus. These tests prove those corners.

import XCTest
import Foundation
@testable import EntityCoreProtocol

final class CodecSelftests: XCTestCase {

    func hexToBytes(_ s: String) -> [UInt8] {
        var out: [UInt8] = []
        var it = s.utf8.makeIterator()
        func val(_ c: UInt8) -> UInt8 {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x61...0x66: return c - 0x61 + 10
            case 0x41...0x46: return c - 0x41 + 10
            default: return 0
            }
        }
        let bytes = Array(s.utf8)
        var i = 0
        while i + 1 < bytes.count {
            out.append((val(bytes[i]) << 4) | val(bytes[i + 1]))
            i += 2
        }
        _ = it
        return out
    }

    // MARK: - Full unsigned 64-bit range (the integer-width trap)

    func testUInt64MaxEncodesAsFullUnsigned() throws {
        // 2^64-1 must encode as 1b ffffffffffffffff — full UInt64, not Int64.
        let v = CBORValue.uint(UInt64.max)
        XCTAssertEqual(Hex.encode(try CBOR.encode(v)), "1bffffffffffffffff")
        // Round-trips back to UInt64.max.
        XCTAssertEqual(try CBOR.decode(hexToBytes("1bffffffffffffffff")), .uint(UInt64.max))
    }

    func testUInt64JustAboveInt64Max() throws {
        // 2^63 = 9223372036854775808 — exactly one past Int64.max, where a signed
        // decode would overflow.
        let n: UInt64 = 1 << 63
        XCTAssertEqual(Hex.encode(try CBOR.encode(.uint(n))), "1b8000000000000000")
        XCTAssertEqual(try CBOR.decode(hexToBytes("1b8000000000000000")), .uint(n))
    }

    func testNintMinIsNegativeTwoToThe64() throws {
        // nint stores n where value = -1 - n. nint(2^64-1) = -2^64 (the min nint).
        let v = CBORValue.nint(UInt64.max)
        XCTAssertEqual(Hex.encode(try CBOR.encode(v)), "3bffffffffffffffff")
        XCTAssertEqual(try CBOR.decode(hexToBytes("3bffffffffffffffff")), .nint(UInt64.max))
    }

    // MARK: - Base58 round-trip + leading-zero preservation

    func testBase58RoundTrip() throws {
        let cases: [[UInt8]] = [
            [],
            [0x00],
            [0x00, 0x00, 0x01],          // leading zeros must survive as leading '1's
            [0xff, 0xff, 0xff],
            Array(0..<34),
            [0x01, 0x00] + Array(repeating: 0xab, count: 32),  // a peer-id-like blob
        ]
        for c in cases {
            let encoded = Base58.encode(c)
            let decoded = try Base58.decode(encoded)
            XCTAssertEqual(decoded, c, "base58 round-trip failed for \(Hex.encode(c)) → \(encoded)")
        }
    }

    func testBase58LeadingZeroPreserved() throws {
        // Two leading 0x00 bytes → two leading '1' chars.
        let encoded = Base58.encode([0x00, 0x00, 0x05])
        XCTAssertTrue(encoded.hasPrefix("11"), "leading zeros not preserved: \(encoded)")
        XCTAssertEqual(try Base58.decode(encoded), [0x00, 0x00, 0x05])
    }

    func testBase58RejectsInvalidChar() {
        // '0', 'O', 'I', 'l' are not in the Bitcoin alphabet.
        XCTAssertThrowsError(try Base58.decode("0OIl"))
    }

    // MARK: - Ed25519 determinism + verify + tamper-reject

    func testEd25519Deterministic() throws {
        let seed = Array(repeating: UInt8(7), count: 32)
        let msg = Array("hello entity".utf8)
        let sig1 = try Signing.sign(seed: seed, message: msg)
        let sig2 = try Signing.sign(seed: seed, message: msg)
        XCTAssertEqual(sig1, sig2, "Ed25519 signing must be deterministic (RFC 8032)")
        XCTAssertEqual(sig1.count, 64)

        let pub = try Signing.publicKey(fromSeed: seed)
        XCTAssertEqual(pub.count, 32)
        XCTAssertTrue(Signing.verify(publicKey: pub, message: msg, signature: sig1))
    }

    func testEd25519TamperReject() throws {
        let seed = Array(repeating: UInt8(0), count: 32)
        let msg = Array("payload".utf8)
        let sig = try Signing.sign(seed: seed, message: msg)
        let pub = try Signing.publicKey(fromSeed: seed)
        // Tamper the message.
        var tampered = msg; tampered[0] ^= 0x01
        XCTAssertFalse(Signing.verify(publicKey: pub, message: tampered, signature: sig))
        // Tamper the signature.
        var badSig = sig; badSig[10] ^= 0xff
        XCTAssertFalse(Signing.verify(publicKey: pub, message: msg, signature: badSig))
    }

    func testEd25519BadSeedThrows() {
        XCTAssertThrowsError(try Signing.sign(seed: [0x00], message: [])) { error in
            XCTAssertEqual(error as? CodecError, .badSeed)
        }
    }

    // MARK: - Recursive tag rejection (N2) at depth > 0

    func testBareTagRejected() {
        // c0 74 ... — tag 0 at top level.
        XCTAssertThrowsError(try CBOR.decode([0xc0, 0x00]))
    }

    func testTagNestedInArrayRejected() {
        // 81 c1 00 — array of one item that is tag 1.
        XCTAssertThrowsError(try CBOR.decode([0x81, 0xc1, 0x00])) { error in
            XCTAssertEqual(error as? CodecError, .tagRejected)
        }
    }

    func testTagNestedInMapValueRejected() {
        // a1 61 61 c0 00 — {"a": tag0(0)}.
        XCTAssertThrowsError(try CBOR.decode([0xa1, 0x61, 0x61, 0xc0, 0x00])) { error in
            XCTAssertEqual(error as? CodecError, .tagRejected)
        }
    }

    func testDeeplyNestedTagRejected() {
        // 81 81 81 c1 00 — array>array>array>tag1.
        XCTAssertThrowsError(try CBOR.decode([0x81, 0x81, 0x81, 0xc1, 0x00])) { error in
            XCTAssertEqual(error as? CodecError, .tagRejected)
        }
    }

    // MARK: - Duplicate-key rejection + empty containers

    func testDuplicateMapKeyRejectedOnDecode() {
        // a2 61 61 01 61 61 02 — {"a":1,"a":2} duplicate key.
        XCTAssertThrowsError(try CBOR.decode([0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02])) { error in
            XCTAssertEqual(error as? CodecError, .duplicateKey)
        }
    }

    func testDuplicateMapKeyRejectedOnEncode() {
        let dup = CBORValue.map([(.text("a"), .uint(1)), (.text("a"), .uint(2))])
        XCTAssertThrowsError(try CBOR.encode(dup)) { error in
            XCTAssertEqual(error as? CodecError, .duplicateKey)
        }
    }

    func testEmptyContainersCanonical() throws {
        XCTAssertEqual(Hex.encode(try CBOR.encode(.map([]))), "a0")    // N3
        XCTAssertEqual(Hex.encode(try CBOR.encode(.array([]))), "80")
        XCTAssertEqual(Hex.encode(try CBOR.encode(.text(""))), "60")
        XCTAssertEqual(Hex.encode(try CBOR.encode(.bytes([]))), "40")
    }

    // MARK: - Indefinite-length + non-minimal rejection

    func testIndefiniteLengthRejected() {
        // 9f 01 ff — indefinite array.
        XCTAssertThrowsError(try CBOR.decode([0x9f, 0x01, 0xff]))
    }

    func testNonMinimalIntRejected() {
        // 18 01 — value 1 with an unnecessary 1-byte argument (non-canonical).
        XCTAssertThrowsError(try CBOR.decode([0x18, 0x01])) { error in
            XCTAssertEqual(error as? CodecError, .nonCanonicalECF("non-minimal 1-byte arg"))
        }
    }

    func testTrailingBytesRejected() {
        // 00 00 — two top-level items; decode expects exactly one.
        XCTAssertThrowsError(try CBOR.decode([0x00, 0x00])) { error in
            XCTAssertEqual(error as? CodecError, .trailingBytes)
        }
    }

    // MARK: - Varint multi-byte path (N1)

    func testVarintMultiByte() throws {
        // 128 → 0x80 0x01 (multicodec LEB128); 300 → 0xac 0x02.
        XCTAssertEqual(Varint.encode(128), [0x80, 0x01])
        XCTAssertEqual(Varint.encode(300), [0xac, 0x02])
        XCTAssertEqual(try Varint.decode([0x80, 0x01], at: 0).value, 128)
        XCTAssertEqual(try Varint.decode([0xac, 0x02], at: 0).value, 300)
        // Single-byte values stay single byte.
        XCTAssertEqual(Varint.encode(1), [0x01])
        XCTAssertEqual(Varint.encode(127), [0x7f])
    }

    // MARK: - PeerID round-trip (incl. multi-byte key_type)

    func testPeerIDRoundTrip() throws {
        let digest = Array(0..<32).map { UInt8($0) }
        for kt: UInt64 in [1, 128, 300] {
            let pid = PeerID(keyType: kt, hashType: 1, digest: digest)
            let s = pid.format()
            let parsed = try PeerID.parse(s)
            XCTAssertEqual(parsed.keyType, kt)
            XCTAssertEqual(parsed.hashType, 1)
            XCTAssertEqual(parsed.digest, digest)
        }
    }

    // MARK: - decode∘encode == identity over the whole corpus

    func testCorpusRoundTripIdentity() throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: ConformanceTests.corpusPath))
        let bytes = [UInt8](data)
        let decoded = try CBOR.decode(bytes)
        guard case let .array(vectors) = decoded else { XCTFail("not array"); return }
        for v in vectors {
            guard let kind = v.mapValue("kind")?.textValue, kind == "encode_equal",
                  let canon = v.mapValue("canonical")?.bytesValue else { continue }
            // Only round-trip the categories whose canonical bytes are themselves a
            // complete ECF value (everything except content_hash/peer_id/signature,
            // whose canonical bytes are a hash/string/sig, not a re-encodable value).
            guard let id = v.mapValue("id")?.textValue else { continue }
            let cat = id.split(separator: ".").first.map(String.init) ?? id
            if ["content_hash", "signature"].contains(cat) { continue }
            if cat == "peer_id" {
                // canonical is the ECF of a text string — decode∘encode it.
                let rt = try CBOR.encode(try CBOR.decode(canon))
                XCTAssertEqual(rt, canon, "peer_id canonical not round-trip stable")
                continue
            }
            let rt = try CBOR.encode(try CBOR.decode(canon))
            XCTAssertEqual(Hex.encode(rt), Hex.encode(canon), "\(id): decode∘encode not identity")
        }
    }

    // MARK: - Content-hash floor (N3 empty-data boundary)

    func testContentHashEmptyEntityFloor() throws {
        // content_hash.1 floor: {type:"system/empty", data:{}} →
        // 00 5f3139e342...0ca396b (the F5-resolved empty-data boundary).
        let ch = try ContentHash.contentHash(type: "system/empty", data: .map([]))
        XCTAssertEqual(Hex.encode(ch), "005f3139e342f5ef35c1e0eb3140c4511c469d604979d20542bc2ab92fd0ca396b")
    }

    // MARK: - UTF-8 byte-length discipline (A-SW-002)

    func testTextLengthIsUTF8BytesNotGraphemes() throws {
        // "café" = 4 graphemes but 5 UTF-8 bytes → text head must be 0x65 (len 5).
        XCTAssertEqual("café".count, 4)            // grapheme count
        XCTAssertEqual("café".utf8.count, 5)       // byte count
        let encoded = try CBOR.encode(.text("café"))
        XCTAssertEqual(encoded[0], 0x65)            // major 3, len 5 — NOT 0x64 (len 4)
        XCTAssertEqual(encoded.count, 6)            // 1 head + 5 bytes
    }

    func testMapKeySortIsOverEncodedBytesNotStringOrdering() throws {
        // Two keys where Swift String ordering and encoded-byte ordering could
        // disagree if naively done: a length-2 vs length-1 key. Length wins first.
        let m = CBORValue.map([(.text("Z"), .uint(1)), (.text("aa"), .uint(2))])
        // "Z" (1 byte) sorts before "aa" (2 bytes) by length-first rule.
        let encoded = Hex.encode(try CBOR.encode(m))
        // a2 615a 01 626161 02
        XCTAssertEqual(encoded, "a2615a01626161 02".replacingOccurrences(of: " ", with: ""))
    }
}
