// Signing.swift — deterministic Ed25519 sign/verify (V7 §7.3, NORMATIVE).
//
// Via swift-crypto `Curve25519.Signing` (the audited, BoringSSL-backed Linux
// CryptoKit-API impl; A-SW-003). RFC 8032 deterministic signing: `signature(for:)`
// needs no RNG, so a fixed seed + fixed message → a fixed signature (the property
// the `signature` conformance vectors rely on). Seed / public key = 32-byte
// rawRepresentation.
//
// Signatures are computed over the FULL content_hash bytes (format code + digest),
// per §7.3 — the caller passes the message bytes (the content_hash) to sign.

import Crypto
// swift-crypto's signing API takes `Data`/`DataProtocol`. We keep the codec in
// [UInt8] (profile [memory].bytes_type) and convert only at this crypto edge.
import struct Foundation.Data

public enum Signing {

    /// Derive the 32-byte Ed25519 public key from a 32-byte seed.
    public static func publicKey(fromSeed seed: [UInt8]) throws(CodecError) -> [UInt8] {
        guard seed.count == 32 else { throw .badSeed }
        do {
            let sk = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            return Array(sk.publicKey.rawRepresentation)
        } catch {
            throw .badSeed
        }
    }

    /// Sign `message` (the full content_hash bytes) with the Ed25519 seed.
    /// Returns the 64-byte signature. Deterministic per RFC 8032.
    public static func sign(seed: [UInt8], message: [UInt8]) throws(CodecError) -> [UInt8] {
        guard seed.count == 32 else { throw .badSeed }
        do {
            let sk = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            let sig = try sk.signature(for: Data(message))
            return Array(sig)
        } catch {
            throw .badSeed
        }
    }

    /// Verify a 64-byte Ed25519 signature over `message` against a 32-byte public key.
    public static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
        guard publicKey.count == 32, signature.count == 64 else { return false }
        guard let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else {
            return false
        }
        return pk.isValidSignature(Data(signature), for: Data(message))
    }
}
