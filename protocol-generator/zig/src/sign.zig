//! Ed25519 signing over canonical-ECF bytes (V7 §1.5 key_type 0x01). RFC 8032
//! Ed25519 is deterministic, so a fixed 32-byte seed + fixed message yields a
//! fixed 64-byte signature — reproducible across impls without an RNG
//! (`KeyPair.sign(msg, null)` uses no noise). std.crypto.sign.Ed25519, in std,
//! audited (profile [codec].ed25519_library). std-only.
//!
//! Ed448 is NOT in Zig std (A-ZIG-002) — agility corpus only; the Ed25519 floor
//! is complete and unaffected.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const seed_length = Ed25519.KeyPair.seed_length; // 32
pub const signature_length = Ed25519.Signature.encoded_length; // 64
pub const public_length = Ed25519.PublicKey.encoded_length; // 32

pub const Error = error{ BadSeed, BadPublicKey, SignFailed };

/// Deterministic Ed25519 signature (64 bytes) over `msg` for the 32-byte `seed`.
pub fn sign(seed: [seed_length]u8, msg: []const u8) Error![signature_length]u8 {
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.BadSeed;
    const sig = kp.sign(msg, null) catch return error.SignFailed;
    return sig.toBytes();
}

/// The Ed25519 public key (32 bytes) for a 32-byte seed.
pub fn publicOfSeed(seed: [seed_length]u8) Error![public_length]u8 {
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.BadSeed;
    return kp.public_key.toBytes();
}

/// Verify a 64-byte signature against `msg` under a 32-byte public key.
pub fn verify(pub_bytes: [public_length]u8, signature: [signature_length]u8, msg: []const u8) bool {
    const pk = Ed25519.PublicKey.fromBytes(pub_bytes) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature);
    sig.verify(msg, pk) catch return false;
    return true;
}

test "deterministic sign + verify + tamper reject" {
    const seed = [_]u8{0} ** 32;
    const msg = "hello entity";
    const sig = try sign(seed, msg);
    const pk = try publicOfSeed(seed);
    try std.testing.expect(verify(pk, sig, msg));
    try std.testing.expect(!verify(pk, sig, "tampered"));
    // determinism: identical inputs -> identical signature
    const sig2 = try sign(seed, msg);
    try std.testing.expectEqualSlices(u8, &sig, &sig2);
}
