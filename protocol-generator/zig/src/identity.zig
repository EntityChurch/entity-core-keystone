//! Identity (L1) — a peer's keypair and the entities derived from it (§1.5, §3.5,
//! §7.3). The peer identity is a 32-byte Ed25519 seed; everything else derives:
//!
//!   public_key    = Ed25519 pub of seed                          (32 bytes)
//!   peer_id       = Base58(varint(1) ‖ varint(0) ‖ public_key)   (§1.5 v7.65
//!                   identity-multihash — A-ZIG-001, NOT the §7.4 SHA-256 form)
//!   peer entity   = system/peer { public_key, key_type }         (§3.5; v7.65 —
//!                   NO peer_id in the hashable basis)
//!   identity_hash = content_hash(peer entity)                    (33 bytes)
//!
//! A-ZIG-001 resolution: we construct the CANONICAL identity-multihash peer_id
//! (hash_type=0x00, digest = raw public_key) per the §1.5 v7.65 canonical-form
//! table — NOT the stale §7.4 "NORMATIVE" SHA-256 form. A fresh §7.4 reader would
//! fail handshake against an oracle expecting the canonical form (independently
//! corroborated by OCaml A-OC-007). Signing is over the full 33-byte content_hash.

const std = @import("std");
const model = @import("model.zig");
const sign = @import("sign.zig");
const peer_id = @import("peer_id.zig");

const Entity = model.Entity;
const Value = model.Value;

pub const Error = error{OutOfMemory} || model.Error || sign.Error || peer_id.Error;

pub const Identity = struct {
    seed: [32]u8,
    public_key: [32]u8,
    peer_id: []const u8, // owned Base58
    peer_entity: Entity, // owned
    identity_hash: []const u8, // borrows peer_entity.hash

    pub fn deinit(self: Identity, gpa: std.mem.Allocator) void {
        gpa.free(self.peer_id);
        self.peer_entity.deinit(gpa);
    }
};

/// Build the system/peer entity for a public key (§3.5; v7.65 — no peer_id field).
pub fn peerEntityOfPubkey(gpa: std.mem.Allocator, public_key: []const u8) Error!Entity {
    var pairs = try gpa.alloc(Value.Pair, 2);
    errdefer gpa.free(pairs);
    pairs[0] = .{ .key = try model.textVal(gpa, "public_key"), .value = try model.bytesVal(gpa, public_key) };
    pairs[1] = .{ .key = try model.textVal(gpa, "key_type"), .value = try model.textVal(gpa, "ed25519") };
    return Entity.make(gpa, "system/peer", .{ .map = pairs });
}

/// Canonical Ed25519 peer_id (§1.5 v7.65 identity-multihash; A-ZIG-001). Owned.
pub fn peerIdOfPubkey(gpa: std.mem.Allocator, public_key: []const u8) Error![]u8 {
    return peer_id.format(gpa, .{ .key_type = 0x01, .hash_type = 0x00, .digest = public_key });
}

pub fn ofSeed(gpa: std.mem.Allocator, seed: [32]u8) Error!Identity {
    const public_key = try sign.publicOfSeed(seed);
    const peer_entity = try peerEntityOfPubkey(gpa, &public_key);
    errdefer peer_entity.deinit(gpa);
    const pid = try peerIdOfPubkey(gpa, &public_key);
    errdefer gpa.free(pid);
    return .{
        .seed = seed,
        .public_key = public_key,
        .peer_id = pid,
        .peer_entity = peer_entity,
        .identity_hash = peer_entity.hash,
    };
}

/// Sign an entity's content_hash; produce the system/signature entity (§3.5).
pub fn signEntity(gpa: std.mem.Allocator, id: Identity, target: Entity) Error!Entity {
    if (target.hash.len != 33) return error.BadEntity;
    var hbuf: [33]u8 = undefined;
    @memcpy(&hbuf, target.hash);
    const sig_bytes = try sign.sign(id.seed, &hbuf);
    var pairs = try gpa.alloc(Value.Pair, 4);
    errdefer gpa.free(pairs);
    pairs[0] = .{ .key = try model.textVal(gpa, "target"), .value = try model.bytesVal(gpa, target.hash) };
    pairs[1] = .{ .key = try model.textVal(gpa, "signer"), .value = try model.bytesVal(gpa, id.identity_hash) };
    pairs[2] = .{ .key = try model.textVal(gpa, "algorithm"), .value = try model.textVal(gpa, "ed25519") };
    pairs[3] = .{ .key = try model.textVal(gpa, "signature"), .value = try model.bytesVal(gpa, &sig_bytes) };
    return Entity.make(gpa, "system/signature", .{ .map = pairs });
}

/// Verify a system/signature entity against the signer's system/peer entity (the
/// §5.2 signer-hash binding is the caller's responsibility).
pub fn verifySignature(signature: Entity, signer_peer: Entity) bool {
    const target = signature.bytesField("target") orelse return false;
    const sig_bytes = signature.bytesField("signature") orelse return false;
    const pub_bytes = signer_peer.bytesField("public_key") orelse return false;
    if (sig_bytes.len != 64 or pub_bytes.len != 32) return false;
    var sig64: [64]u8 = undefined;
    var pub32: [32]u8 = undefined;
    @memcpy(&sig64, sig_bytes);
    @memcpy(&pub32, pub_bytes);
    return sign.verify(pub32, sig64, target);
}

const testing = std.testing;

test "identity derivation + sign/verify leak-clean" {
    const gpa = testing.allocator;
    const id = try ofSeed(gpa, [_]u8{7} ** 32);
    defer id.deinit(gpa);
    // canonical peer_id decodes to key_type=1, hash_type=0, digest = pubkey
    const parsed = try peer_id.parse(gpa, id.peer_id);
    defer parsed.deinit(gpa);
    try testing.expectEqual(@as(u64, 1), parsed.key_type);
    try testing.expectEqual(@as(u64, 0), parsed.hash_type);
    try testing.expectEqualSlices(u8, &id.public_key, parsed.digest());

    const sig = try signEntity(gpa, id, id.peer_entity);
    defer sig.deinit(gpa);
    try testing.expect(verifySignature(sig, id.peer_entity));
}
