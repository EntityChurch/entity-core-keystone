//! Peer identifier (V7 §1.2 / §7.3):
//!
//!   peer_id = Base58(varint(key_type) || varint(hash_type) || digest)
//!
//! key_type/hash_type are LEB128 varints (N1). For the canonical Ed25519
//! identity-multihash form: key_type 0x01 = ed25519, hash_type 0x00, digest =
//! the raw 32-byte public_key (the §1.5 v7.65 canonical-form table — see
//! A-ZIG-001; §7.4's SHA-256 form is decode-only). The corpus peer_id vectors
//! happen to pin hash_type=0x01 over an opaque 32-byte digest, which this
//! format function reproduces faithfully (it is construction-agnostic over the
//! component values). A synthetic key_type >= 0x80 exercises the multi-byte
//! varint prefix (corpus peer_id.3). std-only.

const std = @import("std");
const base58 = @import("base58.zig");
const varint = @import("varint.zig");

pub const Components = struct {
    key_type: u64,
    hash_type: u64,
    digest: []const u8,
};

pub const Error = base58.Error || varint.Error;

/// Format the peer-id string (Base58) for the given components. Owned (caller frees).
pub fn format(gpa: std.mem.Allocator, c: Components) Error![]u8 {
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    try varint.encode(&raw, gpa, c.key_type);
    try varint.encode(&raw, gpa, c.hash_type);
    try raw.appendSlice(gpa, c.digest);
    return base58.encode(gpa, raw.items);
}

/// Parse a peer-id string back into components. The returned `digest` is an
/// owned slice borrowed from a freshly-decoded buffer — free via `freeParsed`.
pub fn parse(gpa: std.mem.Allocator, s: []const u8) Error!Parsed {
    const raw = try base58.decode(gpa, s);
    errdefer gpa.free(raw);
    const k = try varint.decode(raw, 0);
    const h = try varint.decode(raw, k.len);
    const off = k.len + h.len;
    return .{ .key_type = k.value, .hash_type = h.value, .raw = raw, .digest_off = off };
}

pub const Parsed = struct {
    key_type: u64,
    hash_type: u64,
    raw: []u8, // owned backing buffer
    digest_off: usize,

    pub fn digest(self: Parsed) []const u8 {
        return self.raw[self.digest_off..];
    }
    pub fn deinit(self: Parsed, gpa: std.mem.Allocator) void {
        gpa.free(self.raw);
    }
};

test "peer_id format then parse round trip (multi-byte key_type)" {
    const gpa = std.testing.allocator;
    const digest = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const pid = try format(gpa, .{ .key_type = 128, .hash_type = 1, .digest = &digest });
    defer gpa.free(pid);
    const p = try parse(gpa, pid);
    defer p.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 128), p.key_type);
    try std.testing.expectEqual(@as(u64, 1), p.hash_type);
    try std.testing.expectEqualSlices(u8, &digest, p.digest());
}
