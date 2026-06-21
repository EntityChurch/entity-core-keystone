//! content_hash construction (ENTITY-CBOR-ENCODING.md §4.2 / §9.3):
//!
//!   content_hash = varint(format_code) || HASH(ECF({type, data}))
//!
//! format_code 0x00 = ecfv1-sha256 (the required floor). 0x01 = ecfv1-sha384
//! (agility). The varint prefix is LEB128 (N1) — a synthetic code >= 0x80
//! exercises the multi-byte path (corpus content_hash.4). SHA from std.crypto
//! (profile [codec].sha256_source). std-only.

const std = @import("std");
const cbor = @import("cbor.zig");
const varint = @import("varint.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

pub const Error = cbor.Error;

/// ECF of the {type, data} entity. The encoder sorts keys, so "data" precedes
/// "type" (both 5 encoded bytes, lexicographic). Returns owned bytes.
pub fn ecfOfEntity(gpa: std.mem.Allocator, typ: []const u8, data: cbor.Value) Error![]u8 {
    var pairs = [_]cbor.Value.Pair{
        .{ .key = .{ .text = "type" }, .value = .{ .text = typ } },
        .{ .key = .{ .text = "data" }, .value = data },
    };
    return cbor.encode(gpa, .{ .map = &pairs });
}

/// content_hash bytes (caller frees). `format_code` 0 -> SHA-256, 1 -> SHA-384;
/// any other code still emits varint(code) || SHA-256 (the construction side —
/// receive-side dispatch/rejection of unsupported codes is the S3 peer surface).
pub fn contentHash(gpa: std.mem.Allocator, format_code: u64, typ: []const u8, data: cbor.Value) Error![]u8 {
    const ecf = try ecfOfEntity(gpa, typ, data);
    defer gpa.free(ecf);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try varint.encode(&out, gpa, format_code);
    if (format_code == 1) {
        var digest: [Sha384.digest_length]u8 = undefined;
        Sha384.hash(ecf, &digest, .{});
        try out.appendSlice(gpa, &digest);
    } else {
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(ecf, &digest, .{});
        try out.appendSlice(gpa, &digest);
    }
    return out.toOwnedSlice(gpa);
}

test "content_hash empty entity floor" {
    const gpa = std.testing.allocator;
    var empty = [_]cbor.Value.Pair{}; // {}
    const ch = try contentHash(gpa, 0, "system/empty", .{ .map = &empty });
    defer gpa.free(ch);
    var want: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "005f3139e342f5ef35c1e0eb3140c4511c469d604979d20542bc2ab92fd0ca396b");
    try std.testing.expectEqualSlices(u8, &want, ch);
}
