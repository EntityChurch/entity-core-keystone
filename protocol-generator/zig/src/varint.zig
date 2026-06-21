//! Multicodec-style LEB128 varints (V7 §1.5, §7.3 — NORMATIVE).
//!
//! Invariant N1: format codes, key_type and hash_type are framed as LEB128
//! varints, NOT fixed bytes. Every currently-allocated code is < 0x80 (one
//! byte), so this is byte-identical to a fixed field today — the point is that
//! a future code >= 0x80 extends to 2+ bytes and a fixed-width impl breaks
//! silently. Corpus vectors content_hash.4 (format_code 128) and peer_id.3
//! (key_type 128) prove the multi-byte path.
//!
//! No-GC idiom: `encode` writes into a caller-provided `std.ArrayList(u8)`; no
//! allocation is owned by this module.

const std = @import("std");

pub const Error = error{Truncated};

/// Append the LEB128 encoding of `n` to `out`. The list owns its backing
/// allocator; this may return `error.OutOfMemory`.
pub fn encode(out: *std.ArrayList(u8), gpa: std.mem.Allocator, n: u64) !void {
    var v = n;
    while (true) {
        const byte: u8 = @truncate(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            try out.append(gpa, byte);
            break;
        } else {
            try out.append(gpa, byte | 0x80);
        }
    }
}

/// Decode one varint starting at `s[pos]`. Returns the value plus the number of
/// bytes consumed. Rejects a truncated (never-terminating) varint.
pub fn decode(s: []const u8, pos: usize) Error!struct { value: u64, len: usize } {
    var acc: u64 = 0;
    var shift: u6 = 0;
    var i = pos;
    while (true) {
        if (i >= s.len) return error.Truncated;
        const b = s[i];
        acc |= @as(u64, b & 0x7f) << shift;
        i += 1;
        if (b & 0x80 == 0) return .{ .value = acc, .len = i - pos };
        shift += 7;
    }
}

test "varint single + multi byte round trip" {
    const gpa = std.testing.allocator;
    const cases = [_]u64{ 0, 1, 127, 128, 255, 16384, 0xffffffffffffffff };
    for (cases) |n| {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try encode(&buf, gpa, n);
        const d = try decode(buf.items, 0);
        try std.testing.expectEqual(n, d.value);
        try std.testing.expectEqual(buf.items.len, d.len);
    }
}

test "varint 128 is 0x80 0x01" {
    const gpa = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try encode(&buf, gpa, 128);
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, buf.items);
}
