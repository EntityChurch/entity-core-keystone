//! Base58 (Bitcoin alphabet) — hand-rolled, used for peer-id formatting.
//! Standard byte-array long-division; no bignum dependency (std-only, profile
//! [codec].base58_library = hand-rolled). Leading zero bytes map to leading '1'
//! characters. No-GC idiom: both directions return an owned slice (caller frees).

const std = @import("std");

pub const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub const Error = error{ InvalidCharacter, OutOfMemory };

/// Base58-encode `input`. Returns an owned slice (caller frees).
pub fn encode(gpa: std.mem.Allocator, input: []const u8) Error![]u8 {
    const len = input.len;
    var zeros: usize = 0;
    while (zeros < len and input[zeros] == 0) zeros += 1;

    const size = (len * 138 / 100) + 1;
    const b58 = try gpa.alloc(u8, size);
    defer gpa.free(b58);
    @memset(b58, 0);

    var high: usize = size - 1;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        var carry: usize = input[i];
        var j: usize = size - 1;
        while (j > high or carry != 0) {
            carry += 256 * @as(usize, b58[j]);
            b58[j] = @intCast(carry % 58);
            carry /= 58;
            if (j == 0) break;
            j -= 1;
        }
        high = j;
    }

    var start: usize = 0;
    while (start < size and b58[start] == 0) start += 1;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    @memset(try out.addManyAsSlice(gpa, zeros), '1');
    var k: usize = start;
    while (k < size) : (k += 1) try out.append(gpa, alphabet[b58[k]]);
    return out.toOwnedSlice(gpa);
}

fn value(c: u8) i16 {
    return switch (c) {
        '1'...'9' => @as(i16, c - '1'),
        'A'...'H' => @as(i16, c - 'A' + 9),
        'J'...'N' => @as(i16, c - 'J' + 17),
        'P'...'Z' => @as(i16, c - 'P' + 22),
        'a'...'k' => @as(i16, c - 'a' + 33),
        'm'...'z' => @as(i16, c - 'm' + 44),
        else => -1,
    };
}

/// Base58-decode `s`. Returns an owned slice (caller frees).
pub fn decode(gpa: std.mem.Allocator, s: []const u8) Error![]u8 {
    const len = s.len;
    var ones: usize = 0;
    while (ones < len and s[ones] == '1') ones += 1;

    const size = (len * 733 / 1000) + 1; // log(58)/log(256) ≈ 0.733
    const b256 = try gpa.alloc(u8, size);
    defer gpa.free(b256);
    @memset(b256, 0);

    var high: usize = size - 1;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const d = value(s[i]);
        if (d < 0) return error.InvalidCharacter;
        var carry: usize = @intCast(d);
        var j: usize = size - 1;
        while (j > high or carry != 0) {
            carry += 58 * @as(usize, b256[j]);
            b256[j] = @truncate(carry);
            carry >>= 8;
            if (j == 0) break;
            j -= 1;
        }
        high = j;
    }

    var start: usize = 0;
    while (start < size and b256[start] == 0) start += 1;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    @memset(try out.addManyAsSlice(gpa, ones), 0);
    try out.appendSlice(gpa, b256[start..]);
    return out.toOwnedSlice(gpa);
}

test "base58 round trip with leading zeros" {
    const gpa = std.testing.allocator;
    const cases = [_][]const u8{
        &.{0x00},
        &.{ 0x00, 0x00, 0x01, 0x02 },
        &.{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        "hello world",
    };
    for (cases) |c| {
        const enc = try encode(gpa, c);
        defer gpa.free(enc);
        const dec = try decode(gpa, enc);
        defer gpa.free(dec);
        try std.testing.expectEqualSlices(u8, c, dec);
    }
}
