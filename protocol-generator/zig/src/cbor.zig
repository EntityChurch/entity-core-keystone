//! Entity Canonical Form (ECF) — hand-rolled canonical CBOR.
//!
//! Why hand-rolled and not a Zig CBOR package (profile [codec], A-005): ECF
//! (ENTITY-CBOR-ENCODING.md §4, RFC 8949 §4.2 with Entity clarifications) needs
//! (a) length-then-lex map key ordering, (b) shortest-float minimisation incl.
//! f16, (c) recursive major-type-6 tag rejection on decode, (d) full uint64/nint
//! range. Zig has NO std CBOR and no surveyed third-party lib offers these, and a
//! faithful ECF codec must own the canonical layer regardless. std-only.
//!
//! No-GC idiom: every API that allocates takes an explicit `std.mem.Allocator`.
//! `Value` decode produces an owned tree; `Value.deinit(gpa)` frees it
//! (decode_ownership = caller-frees). `encode`/`encodeInto` borrow the tree and
//! allocate only the output buffer. `std.testing.allocator` turns any leak into
//! a test failure (free-correctness is a first-class conformance concern here).

const std = @import("std");

/// The CBOR value model. Integers carry the full unsigned 64-bit pattern:
///   - `uint`  is major type 0, value = the bit pattern read as unsigned.
///   - `nint`  is major type 1; the stored u64 is `n` where the encoded value is
///             `-1 - n`. So nint(0) == -1 and nint(0xff..ff) == -2^64.
/// This covers the whole 0..2^64-1 (uint) and -1..-2^64 (nint) spec range,
/// including values above i64-max that the corpus does not yet exercise.
pub const Value = union(enum) {
    uint: u64,
    nint: u64, // encodes -1 - n; stores n
    bytes: []const u8,
    text: []const u8,
    array: []Value,
    map: []Pair,
    boolean: bool,
    null,
    float: f64,

    pub const Pair = struct { key: Value, value: Value };

    /// Recursively free an owned (decoded) value tree.
    pub fn deinit(self: Value, gpa: std.mem.Allocator) void {
        switch (self) {
            .bytes, .text => |s| gpa.free(s),
            .array => |items| {
                for (items) |it| it.deinit(gpa);
                gpa.free(items);
            },
            .map => |pairs| {
                for (pairs) |p| {
                    p.key.deinit(gpa);
                    p.value.deinit(gpa);
                }
                gpa.free(pairs);
            },
            else => {},
        }
    }
};

/// Decode failures. Tag-policy / canonical violations surface to the peer layer
/// (S3) as `400 non_canonical_ecf`; carried here as members of this error set
/// (profile [error_model]: CodecError, error unions, no exceptions).
pub const Error = error{
    Truncated,
    NonCanonicalEcf, // indefinite / reserved length argument
    TagRejected, // any CBOR tag (major type 6) — N2
    UnsupportedSimple,
    UnsupportedMajor,
    TrailingBytes,
    DuplicateKey,
    OutOfMemory,
};

// ── half-precision (float16) helpers ────────────────────────────────────────

/// Exact float16 -> f64. Used on decode and for the encoder's round-trip check.
fn halfToDouble(h: u16) f64 {
    const sign: u1 = @truncate(h >> 15);
    const exp: u5 = @truncate(h >> 10);
    const mant: u10 = @truncate(h);
    const s: f64 = if (sign == 1) -1.0 else 1.0;
    if (exp == 0) {
        if (mant == 0) return s * 0.0; // ±0
        return s * @as(f64, @floatFromInt(mant)) * std.math.pow(f64, 2.0, -24.0); // subnormal
    } else if (exp == 0x1f) {
        if (mant == 0) return s * std.math.inf(f64);
        return std.math.nan(f64); // NaN
    } else {
        const e: i32 = @as(i32, exp) - 15;
        return s * (1.0 + @as(f64, @floatFromInt(mant)) / 1024.0) * std.math.pow(f64, 2.0, @floatFromInt(e));
    }
}

/// Round-to-nearest-even f64 -> float16 bits. The encoder only EMITS the result
/// when it round-trips bit-exactly through `halfToDouble`, so an imperfect
/// subnormal rounding can never produce wrong canonical bytes — it only falls
/// back to f32/f64. (Corpus exercises f16 normals + specials.)
fn doubleToHalfBits(x: f64) u16 {
    const bits: u64 = @bitCast(x);
    const sign: u16 = @as(u16, @truncate(bits >> 63)) & 1;
    const sbit: u16 = sign << 15;
    const exp: u16 = @truncate((bits >> 52) & 0x7ff);
    const mant: u64 = bits & 0xFFFFFFFFFFFFF;
    if (exp == 0x7ff) {
        return if (mant == 0) sbit | 0x7c00 else 0x7e00;
    }
    const e: i32 = @as(i32, exp) - 1023;
    if (e > 15) return sbit | 0x7c00;
    if (e >= -14) {
        // normal half: take top 10 of the 52 mantissa bits, round half-to-even.
        const drop: u6 = 42;
        var m: u32 = @truncate(mant >> drop);
        const rem: u64 = mant & ((@as(u64, 1) << drop) - 1);
        const halfway: u64 = @as(u64, 1) << (drop - 1);
        const round_up = rem > halfway or (rem == halfway and (m & 1) == 1);
        if (round_up) m += 1;
        var half_exp: i32 = e + 15;
        if (m == 1024) {
            half_exp += 1;
            m = 0;
        }
        if (half_exp >= 0x1f) return sbit | 0x7c00;
        return sbit | (@as(u16, @intCast(half_exp)) << 10) | @as(u16, @truncate(m & 0x3ff));
    }
    if (e < -25) return sbit; // underflow -> ±0
    // subnormal half: value = m * 2^-24.
    const full: u64 = (@as(u64, 1) << 52) | mant; // 53-bit significand
    const shift: u6 = @intCast(28 - e);
    var m: u32 = @truncate(full >> shift);
    const rem: u64 = full & ((@as(u64, 1) << shift) - 1);
    const halfway: u64 = @as(u64, 1) << (shift - 1);
    const round_up = rem > halfway or (rem == halfway and (m & 1) == 1);
    if (round_up) m += 1;
    if (m >= 1024) return sbit | (@as(u16, 1) << 10);
    return sbit | @as(u16, @truncate(m & 0x3ff));
}

// ── big-endian integer emit helpers ─────────────────────────────────────────

fn addBe(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u64, nbytes: usize) !void {
    var i: usize = nbytes;
    while (i > 0) {
        i -= 1;
        const shift: u6 = @intCast(i * 8);
        try out.append(gpa, @truncate((v >> shift) & 0xff));
    }
}

/// Emit a CBOR head: major type (0..7) + minimal-length unsigned argument.
fn addHead(out: *std.ArrayList(u8), gpa: std.mem.Allocator, major: u3, arg: u64) !void {
    const mt: u8 = @as(u8, major) << 5;
    if (arg < 24) {
        try out.append(gpa, mt | @as(u8, @truncate(arg)));
    } else if (arg < 256) {
        try out.append(gpa, mt | 24);
        try addBe(out, gpa, arg, 1);
    } else if (arg < 65536) {
        try out.append(gpa, mt | 25);
        try addBe(out, gpa, arg, 2);
    } else if (arg < 4294967296) {
        try out.append(gpa, mt | 26);
        try addBe(out, gpa, arg, 4);
    } else {
        try out.append(gpa, mt | 27);
        try addBe(out, gpa, arg, 8);
    }
}

// ── canonical encode ─────────────────────────────────────────────────────────

/// RFC 8949 §4.2.1 deterministic key ordering: compare the *encoded* key bytes
/// by length first, then bytewise-lexicographically.
fn compareCanon(_: void, a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return a.len < b.len;
    return std.mem.order(u8, a, b) == .lt;
}

const EncodedKey = struct { bytes: []u8, value: Value };

fn keyLess(_: void, a: EncodedKey, b: EncodedKey) bool {
    return compareCanon({}, a.bytes, b.bytes);
}

fn encodeFloat(out: *std.ArrayList(u8), gpa: std.mem.Allocator, x: f64) !void {
    if (std.math.isNan(x)) {
        // canonical NaN: f9 7e00
        try out.append(gpa, 0xf9);
        try addBe(out, gpa, 0x7e00, 2);
        return;
    }
    const h = doubleToHalfBits(x);
    if (@as(u64, @bitCast(halfToDouble(h))) == @as(u64, @bitCast(x))) {
        try out.append(gpa, 0xf9);
        try addBe(out, gpa, h, 2);
        return;
    }
    const s32: u32 = @bitCast(@as(f32, @floatCast(x)));
    if (@as(u64, @bitCast(@as(f64, @as(f32, @bitCast(s32))))) == @as(u64, @bitCast(x))) {
        try out.append(gpa, 0xfa);
        try addBe(out, gpa, s32, 4);
        return;
    }
    try out.append(gpa, 0xfb);
    try addBe(out, gpa, @bitCast(x), 8);
}

/// Encode `v` into `out` (canonical ECF). Allocates scratch for map-key sorting.
pub fn encodeInto(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: Value) Error!void {
    switch (v) {
        .uint => |n| try addHead(out, gpa, 0, n),
        .nint => |n| try addHead(out, gpa, 1, n),
        .bytes => |s| {
            try addHead(out, gpa, 2, s.len);
            try out.appendSlice(gpa, s);
        },
        .text => |s| {
            try addHead(out, gpa, 3, s.len);
            try out.appendSlice(gpa, s);
        },
        .array => |items| {
            try addHead(out, gpa, 4, items.len);
            for (items) |it| try encodeInto(out, gpa, it);
        },
        .map => |pairs| {
            // Encode each key, sort by encoded-key (length-then-lex), reject dups.
            const encoded = try gpa.alloc(EncodedKey, pairs.len);
            defer {
                for (encoded) |ek| gpa.free(ek.bytes);
                gpa.free(encoded);
            }
            for (pairs, 0..) |p, i| {
                var kb: std.ArrayList(u8) = .empty;
                errdefer kb.deinit(gpa);
                try encodeInto(&kb, gpa, p.key);
                encoded[i] = .{ .bytes = try kb.toOwnedSlice(gpa), .value = p.value };
            }
            std.mem.sort(EncodedKey, encoded, {}, keyLess);
            // Rule 5: reject duplicate keys (adjacent after sort).
            var i: usize = 1;
            while (i < encoded.len) : (i += 1) {
                if (std.mem.eql(u8, encoded[i - 1].bytes, encoded[i].bytes)) return error.DuplicateKey;
            }
            try addHead(out, gpa, 5, pairs.len);
            for (encoded) |ek| {
                try out.appendSlice(gpa, ek.bytes);
                try encodeInto(out, gpa, ek.value);
            }
        },
        .boolean => |b| try out.append(gpa, if (b) 0xf5 else 0xf4),
        .null => try out.append(gpa, 0xf6),
        .float => |x| try encodeFloat(out, gpa, x),
    }
}

/// Encode `v` to a freshly-allocated owned byte slice (caller frees).
pub fn encode(gpa: std.mem.Allocator, v: Value) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try encodeInto(&out, gpa, v);
    return out.toOwnedSlice(gpa);
}

// ── decode (rejects tags + indefinite lengths) ───────────────────────────────

const Decoder = struct {
    s: []const u8,
    pos: usize = 0,
    gpa: std.mem.Allocator,

    fn need(self: *Decoder, k: usize) Error!void {
        if (self.pos + k > self.s.len) return error.Truncated;
    }
    fn readByte(self: *Decoder) Error!u8 {
        try self.need(1);
        const c = self.s[self.pos];
        self.pos += 1;
        return c;
    }
    fn take(self: *Decoder, k: usize) Error![]const u8 {
        try self.need(k);
        const r = self.s[self.pos .. self.pos + k];
        self.pos += k;
        return r;
    }
    fn be(self: *Decoder, k: usize) Error!u64 {
        try self.need(k);
        var v: u64 = 0;
        var j: usize = 0;
        while (j < k) : (j += 1) {
            v = (v << 8) | self.s[self.pos];
            self.pos += 1;
        }
        return v;
    }
    fn readArg(self: *Decoder, ai: u5) Error!u64 {
        if (ai < 24) return ai;
        return switch (ai) {
            24 => try self.be(1),
            25 => try self.be(2),
            26 => try self.be(4),
            27 => try self.be(8),
            else => error.NonCanonicalEcf, // 28..31 indefinite/reserved
        };
    }

    fn item(self: *Decoder) Error!Value {
        const ib = try self.readByte();
        const major: u3 = @truncate(ib >> 5);
        const ai: u5 = @truncate(ib);
        switch (major) {
            0 => return .{ .uint = try self.readArg(ai) },
            1 => return .{ .nint = try self.readArg(ai) },
            2 => {
                const len = try self.readArg(ai);
                const src = try self.take(@intCast(len));
                return .{ .bytes = try self.gpa.dupe(u8, src) };
            },
            3 => {
                const len = try self.readArg(ai);
                const src = try self.take(@intCast(len));
                return .{ .text = try self.gpa.dupe(u8, src) };
            },
            4 => {
                const len: usize = @intCast(try self.readArg(ai));
                const items = try self.gpa.alloc(Value, len);
                var built: usize = 0;
                errdefer {
                    for (items[0..built]) |it| it.deinit(self.gpa);
                    self.gpa.free(items);
                }
                while (built < len) : (built += 1) items[built] = try self.item();
                return .{ .array = items };
            },
            5 => {
                const len: usize = @intCast(try self.readArg(ai));
                const pairs = try self.gpa.alloc(Value.Pair, len);
                var built: usize = 0;
                errdefer {
                    for (pairs[0..built]) |p| {
                        p.key.deinit(self.gpa);
                        p.value.deinit(self.gpa);
                    }
                    self.gpa.free(pairs);
                }
                while (built < len) {
                    const k = try self.item();
                    errdefer k.deinit(self.gpa);
                    const v = try self.item();
                    pairs[built] = .{ .key = k, .value = v };
                    built += 1;
                }
                return .{ .map = pairs };
            },
            6 => return error.TagRejected, // N2: any CBOR tag, at any depth
            7 => return switch (ai) {
                20 => .{ .boolean = false },
                21 => .{ .boolean = true },
                22 => .null,
                25 => .{ .float = halfToDouble(@truncate(try self.be(2))) },
                26 => .{ .float = @as(f32, @bitCast(@as(u32, @truncate(try self.be(4))))) },
                27 => .{ .float = @bitCast(try self.be(8)) },
                else => error.UnsupportedSimple,
            },
        }
    }
};

/// Decode a single top-level ECF item; rejects trailing bytes. Returns an owned
/// tree — free with `Value.deinit(gpa)`.
pub fn decode(gpa: std.mem.Allocator, s: []const u8) Error!Value {
    var d = Decoder{ .s = s, .gpa = gpa };
    const v = try d.item();
    errdefer v.deinit(gpa);
    if (d.pos != s.len) return error.TrailingBytes;
    return v;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectEncode(comptime want_hex: []const u8, v: Value) !void {
    const gpa = testing.allocator;
    const got = try encode(gpa, v);
    defer gpa.free(got);
    var want: [want_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, want_hex);
    try testing.expectEqualSlices(u8, &want, got);
}

test "int minimal encoding boundaries" {
    try expectEncode("00", .{ .uint = 0 });
    try expectEncode("17", .{ .uint = 23 });
    try expectEncode("1818", .{ .uint = 24 });
    try expectEncode("1903e8", .{ .uint = 1000 });
    try expectEncode("1b7fffffffffffffff", .{ .uint = 9223372036854775807 });
    try expectEncode("20", .{ .nint = 0 }); // -1
    try expectEncode("3818", .{ .nint = 24 }); // -25
}

test "float ladder f16/f32/f64" {
    try expectEncode("f93c00", .{ .float = 1.0 });
    try expectEncode("f97c00", .{ .float = std.math.inf(f64) });
    try expectEncode("f97bff", .{ .float = 65504.0 });
    try expectEncode("fa477fdf00", .{ .float = 65503.0 });
    try expectEncode("fb3ff199999999999a", .{ .float = 1.1 });
}

test "decode then re-encode round trips (and frees clean)" {
    const gpa = testing.allocator;
    const bytes = [_]u8{ 0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02 }; // {a:1,b:2}
    const v = try decode(gpa, &bytes);
    defer v.deinit(gpa);
    const re = try encode(gpa, v);
    defer gpa.free(re);
    try testing.expectEqualSlices(u8, &bytes, re);
}

test "decoder rejects a bare tag (N2)" {
    const gpa = testing.allocator;
    try testing.expectError(error.TagRejected, decode(gpa, &.{ 0xc0, 0x00 }));
}

test "decoder rejects a nested tag at depth (N2)" {
    const gpa = testing.allocator;
    // {"data": tag0("x")} — tag must be rejected even inside a map value.
    const bytes = [_]u8{ 0xa1, 0x64, 'd', 'a', 't', 'a', 0xc0, 0x61, 'x' };
    try testing.expectError(error.TagRejected, decode(gpa, &bytes));
}

test "uncovered uint range above i64-max (codec-review heuristic)" {
    // The corpus int set tops out at 2^63-1 (i64::MAX). Pin the full u64 range
    // — the exact spot a signed-int decode would silently overflow.
    try expectEncode("1bffffffffffffffff", .{ .uint = 0xffffffffffffffff }); // 2^64-1
    try expectEncode("1b8000000000000000", .{ .uint = 0x8000000000000000 }); // 2^63
    // nint minimum: -2^64 == nint(2^64-1).
    try expectEncode("3bffffffffffffffff", .{ .nint = 0xffffffffffffffff });
}

test "empty containers and N3 empty map = 0xA0" {
    var empty_map = [_]Value.Pair{};
    try expectEncode("a0", .{ .map = &empty_map });
    var empty_arr = [_]Value{};
    try expectEncode("80", .{ .array = &empty_arr });
}

test "duplicate map keys rejected (Rule 5)" {
    const gpa = testing.allocator;
    var pairs = [_]Value.Pair{
        .{ .key = .{ .text = "a" }, .value = .{ .uint = 1 } },
        .{ .key = .{ .text = "a" }, .value = .{ .uint = 2 } },
    };
    try testing.expectError(error.DuplicateKey, encode(gpa, .{ .map = &pairs }));
}
