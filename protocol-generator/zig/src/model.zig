//! Entity model (L-foundation) — the materialized `{type, data, content_hash}`
//! form (V7 §1.1, §3.4) and the protocol envelope (§3.1), lifted onto the S2
//! `cbor.Value` tree.
//!
//! No-GC ownership contract (profile [memory]): an `Entity` OWNS its `typ`
//! string, its `data` cbor.Value tree, and its 33-byte `hash`. `Entity.deinit`
//! frees all three. An `Envelope` owns its `root` Entity and every `included`
//! Entity plus the duped key bytes. This is the documented caller-frees seam the
//! GC'd peers never had to author (A-ZIG-004). `std.testing.allocator` and a
//! leak-checking GPA in the smoke turn any un-freed entity into a failure.
//!
//! N4 original-byte forwarding: at the peer surface a decoded inbound entity is
//! re-materialized through our own codec (recomputing the hash from {type,data})
//! — §5.2 validate-before-trust. We trust our recomputed hash, not the wire
//! bytes, so a forwarded entity is canonical by construction.

const std = @import("std");
const cbor = @import("cbor.zig");
const hash = @import("hash.zig");

pub const Value = cbor.Value;

pub const Error = error{
    BadEntity,
    ContentHashMismatch,
    IncludedKeyMismatch,
    OutOfMemory,
} || cbor.Error;

/// A materialized entity: owns its type name, data tree, and content_hash.
pub const Entity = struct {
    typ: []const u8, // owned
    data: Value, // owned tree
    hash: []const u8, // owned, 33 bytes (format byte 0x00 ‖ 32-byte SHA-256)

    /// Construct a materialized entity, computing the content_hash under the
    /// ecfv1-sha256 floor (format_code 0). Takes ownership of `data` and dupes
    /// `typ` — the caller keeps ownership of whatever it passed for `typ` (a
    /// borrowed slice) but transfers `data`.
    pub fn make(gpa: std.mem.Allocator, typ: []const u8, data: Value) Error!Entity {
        const owned_typ = try gpa.dupe(u8, typ);
        errdefer gpa.free(owned_typ);
        const h = try hash.contentHash(gpa, 0, typ, data);
        errdefer gpa.free(h);
        return .{ .typ = owned_typ, .data = data, .hash = h };
    }

    pub fn deinit(self: Entity, gpa: std.mem.Allocator) void {
        gpa.free(self.typ);
        self.data.deinit(gpa);
        gpa.free(self.hash);
    }

    /// A deep, independently-owned clone (used when an entity must live in both
    /// the store and an outgoing envelope's `included`).
    pub fn clone(self: Entity, gpa: std.mem.Allocator) Error!Entity {
        const owned_typ = try gpa.dupe(u8, self.typ);
        errdefer gpa.free(owned_typ);
        const data = try cloneValue(gpa, self.data);
        errdefer data.deinit(gpa);
        const h = try gpa.dupe(u8, self.hash);
        return .{ .typ = owned_typ, .data = data, .hash = h };
    }

    // ── field accessors (data is a map) ──────────────────────────────────────

    pub fn field(self: Entity, key: []const u8) ?Value {
        return mapGet(self.data, key);
    }
    pub fn textField(self: Entity, key: []const u8) ?[]const u8 {
        return switch (self.field(key) orelse return null) {
            .text => |s| s,
            else => null,
        };
    }
    pub fn bytesField(self: Entity, key: []const u8) ?[]const u8 {
        return switch (self.field(key) orelse return null) {
            .bytes => |s| s,
            else => null,
        };
    }
    pub fn uintField(self: Entity, key: []const u8) ?u64 {
        return switch (self.field(key) orelse return null) {
            .uint => |n| n,
            else => null,
        };
    }
    /// Parse a sub-entity carried as a CBOR map field (e.g. params, the inner
    /// entity in a put). Returns an owned Entity the caller frees.
    pub fn entityField(self: Entity, gpa: std.mem.Allocator, key: []const u8) Error!?Entity {
        const v = self.field(key) orelse return null;
        return try ofCbor(gpa, v);
    }

    /// Wire form: the entity carries its content_hash so it is self-describing
    /// across serialization (§3.1). Returns an owned Value tree.
    pub fn toCbor(self: Entity, gpa: std.mem.Allocator) Error!Value {
        var pairs = try gpa.alloc(Value.Pair, 3);
        errdefer gpa.free(pairs);
        pairs[0] = .{ .key = try textVal(gpa, "type"), .value = try textVal(gpa, self.typ) };
        pairs[1] = .{ .key = try textVal(gpa, "data"), .value = try cloneValue(gpa, self.data) };
        pairs[2] = .{ .key = try textVal(gpa, "content_hash"), .value = try bytesVal(gpa, self.hash) };
        return .{ .map = pairs };
    }
};

/// Parse a wire entity, recomputing the hash from {type,data} and validating it
/// against the carried content_hash (§1.8 fidelity). Returns the recomputed
/// canonical entity (we trust our hash, not the wire bytes — §5.2). The returned
/// entity OWNS fresh copies; the input `c` is left to the caller.
pub fn ofCbor(gpa: std.mem.Allocator, c: Value) Error!Entity {
    const typ = switch (mapGet(c, "type") orelse return error.BadEntity) {
        .text => |s| s,
        else => return error.BadEntity,
    };
    const data_src = mapGet(c, "data") orelse return error.BadEntity;
    const data = try cloneValue(gpa, data_src);
    errdefer data.deinit(gpa);
    const e = try Entity.make(gpa, typ, data);
    errdefer e.deinit(gpa);
    if (mapGet(c, "content_hash")) |ch| {
        switch (ch) {
            .bytes => |h| if (!std.mem.eql(u8, h, e.hash)) return error.ContentHashMismatch,
            else => {},
        }
    }
    return e;
}

// ── envelope (§3.1) ──────────────────────────────────────────────────────────

pub const Included = struct {
    key: []const u8, // owned: the entity's content_hash bytes
    entity: Entity, // owned
};

pub const Envelope = struct {
    root: Entity,
    included: []Included,

    pub fn deinit(self: Envelope, gpa: std.mem.Allocator) void {
        self.root.deinit(gpa);
        for (self.included) |inc| {
            gpa.free(inc.key);
            inc.entity.deinit(gpa);
        }
        gpa.free(self.included);
    }

    pub fn includedGet(self: Envelope, h: []const u8) ?Entity {
        for (self.included) |inc| {
            if (std.mem.eql(u8, inc.key, h)) return inc.entity;
        }
        return null;
    }

    pub fn toCbor(self: Envelope, gpa: std.mem.Allocator) Error!Value {
        const inc_pairs = try gpa.alloc(Value.Pair, self.included.len);
        var built: usize = 0;
        errdefer {
            for (inc_pairs[0..built]) |p| {
                p.key.deinit(gpa);
                p.value.deinit(gpa);
            }
            gpa.free(inc_pairs);
        }
        while (built < self.included.len) : (built += 1) {
            const inc = self.included[built];
            inc_pairs[built] = .{
                .key = try bytesVal(gpa, inc.key),
                .value = try inc.entity.toCbor(gpa),
            };
        }
        var pairs = try gpa.alloc(Value.Pair, 2);
        errdefer gpa.free(pairs);
        pairs[0] = .{ .key = try textVal(gpa, "root"), .value = try self.root.toCbor(gpa) };
        pairs[1] = .{ .key = try textVal(gpa, "included"), .value = .{ .map = inc_pairs } };
        return .{ .map = pairs };
    }

    pub fn encode(self: Envelope, gpa: std.mem.Allocator) Error![]u8 {
        const v = try self.toCbor(gpa);
        defer v.deinit(gpa);
        return cbor.encode(gpa, v);
    }
};

/// Build an owned Envelope from a (just-decoded) cbor.Value. Validates each
/// included key matches its entity hash (§3.1). Frees nothing of the caller's.
pub fn envelopeOfCbor(gpa: std.mem.Allocator, c: Value) Error!Envelope {
    const root_src = mapGet(c, "root") orelse return error.BadEntity;
    const root = try ofCbor(gpa, root_src);
    errdefer root.deinit(gpa);

    var list: std.ArrayList(Included) = .empty;
    errdefer {
        for (list.items) |inc| {
            gpa.free(inc.key);
            inc.entity.deinit(gpa);
        }
        list.deinit(gpa);
    }
    if (mapGet(c, "included")) |inc_v| {
        switch (inc_v) {
            .map => |kvs| {
                for (kvs) |p| {
                    const key_bytes = switch (p.key) {
                        .bytes => |b| b,
                        else => return error.BadEntity,
                    };
                    const e = try ofCbor(gpa, p.value);
                    errdefer e.deinit(gpa);
                    if (!std.mem.eql(u8, key_bytes, e.hash)) return error.IncludedKeyMismatch;
                    const key = try gpa.dupe(u8, key_bytes);
                    errdefer gpa.free(key);
                    try list.append(gpa, .{ .key = key, .entity = e });
                }
            },
            else => return error.BadEntity,
        }
    }
    return .{ .root = root, .included = try list.toOwnedSlice(gpa) };
}

pub fn envelopeOfFrame(gpa: std.mem.Allocator, payload: []const u8) Error!Envelope {
    const v = try cbor.decode(gpa, payload);
    defer v.deinit(gpa);
    return envelopeOfCbor(gpa, v);
}

// ── small cbor.Value helpers (owned allocations) ─────────────────────────────

pub fn mapGet(c: Value, key: []const u8) ?Value {
    switch (c) {
        .map => |kvs| {
            for (kvs) |p| {
                switch (p.key) {
                    .text => |t| if (std.mem.eql(u8, t, key)) return p.value,
                    else => {},
                }
            }
            return null;
        },
        else => return null,
    }
}

pub fn textVal(gpa: std.mem.Allocator, s: []const u8) Error!Value {
    return .{ .text = try gpa.dupe(u8, s) };
}
pub fn bytesVal(gpa: std.mem.Allocator, s: []const u8) Error!Value {
    return .{ .bytes = try gpa.dupe(u8, s) };
}

/// Deep clone of a cbor.Value tree (borrowed-in → owned-out).
pub fn cloneValue(gpa: std.mem.Allocator, v: Value) Error!Value {
    return switch (v) {
        .uint, .nint, .boolean, .null, .float => v,
        .bytes => |s| .{ .bytes = try gpa.dupe(u8, s) },
        .text => |s| .{ .text = try gpa.dupe(u8, s) },
        .array => |items| blk: {
            const out = try gpa.alloc(Value, items.len);
            var built: usize = 0;
            errdefer {
                for (out[0..built]) |it| it.deinit(gpa);
                gpa.free(out);
            }
            while (built < items.len) : (built += 1) out[built] = try cloneValue(gpa, items[built]);
            break :blk .{ .array = out };
        },
        .map => |pairs| blk: {
            const out = try gpa.alloc(Value.Pair, pairs.len);
            var built: usize = 0;
            errdefer {
                for (out[0..built]) |p| {
                    p.key.deinit(gpa);
                    p.value.deinit(gpa);
                }
                gpa.free(out);
            }
            while (built < pairs.len) : (built += 1) {
                const k = try cloneValue(gpa, pairs[built].key);
                errdefer k.deinit(gpa);
                const val = try cloneValue(gpa, pairs[built].value);
                out[built] = .{ .key = k, .value = val };
            }
            break :blk .{ .map = out };
        },
    };
}

/// Lowercase hex of a byte slice (for tree-path hash segments). Owned.
pub fn hex(gpa: std.mem.Allocator, s: []const u8) Error![]u8 {
    const out = try gpa.alloc(u8, s.len * 2);
    const digits = "0123456789abcdef";
    for (s, 0..) |b, i| {
        out[i * 2] = digits[b >> 4];
        out[i * 2 + 1] = digits[b & 0xf];
    }
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "entity make/deinit round trip leak-clean" {
    const gpa = testing.allocator;
    var pairs = [_]Value.Pair{.{ .key = .{ .text = "k" }, .value = .{ .uint = 1 } }};
    const data = try cloneValue(gpa, .{ .map = &pairs });
    const e = try Entity.make(gpa, "system/test", data);
    defer e.deinit(gpa);
    try testing.expectEqual(@as(usize, 33), e.hash.len);
    try testing.expectEqual(@as(u64, 1), e.uintField("k").?);
}

test "entity wire round trip validates content_hash (§1.8)" {
    const gpa = testing.allocator;
    var pairs = [_]Value.Pair{.{ .key = .{ .text = "x" }, .value = .{ .uint = 7 } }};
    const data = try cloneValue(gpa, .{ .map = &pairs });
    const e = try Entity.make(gpa, "system/test", data);
    defer e.deinit(gpa);
    const wire = try e.toCbor(gpa);
    defer wire.deinit(gpa);
    const back = try ofCbor(gpa, wire);
    defer back.deinit(gpa);
    try testing.expectEqualSlices(u8, e.hash, back.hash);
}

test "envelope round trip through frame leak-clean" {
    const gpa = testing.allocator;
    const root = try Entity.make(gpa, "system/root", .{ .map = &.{} });
    // envelope takes ownership of root; build with empty included.
    const env = Envelope{ .root = root, .included = try gpa.alloc(Included, 0) };
    defer env.deinit(gpa);
    const frame = try env.encode(gpa);
    defer gpa.free(frame);
    const back = try envelopeOfFrame(gpa, frame);
    defer back.deinit(gpa);
    try testing.expectEqualSlices(u8, root.hash, back.root.hash);
}
