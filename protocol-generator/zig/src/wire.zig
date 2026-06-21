//! Wire framing (§1.6) and the two L2 message builders (§3.2 EXECUTE, §3.3
//! EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR-encoded envelope payload].
//! Reads/writes a full frame over a std.net.Stream; the reader/writer threading
//! lives in transport.zig (A-ZIG-003 std.Thread model).
//!
//! No-GC idiom: builders return owned Entities the caller frees; frame I/O uses a
//! caller-provided allocator for the read buffer (caller frees).

const std = @import("std");
const cbor = @import("cbor.zig");
const model = @import("model.zig");

const Entity = model.Entity;
const Value = model.Value;

pub const max_frame: usize = 16 * 1024 * 1024; // §1.6 SHOULD bound — 16 MiB

pub const Error = error{
    Closed,
    FrameTooLarge,
    WriteFailed,
} || model.Error;

/// Builders allocate but do no I/O — they carry only the codec/entity errors.
pub const BuildError = model.Error;

// ── fd read/write of a full frame ────────────────────────────────────────────

fn readExact(stream: std.net.Stream, buf: []u8) Error!void {
    var off: usize = 0;
    while (off < buf.len) {
        const r = stream.read(buf[off..]) catch return error.Closed;
        if (r == 0) return error.Closed;
        off += r;
    }
}

/// Read one length-prefixed frame; returns the owned payload (caller frees).
pub fn readFrame(gpa: std.mem.Allocator, stream: std.net.Stream) Error![]u8 {
    var hdr: [4]u8 = undefined;
    try readExact(stream, &hdr);
    const len = (@as(usize, hdr[0]) << 24) | (@as(usize, hdr[1]) << 16) |
        (@as(usize, hdr[2]) << 8) | @as(usize, hdr[3]);
    if (len > max_frame) return error.FrameTooLarge;
    const payload = try gpa.alloc(u8, len);
    errdefer gpa.free(payload);
    try readExact(stream, payload);
    return payload;
}

/// Write a length-prefixed frame. The caller serializes concurrent writes (the
/// transport holds a mutex over the shared stream).
pub fn writeFrame(stream: std.net.Stream, payload: []const u8) Error!void {
    var hdr: [4]u8 = undefined;
    const len = payload.len;
    hdr[0] = @truncate(len >> 24);
    hdr[1] = @truncate(len >> 16);
    hdr[2] = @truncate(len >> 8);
    hdr[3] = @truncate(len);
    stream.writeAll(&hdr) catch return error.WriteFailed;
    stream.writeAll(payload) catch return error.WriteFailed;
}

// ── envelope <-> frame ───────────────────────────────────────────────────────

pub fn frameOfEnvelope(gpa: std.mem.Allocator, env: model.Envelope) BuildError![]u8 {
    return env.encode(gpa);
}

// ── EXECUTE_RESPONSE builder (§3.3) ──────────────────────────────────────────

/// Build an EXECUTE_RESPONSE entity. Takes ownership of `result` (consumed into
/// the response's data tree). Returns an owned Entity the caller frees.
pub fn makeResponse(gpa: std.mem.Allocator, request_id: []const u8, status: u64, result: Entity) BuildError!Entity {
    const result_cbor = try result.toCbor(gpa);
    result.deinit(gpa);
    errdefer result_cbor.deinit(gpa);

    var pairs = try gpa.alloc(Value.Pair, 3);
    errdefer gpa.free(pairs);
    pairs[0] = .{ .key = try model.textVal(gpa, "request_id"), .value = try model.textVal(gpa, request_id) };
    pairs[1] = .{ .key = try model.textVal(gpa, "status"), .value = .{ .uint = status } };
    pairs[2] = .{ .key = try model.textVal(gpa, "result"), .value = result_cbor };
    return Entity.make(gpa, "system/protocol/execute/response", .{ .map = pairs });
}

// ── EXECUTE builder (§3.2) ───────────────────────────────────────────────────

pub const ExecuteFields = struct {
    request_id: []const u8,
    uri: []const u8,
    operation: []const u8,
    params: Entity, // consumed
    /// optional resource target value (consumed if present)
    resource: ?Value = null,
    author: ?[]const u8 = null,
    capability: ?[]const u8 = null,
};

/// Build an EXECUTE entity. Consumes `params` (and `resource` if present).
pub fn makeExecute(gpa: std.mem.Allocator, f: ExecuteFields) BuildError!Entity {
    const params_cbor = try f.params.toCbor(gpa);
    f.params.deinit(gpa);
    errdefer params_cbor.deinit(gpa);

    var list: std.ArrayList(Value.Pair) = .empty;
    errdefer {
        for (list.items) |p| {
            p.key.deinit(gpa);
            p.value.deinit(gpa);
        }
        list.deinit(gpa);
    }
    try list.append(gpa, .{ .key = try model.textVal(gpa, "request_id"), .value = try model.textVal(gpa, f.request_id) });
    try list.append(gpa, .{ .key = try model.textVal(gpa, "uri"), .value = try model.textVal(gpa, f.uri) });
    try list.append(gpa, .{ .key = try model.textVal(gpa, "operation"), .value = try model.textVal(gpa, f.operation) });
    try list.append(gpa, .{ .key = try model.textVal(gpa, "params"), .value = params_cbor });
    if (f.author) |a| try list.append(gpa, .{ .key = try model.textVal(gpa, "author"), .value = try model.bytesVal(gpa, a) });
    if (f.capability) |c| try list.append(gpa, .{ .key = try model.textVal(gpa, "capability"), .value = try model.bytesVal(gpa, c) });
    if (f.resource) |r| try list.append(gpa, .{ .key = try model.textVal(gpa, "resource"), .value = r });
    const pairs = try list.toOwnedSlice(gpa);
    return Entity.make(gpa, "system/protocol/execute", .{ .map = pairs });
}

// ── small result entities ────────────────────────────────────────────────────

/// system/protocol/error result entity (§3.3). Owned.
pub fn errorResult(gpa: std.mem.Allocator, code: []const u8, message: ?[]const u8) BuildError!Entity {
    var list: std.ArrayList(Value.Pair) = .empty;
    errdefer {
        for (list.items) |p| {
            p.key.deinit(gpa);
            p.value.deinit(gpa);
        }
        list.deinit(gpa);
    }
    try list.append(gpa, .{ .key = try model.textVal(gpa, "code"), .value = try model.textVal(gpa, code) });
    if (message) |m| try list.append(gpa, .{ .key = try model.textVal(gpa, "message"), .value = try model.textVal(gpa, m) });
    return Entity.make(gpa, "system/protocol/error", .{ .map = try list.toOwnedSlice(gpa) });
}

/// Empty-params entity (§3.2): primitive/any whose data is the canonical empty map.
pub fn emptyParams(gpa: std.mem.Allocator) BuildError!Entity {
    return Entity.make(gpa, "primitive/any", .{ .map = try gpa.alloc(Value.Pair, 0) });
}

const testing = std.testing;

test "response builder consumes result and is well-formed" {
    const gpa = testing.allocator;
    const result = try emptyParams(gpa);
    const resp = try makeResponse(gpa, "r1", 404, result);
    defer resp.deinit(gpa);
    try testing.expectEqualStrings("system/protocol/execute/response", resp.typ);
    try testing.expectEqual(@as(u64, 404), resp.uintField("status").?);
    try testing.expectEqualStrings("r1", resp.textField("request_id").?);
}
