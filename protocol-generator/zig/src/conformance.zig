//! ECF conformance harness — loads the normative fixture
//! (conformance-vectors-v1.cbor) and runs every vector through the codec,
//! checking byte-identity (encode_equal) or rejection (decode_reject) per
//! Appendix E §E.3. The fixture carries its own cross-blessed `canonical` bytes
//! (produced + 3-way cross-blessed by the Go/Rust/Python oracles), so this is
//! self-contained — no running Go oracle needed at S2 (the Go wire-conformance
//! binary is the fixture producer, not a runtime checker). std.testing.allocator
//! is NOT used here (this is a CLI exe, not a test); a GeneralPurposeAllocator
//! with leak detection backs it instead so any leak is reported on exit.

const std = @import("std");
const codec = @import("root.zig");
const cbor = codec.cbor;

const Value = cbor.Value;

fn mapGet(m: []Value.Pair, name: []const u8) ?Value {
    for (m) |p| {
        switch (p.key) {
            .text => |t| if (std.mem.eql(u8, t, name)) return p.value,
            else => {},
        }
    }
    return null;
}

fn asMap(v: Value) []Value.Pair {
    return switch (v) {
        .map => |m| m,
        else => unreachable,
    };
}
fn asText(v: Value) []const u8 {
    return switch (v) {
        .text => |t| t,
        else => unreachable,
    };
}
fn asBytes(v: Value) []const u8 {
    return switch (v) {
        .bytes => |b| b,
        else => unreachable,
    };
}
fn asUint(v: Value) u64 {
    return switch (v) {
        .uint => |n| n,
        else => unreachable,
    };
}

fn category(id: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, id, '.')) |i| return id[0..i];
    return id;
}

const Outcome = union(enum) { pass, fail: []const u8 };

/// Run one vector. `scratch` is a per-vector arena (freed by the caller); any
/// produced bytes live in it, so we never leak across vectors.
fn runVector(scratch: std.mem.Allocator, vm: []Value.Pair) !Outcome {
    const id = asText(mapGet(vm, "id").?);
    const kind = asText(mapGet(vm, "kind").?);
    const canon = asBytes(mapGet(vm, "canonical").?);
    const cat = category(id);

    if (std.mem.eql(u8, kind, "decode_reject")) {
        // The decoder MUST reject these wire bytes (tags / non-canonical).
        if (cbor.decode(scratch, canon)) |v| {
            v.deinit(scratch);
            return .{ .fail = "decoder accepted a reject vector" };
        } else |_| {
            return .pass;
        }
    }

    // encode_equal: produce bytes per category, compare to canon.
    var produced: []u8 = undefined;
    if (std.mem.eql(u8, cat, "content_hash")) {
        const input = asMap(mapGet(vm, "input").?);
        const typ = asText(mapGet(input, "type").?);
        const data = mapGet(input, "data").?;
        const fc: u64 = if (mapGet(input, "format_code")) |v| asUint(v) else 0;
        produced = try codec.hash.contentHash(scratch, fc, typ, data);
    } else if (std.mem.eql(u8, cat, "peer_id")) {
        const input = asMap(mapGet(vm, "input").?);
        const key_type = asUint(mapGet(input, "key_type").?);
        const hash_type = asUint(mapGet(input, "hash_type").?);
        const digest = asBytes(mapGet(input, "digest").?);
        const pid = try codec.peer_id.format(scratch, .{ .key_type = key_type, .hash_type = hash_type, .digest = digest });
        // canonical bytes are the ECF encoding of the peer-id text string.
        produced = try cbor.encode(scratch, .{ .text = pid });
    } else if (std.mem.eql(u8, cat, "signature")) {
        const input = asMap(mapGet(vm, "input").?);
        const seed_b = asBytes(mapGet(input, "seed").?);
        const entity = asMap(mapGet(input, "entity").?);
        const typ = asText(mapGet(entity, "type").?);
        const data = mapGet(entity, "data").?;
        const msg = try codec.hash.ecfOfEntity(scratch, typ, data);
        var seed: [32]u8 = undefined;
        @memcpy(&seed, seed_b[0..32]);
        const sig = try codec.sign.sign(seed, msg);
        produced = try scratch.dupe(u8, &sig);
    } else {
        // float / int / map_keys / length / primitive / nested / envelope:
        // re-encode the decoded input value canonically.
        produced = try cbor.encode(scratch, mapGet(vm, "input").?);
    }

    if (std.mem.eql(u8, produced, canon)) return .pass;
    const msg = try std.fmt.allocPrint(scratch, "want {x} got {x}", .{ canon, produced });
    return .{ .fail = msg };
}

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var args = try std.process.argsWithAllocator(gpa);
    defer args.deinit();
    _ = args.next(); // exe name
    const path = args.next() orelse "../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor";

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const bytes = try file.readToEndAlloc(gpa, 1 << 24);
    defer gpa.free(bytes);

    const fixture = try cbor.decode(gpa, bytes);
    defer fixture.deinit(gpa);
    const vectors = switch (fixture) {
        .array => |a| a,
        else => return error.FixtureNotArray,
    };

    const stdout = std.fs.File.stdout();
    var pass: usize = 0;
    var fail: usize = 0;

    // per-category tallies
    var cats: std.StringArrayHashMapUnmanaged([2]usize) = .empty;
    defer cats.deinit(gpa);

    for (vectors) |vraw| {
        const vm = asMap(vraw);
        const id = asText(mapGet(vm, "id").?);
        const cat = category(id);

        // per-vector arena — everything runVector allocates dies here.
        var arena = std.heap.ArenaAllocator.init(gpa);
        const outcome = try runVector(arena.allocator(), vm);

        const gop = try cats.getOrPut(gpa, cat);
        if (!gop.found_existing) gop.value_ptr.* = .{ 0, 0 };
        switch (outcome) {
            .pass => {
                pass += 1;
                gop.value_ptr.*[0] += 1;
            },
            .fail => |m| {
                fail += 1;
                gop.value_ptr.*[1] += 1;
                var buf: [512]u8 = undefined;
                const line = std.fmt.bufPrint(&buf, "FAIL {s}  {s}\n", .{ id, m }) catch "FAIL (msg too long)\n";
                _ = stdout.writeAll(line) catch {};
            },
        }
        arena.deinit();
    }

    var buf: [256]u8 = undefined;
    _ = stdout.writeAll("\n-- by category --\n") catch {};
    var it = cats.iterator();
    while (it.next()) |e| {
        const p = e.value_ptr.*[0];
        const f = e.value_ptr.*[1];
        const line = std.fmt.bufPrint(&buf, "  {s:<14} {d}/{d}\n", .{ e.key_ptr.*, p, p + f }) catch continue;
        _ = stdout.writeAll(line) catch {};
    }
    const total = std.fmt.bufPrint(&buf, "\nTOTAL: {d} passed, {d} failed (of {d})\n", .{ pass, fail, pass + fail }) catch "";
    _ = stdout.writeAll(total) catch {};

    if (fail > 0) std.process.exit(1);
}
