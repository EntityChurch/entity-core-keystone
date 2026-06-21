//! S3 smoke runner — the phase exit gate. Two Zig peers talk over real loopback
//! TCP through the full dispatch chain: the §4.1 handshake (initiator hello →
//! authenticate, both legs answered by the responder over real frames), 404 on an
//! unregistered path, an authority-gated tree get (200), a capability request
//! (200), and 8-way `request_id` demux of concurrently-issued replies (N7). Then a
//! clean teardown.
//!
//! Leak-checked: the whole run uses a GeneralPurposeAllocator (safety on); any
//! un-freed entity / envelope / store binding fails the run with a leak report —
//! the free-correctness conformance bonus unique to the no-GC peer (A-ZIG-004).
//!
//! Run (in-container): `zig build smoke`.

const std = @import("std");
const root = @import("root.zig");
const model = root.model;
const wire = root.wire;
const peer_mod = root.peer;
const transport = root.transport;

const Peer = peer_mod.Peer;
const Conn = peer_mod.Conn;
const Entity = model.Entity;
const Value = model.Value;
const Envelope = model.Envelope;

var pass_count: usize = 0;
var fail_count: usize = 0;

fn check(name: []const u8, ok: bool) void {
    if (ok) pass_count += 1 else fail_count += 1;
    std.debug.print("  [{s}] {s}\n", .{ if (ok) "PASS" else "FAIL", name });
}

// ── responder serve orchestration ────────────────────────────────────────────

const ServeArgs = struct {
    peer: *Peer,
    server: *std.net.Server,
    gpa: std.mem.Allocator,
};

const ConnState = struct {
    io: transport.Io,
    conn: Conn,
};

/// Accept one connection, run its reader loop to completion, tear it down. The
/// responder side: the reader dispatches the initiator's hello + authenticate and
/// every subsequent EXECUTE, writing each response over the shared stream.
fn serveOne(args: *ServeArgs) void {
    const gpa = args.gpa;
    const accepted = args.server.accept() catch return;
    var cs = gpa.create(ConnState) catch {
        accepted.stream.close();
        return;
    };
    cs.* = .{ .io = transport.Io.init(gpa, accepted.stream), .conn = .{} };
    // wire the §6.13(b) outbound seam to this connection (reentry available)
    transport.readLoop(args.peer, &cs.conn, &cs.io); // blocks until close
    cs.io.deinit();
    cs.conn.deinit(gpa);
    accepted.stream.close();
    gpa.destroy(cs);
}

// ── a resource-target value for system/type/system/peer ──────────────────────

fn typeTarget(gpa: std.mem.Allocator) !Value {
    const targets = try gpa.alloc(Value, 1);
    targets[0] = try model.textVal(gpa, "system/type/system/peer");
    var pairs = try gpa.alloc(Value.Pair, 1);
    pairs[0] = .{ .key = try model.textVal(gpa, "targets"), .value = .{ .array = targets } };
    return .{ .map = pairs };
}

// ── capability/request params: a request for system/tree get on system/type/* ─

fn requestParams(gpa: std.mem.Allocator) !Entity {
    const scope = struct {
        fn f(a: std.mem.Allocator, incl: []const u8) !Value {
            const items = try a.alloc(Value, 1);
            items[0] = try model.textVal(a, incl);
            var p = try a.alloc(Value.Pair, 1);
            p[0] = .{ .key = try model.textVal(a, "include"), .value = .{ .array = items } };
            return .{ .map = p };
        }
    }.f;
    var gpairs = try gpa.alloc(Value.Pair, 3);
    gpairs[0] = .{ .key = try model.textVal(gpa, "handlers"), .value = try scope(gpa, "system/tree") };
    gpairs[1] = .{ .key = try model.textVal(gpa, "resources"), .value = try scope(gpa, "system/type/*") };
    gpairs[2] = .{ .key = try model.textVal(gpa, "operations"), .value = try scope(gpa, "get") };
    const grants = try gpa.alloc(Value, 1);
    grants[0] = .{ .map = gpairs };
    var ppairs = try gpa.alloc(Value.Pair, 1);
    ppairs[0] = .{ .key = try model.textVal(gpa, "grants"), .value = .{ .array = grants } };
    return Entity.make(gpa, "system/capability/request", .{ .map = ppairs });
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer {
        const leaked = gpa_state.deinit();
        if (leaked == .leak) {
            std.debug.print("\nLEAK DETECTED — SMOKE: FAIL\n", .{});
            std.process.exit(2);
        }
    }
    const gpa = gpa_state.allocator();

    var responder = try peer_mod.create(gpa, .{ .seed = [_]u8{1} ** 32, .open_grants = false });
    defer responder.deinit();
    var initiator = try peer_mod.create(gpa, .{ .seed = [_]u8{2} ** 32, .open_grants = false });
    defer initiator.deinit();

    var server = try transport.listen(0);
    defer server.deinit();
    const bound_port = server.listen_address.getPort();

    var serve_args = ServeArgs{ .peer = &responder, .server = &server, .gpa = gpa };
    const serve_thread = try std.Thread.spawn(.{}, serveOne, .{&serve_args});

    // ── dial + handshake ─────────────────────────────────────────────────────
    const addr = try std.net.Address.parseIp4("127.0.0.1", bound_port);
    const stream = try std.net.tcpConnectToAddress(addr);
    var io = transport.Io.init(gpa, stream);
    var conn = Conn{};
    // run the initiator's reader loop on its own thread so responses demux (N7)
    const reader_thread = try std.Thread.spawn(.{}, transport.readLoop, .{ &initiator, &conn, &io });

    std.debug.print("Handshake:\n", .{});
    var session = try transport.initiate(gpa, &initiator, &io, &conn);
    defer session.deinit(gpa);
    check("session established (initial capability granted)", session.capability.hash.len == 33);
    check("remote peer_id matches responder", std.mem.eql(u8, session.remote_peer_id, responder.local_peer));

    const remote = responder.local_peer;

    // ── dispatch ─────────────────────────────────────────────────────────────
    std.debug.print("Dispatch:\n", .{});
    {
        const uri = try std.fmt.allocPrint(gpa, "/{s}/does/not/exist", .{remote});
        defer gpa.free(uri);
        const resp = (try session.execute(gpa, uri, "noop", try wire.emptyParams(gpa), null)) orelse return error.NoResponse;
        defer resp.deinit(gpa);
        check("unregistered path -> 404", resp.root.uintField("status") == 404);
    }
    {
        const uri = try std.fmt.allocPrint(gpa, "/{s}/system/tree", .{remote});
        defer gpa.free(uri);
        const resp = (try session.execute(gpa, uri, "get", try wire.emptyParams(gpa), try typeTarget(gpa))) orelse return error.NoResponse;
        defer resp.deinit(gpa);
        check("granted tree get -> 200", resp.root.uintField("status") == 200);
        const result = try resp.root.entityField(gpa, "result");
        defer if (result) |r| r.deinit(gpa);
        check("tree get returns a system/type entity", result != null and std.mem.eql(u8, result.?.typ, "system/type"));
    }
    {
        const uri = try std.fmt.allocPrint(gpa, "/{s}/system/capability", .{remote});
        defer gpa.free(uri);
        const resp = (try session.execute(gpa, uri, "request", try requestParams(gpa), null)) orelse return error.NoResponse;
        defer resp.deinit(gpa);
        check("capability request -> 200", resp.root.uintField("status") == 200);
    }

    // ── concurrency: request_id demux (N7) ───────────────────────────────────
    std.debug.print("Concurrency (request_id demux):\n", .{});
    {
        const N = 8;
        var threads: [N]std.Thread = undefined;
        var oks = [_]bool{false} ** N;
        const Worker = struct {
            fn run(s: *transport.Session, g: std.mem.Allocator, rem: []const u8, ok_out: *bool) void {
                const uri = std.fmt.allocPrint(g, "/{s}/system/tree", .{rem}) catch return;
                defer g.free(uri);
                const tt = blk: {
                    const targets = g.alloc(Value, 1) catch return;
                    targets[0] = model.textVal(g, "system/type/system/peer") catch return;
                    var pairs = g.alloc(Value.Pair, 1) catch return;
                    pairs[0] = .{ .key = model.textVal(g, "targets") catch return, .value = .{ .array = targets } };
                    break :blk Value{ .map = pairs };
                };
                const params = wire.emptyParams(g) catch return;
                const resp = (s.execute(g, uri, "get", params, tt) catch return) orelse return;
                defer resp.deinit(g);
                if (resp.root.uintField("status") != 200) return;
                const result = resp.root.entityField(g, "result") catch return;
                defer if (result) |r| r.deinit(g);
                ok_out.* = result != null and std.mem.eql(u8, result.?.typ, "system/type");
            }
        };
        for (0..N) |i| threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ &session, gpa, remote, &oks[i] });
        for (0..N) |i| threads[i].join();
        var correlated: usize = 0;
        for (oks) |o| {
            if (o) correlated += 1;
        }
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "8 interleaved requests each correlated -> {d}/8", .{correlated}) catch "demux";
        check(msg, correlated == N);
    }

    // ── teardown ─────────────────────────────────────────────────────────────
    // shutdown(both) forces a blocked read() to return (a bare close() of an fd a
    // thread is parked in read() on does not reliably wake it on Linux); this EOFs
    // the initiator's own reader AND, peer-side, the responder's reader.
    io.close();
    std.posix.shutdown(stream.handle, .both) catch {};
    reader_thread.join();
    serve_thread.join();
    stream.close();
    io.deinit();

    const all_pass = fail_count == 0;
    std.debug.print("\nTeardown clean.   ->   SMOKE: {s} ({d} pass, {d} fail)\n", .{ if (all_pass) "PASS" else "FAIL", pass_count, fail_count });
    if (!all_pass) std.process.exit(1);
}
