//! entity-core-protocol-zig — standalone peer host.
//!
//! The runnable target for S4 conformance: boots a single Peer listener on a TCP
//! port and blocks until signalled, so an external oracle (entity-core-go
//! `validate-peer`) can drive the live wire surface against it. Twin of the C#
//! `EntityCore.Protocol.Host` / TS `host.ts` programs.
//!
//!   --port N               listen port (default 7777; 0 = auto-assign)
//!   --debug-open-grants    select the degenerate `default → *` seed policy
//!                          (the retired wide-open admin grant, routed through the
//!                          real §6.9a mechanism). Debug only.
//!   --validate             register the §7a system/validate/* conformance handlers
//!                          (off by default; deferred bodies land in S4).
//!   --name NAME            load a persistent Ed25519 identity from the standard
//!                          on-disk location ~/.entity/peers/NAME/keypair (the
//!                          entity-core PEM keypair: base64 of a 32-byte seed
//!                          between BEGIN/END ENTITY PRIVATE KEY lines — the same
//!                          convention the Go entity-peer --name / peer-manager use).
//!                          Without --name a random seed is used.
//!
//! Binds loopback (127.0.0.1); run the validator in the same network namespace. A
//! single `LISTENING …` line goes to stdout once bound — a run script waits for it.
//!
//! Run (in-container): `zig build && ./zig-out/bin/host --port 7777 [--debug-open-grants]`.

const std = @import("std");
const root = @import("root.zig");
const peer_mod = root.peer;
const transport = root.transport;

const Peer = peer_mod.Peer;
const Conn = peer_mod.Conn;

const ConnState = struct {
    io: transport.Io,
    conn: Conn,
};

fn serveConnection(peer: *Peer, gpa: std.mem.Allocator, stream: std.net.Stream) void {
    transport.setNoDelay(stream); // low-latency request/response (handshake churn — §7b t2_2)
    var cs = gpa.create(ConnState) catch {
        stream.close();
        return;
    };
    cs.* = .{ .io = transport.Io.init(gpa, stream), .conn = .{} };
    transport.readLoop(peer, &cs.conn, &cs.io);
    cs.io.deinit();
    cs.conn.deinit(gpa);
    stream.close();
    gpa.destroy(cs);
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var port: u16 = 7777;
    var open_grants = false;
    var validate = false;
    var seed = randomSeed();

    var args = try std.process.argsWithAllocator(gpa);
    defer args.deinit();
    _ = args.next(); // exe name
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            const next = args.next() orelse {
                std.debug.print("error: --port requires an integer\n", .{});
                std.process.exit(2);
            };
            port = std.fmt.parseInt(u16, next, 10) catch {
                std.debug.print("error: bad --port value\n", .{});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, arg, "--name")) {
            const next = args.next() orelse {
                std.debug.print("error: --name requires a value\n", .{});
                std.process.exit(2);
            };
            seed = loadSeedFromName(gpa, next);
        } else if (std.mem.eql(u8, arg, "--debug-open-grants")) {
            open_grants = true;
        } else if (std.mem.eql(u8, arg, "--validate")) {
            validate = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("usage: host [--port N] [--name NAME] [--debug-open-grants] [--validate]\n", .{});
            return;
        } else {
            std.debug.print("error: unknown argument '{s}'\n", .{arg});
            std.process.exit(2);
        }
    }

    var peer = try peer_mod.create(gpa, .{ .seed = seed, .open_grants = open_grants, .conformance = validate });
    defer peer.deinit();

    var server = try transport.listen(port);
    defer server.deinit();
    const bound = server.listen_address.getPort();

    // single readiness line on stdout (matches the C#/TS host contract)
    const stdout = std.fs.File.stdout();
    var buf: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "LISTENING 127.0.0.1:{d} peer_id={s} open_grants={} validate={}\n", .{ bound, peer.local_peer, open_grants, validate });
    _ = try stdout.write(line);

    // accept loop — each connection served on its own thread (§4.8)
    while (true) {
        const accepted = server.accept() catch break;
        const th = std.Thread.spawn(.{}, serveConnection, .{ &peer, gpa, accepted.stream }) catch {
            accepted.stream.close();
            continue;
        };
        th.detach();
    }
}

fn randomSeed() [32]u8 {
    var s: [32]u8 = undefined;
    std.crypto.random.bytes(&s);
    return s;
}

/// Load the 32-byte Ed25519 seed from the standard on-disk keypair (Go entity-peer
/// --name / peer-manager convention): ~/.entity/peers/NAME/keypair, a PEM whose body
/// is base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines. Missing or malformed
/// → stderr + exit(2). Reads into an arena freed before return (no-GC posture); the
/// returned seed is a value copy, so nothing dangles.
fn loadSeedFromName(gpa: std.mem.Allocator, name: []const u8) [32]u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const home = std.process.getEnvVarOwned(a, "HOME") catch "/root";
    const path = std.fs.path.join(a, &.{ home, ".entity", "peers", name, "keypair" }) catch {
        std.debug.print("error: --name {s}: out of memory\n", .{name});
        std.process.exit(2);
    };

    const data = std.fs.cwd().readFileAlloc(a, path, 64 * 1024) catch |err| {
        std.debug.print("error: --name {s}: cannot read {s}: {s}\n", .{ name, path, @errorName(err) });
        std.process.exit(2);
    };

    // Concatenate the base64 body: every line that does not start with '-'.
    var body: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '-') continue;
        body.appendSlice(a, line) catch {
            std.debug.print("error: --name {s}: out of memory\n", .{name});
            std.process.exit(2);
        };
    }

    const dec = std.base64.standard.Decoder;
    const out_len = dec.calcSizeForSlice(body.items) catch {
        std.debug.print("error: --name {s}: malformed base64 keypair\n", .{name});
        std.process.exit(2);
    };
    if (out_len != 32) {
        std.debug.print("error: --name {s}: expected a 32-byte seed, got {d} bytes\n", .{ name, out_len });
        std.process.exit(2);
    }
    var seed: [32]u8 = undefined;
    dec.decode(&seed, body.items) catch {
        std.debug.print("error: --name {s}: malformed base64 keypair\n", .{name});
        std.process.exit(2);
    };
    return seed;
}
