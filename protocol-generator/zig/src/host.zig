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

// ── §4.10(c) connection-admission bound ──────────────────────────────────────
//
// This peer is thread-per-connection, so an unbounded accept loop turns a
// connection flood into that many concurrent threads. It had no bound at all, and
// `resource_bounds/r3_connection_flood` WARNed by design — §4.10(c) is a SHOULD,
// and "no self-imposed bound, admission delegated externally" is an accepted
// answer. It was not, however, a harmless one: measured over 22 full `--profile
// core` runs, r3 FAILED 4 times with *"admitted all 256 connections without
// refusal AND fell over on the serve probe … i/o timeout"*. The peer was not
// crashing and the accept loop was not exiting (both are instrumented above and
// stayed silent) — 256 live connection threads simply left it unable to answer the
// post-flood probe inside the oracle's deadline. An intermittent whose mechanism is
// saturation looks like flakiness and is not.
//
// THE RELEASE PATH IS THE WHOLE DESIGN. A counter that admits but never releases
// presents as a DEAD peer, not an over-permissive one, so:
//   * increment BEFORE the spawn — a detached thread can run to completion before
//     `spawn()` even returns, and a post-spawn increment can therefore go negative
//     or double-count;
//   * decrement LAST in the worker's teardown, after the stream is closed and the
//     state destroyed, so a slot is never free while its resources are still held.
// Refusal is a clean immediate close, which is what §4.10(c) asks for and what the
// oracle scores as self-bounded.
const max_connections: u32 = 64;
var live_connections = std.atomic.Value(u32).init(0);

fn serveConnection(peer: *Peer, gpa: std.mem.Allocator, stream: std.net.Stream) void {
    // Released LAST, and on every exit path including the early `create` failure.
    defer _ = live_connections.fetchSub(1, .release);

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
    //
    // A TRANSIENT accept() error MUST NOT end the loop. This used to be
    // `server.accept() catch break`, which treated every AcceptError as fatal —
    // and most of that error set is recoverable:
    //
    //   ConnectionAborted       the peer sent SYN then closed before we accepted
    //                           (ECONNABORTED). Rapid open→close churn MANUFACTURES
    //                           this race; §7b t2_2 does 100 such cycles.
    //   ProcessFdQuotaExceeded  EMFILE — transient, clears as connections drain
    //   SystemFdQuotaExceeded   ENFILE — likewise, host-wide
    //   SystemResources         ENOBUFS/ENOMEM under socket-buffer pressure
    //   WouldBlock              EAGAIN on a non-blocking listener
    //
    // Breaking on any of those stops the peer LISTENING while the process stays
    // alive and healthy, so every later connection gets `connection refused` and
    // the peer reads as crashed. Measured here: a census run failed
    // t2_2_connection_churn at cycle 53 and then failed 27 downstream checks with
    // connection-refused, while an isolated re-run of the same binary passed —
    // the timing of the client's close decides whether the race fires, so the
    // defect presents as flakiness. It is not flakiness: a client that opens and
    // immediately aborts one connection can permanently kill this listener.
    //
    // Only a genuinely fatal condition ends the loop — the listening socket is
    // gone or was never a listening socket, which is the shutdown path the old
    // `break` was actually written for.
    while (true) {
        const accepted = server.accept() catch |err| switch (err) {
            error.ConnectionAborted, error.WouldBlock, error.ProtocolFailure => continue,
            // Resource exhaustion: retry, but yield first so we do not spin hot
            // against a full descriptor table.
            error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => {
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            },
            // FileDescriptorNotASocket, SocketNotListening, BlockedByFirewall,
            // Unexpected — the listener is unusable; stop.
            //
            // SAY SO ON THE WAY OUT. A peer that stops accepting while the process
            // stays alive is indistinguishable from a crash to every client — they
            // all get `connection refused` — and indistinguishable from nothing at
            // all to anyone reading stderr afterwards, which is exactly the state
            // that made the r3/churn intermittent unattributable: no panic, no
            // backtrace, empty stderr, and a listener that had quietly gone away.
            // One line converts "not root-caused" into a named errno.
            else => {
                std.debug.print("host: accept loop EXITING on fatal error: {s}\n", .{@errorName(err)});
                break;
            },
        };
        // §4.10(c): reserve the slot BEFORE spawning (see the note on the counter).
        // Over the bound, refuse cleanly — close immediately, keep accepting — so a
        // flood is shed rather than absorbed, and the peer stays answerable.
        if (live_connections.fetchAdd(1, .acquire) >= max_connections) {
            _ = live_connections.fetchSub(1, .release);
            accepted.stream.close();
            continue;
        }

        // A spawn failure closes the connection and keeps serving — correct, but it
        // is ALSO a silent refusal, so name the errno for the same reason as the
        // accept arm above. The reserved slot is released here because the worker
        // that would have released it never started.
        const th = std.Thread.spawn(.{}, serveConnection, .{ &peer, gpa, accepted.stream }) catch |err| {
            std.debug.print("host: thread spawn refused a connection: {s}\n", .{@errorName(err)});
            _ = live_connections.fetchSub(1, .release);
            accepted.stream.close();
            continue;
        };
        // KNOWN RESIDUAL, root-caused here and NOT fixed — do not read the admission
        // bound above as closing it. `detach()` hands the thread's own teardown the
        // job of freeing its stack+TLS+Instance mapping, and that teardown aborts the
        // PROCESS intermittently:
        //
        //   thread NNNNN panic: reached unreachable code
        //   /opt/zig/lib/std/Thread.zig:1377:31 in entryFn
        //       defer switch (self.thread.completion.swap(.completed, .seq_cst)) {
        //
        // That arm is `.completed => unreachable`, so the completion was ALREADY
        // `.completed` when this thread finished — i.e. an `Instance` mapping was
        // reused while its previous thread was still inside this `defer`. It is the
        // detached-thread lifetime race one level below our code: `freeAndExit`
        // munmaps the region, and a concurrent `spawn()` can be handed the same
        // address.
        //
        // Measured, because "flaky" is not a diagnosis: over 60 full `--profile core`
        // runs with the bound in place it aborted 5 times (8%), always first visible
        // as `t2_2_connection_churn` failing mid-cycle with `broken pipe`, after which
        // every later check reports `connection refused` — INCLUDING r3, whose
        // "admission slots leaked" message is the oracle's inference from a dead peer
        // and is not the mechanism. The accept-loop-exit line below never fires in
        // those runs, which is what proves the process died rather than stopped
        // listening.
        //
        // Fixing it means not detaching — owning the handles and joining them — which
        // is real machinery and is not attempted here.
        th.detach();
    }
    std.debug.print("host: accept loop has EXITED — no longer listening\n", .{});
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
