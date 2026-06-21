//! Transport (L4) — TCP listener + dialer + per-connection serve loop, on
//! std.Thread (A-ZIG-003: Zig's async is in flux; OS threads are stable + std-only).
//!
//! Concurrency model (validates A-ZIG-003 / N6 / N7):
//!   - One READER thread per connection demuxes inbound frames (§6.11). An
//!     EXECUTE_RESPONSE is routed to the awaiting outbound caller by request_id; an
//!     inbound EXECUTE is dispatched on its OWN thread (§4.8) so a handler that
//!     originates an outbound EXECUTE (§6.13(b)) and awaits its reply does NOT block
//!     the reader — the reader keeps reading and routes the reply back.
//!   - Writes (responses + outbound requests share the stream) are serialized by a
//!     std.Thread.Mutex (A-ZIG-003 primitive).
//!   - A pending-request table (request_id → slot+condvar) is the §6.11 demux. A
//!     never-arriving reply is bounded by connection close (broadcasts all waiters).
//!
//! No-GC idiom: every inbound frame's decoded envelope is freed after dispatch;
//! pending slots own their response envelope until the waiter takes it. A
//! per-connection GeneralPurposeAllocator-or-shared gpa threads through.

const std = @import("std");
const model = @import("model.zig");
const wire = @import("wire.zig");
const peer_mod = @import("peer.zig");

const Envelope = model.Envelope;
const Entity = model.Entity;
const Value = model.Value;
const Peer = peer_mod.Peer;
const Conn = peer_mod.Conn;

pub const Error = error{ OutOfMemory, Timeout, ConnectionBroken } || wire.Error || peer_mod.Error;

const PendingSlot = struct {
    response: ?Envelope = null,
    done: bool = false,
};

/// Per-connection IO state: the shared stream, write serialization, and the
/// §6.11 pending-response demux table.
pub const Io = struct {
    gpa: std.mem.Allocator,
    stream: std.net.Stream,
    write_mutex: std.Thread.Mutex = .{},
    pending_mutex: std.Thread.Mutex = .{},
    pending_cond: std.Thread.Condition = .{},
    pending: std.StringHashMapUnmanaged(*PendingSlot) = .{},
    closed: bool = false,

    pub fn init(gpa: std.mem.Allocator, stream: std.net.Stream) Io {
        return .{ .gpa = gpa, .stream = stream };
    }

    pub fn deinit(self: *Io) void {
        self.pending.deinit(self.gpa);
    }

    /// Serialized framed write (responses + outbound requests share the stream).
    pub fn writeFramed(self: *Io, env: Envelope) Error!void {
        const payload = try wire.frameOfEnvelope(self.gpa, env);
        defer self.gpa.free(payload);
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        try wire.writeFrame(self.stream, payload);
    }

    /// Route an inbound EXECUTE_RESPONSE to its awaiting outbound caller (§6.11).
    /// Takes ownership of `env` (stored in the slot or freed if unmatched).
    fn routeResponse(self: *Io, env: Envelope) void {
        const request_id = env.root.textField("request_id") orelse "";
        self.pending_mutex.lock();
        defer self.pending_mutex.unlock();
        if (self.pending.get(request_id)) |slot| {
            slot.response = env;
            slot.done = true;
            self.pending_cond.broadcast();
        } else {
            env.deinit(self.gpa);
        }
    }

    /// §6.13(b) outbound: send a request envelope, await its correlated reply.
    /// Returns the owned response Envelope (caller frees), or null on close.
    pub fn outbound(self: *Io, request: Envelope) Error!?Envelope {
        const request_id_src = request.root.textField("request_id") orelse "";
        const request_id = try self.gpa.dupe(u8, request_id_src);
        var slot = PendingSlot{};
        {
            self.pending_mutex.lock();
            defer self.pending_mutex.unlock();
            if (self.closed) {
                self.gpa.free(request_id);
                return null;
            }
            try self.pending.put(self.gpa, request_id, &slot);
        }
        try self.writeFramed(request);
        self.pending_mutex.lock();
        while (!slot.done and !self.closed) self.pending_cond.wait(&self.pending_mutex);
        _ = self.pending.remove(request_id);
        self.pending_mutex.unlock();
        self.gpa.free(request_id);
        return slot.response;
    }

    /// Wake every pending outbound waiter on connection close.
    pub fn close(self: *Io) void {
        self.pending_mutex.lock();
        self.closed = true;
        self.pending_cond.broadcast();
        self.pending_mutex.unlock();
    }
};

// ── reader loop (§6.11 demux) ────────────────────────────────────────────────

const DispatchCtx = struct {
    peer: *Peer,
    conn: *Conn,
    io: *Io,
    env: Envelope,
};

/// §6.11 reentry shim: adapt `Io.outbound` to the peer's OutboundFn ABI so a §7a
/// dispatch-outbound handler can originate back over the inbound connection. The
/// `ctx` is the `*Io`; `gpa` is the handler's (arena) allocator. The reply arrives
/// io.gpa-owned; we deep-clone it into the handler's arena and free the original,
/// so the returned Envelope is owned by the handler's arena (freed on arena reset).
fn outboundShim(ctx: ?*anyopaque, gpa: std.mem.Allocator, req: Envelope) ?Envelope {
    const io: *Io = @ptrCast(@alignCast(ctx.?));
    const reply = (io.outbound(req) catch null) orelse return null;
    defer reply.deinit(io.gpa);
    // re-root into the handler's arena
    const root = reply.root.clone(gpa) catch return null;
    const included = gpa.alloc(model.Included, reply.included.len) catch return null;
    for (reply.included, 0..) |inc, i| {
        included[i] = .{
            .key = gpa.dupe(u8, inc.key) catch return null,
            .entity = inc.entity.clone(gpa) catch return null,
        };
    }
    return Envelope{ .root = root, .included = included };
}

/// Dispatch one inbound EXECUTE on its own thread (§4.8); frees `ctx` + `env`.
fn dispatchExecuteThread(ctx: *DispatchCtx) void {
    const io = ctx.io;
    const env = ctx.env;
    defer {
        env.deinit(io.gpa);
        io.gpa.destroy(ctx);
    }
    // Bind the §6.11 reentry seam so a §7a dispatch-outbound handler can originate.
    ctx.conn.outbound = &outboundShim;
    ctx.conn.outbound_ctx = io;
    const resp = peer_mod.dispatch(ctx.peer, ctx.conn, env) catch {
        const er = peer_mod.internalErrorResponse(ctx.peer, env) catch return;
        defer er.deinit(io.gpa);
        io.writeFramed(er) catch {};
        return;
    };
    if (resp) |r| {
        defer r.deinit(io.gpa);
        io.writeFramed(r) catch {};
    }
}


/// The reader loop: EXECUTE_RESPONSE → route; EXECUTE → dispatch on its own thread.
/// Runs until the connection closes / a frame ends it.
pub fn readLoop(peer: *Peer, conn: *Conn, io: *Io) void {
    const gpa = io.gpa;
    while (true) {
        const payload = wire.readFrame(gpa, io.stream) catch break;
        defer gpa.free(payload);
        const env = model.envelopeOfFrame(gpa, payload) catch continue; // malformed → drop, keep reading
        if (std.mem.eql(u8, env.root.typ, "system/protocol/execute/response")) {
            io.routeResponse(env); // takes ownership
        } else {
            // dispatch on its own thread (§4.8). The thread owns `env`. The
            // reader keeps reading/routing §6.11 reentry responses meanwhile.
            const ctx = gpa.create(DispatchCtx) catch {
                env.deinit(gpa);
                continue;
            };
            ctx.* = .{ .peer = peer, .conn = conn, .io = io, .env = env };
            const th = std.Thread.spawn(.{}, dispatchExecuteThread, .{ctx}) catch {
                env.deinit(gpa);
                gpa.destroy(ctx);
                continue;
            };
            th.detach();
        }
    }
    io.close();
}

// ── listener / dialer ────────────────────────────────────────────────────────

pub fn listen(port: u16) Error!std.net.Server {
    const addr = std.net.Address.parseIp4("127.0.0.1", port) catch return error.ConnectionBroken;
    return addr.listen(.{ .reuse_address = true }) catch error.ConnectionBroken;
}

/// Disable Nagle on a connection. This is a request/response protocol with small
/// handshake + dispatch frames; with Nagle on, each small write waits for the
/// peer's delayed ACK (~40ms), and a multi-round-trip handshake pays it every
/// connection — which dominated connection churn at ~340ms/cycle (keystone §7b
/// t2_2). Best-effort: a failure just leaves Nagle on, not fatal.
pub fn setNoDelay(stream: std.net.Stream) void {
    std.posix.setsockopt(
        stream.handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        &std.mem.toBytes(@as(c_int, 1)),
    ) catch {};
}

// ── high-level handshake (§4.1) + session ────────────────────────────────────

const identity_mod = @import("identity.zig");
const sign = @import("sign.zig");

/// An authenticated session over an established connection (§4.4 / §5.8). Owns
/// the capability chain entities it re-presents on every request.
pub const Session = struct {
    io: *Io,
    local: *Peer,
    remote_peer_id: []const u8, // owned
    capability: Entity, // owned
    granter_peer: Entity, // owned
    cap_signature: Entity, // owned
    req_counter: u32 = 0,

    pub fn deinit(self: *Session, gpa: std.mem.Allocator) void {
        gpa.free(self.remote_peer_id);
        self.capability.deinit(gpa);
        self.granter_peer.deinit(gpa);
        self.cap_signature.deinit(gpa);
    }

    /// Build, sign, and send an authenticated EXECUTE; await the correlated reply
    /// (§5.8 chain inclusion: cap, granter, grantee, cap-sig, exec-sig in included).
    /// `resource` (if any) is consumed. Returns the owned response Envelope.
    pub fn execute(self: *Session, gpa: std.mem.Allocator, uri: []const u8, operation: []const u8, params: Entity, resource: ?Value) Error!?Envelope {
        self.req_counter += 1;
        var ridbuf: [24]u8 = undefined;
        const rid = std.fmt.bufPrint(&ridbuf, "req-{d}", .{self.req_counter}) catch "req";
        const exec = try wire.makeExecute(gpa, .{
            .request_id = rid,
            .uri = uri,
            .operation = operation,
            .params = params,
            .resource = resource,
            .author = self.local.identity.identity_hash,
            .capability = self.capability.hash,
        });
        const exec_sig = blk: {
            errdefer exec.deinit(gpa);
            break :blk try identity_mod.signEntity(gpa, self.local.identity, exec);
        };
        defer exec_sig.deinit(gpa); // cloned into `inc` below; free the standalone copy

        // Assemble the request envelope; once built, `req.deinit` is the sole owner
        // of `exec` and `inc`. Until then this block frees both on any failure.
        const req = blk: {
            var inc = try gpa.alloc(model.Included, 5);
            const items = [_]Entity{ self.capability, self.granter_peer, self.local.identity.peer_entity, self.cap_signature, exec_sig };
            var built: usize = 0;
            errdefer {
                for (inc[0..built]) |i| {
                    gpa.free(i.key);
                    i.entity.deinit(gpa);
                }
                gpa.free(inc);
                exec.deinit(gpa);
            }
            while (built < items.len) : (built += 1) {
                const e = try items[built].clone(gpa);
                errdefer e.deinit(gpa);
                inc[built] = .{ .key = try gpa.dupe(u8, items[built].hash), .entity = e };
            }
            break :blk Envelope{ .root = exec, .included = inc };
        };
        defer req.deinit(gpa);
        return self.io.outbound(req);
    }
};

/// A connect-path EXECUTE carries no author/capability (§4.2 pre-authorization).
fn sendConnect(gpa: std.mem.Allocator, io: *Io, conn: *Conn, operation: []const u8, params: Entity, included: []const Entity) Error!?Envelope {
    conn.out_counter += 1;
    var ridbuf: [24]u8 = undefined;
    const rid = std.fmt.bufPrint(&ridbuf, "h-{d}", .{conn.out_counter}) catch "h";
    const exec = try wire.makeExecute(gpa, .{ .request_id = rid, .uri = "system/protocol/connect", .operation = operation, .params = params });
    const req = blk: {
        var inc = try gpa.alloc(model.Included, included.len);
        var built: usize = 0;
        errdefer {
            for (inc[0..built]) |i| {
                gpa.free(i.key);
                i.entity.deinit(gpa);
            }
            gpa.free(inc);
            exec.deinit(gpa);
        }
        while (built < included.len) : (built += 1) {
            const e = try included[built].clone(gpa);
            errdefer e.deinit(gpa);
            inc[built] = .{ .key = try gpa.dupe(u8, included[built].hash), .entity = e };
        }
        break :blk Envelope{ .root = exec, .included = inc };
    };
    defer req.deinit(gpa);
    return io.outbound(req);
}

/// Initiator handshake (§4.1): hello → authenticate, returning a Session.
pub fn initiate(gpa: std.mem.Allocator, local: *Peer, io: *Io, conn: *Conn) Error!Session {
    // 1. hello
    const hello_params = try wire.emptyParams(gpa);
    const r1 = (try sendConnect(gpa, io, conn, "hello", hello_params, &.{})) orelse return error.ConnectionBroken;
    defer r1.deinit(gpa);
    if (r1.root.uintField("status") != 200) return error.ConnectionBroken;
    const remote_hello = try r1.root.entityField(gpa, "result") orelse return error.ConnectionBroken;
    defer remote_hello.deinit(gpa);
    const remote_peer_id = remote_hello.textField("peer_id") orelse return error.ConnectionBroken;
    const remote_nonce = remote_hello.bytesField("nonce") orelse return error.ConnectionBroken;

    // 2. authenticate
    return authenticate(gpa, local, io, conn, remote_nonce, remote_peer_id);
}

fn authenticate(gpa: std.mem.Allocator, local: *Peer, io: *Io, conn: *Conn, remote_nonce: []const u8, remote_peer_id: []const u8) Error!Session {
    var apairs = try gpa.alloc(Value.Pair, 4);
    apairs[0] = .{ .key = try model.textVal(gpa, "peer_id"), .value = try model.textVal(gpa, local.identity.peer_id) };
    apairs[1] = .{ .key = try model.textVal(gpa, "public_key"), .value = try model.bytesVal(gpa, &local.identity.public_key) };
    apairs[2] = .{ .key = try model.textVal(gpa, "key_type"), .value = try model.textVal(gpa, "ed25519") };
    apairs[3] = .{ .key = try model.textVal(gpa, "nonce"), .value = try model.bytesVal(gpa, remote_nonce) };
    const auth = try Entity.make(gpa, "system/protocol/connect/authenticate", .{ .map = apairs });
    defer auth.deinit(gpa);
    const auth_sig = try identity_mod.signEntity(gpa, local.identity, auth);
    defer auth_sig.deinit(gpa);

    const included = [_]Entity{ local.identity.peer_entity, auth_sig };
    const response = (try sendConnect(gpa, io, conn, "authenticate", try auth.clone(gpa), &included)) orelse return error.ConnectionBroken;
    defer response.deinit(gpa);
    if (response.root.uintField("status") != 200) return error.ConnectionBroken;

    const grant = try response.root.entityField(gpa, "result") orelse return error.ConnectionBroken;
    defer grant.deinit(gpa);
    const token_hash = grant.bytesField("token") orelse return error.ConnectionBroken;
    const token = response.includedGet(token_hash) orelse return error.ConnectionBroken;
    const granter_h = token.bytesField("granter") orelse return error.ConnectionBroken;
    const granter_peer = response.includedGet(granter_h) orelse return error.ConnectionBroken;
    const cap_sig = cap_findSignature(response, token.hash) orelse return error.ConnectionBroken;

    return .{
        .io = io,
        .local = local,
        .remote_peer_id = try gpa.dupe(u8, remote_peer_id),
        .capability = try token.clone(gpa),
        .granter_peer = try granter_peer.clone(gpa),
        .cap_signature = try cap_sig.clone(gpa),
    };
}

fn cap_findSignature(env: Envelope, target: []const u8) ?Entity {
    for (env.included) |inc| {
        const e = inc.entity;
        if (std.mem.eql(u8, e.typ, "system/signature")) {
            if (e.bytesField("target")) |t| if (std.mem.eql(u8, t, target)) return e;
        }
    }
    return null;
}
