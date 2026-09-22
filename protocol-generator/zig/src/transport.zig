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

    /// The §4.8 dispatch threads running against THIS connection, owned.
    ///
    /// readLoop spawns one per inbound EXECUTE; each holds a `*Io` and a `*Conn`
    /// that point INTO the connection's ConnState, which host.serveConnection frees
    /// as soon as readLoop returns. Without ownership, a client that closes right
    /// after sending a request makes readLoop return while a dispatch thread is
    /// still running, and that thread then dereferences freed memory — a
    /// use-after-free that SEGFAULTS the whole process, taking every other
    /// connection with it.
    ///
    /// Measured, not theorised: 3 of 5 consecutive `--profile core` runs on an
    /// otherwise idle host died with `Segmentation fault ... transport.zig:
    /// io.gpa.destroy(ctx)` during t2_2_connection_churn (100 open → request →
    /// close cycles, which is precisely the shape that closes the connection
    /// mid-dispatch), then reported 27 downstream checks as connection-refused.
    ///
    /// This was first fixed with an in-flight COUNTER and a `th.detach()`, which
    /// made the free safe and left a second lifetime bug one level down: a detached
    /// thread frees its own stack+TLS mapping, and the runtime aborted when a new
    /// spawn was handed an address the previous thread had not finished with (see
    /// the note at the accept loop in host.zig). Holding the handle answers both —
    /// `join()` waits for the thread AND frees the mapping, in that order, from the
    /// owner. Only the reader thread touches this list, so it needs no lock.
    workers: std.ArrayList(Worker) = .empty,

    pub fn init(gpa: std.mem.Allocator, stream: std.net.Stream) Io {
        return .{ .gpa = gpa, .stream = stream };
    }

    pub fn deinit(self: *Io) void {
        self.pending.deinit(self.gpa);
        self.workers.deinit(self.gpa);
    }

    /// Join every dispatch thread that has signalled completion. Called from the
    /// reader before each spawn, so a long-lived connection reaps as it goes
    /// instead of accumulating one unfreed thread mapping per request.
    fn reapWorkers(self: *Io) void {
        var i: usize = 0;
        while (i < self.workers.items.len) {
            const w = self.workers.items[i];
            if (w.done.load(.acquire)) {
                w.thread.join();
                self.gpa.destroy(w.done);
                _ = self.workers.swapRemove(i);
            } else i += 1;
        }
    }

    /// Block until every dispatch thread spawned for this connection has finished,
    /// and release each one's runtime resources. MUST be called before the owner
    /// frees the ConnState these threads point at.
    pub fn joinWorkers(self: *Io) void {
        for (self.workers.items) |w| {
            w.thread.join();
            self.gpa.destroy(w.done);
        }
        self.workers.clearRetainingCapacity();
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

/// One owned §4.8 dispatch thread. `done` is heap-allocated rather than stored
/// inline because the worker holds a pointer to it and `workers` is an ArrayList
/// that reallocates — a flag living in the list's buffer would move underneath the
/// thread that writes it.
const Worker = struct {
    thread: std.Thread,
    done: *std.atomic.Value(bool),
};

const DispatchCtx = struct {
    peer: *Peer,
    conn: *Conn,
    io: *Io,
    env: Envelope,
    /// Set to true as the LAST act of the dispatch thread; read by the reader.
    done: *std.atomic.Value(bool),
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
    const done = ctx.done; // read before ctx is destroyed
    defer {
        env.deinit(io.gpa);
        io.gpa.destroy(ctx);
        // Release LAST: the reader may join this thread and free the ConnState (and
        // therefore `io` itself) the instant it observes this flag, so nothing may
        // touch anything this connection owns after this line.
        done.store(true, .release);
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


/// §6.3: answer a rejected frame with `400 non_canonical_ecf`, correlated by the
/// request_id salvaged from it. Best-effort — a failure here degrades to the silence
/// this exists to remove, which is no worse than the old behaviour.
fn rejectFrame(io: *Io, payload: []const u8) void {
    const gpa = io.gpa;
    const rid = model.salvageRequestId(gpa, payload) orelse return;
    defer gpa.free(rid);
    // makeResponse CONSUMES `result` — no deinit here, or it is a double free.
    const result = wire.errorResult(gpa, "non_canonical_ecf", null) catch return;
    const root = wire.makeResponse(gpa, rid, 400, result) catch return;
    defer root.deinit(gpa);
    const included = gpa.alloc(model.Included, 0) catch return;
    const env = Envelope{ .root = root, .included = included };
    defer gpa.free(included);
    io.writeFramed(env) catch {};
}

/// The reader loop: EXECUTE_RESPONSE → route; EXECUTE → dispatch on its own thread.
/// Runs until the connection closes / a frame ends it.
pub fn readLoop(peer: *Peer, conn: *Conn, io: *Io) void {
    const gpa = io.gpa;
    while (true) {
        const payload = wire.readFrame(gpa, io.stream) catch break;
        defer gpa.free(payload);
        const env = model.envelopeOfFrame(gpa, payload) catch {
            // §6.3: "Rejection returns 400 non_canonical_ecf" — a rejected frame is
            // owed a STATUS, not silence. This used to `continue`, which rejected the
            // frame (correct) and then dropped it on the floor (wrong): the sender saw
            // no response at all and blocked until its own timeout, violating §6.3's
            // second sentence and §4.9(c) deliver-or-signal. It also made a refusal
            // indistinguishable from a dead peer, and on a single-connection oracle run
            // it poisons every later request on the same connection.
            //
            // The frame is still REJECTED — only enough is salvaged to correlate the
            // response. If even the request_id is unrecoverable the frame is
            // unattributable and silence is the only option left.
            rejectFrame(io, payload);
            continue; // keep reading
        };
        if (std.mem.eql(u8, env.root.typ, "system/protocol/execute/response")) {
            io.routeResponse(env); // takes ownership
        } else {
            // dispatch on its own thread (§4.8). The thread owns `env`. The
            // reader keeps reading/routing §6.11 reentry responses meanwhile.
            io.reapWorkers(); // join whatever finished since the last frame
            const ctx = gpa.create(DispatchCtx) catch {
                env.deinit(gpa);
                continue;
            };
            const done = gpa.create(std.atomic.Value(bool)) catch {
                env.deinit(gpa);
                gpa.destroy(ctx);
                continue;
            };
            done.* = std.atomic.Value(bool).init(false);
            ctx.* = .{ .peer = peer, .conn = conn, .io = io, .env = env, .done = done };
            const th = std.Thread.spawn(.{}, dispatchExecuteThread, .{ctx}) catch {
                env.deinit(gpa);
                gpa.destroy(ctx);
                gpa.destroy(done);
                continue;
            };
            // Record the handle BEFORE anything else can need it. If even this
            // allocation fails there is no way to track the thread, and abandoning
            // it is exactly the detach we are here to remove — so join it inline.
            // That blocks the reader, which is the right trade when the alternative
            // is an untracked thread pointing at state we are about to free.
            io.workers.append(gpa, .{ .thread = th, .done = done }) catch {
                th.join();
                gpa.destroy(done);
            };
        }
    }
    // The reader is done, but dispatch threads may still be holding this `*Io` and
    // the `*Conn` beside it. host.serveConnection frees that state the moment we
    // return, so joining here is what makes the free safe (§4.8).
    //
    // CLOSE FIRST. A dispatch thread parked in `Io.outbound` is waiting for a reply
    // that this reader will never route again, and joining it before waking it is a
    // hang, not a wait — `close()` broadcasts to every pending waiter so they can
    // finish and be joined.
    io.close();
    io.joinWorkers();
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
    const one = std.mem.toBytes(@as(c_int, 1));
    // Deliberately the RAW syscall, not std.posix.setsockopt, and the `catch {}`
    // this replaced was never able to make it best-effort.
    //
    // std.posix.setsockopt maps BADF / NOTSOCK / INVAL / FAULT to `unreachable`
    // — its own source comments them "always a race condition" — and in a safe
    // build `unreachable` is a PANIC, which no `catch` can intercept. So the
    // moment the kernel disagrees about this socket's state, a call documented
    // as "not fatal" aborts the entire process, killing every other connection.
    //
    // And that race is routine here, not exotic: this runs on the per-connection
    // thread, so between accept() returning the fd and this line executing, the
    // client may already have closed or reset. §7b t2_2 does 100 open → request →
    // close cycles and manufactures exactly that window. Measured: 2 of 8
    // otherwise-clean runs died with `panic: reached unreachable code ...
    // posix.zig setsockopt`, then reported 27 downstream checks as
    // connection-refused — which reads as a peer that crashed for no reason.
    //
    // Nagle is a latency optimisation. Failing to disable it must cost latency,
    // never the process.
    _ = std.posix.system.setsockopt(
        stream.handle,
        @as(i32, std.posix.IPPROTO.TCP),
        @as(u32, std.posix.TCP.NODELAY),
        &one,
        @as(std.posix.socklen_t, @sizeOf(c_int)),
    );
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

/// The initiator's §4.5 hello params. `protocols` is the load-bearing field: it is
/// Required with no default, so omitting it is a malformed hello, not a lenient one.
fn helloParams(gpa: std.mem.Allocator, local_peer: []const u8) Error!Entity {
    var list: std.ArrayList(Value.Pair) = .empty;
    try list.append(gpa, .{ .key = try model.textVal(gpa, "peer_id"), .value = try model.textVal(gpa, local_peer) });
    const protos = try gpa.alloc(Value, 1);
    protos[0] = try model.textVal(gpa, "entity-core/1.0");
    try list.append(gpa, .{ .key = try model.textVal(gpa, "protocols"), .value = .{ .array = protos } });
    const hf = try gpa.alloc(Value, 1);
    hf[0] = try model.textVal(gpa, "ecfv1-sha256");
    try list.append(gpa, .{ .key = try model.textVal(gpa, "hash_formats"), .value = .{ .array = hf } });
    const kt = try gpa.alloc(Value, 1);
    kt[0] = try model.textVal(gpa, "ed25519");
    try list.append(gpa, .{ .key = try model.textVal(gpa, "key_types"), .value = .{ .array = kt } });
    return Entity.make(gpa, "primitive/any", .{ .map = try list.toOwnedSlice(gpa) });
}

/// Initiator handshake (§4.1): hello → authenticate, returning a Session.
pub fn initiate(gpa: std.mem.Allocator, local: *Peer, io: *Io, conn: *Conn) Error!Session {
    // 1. hello
    // §4.5 makes `protocols` Required with NO default, so a hello that omits it is a
    // MALFORMED hello and a conforming responder answers 400 invalid_request. This
    // dialer used to send empty params and it worked only because no peer enforced
    // the rule — the moment the responder side landed, the peer could not complete a
    // handshake with itself. THE ORACLE CANNOT SEE THIS: its origination check
    // reuses the INBOUND connection and never makes us dial.
    const hello_params = try helloParams(gpa, local.local_peer);
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
