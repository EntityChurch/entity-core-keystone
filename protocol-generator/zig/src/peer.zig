//! Peer assembly (L1–L4 + foundation) — bootstrap, the four MUST system handlers
//! (§6.2: tree, handler, capability, connect), the dispatch chain (§6.5), per-
//! connection state, and the §6.9a peer-authority seed bootstrap.
//!
//! The handshake (§4.1/§4.6 three-check proof-of-possession), dispatch-chain order
//! (verify → resolve → check_permission → handler), §4.4 initial-grant delivery,
//! and §6.9a seed-policy authority are derived from V7. Transport lives in
//! transport.zig; this module is the pure protocol brain — a function from inbound
//! envelope to outbound response envelope plus per-connection state.
//!
//! No-GC idiom: every dispatch runs against a per-request ARENA (handlers allocate
//! freely; the chain walk's scratch is arena-scoped); the final response envelope
//! is deep-cloned into the long-lived gpa so it outlives the arena reset. The
//! store owns persistent entities (it dupes on bind). Handler outcomes carry an
//! Outcome { status, result, included } whose entities live in the arena until
//! materialized.

const std = @import("std");
const model = @import("model.zig");
const wire = @import("wire.zig");
const store_mod = @import("store.zig");
const identity_mod = @import("identity.zig");
const cap = @import("capability.zig");
const type_defs = @import("type_defs.zig");
const sign = @import("sign.zig");
const peer_id = @import("peer_id.zig");

const Entity = model.Entity;
const Value = model.Value;
const Store = store_mod.Store;
const Identity = identity_mod.Identity;
const Envelope = model.Envelope;

pub const Error = error{ OutOfMemory, NoOutbound } || model.Error || cap.Error || identity_mod.Error;

/// An included entity bundle carried in a response (arena-owned during dispatch).
const Inc = struct { key: []const u8, entity: Entity };

/// A handler outcome: status, the result entity, and protocol entities to bundle.
/// All entities are allocated from the per-request arena.
const Outcome = struct {
    status: u64,
    result: Entity,
    included: []Inc = &.{},
};

pub const Peer = struct {
    gpa: std.mem.Allocator,
    identity: Identity,
    store: Store,
    local_peer: []const u8, // == identity.peer_id (borrowed)
    open_grants: bool,
    conformance: bool,

    pub fn deinit(self: *Peer) void {
        self.store.deinit();
        self.identity.deinit(self.gpa);
    }
};

// Per-connection state (§4.2 — per-connection).
pub const Conn = struct {
    established: bool = false,
    issued_nonce: ?[32]u8 = null, // nonce we issued in our hello response
    hello_peer_id: ?[]const u8 = null, // owned dup of initiator's claimed peer_id
    /// §6.13(b) handler-facing outbound reentry seam. The live primitive is
    /// `transport.Io.outbound` (reached from the dispatch thread's context); these
    /// fields are the hook a §7a dispatch-outbound handler binds in S4. Unused in
    /// the S3 core floor (no core handler originates).
    outbound: ?*const OutboundFn = null,
    outbound_ctx: ?*anyopaque = null,
    out_counter: u32 = 0,

    pub fn deinit(self: *Conn, gpa: std.mem.Allocator) void {
        if (self.hello_peer_id) |p| gpa.free(p);
    }
};

pub const OutboundFn = fn (ctx: ?*anyopaque, gpa: std.mem.Allocator, req: Envelope) ?Envelope;

// ── arena outcome helpers ────────────────────────────────────────────────────

fn ok(result: Entity) Outcome {
    return .{ .status = 200, .result = result, .included = &.{} };
}
fn okInc(result: Entity, included: []Inc) Outcome {
    return .{ .status = 200, .result = result, .included = included };
}
fn errOut(a: std.mem.Allocator, status: u64, code: []const u8, message: ?[]const u8) Error!Outcome {
    return .{ .status = status, .result = try wire.errorResult(a, code, message), .included = &.{} };
}

// ── randomness (§4.6 SHOULD ≥32-byte CSPRNG) ─────────────────────────────────

fn randomNonce() [32]u8 {
    var buf: [32]u8 = undefined;
    std.crypto.random.bytes(&buf);
    return buf;
}

fn nowMs() u64 {
    return @intCast(std.time.milliTimestamp());
}

// ── grant construction (§4.4 / §5.4) ─────────────────────────────────────────

fn scopeVal(a: std.mem.Allocator, incl: []const []const u8) Error!Value {
    const items = try a.alloc(Value, incl.len);
    for (incl, 0..) |s, i| items[i] = try model.textVal(a, s);
    var pairs = try a.alloc(Value.Pair, 1);
    pairs[0] = .{ .key = try model.textVal(a, "include"), .value = .{ .array = items } };
    return .{ .map = pairs };
}

fn grantVal(a: std.mem.Allocator, handlers: []const []const u8, resources: []const []const u8, operations: []const []const u8, peers: ?[]const []const u8) Error!Value {
    var list: std.ArrayList(Value.Pair) = .empty;
    try list.append(a, .{ .key = try model.textVal(a, "handlers"), .value = try scopeVal(a, handlers) });
    try list.append(a, .{ .key = try model.textVal(a, "resources"), .value = try scopeVal(a, resources) });
    try list.append(a, .{ .key = try model.textVal(a, "operations"), .value = try scopeVal(a, operations) });
    if (peers) |p| try list.append(a, .{ .key = try model.textVal(a, "peers"), .value = try scopeVal(a, p) });
    return .{ .map = try list.toOwnedSlice(a) };
}

/// §4.4 discovery floor: every authenticated identity gets at least this.
fn discoveryFloor(a: std.mem.Allocator) Error![]Value {
    var out = try a.alloc(Value, 2);
    out[0] = try grantVal(a, &.{"system/tree"}, &.{ "system/type/*", "system/handler/*" }, &.{"get"}, null);
    out[1] = try grantVal(a, &.{"system/capability"}, &.{}, &.{"request"}, null);
    return out;
}

/// The degenerate `default → *` (= retired --debug-open-grants).
fn openGrantsScope(a: std.mem.Allocator) Error![]Value {
    var out = try a.alloc(Value, 1);
    out[0] = try grantVal(a, &.{"*"}, &.{ "*", "/*/*" }, &.{"*"}, &.{"*"});
    return out;
}

/// Full owner authority over the local namespace (§6.9a).
fn ownerGrants(a: std.mem.Allocator, local_peer: []const u8) Error![]Value {
    var out = try a.alloc(Value, 1);
    out[0] = try grantVal(a, &.{"*"}, &.{"*"}, &.{"*"}, &.{local_peer});
    return out;
}

// ── token minting (§4.4 / §5.4) ──────────────────────────────────────────────

const Minted = struct { token: Entity, signature: Entity };

/// Mint a capability token granted by us to `grantee_hash`; sign it. Both entities
/// are allocated from `a`.
fn mintToken(p: *Peer, a: std.mem.Allocator, grantee_hash: []const u8, parent: ?[]const u8, grants: []Value) Error!Minted {
    var list: std.ArrayList(Value.Pair) = .empty;
    try list.append(a, .{ .key = try model.textVal(a, "granter"), .value = try model.bytesVal(a, p.identity.identity_hash) });
    try list.append(a, .{ .key = try model.textVal(a, "grantee"), .value = try model.bytesVal(a, grantee_hash) });
    const grants_copy = try a.alloc(Value, grants.len);
    @memcpy(grants_copy, grants);
    try list.append(a, .{ .key = try model.textVal(a, "grants"), .value = .{ .array = grants_copy } });
    try list.append(a, .{ .key = try model.textVal(a, "created_at"), .value = .{ .uint = nowMs() } });
    if (parent) |ph| try list.append(a, .{ .key = try model.textVal(a, "parent"), .value = try model.bytesVal(a, ph) });
    const token = try Entity.make(a, "system/capability/token", .{ .map = try list.toOwnedSlice(a) });
    const signature = try identity_mod.signEntity(a, p.identity, token);
    return .{ .token = token, .signature = signature };
}

// ── §6.9a seed-policy derivation ─────────────────────────────────────────────

/// authenticate-time derivation: dual-form lookup (hex → Base58 → default), then
/// UNION the matched scope with the §4.4 discovery floor. Returns arena-owned grants.
fn deriveSeedGrants(p: *Peer, a: std.mem.Allocator, remote_peer: Entity, remote_peer_id: []const u8) Error![]Value {
    const base = try std.fmt.allocPrint(a, "/{s}/system/capability/policy/", .{p.local_peer});
    const hex = try model.hex(a, remote_peer.hash);
    const entry: ?Entity = blk: {
        if (p.store.getAt(try std.fmt.allocPrint(a, "{s}{s}", .{ base, hex }))) |e| break :blk e;
        if (p.store.getAt(try std.fmt.allocPrint(a, "{s}{s}", .{ base, remote_peer_id }))) |e| break :blk e;
        if (p.store.getAt(try std.fmt.allocPrint(a, "{s}default", .{base}))) |e| break :blk e;
        break :blk null;
    };
    const floor = try discoveryFloor(a);
    const policy_grants: []Value = if (entry) |e| try seedEntryGrants(p, a, e) else &.{};
    if (policy_grants.len == 0) return floor;
    const out = try a.alloc(Value, floor.len + policy_grants.len);
    @memcpy(out[0..floor.len], floor);
    @memcpy(out[floor.len..], policy_grants);
    return out;
}

/// Extract the grants array from a seed-policy entry, handling both §6.9a.0 shapes:
/// a capability token (detached-signature shape — verify the sig at the §3.5 pointer
/// before trusting) or a policy-entry (scope template).
fn seedEntryGrants(p: *Peer, a: std.mem.Allocator, e: Entity) Error![]Value {
    const grants_of = struct {
        fn f(al: std.mem.Allocator, ent: Entity) Error![]Value {
            const arr = switch (ent.field("grants") orelse return &.{}) {
                .array => |x| x,
                else => return &.{},
            };
            const out = try al.alloc(Value, arr.len);
            @memcpy(out, arr);
            return out;
        }
    }.f;
    if (std.mem.eql(u8, e.typ, "system/capability/token")) {
        const hex = try model.hex(a, e.hash);
        const sig_path = try std.fmt.allocPrint(a, "/{s}/system/signature/{s}", .{ p.local_peer, hex });
        if (p.store.getAt(sig_path)) |sgn| {
            if (identity_mod.verifySignature(sgn, p.identity.peer_entity)) return grants_of(a, e);
        }
        return &.{}; // unverifiable seed cap → no authority
    } else if (std.mem.eql(u8, e.typ, "system/capability/policy-entry")) {
        return grants_of(a, e);
    }
    return &.{};
}

// ── connect handler (§4.1, §4.6) ─────────────────────────────────────────────

fn connectHandler(p: *Peer, a: std.mem.Allocator, conn: *Conn, exec: Entity, env: Envelope) Error!Outcome {
    const op = exec.textField("operation") orelse "";
    if (std.mem.eql(u8, op, "hello")) {
        if (conn.established) return errOut(a, 409, "connection_already_established", null);
        const params = try exec.entityField(a, "params");
        // §4.5 negotiation: reject disjoint hash_formats / key_types up front.
        if (params) |pe| {
            if (negotiationReject(pe, "hash_formats", "ecfv1-sha256")) return errOut(a, 400, "incompatible_hash_format", null);
            if (negotiationReject(pe, "key_types", "ed25519")) return errOut(a, 400, "unsupported_key_type", null);
            if (pe.textField("peer_id")) |pid| {
                if (conn.hello_peer_id) |old| p.gpa.free(old);
                conn.hello_peer_id = try p.gpa.dupe(u8, pid);
            }
        }
        const nonce = randomNonce();
        conn.issued_nonce = nonce;
        var list: std.ArrayList(Value.Pair) = .empty;
        try list.append(a, .{ .key = try model.textVal(a, "peer_id"), .value = try model.textVal(a, p.local_peer) });
        try list.append(a, .{ .key = try model.textVal(a, "nonce"), .value = try model.bytesVal(a, &nonce) });
        const protos = try a.alloc(Value, 1);
        protos[0] = try model.textVal(a, "entity-core/1.0");
        try list.append(a, .{ .key = try model.textVal(a, "protocols"), .value = .{ .array = protos } });
        try list.append(a, .{ .key = try model.textVal(a, "timestamp"), .value = .{ .uint = nowMs() } });
        const hf = try a.alloc(Value, 1);
        hf[0] = try model.textVal(a, "ecfv1-sha256");
        try list.append(a, .{ .key = try model.textVal(a, "hash_formats"), .value = .{ .array = hf } });
        const kt = try a.alloc(Value, 1);
        kt[0] = try model.textVal(a, "ed25519");
        try list.append(a, .{ .key = try model.textVal(a, "key_types"), .value = .{ .array = kt } });
        const hello = try Entity.make(a, "system/protocol/connect/hello", .{ .map = try list.toOwnedSlice(a) });
        return ok(hello);
    } else if (std.mem.eql(u8, op, "authenticate")) {
        if (conn.established) return errOut(a, 409, "connection_already_established", null);
        const issued = conn.issued_nonce orelse return errOut(a, 401, "invalid_nonce", null);
        const auth = (try exec.entityField(a, "params")) orelse return errOut(a, 401, "authentication_failed", null);
        // §4.6 hardening: reject an unsupported key_type (field, non-32B pubkey, or peer_id prefix).
        if (auth.textField("key_type")) |kt| if (!std.mem.eql(u8, kt, "ed25519")) return errOut(a, 400, "unsupported_key_type", null);
        if (auth.bytesField("public_key")) |pk| if (pk.len != 32) return errOut(a, 400, "unsupported_key_type", null);
        if (auth.textField("peer_id")) |pid| {
            const parsed = peer_id.parse(a, pid) catch null;
            if (parsed) |pp| {
                defer pp.deinit(a);
                if (pp.key_type != 0x01) return errOut(a, 400, "unsupported_key_type", null);
            }
        }
        const echoed = auth.bytesField("nonce");
        if (echoed == null or !std.mem.eql(u8, echoed.?, &issued)) return errOut(a, 401, "invalid_nonce", null);
        const public_key = auth.bytesField("public_key") orelse return errOut(a, 401, "authentication_failed", null);
        // step 2: proof of possession — find the auth signature in included
        const sig_ok = blk: {
            const sgn = cap.findSignature(env, auth.hash) orelse break :blk false;
            const sb = sgn.bytesField("signature") orelse break :blk false;
            if (sb.len != 64 or public_key.len != 32) break :blk false;
            var s64: [64]u8 = undefined;
            var p32: [32]u8 = undefined;
            @memcpy(&s64, sb);
            @memcpy(&p32, public_key);
            break :blk sign.verify(p32, s64, auth.hash);
        };
        if (!sig_ok) return errOut(a, 401, "authentication_failed", null);
        // step 3: identity binding
        const claimed = auth.textField("peer_id");
        const derived = try identity_mod.peerIdOfPubkey(a, public_key);
        if (claimed == null or !std.mem.eql(u8, claimed.?, derived)) return errOut(a, 401, "identity_mismatch", null);
        if (conn.hello_peer_id) |hp| if (!std.mem.eql(u8, hp, claimed.?)) return errOut(a, 401, "identity_mismatch", null);
        // success: mint the initial capability (§4.4 / §6.9a)
        const remote_peer = try identity_mod.peerEntityOfPubkey(a, public_key);
        const grants = try deriveSeedGrants(p, a, remote_peer, claimed.?);
        const minted = try mintToken(p, a, remote_peer.hash, null, grants);
        conn.established = true;
        var gpairs = try a.alloc(Value.Pair, 1);
        gpairs[0] = .{ .key = try model.textVal(a, "token"), .value = try model.bytesVal(a, minted.token.hash) };
        const grant_result = try Entity.make(a, "system/capability/grant", .{ .map = gpairs });
        var inc = try a.alloc(Inc, 3);
        inc[0] = .{ .key = minted.token.hash, .entity = minted.token };
        inc[1] = .{ .key = p.identity.identity_hash, .entity = p.identity.peer_entity };
        inc[2] = .{ .key = minted.signature.hash, .entity = minted.signature };
        return okInc(grant_result, inc);
    }
    return errOut(a, 501, "unsupported_operation", op);
}

fn negotiationReject(params: Entity, key: []const u8, required: []const u8) bool {
    const arr = switch (params.field(key) orelse return false) {
        .array => |x| x,
        else => return false,
    };
    for (arr) |it| switch (it) {
        .text => |s| if (std.mem.eql(u8, s, required)) return false,
        else => {},
    };
    return true; // present but disjoint
}

// ── tree handler (§6.3) ──────────────────────────────────────────────────────

fn resourceTarget(exec: Entity) ?[]const u8 {
    const r = exec.field("resource") orelse return null;
    const targets = model.mapGet(r, "targets") orelse return null;
    return switch (targets) {
        .array => |arr| if (arr.len > 0) switch (arr[0]) {
            .text => |s| s,
            else => null,
        } else null,
        else => null,
    };
}

/// §1.4 / §5.4 path-flex validation: reject null byte, non-peer-id leading slash,
/// ./ ../ and interior empty segments. A single trailing "/" is the listing marker.
fn pathFlexOk(target: []const u8) bool {
    if (std.mem.indexOfScalar(u8, target, 0) != null) return false;
    var body = target;
    if (cap.startsWith(target, "/")) {
        // /{peer_id}/rest — first segment must be a peer_id
        const rest = target[1..];
        const i = std.mem.indexOfScalar(u8, rest, '/') orelse return cap.isPeerId(rest);
        if (!cap.isPeerId(rest[0..i])) return false;
        body = rest[i + 1 ..];
    }
    // strip a single trailing slash (listing marker)
    if (body.len > 0 and body[body.len - 1] == '/') body = body[0 .. body.len - 1];
    // a bare peer-root listing (`/{peer_id}/` → empty body) is valid (§1.4 R1):
    // the universal-tree-root walk lists the namespace under that peer-id.
    if (body.len == 0) return true;
    var it = std.mem.splitScalar(u8, body, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
    }
    return true;
}

fn buildListing(p: *Peer, a: std.mem.Allocator, path: []const u8) Error!Outcome {
    const entries = try p.store.listing(a, path);
    var entry_pairs: std.ArrayList(Value.Pair) = .empty;
    var emitted: u64 = 0;
    for (entries) |le| {
        // §6.3 / v7.72 §9.5a CORE-TREE-DELETE-1: a leaf bound to a
        // system/deletion-marker is a tombstone — omit it from the listing
        // (siblings under the same prefix stay; a path that only has deeper
        // children, hash==null, is never a marker leaf).
        if (le.hash) |h| {
            if (p.store.getByHash(h)) |bound| {
                if (std.mem.eql(u8, bound.typ, "system/deletion-marker")) continue;
            }
        }
        var fields: std.ArrayList(Value.Pair) = .empty;
        try fields.append(a, .{ .key = try model.textVal(a, "has_children"), .value = .{ .boolean = le.has_children } });
        if (le.hash) |h| try fields.append(a, .{ .key = try model.textVal(a, "hash"), .value = try model.bytesVal(a, h) });
        const le_entity = try Entity.make(a, "system/tree/listing-entry", .{ .map = try fields.toOwnedSlice(a) });
        try entry_pairs.append(a, .{ .key = try model.textVal(a, le.seg), .value = try le_entity.toCbor(a) });
        emitted += 1;
    }
    var top: std.ArrayList(Value.Pair) = .empty;
    try top.append(a, .{ .key = try model.textVal(a, "path"), .value = try model.textVal(a, path) });
    try top.append(a, .{ .key = try model.textVal(a, "entries"), .value = .{ .map = try entry_pairs.toOwnedSlice(a) } });
    try top.append(a, .{ .key = try model.textVal(a, "count"), .value = .{ .uint = emitted } });
    try top.append(a, .{ .key = try model.textVal(a, "offset"), .value = .{ .uint = 0 } });
    return ok(try Entity.make(a, "system/tree/listing", .{ .map = try top.toOwnedSlice(a) }));
}

fn treeHandler(p: *Peer, a: std.mem.Allocator, exec: Entity) Error!Outcome {
    const op = exec.textField("operation") orelse "";
    const target = resourceTarget(exec);
    if ((std.mem.eql(u8, op, "get") or std.mem.eql(u8, op, "put")) and target != null and !pathFlexOk(target.?))
        return errOut(a, 400, "invalid_path", target.?);

    if (std.mem.eql(u8, op, "get")) {
        if (target == null) {
            const root_path = try std.fmt.allocPrint(a, "/{s}/", .{p.local_peer});
            return buildListing(p, a, root_path);
        }
        const tgt = target.?;
        if (tgt.len == 0 or tgt[tgt.len - 1] == '/') {
            return buildListing(p, a, try cap.canonicalize(a, p.local_peer, tgt));
        }
        const path = try cap.canonicalize(a, p.local_peer, tgt);
        const e = p.store.getAt(path) orelse return errOut(a, 404, "not_found", path);
        // mode=hash → return system/hash
        if (try exec.entityField(a, "params")) |pe| {
            if (pe.textField("mode")) |m| if (std.mem.eql(u8, m, "hash")) {
                return ok(try Entity.make(a, "system/hash", try model.bytesVal(a, e.hash)));
            };
        }
        return ok(try e.clone(a));
    } else if (std.mem.eql(u8, op, "put")) {
        if (target == null) return errOut(a, 400, "ambiguous_resource", "tree: missing resource target");
        const path = try cap.canonicalize(a, p.local_peer, target.?);
        const params = try exec.entityField(a, "params");
        const entity = if (params) |pe| try pe.entityField(a, "entity") else null;
        const expected = if (params) |pe| pe.bytesField("expected_hash") else null;
        // §3.9 CAS
        const current = p.store.hashAt(path);
        const zero33 = [_]u8{0} ** 33;
        const cas_ok = if (expected) |h| (if (std.mem.eql(u8, h, &zero33)) current == null else (current != null and std.mem.eql(u8, current.?, h))) else true;
        if (!cas_ok) return errOut(a, 409, "hash_mismatch", path);
        if (entity) |e| {
            try p.store.bind(path, e);
            return ok(try Entity.make(a, "system/hash", try model.bytesVal(a, e.hash)));
        }
        return errOut(a, 400, "unexpected_params", "put: missing entity");
    }
    return errOut(a, 501, "unsupported_operation", op);
}

// ── capability handler (§6.2) ────────────────────────────────────────────────

fn isZeroHash(h: []const u8) bool {
    for (h) |c| if (c != 0) return false;
    return true;
}

fn reqGrants(a: std.mem.Allocator, params: ?Entity) Error![]Value {
    const pe = params orelse return &.{};
    const arr = switch (pe.field("grants") orelse return &.{}) {
        .array => |x| x,
        else => return &.{},
    };
    const out = try a.alloc(Value, arr.len);
    @memcpy(out, arr);
    return out;
}

/// Mint a token for `grantee_hash`, bounded as a subset of the caller's cap
/// (§6.2 subset-validation).
fn mintBounded(p: *Peer, a: std.mem.Allocator, caller_cap: ?Entity, req_grants: []Value, grantee_hash: []const u8, parent: ?[]const u8) Error!Outcome {
    const bounded = blk: {
        const cc = caller_cap orelse break :blk false;
        // §6.2 mint-time subset check on the local frame (child=parent=local).
        for (req_grants) |cg| {
            const c = try parseGrantPublic(a, cg);
            var matched = false;
            const parent_grants = try grantsOfTokenPublic(a, cc);
            for (parent_grants) |pg| {
                if (try cap.grantSubsetLocal(a, p.local_peer, c, pg)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) break :blk false;
        }
        break :blk true;
    };
    if (!bounded) return errOut(a, 403, "scope_exceeds_authority", null);
    const minted = try mintToken(p, a, grantee_hash, parent, req_grants);
    var gpairs = try a.alloc(Value.Pair, 1);
    gpairs[0] = .{ .key = try model.textVal(a, "token"), .value = try model.bytesVal(a, minted.token.hash) };
    const grant_result = try Entity.make(a, "system/capability/grant", .{ .map = gpairs });
    var inc = try a.alloc(Inc, 3);
    inc[0] = .{ .key = minted.token.hash, .entity = minted.token };
    inc[1] = .{ .key = p.identity.identity_hash, .entity = p.identity.peer_entity };
    inc[2] = .{ .key = minted.signature.hash, .entity = minted.signature };
    return okInc(grant_result, inc);
}

fn capabilityHandler(p: *Peer, a: std.mem.Allocator, exec: Entity, caller_cap: ?Entity) Error!Outcome {
    const op = exec.textField("operation") orelse "";
    const params = try exec.entityField(a, "params");
    const author = exec.bytesField("author");
    if (std.mem.eql(u8, op, "request")) {
        const grantee = author orelse return errOut(a, 403, "capability_denied", null);
        return mintBounded(p, a, caller_cap, try reqGrants(a, params), grantee, null);
    } else if (std.mem.eql(u8, op, "delegate")) {
        const parent = if (params) |pe| pe.bytesField("parent") else null;
        if (parent == null) return errOut(a, 400, "unexpected_params", "delegate: parent required");
        if (isZeroHash(parent.?)) return errOut(a, 400, "unexpected_params", "delegate: zero parent");
        // delegate is same-peer-only in v1
        if (author == null or !std.mem.eql(u8, author.?, p.identity.identity_hash))
            return errOut(a, 501, "unsupported_operation", "delegate: same-peer-only in v1");
        return mintBounded(p, a, caller_cap, try reqGrants(a, params), author.?, parent.?);
    } else if (std.mem.eql(u8, op, "revoke")) {
        const token_h = if (params) |pe| pe.bytesField("token") else null;
        if (token_h == null) return errOut(a, 400, "unexpected_params", "revoke: missing token");
        if (isZeroHash(token_h.?)) return errOut(a, 400, "unexpected_params", "revoke: zero token");
        var mpairs: std.ArrayList(Value.Pair) = .empty;
        try mpairs.append(a, .{ .key = try model.textVal(a, "token"), .value = try model.bytesVal(a, token_h.?) });
        try mpairs.append(a, .{ .key = try model.textVal(a, "revoked_at"), .value = .{ .uint = nowMs() } });
        const marker = try Entity.make(a, "system/capability/revocation", .{ .map = try mpairs.toOwnedSlice(a) });
        defer marker.deinit(a);
        const hex = try model.hex(a, token_h.?);
        const path = try std.fmt.allocPrint(a, "/{s}/system/capability/revocations/{s}", .{ p.local_peer, hex });
        try p.store.bind(path, marker);
        return ok(try wire.emptyParams(a));
    } else if (std.mem.eql(u8, op, "configure")) {
        const pp = if (params) |pe| pe.textField("peer_pattern") else null;
        if (pp == null) return errOut(a, 400, "unexpected_params", "configure: missing peer_pattern");
        const is_hex = pp.?.len == 66 and blk: {
            for (pp.?) |c| if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) break :blk false;
            break :blk true;
        };
        if (!(std.mem.eql(u8, pp.?, "default") or is_hex or cap.isPeerId(pp.?)))
            return errOut(a, 400, "invalid_peer_pattern", pp.?);
        const path = try std.fmt.allocPrint(a, "/{s}/system/capability/policy/{s}", .{ p.local_peer, pp.? });
        try p.store.bind(path, params.?);
        return ok(try wire.emptyParams(a));
    }
    return errOut(a, 501, "unsupported_operation", op);
}

// thin public wrappers so the capability module's private parse helpers can be
// reused here (kept on the local frame for the mint-time subset check).
fn parseGrantPublic(a: std.mem.Allocator, v: Value) cap.Error!cap.PubGrant {
    return cap.parseGrantPublic(a, v);
}
fn grantsOfTokenPublic(a: std.mem.Allocator, token: Entity) cap.Error![]cap.PubGrant {
    return cap.grantsOfTokenPublic(a, token);
}

// ── handlers handler (§6.2 / §6.13(a)) — register/unregister ─────────────────

fn registerPattern(a: std.mem.Allocator, exec: Entity) Error!union(enum) { pattern: []const u8, err: Outcome } {
    const target = resourceTarget(exec) orelse return .{ .err = try errOut(a, 400, "ambiguous_resource", "register/unregister require exactly one resource target") };
    const prefix = "system/handler/";
    if (!cap.startsWith(target, prefix) or target.len == prefix.len)
        return .{ .err = try errOut(a, 400, "invalid_resource", "resource target MUST be system/handler/{pattern}") };
    return .{ .pattern = target[prefix.len..] };
}

fn registerHandler(p: *Peer, a: std.mem.Allocator, exec: Entity) Error!Outcome {
    const rp = try registerPattern(a, exec);
    const pattern = switch (rp) {
        .err => |e| return e,
        .pattern => |s| s,
    };
    const req = (try exec.entityField(a, "params")) orelse return errOut(a, 400, "unexpected_params", "register: missing params");
    if (!std.mem.eql(u8, req.typ, "system/handler/register-request"))
        return errOut(a, 400, "unexpected_params", "register expects register-request");
    const manifest = req.field("manifest") orelse Value{ .map = &.{} };
    const name = blk: {
        if (model.mapGet(manifest, "name")) |v| switch (v) {
            .text => |s| break :blk s,
            else => {},
        };
        break :blk pattern;
    };
    const operations = model.mapGet(manifest, "operations") orelse Value{ .map = &.{} };
    const expression_path = blk: {
        if (model.mapGet(manifest, "expression_path")) |v| switch (v) {
            .text => |s| break :blk s,
            else => {},
        };
        break :blk null;
    };
    const internal_scope = model.mapGet(manifest, "internal_scope");
    // grant scope = requested_scope ?? internal_scope ?? []
    var grant_scope: []Value = &.{};
    if (req.field("requested_scope")) |v| switch (v) {
        .array => |arr| {
            grant_scope = try a.alloc(Value, arr.len);
            @memcpy(grant_scope, arr);
        },
        else => {},
    } else if (internal_scope) |v| switch (v) {
        .array => |arr| {
            grant_scope = try a.alloc(Value, arr.len);
            @memcpy(grant_scope, arr);
        },
        else => {},
    };

    const interface_rel = try std.fmt.allocPrint(a, "system/handler/{s}", .{pattern});
    // (1) handler manifest at the pattern path
    var hpairs: std.ArrayList(Value.Pair) = .empty;
    try hpairs.append(a, .{ .key = try model.textVal(a, "interface"), .value = try model.textVal(a, interface_rel) });
    if (expression_path) |ep| try hpairs.append(a, .{ .key = try model.textVal(a, "expression_path"), .value = try model.textVal(a, ep) });
    if (internal_scope) |is| try hpairs.append(a, .{ .key = try model.textVal(a, "internal_scope"), .value = try model.cloneValue(a, is) });
    const handler_e = try Entity.make(a, "system/handler", .{ .map = try hpairs.toOwnedSlice(a) });
    defer handler_e.deinit(a);
    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/{s}", .{ p.local_peer, pattern }), handler_e);

    // (2) associated types
    if (req.field("types")) |v| switch (v) {
        .map => |kvs| {
            for (kvs) |kv| switch (kv.key) {
                .text => |tn| {
                    const te = try Entity.make(a, "system/type", try model.cloneValue(a, kv.value));
                    defer te.deinit(a);
                    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/system/type/{s}", .{ p.local_peer, tn }), te);
                },
                else => {},
            };
        },
        else => {},
    };

    // (3)+(4) self-issued signed handler grant + grant-signature at the §3.5 pointer
    const minted = try mintToken(p, a, p.identity.identity_hash, null, grant_scope);
    defer minted.token.deinit(a);
    defer minted.signature.deinit(a);
    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/system/capability/grants/{s}", .{ p.local_peer, pattern }), minted.token);
    const thex = try model.hex(a, minted.token.hash);
    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/system/signature/{s}", .{ p.local_peer, thex }), minted.signature);

    // (5) handler interface entity (discovery index)
    var ipairs: std.ArrayList(Value.Pair) = .empty;
    try ipairs.append(a, .{ .key = try model.textVal(a, "pattern"), .value = try model.textVal(a, pattern) });
    try ipairs.append(a, .{ .key = try model.textVal(a, "name"), .value = try model.textVal(a, name) });
    try ipairs.append(a, .{ .key = try model.textVal(a, "operations"), .value = try model.cloneValue(a, operations) });
    const iface_e = try Entity.make(a, "system/handler/interface", .{ .map = try ipairs.toOwnedSlice(a) });
    defer iface_e.deinit(a);
    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/{s}", .{ p.local_peer, interface_rel }), iface_e);

    var rpairs: std.ArrayList(Value.Pair) = .empty;
    try rpairs.append(a, .{ .key = try model.textVal(a, "pattern"), .value = try model.textVal(a, pattern) });
    try rpairs.append(a, .{ .key = try model.textVal(a, "grant"), .value = try model.cloneValue(a, minted.token.data) });
    return ok(try Entity.make(a, "system/handler/register-result", .{ .map = try rpairs.toOwnedSlice(a) }));
}

fn unregisterHandler(p: *Peer, a: std.mem.Allocator, exec: Entity) Error!Outcome {
    const rp = try registerPattern(a, exec);
    const pattern = switch (rp) {
        .err => |e| return e,
        .pattern => |s| s,
    };
    const grant_path = try std.fmt.allocPrint(a, "/{s}/system/capability/grants/{s}", .{ p.local_peer, pattern });
    if (p.store.getAt(grant_path)) |g| {
        const ghex = try model.hex(a, g.hash);
        p.store.unbind(try std.fmt.allocPrint(a, "/{s}/system/signature/{s}", .{ p.local_peer, ghex }));
        p.store.unbind(grant_path);
    }
    p.store.unbind(try std.fmt.allocPrint(a, "/{s}/{s}", .{ p.local_peer, pattern }));
    p.store.unbind(try std.fmt.allocPrint(a, "/{s}/system/handler/{s}", .{ p.local_peer, pattern }));
    return ok(try wire.emptyParams(a));
}

fn handlersHandler(p: *Peer, a: std.mem.Allocator, exec: Entity) Error!Outcome {
    const op = exec.textField("operation") orelse "";
    if (std.mem.eql(u8, op, "register")) return registerHandler(p, a, exec);
    if (std.mem.eql(u8, op, "unregister")) return unregisterHandler(p, a, exec);
    return errOut(a, 501, "unsupported_operation", op);
}

fn typesHandler(a: std.mem.Allocator, exec: Entity) Error!Outcome {
    return errOut(a, 501, "unsupported_operation", exec.textField("operation") orelse "");
}

// ── entity-native handler dispatch (§6.13(a)) — the register round-trip body ──
//
// A dynamically-registered handler binds its body via an `expression_path` on
// its `system/handler` entity (V7 §9.4 — the body-binding mechanism is
// impl-private; the entity-native expression form is the spec's default seam).
// On dispatch, resolve the expression entity and evaluate it. The core peer
// implements the minimal entity-native floor: `compute/literal {value}` → a
// `compute/result {value, expression}` (the §2.4 result shape). This is exactly
// what the v7.74 §10.1 core_register_dispatch_roundtrip gate exercises (a bound
// literal must round-trip on dispatch). Richer expression types are extension
// surface (the full entity-native category, not --profile core).
fn entityNativeDispatch(p: *Peer, a: std.mem.Allocator, handler_entity: Entity) Error!Outcome {
    const expr_path_rel = handler_entity.textField("expression_path") orelse
        return errOut(a, 501, "no_handler_body", "registered handler has no expression_path");
    const expr_path = try cap.canonicalize(a, p.local_peer, expr_path_rel);
    const expr = p.store.getAt(expr_path) orelse
        return errOut(a, 404, "expression_not_found", expr_path);

    if (std.mem.eql(u8, expr.typ, "compute/literal")) {
        const value = expr.field("value") orelse Value{ .null = {} };
        var pairs: std.ArrayList(Value.Pair) = .empty;
        try pairs.append(a, .{ .key = try model.textVal(a, "value"), .value = try model.cloneValue(a, value) });
        try pairs.append(a, .{ .key = try model.textVal(a, "expression"), .value = try model.bytesVal(a, expr.hash) });
        return ok(try Entity.make(a, "compute/result", .{ .map = try pairs.toOwnedSlice(a) }));
    }
    // The core floor only evaluates the literal seam; richer expression
    // evaluation is the extension entity-native surface (out of --profile core).
    return errOut(a, 501, "unsupported_expression", expr.typ);
}

// ── §7a conformance handlers (GUIDE-CONFORMANCE §7a) ─────────────────────────
//
// `system/validate/*` are conformance SCAFFOLDING, NOT core protocol (not in the
// §9.5 floor / §9.0 categories). Present only when the peer is built with
// `conformance=true` (host `--validate`, off by default — dispatch-outbound is a
// standing dialer). They give a black-box validator a native, compute-free way to
// drive the two extensibility hooks that have no other wire-reachable trigger in a
// core-only peer: `echo` (§6.13(a) resolve→dispatch, closes A-011) and
// `dispatch-outbound` (§6.13(b)/§6.11 outbound reentry, closes A-013). The cohort
// (C# Handlers/ConformanceHandlers.cs, TS conformance-handlers.ts) added these;
// this is the faithful Zig port.

const conformance_handlers = [_]BootHandler{
    .{ .pattern = "system/validate/echo", .name = "validate-echo", .operations = &.{"echo"} },
    .{ .pattern = "system/validate/dispatch-outbound", .name = "validate-dispatch-outbound", .operations = &.{"dispatch"} },
};

/// §7a `system/validate/echo`: returns the params entity verbatim (the literal in
/// params round-trips out). Native body, no compute — the portable replacement for
/// the A-011 compute/literal dispatch step.
fn echoHandler(p: *Peer, a: std.mem.Allocator, exec: Entity) Error!Outcome {
    _ = p;
    const params = (try exec.entityField(a, "params")) orelse
        return ok(try wire.emptyParams(a));
    return ok(params);
}

/// §7a `system/validate/dispatch-outbound`: originate one outbound EXECUTE via the
/// §6.11 reentry seam (`conn.outbound`) back to the caller, invoking `operation` on
/// `target` with `value`, and return the downstream response. Proves the target can
/// ORIGINATE, not just respond. The reentry direction (this peer → caller) is
/// authorized only by the caller, so the caller carries the minted authority
/// entities in-band (reentry_capability / reentry_granter / reentry_cap_signature).
fn dispatchOutboundHandler(p: *Peer, a: std.mem.Allocator, conn: *Conn, exec: Entity) Error!Outcome {
    const out_fn = conn.outbound orelse
        return errOut(a, 503, "no_outbound_seam", "dispatch-outbound requires a live §6.11 reentry connection");
    const params = (try exec.entityField(a, "params")) orelse
        return errOut(a, 400, "unexpected_params", "dispatch-outbound: missing params");
    const target = params.textField("target") orelse return errOut(a, 400, "unexpected_params", "missing target");
    const operation = params.textField("operation") orelse return errOut(a, 400, "unexpected_params", "missing operation");
    const value = params.field("value") orelse return errOut(a, 400, "unexpected_params", "missing value");

    // Caller-minted reentry authority, carried in-band (this peer is the grantee).
    const cap_e = try params.entityField(a, "reentry_capability") orelse return errOut(a, 400, "unexpected_params", "missing reentry_capability");
    const granter_e = try params.entityField(a, "reentry_granter") orelse return errOut(a, 400, "unexpected_params", "missing reentry_granter");
    const capsig_e = try params.entityField(a, "reentry_cap_signature") orelse return errOut(a, 400, "unexpected_params", "missing reentry_cap_signature");

    // §7a.1: the `value` field IS the outbound params entity data — pass it through
    // (the reference uses it directly). Re-wrapping as { value } double-wraps, so the
    // echo's result.value returns a map, not the sent value (keystone §7b t1_2).
    const inner = try Entity.make(a, "primitive/any", try model.cloneValue(a, value));

    // Build a signed, authority-bearing outbound EXECUTE back to the caller.
    const req = try buildReentryExecute(p, a, conn, target, operation, inner, cap_e, granter_e, capsig_e);
    const resp = (out_fn(conn.outbound_ctx, a, req)) orelse
        return errOut(a, 504, "outbound_timeout", "downstream did not reply");
    defer resp.deinit(a);

    const status = resp.root.uintField("status") orelse 0;
    const result = resp.root.field("result") orelse Value{ .null = {} };
    var rpairs = try a.alloc(Value.Pair, 2);
    rpairs[0] = .{ .key = try model.textVal(a, "status"), .value = .{ .uint = status } };
    rpairs[1] = .{ .key = try model.textVal(a, "result"), .value = try model.cloneValue(a, result) };
    return ok(try Entity.make(a, "primitive/any", .{ .map = rpairs }));
}

/// Assemble a signed reentry EXECUTE (the caller-minted authority in `included`).
fn buildReentryExecute(p: *Peer, a: std.mem.Allocator, conn: *Conn, target: []const u8, operation: []const u8, inner: Entity, cap_e: Entity, granter_e: Entity, capsig_e: Entity) Error!Envelope {
    conn.out_counter += 1;
    const rid = try std.fmt.allocPrint(a, "ro-{d}", .{conn.out_counter});
    var rpairs = try a.alloc(Value.Pair, 1);
    rpairs[0] = .{ .key = try model.textVal(a, "targets"), .value = blk: {
        const t = try a.alloc(Value, 1);
        t[0] = try model.textVal(a, try std.fmt.allocPrint(a, "system/handler/{s}", .{target}));
        break :blk .{ .array = t };
    } };
    const resource = Value{ .map = rpairs };
    const exec = try wire.makeExecute(a, .{
        .request_id = rid,
        .uri = target,
        .operation = operation,
        .params = inner,
        .resource = resource,
        .author = p.identity.identity_hash,
        .capability = cap_e.hash,
    });
    const exec_sig = try identity_mod.signEntity(a, p.identity, exec);
    var inc = try a.alloc(Inc, 4);
    inc[0] = .{ .key = cap_e.hash, .entity = cap_e };
    inc[1] = .{ .key = granter_e.hash, .entity = granter_e };
    inc[2] = .{ .key = capsig_e.hash, .entity = capsig_e };
    inc[3] = .{ .key = exec_sig.hash, .entity = exec_sig };
    // Materialize into an Envelope (arena-owned; out_fn must NOT free our entities).
    var included = try a.alloc(model.Included, inc.len);
    for (inc, 0..) |i, idx| included[idx] = .{ .key = i.key, .entity = i.entity };
    return Envelope{ .root = exec, .included = included };
}

fn conformanceHandler(p: *Peer, a: std.mem.Allocator, conn: *Conn, exec: Entity, stripped: []const u8) Error!Outcome {
    if (std.mem.eql(u8, stripped, "system/validate/echo")) return echoHandler(p, a, exec);
    if (std.mem.eql(u8, stripped, "system/validate/dispatch-outbound")) return dispatchOutboundHandler(p, a, conn, exec);
    return errOut(a, 501, "no_handler_body", stripped);
}

// ── dispatcher-level signature ingestion (§6.5) ──────────────────────────────

fn ingestSignatures(p: *Peer, a: std.mem.Allocator, env: Envelope) Error!void {
    for (env.included) |inc| {
        const e = inc.entity;
        if (!std.mem.eql(u8, e.typ, "system/signature")) continue;
        try p.store.putEntity(e);
        const signer_h = e.bytesField("signer") orelse continue;
        const signer_peer = env.includedGet(signer_h) orelse continue;
        try p.store.putEntity(signer_peer);
        const target = e.bytesField("target") orelse continue;
        const pk = signer_peer.bytesField("public_key") orelse continue;
        const pid = try identity_mod.peerIdOfPubkey(a, pk);
        const hex = try model.hex(a, target);
        const path = try std.fmt.allocPrint(a, "/{s}/system/signature/{s}", .{ pid, hex });
        try p.store.bind(path, e);
    }
}

// ── handler resolution (§6.6) — backward tree-walk ───────────────────────────

fn resolveHandler(p: *Peer, path: []const u8) ?[]const u8 {
    // try successively shorter prefixes split on '/'
    var end = path.len;
    while (end > 0) {
        const prefix = path[0..end];
        if (p.store.getAt(prefix)) |e| {
            if (std.mem.eql(u8, e.typ, "system/handler")) return prefix;
        }
        end = std.mem.lastIndexOfScalar(u8, path[0..end], '/') orelse break;
    }
    return null;
}

fn stripLocal(p: *Peer, pattern: []const u8) []const u8 {
    const prefix_len = 1 + p.local_peer.len + 1; // "/{local}/"
    if (pattern.len > prefix_len and cap.startsWith(pattern, "/") and
        std.mem.eql(u8, pattern[1 .. 1 + p.local_peer.len], p.local_peer) and
        pattern[1 + p.local_peer.len] == '/')
        return pattern[prefix_len..];
    return pattern;
}

// ── dispatch chain (§6.5) ────────────────────────────────────────────────────

/// Run dispatch against a per-request arena. Returns an arena-owned Outcome;
/// `materializeResponse` clones the survivors into gpa. `exec` is the env root.
fn dispatchOutcome(p: *Peer, a: std.mem.Allocator, conn: *Conn, env: Envelope) Error!Outcome {
    const exec = env.root;
    const uri = exec.textField("uri") orelse "";
    if (std.mem.eql(u8, uri, "system/protocol/connect"))
        return connectHandler(p, a, conn, exec, env);

    try ingestSignatures(p, a, env);
    const rv = cap.verifyRequest(a, env, &p.store, p.local_peer) catch |e| switch (e) {
        error.UnresolvableGrantee => return errOut(a, 401, "unresolvable_grantee", null),
        else => |x| return x,
    };
    switch (rv) {
        .authn_fail => return errOut(a, 401, "authentication_failed", null),
        .authz_deny => return errOut(a, 403, "capability_denied", null),
        .chain_too_deep => return errOut(a, 400, "chain_depth_exceeded", null),
        .allow => {},
    }
    const norm = try cap.normalizeUri(a, uri);
    const path = try cap.canonicalize(a, p.local_peer, norm);
    // §1.4: inbound dispatch must target the local peer
    const tp = try cap.extractPeer(a, p.local_peer, path);
    if (!std.mem.eql(u8, tp, p.local_peer)) return errOut(a, 404, "handler_not_found", "not local peer");
    const pattern = resolveHandler(p, path) orelse return errOut(a, 404, "handler_not_found", path);

    const caller_cap = blk: {
        const ch = exec.bytesField("capability") orelse break :blk null;
        break :blk env.includedGet(ch);
    };
    const cc = caller_cap orelse return errOut(a, 403, "capability_denied", null);
    const granter_peer = try cap.granterFrame(a, env, &p.store, p.local_peer, cc);
    const verdict = try cap.checkPermission(a, p.local_peer, granter_peer, exec, cc, pattern);
    if (verdict == .deny) return errOut(a, 403, "capability_denied", null);

    const stripped = stripLocal(p, pattern);
    if (std.mem.eql(u8, stripped, "system/tree")) return treeHandler(p, a, exec);
    if (std.mem.eql(u8, stripped, "system/capability")) return capabilityHandler(p, a, exec, caller_cap);
    if (std.mem.eql(u8, stripped, "system/handler")) return handlersHandler(p, a, exec);
    if (std.mem.eql(u8, stripped, "system/type")) return typesHandler(a, exec);
    // §7a conformance handlers (only bootstrapped when conformance=true)
    if (p.conformance and cap.startsWith(stripped, "system/validate/"))
        return conformanceHandler(p, a, conn, exec, stripped);
    // a dynamically-registered handler: dispatch its entity-native body
    // (§6.13(a) — the v7.74 §10.1 register round-trip). The resolved handler
    // entity carries the expression_path seam.
    if (p.store.getAt(pattern)) |handler_entity| {
        if (std.mem.eql(u8, handler_entity.typ, "system/handler"))
            return entityNativeDispatch(p, a, handler_entity);
    }
    return errOut(a, 501, "no_handler_body", stripped);
}

/// Materialize the arena-owned Outcome into a gpa-owned response Envelope that
/// survives the arena reset. Returns null only for a non-EXECUTE root (ignored).
pub fn dispatch(p: *Peer, conn: *Conn, env: Envelope) Error!?Envelope {
    const exec = env.root;
    if (!std.mem.eql(u8, exec.typ, "system/protocol/execute")) return null; // §3.3 server ignores non-EXECUTE
    const request_id = exec.textField("request_id") orelse "";

    var arena_inst = std.heap.ArenaAllocator.init(p.gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    const outcome = dispatchOutcome(p, a, conn, env) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => blk: {
            // any other dispatch error → 500, keep the connection alive (§3.3)
            break :blk Outcome{ .status = 500, .result = try wire.errorResult(a, "internal_error", null), .included = &.{} };
        },
    };

    // Build the response in gpa (so it outlives the arena).
    const gpa = p.gpa;
    const result_clone = try outcome.result.clone(gpa);
    const response_root = try wire.makeResponse(gpa, request_id, outcome.status, result_clone);
    errdefer response_root.deinit(gpa);
    var inc_list = try gpa.alloc(model.Included, outcome.included.len);
    var built: usize = 0;
    errdefer {
        for (inc_list[0..built]) |i| {
            gpa.free(i.key);
            i.entity.deinit(gpa);
        }
        gpa.free(inc_list);
    }
    while (built < outcome.included.len) : (built += 1) {
        const src = outcome.included[built];
        const e = try src.entity.clone(gpa);
        errdefer e.deinit(gpa);
        inc_list[built] = .{ .key = try gpa.dupe(u8, src.key), .entity = e };
    }
    return Envelope{ .root = response_root, .included = inc_list };
}

/// A 500 response (gpa-owned) for an envelope whose dispatch raised unexpectedly.
pub fn internalErrorResponse(p: *Peer, env: Envelope) Error!Envelope {
    const gpa = p.gpa;
    const request_id = env.root.textField("request_id") orelse "";
    const er = try wire.errorResult(gpa, "internal_error", null);
    const root = try wire.makeResponse(gpa, request_id, 500, er);
    return Envelope{ .root = root, .included = try gpa.alloc(model.Included, 0) };
}

// ── bootstrap (§6.9) ─────────────────────────────────────────────────────────

const BootHandler = struct { pattern: []const u8, name: []const u8, operations: []const []const u8 };

// The four MUST handlers' interface operation sets (§6.2). The oracle's
// handlers.handler_<name>_operations_match check requires these op keys present
// in the published interface's `operations` map (connect={hello,authenticate},
// tree core={get,put}, capability={request,delegate,revoke}). Types is SHOULD.
const bootstrap_handlers = [_]BootHandler{
    .{ .pattern = "system/tree", .name = "Tree", .operations = &.{ "get", "put" } },
    .{ .pattern = "system/handler", .name = "Handlers", .operations = &.{ "register", "unregister" } },
    .{ .pattern = "system/type", .name = "Types", .operations = &.{} },
    .{ .pattern = "system/capability", .name = "Capability", .operations = &.{ "request", "delegate", "revoke" } },
    .{ .pattern = "system/protocol/connect", .name = "Connect", .operations = &.{ "hello", "authenticate" } },
};

/// Build the interface `operations` map: `{op_name -> operation-spec data}`. The
/// value is the §6.2 operation-spec DATA map (the oracle decodes it as
/// HandlerOperationSpec, NOT a wrapped entity); an op with no declared I/O types
/// is the empty map. Arena-allocated.
fn operationsMap(a: std.mem.Allocator, ops: []const []const u8) Error!Value {
    const pairs = try a.alloc(Value.Pair, ops.len);
    for (ops, 0..) |op, i| {
        pairs[i] = .{ .key = try model.textVal(a, op), .value = .{ .map = &.{} } };
    }
    return .{ .map = pairs };
}

/// Bootstrap one handler: handler entity at the pattern path, interface entity at
/// the discovery index (system/handler/{pattern}), and a self-issued grant.
fn bootstrapHandler(p: *Peer, a: std.mem.Allocator, local_peer: []const u8, bh: BootHandler) Error!void {
    var hpairs = try a.alloc(Value.Pair, 1);
    hpairs[0] = .{ .key = try model.textVal(a, "interface"), .value = try model.textVal(a, try std.fmt.allocPrint(a, "system/handler/{s}", .{bh.pattern})) };
    const handler_e = try Entity.make(a, "system/handler", .{ .map = hpairs });
    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/{s}", .{ local_peer, bh.pattern }), handler_e);
    var ipairs = try a.alloc(Value.Pair, 3);
    ipairs[0] = .{ .key = try model.textVal(a, "pattern"), .value = try model.textVal(a, bh.pattern) };
    ipairs[1] = .{ .key = try model.textVal(a, "name"), .value = try model.textVal(a, bh.name) };
    ipairs[2] = .{ .key = try model.textVal(a, "operations"), .value = try operationsMap(a, bh.operations) };
    const iface_e = try Entity.make(a, "system/handler/interface", .{ .map = ipairs });
    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/system/handler/{s}", .{ local_peer, bh.pattern }), iface_e);
    const minted = try mintToken(p, a, p.identity.identity_hash, null, &.{});
    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/system/capability/grants/{s}", .{ local_peer, bh.pattern }), minted.token);
}

pub const CreateOptions = struct {
    seed: [32]u8,
    open_grants: bool = false,
    conformance: bool = false,
};

/// Build and bootstrap a peer (§6.9 + §6.9a). The peer owns its store + identity.
pub fn create(gpa: std.mem.Allocator, opts: CreateOptions) Error!Peer {
    const identity = try identity_mod.ofSeed(gpa, opts.seed);
    errdefer identity.deinit(gpa);
    var st = Store.init(gpa);
    errdefer st.deinit();
    const local_peer = identity.peer_id;

    var p = Peer{
        .gpa = gpa,
        .identity = identity,
        .store = st,
        .local_peer = local_peer,
        .open_grants = opts.open_grants,
        .conformance = opts.conformance,
    };

    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    // local identity entity in the store (root-granter resolution + §3.13 self)
    try p.store.putEntity(p.identity.peer_entity);
    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/system/peer/self", .{local_peer}), p.identity.peer_entity);

    // §9.5 core types (minimal S3 subset; full registry deferred to S4)
    try type_defs.publish(gpa, &p.store, local_peer);

    // bootstrap the four MUST handlers (§6.2). When conformance=true, also
    // bootstrap the §7a system/validate/* scaffolding handlers.
    for (bootstrap_handlers) |bh| try bootstrapHandler(&p, a, local_peer, bh);
    if (opts.conformance) {
        for (conformance_handlers) |bh| try bootstrapHandler(&p, a, local_peer, bh);
    }

    // §6.9a peer-authority bootstrap (L0 write-set): self-owner cap + default entry.
    const policy_base = try std.fmt.allocPrint(a, "/{s}/system/capability/policy/", .{local_peer});
    const owner = try mintToken(&p, a, p.identity.identity_hash, null, try ownerGrants(a, local_peer));
    const ohex = try model.hex(a, p.identity.identity_hash);
    try p.store.bind(try std.fmt.allocPrint(a, "{s}{s}", .{ policy_base, ohex }), owner.token);
    const othex = try model.hex(a, owner.token.hash);
    try p.store.bind(try std.fmt.allocPrint(a, "/{s}/system/signature/{s}", .{ local_peer, othex }), owner.signature);

    const default_grants = if (opts.open_grants) try openGrantsScope(a) else try discoveryFloor(a);
    var dpairs = try a.alloc(Value.Pair, 2);
    dpairs[0] = .{ .key = try model.textVal(a, "peer_pattern"), .value = try model.textVal(a, "default") };
    const dg = try a.alloc(Value, default_grants.len);
    @memcpy(dg, default_grants);
    dpairs[1] = .{ .key = try model.textVal(a, "grants"), .value = .{ .array = dg } };
    const default_entry = try Entity.make(a, "system/capability/policy-entry", .{ .map = dpairs });
    try p.store.bind(try std.fmt.allocPrint(a, "{s}default", .{policy_base}), default_entry);

    return p;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "peer bootstrap leak-clean + tree entries seeded" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{3} ** 32 });
    defer p.deinit();
    // system/peer type seeded
    const type_path = try std.fmt.allocPrint(gpa, "/{s}/system/type/system/peer", .{p.local_peer});
    defer gpa.free(type_path);
    try testing.expect(p.store.getAt(type_path) != null);
    // connect handler bootstrapped
    const connect_path = try std.fmt.allocPrint(gpa, "/{s}/system/protocol/connect", .{p.local_peer});
    defer gpa.free(connect_path);
    try testing.expect(p.store.getAt(connect_path) != null);
}

test "dispatch hello returns a hello response" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{5} ** 32 });
    defer p.deinit();
    var conn = Conn{};
    defer conn.deinit(gpa);
    // build a connect/hello EXECUTE envelope
    const params = try wire.emptyParams(gpa);
    const exec = try wire.makeExecute(gpa, .{ .request_id = "r1", .uri = "system/protocol/connect", .operation = "hello", .params = params });
    const env = Envelope{ .root = exec, .included = try gpa.alloc(model.Included, 0) };
    defer env.deinit(gpa);
    const resp = (try dispatch(&p, &conn, env)).?;
    defer resp.deinit(gpa);
    try testing.expectEqual(@as(u64, 200), resp.root.uintField("status").?);
}

test "deletion-marker is omitted from listings (CORE-TREE-DELETE-1)" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{7} ** 32 });
    defer p.deinit();
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    const base = try std.fmt.allocPrint(a, "/{s}/app/del", .{p.local_peer});
    const real = try Entity.make(a, "system/test", .{ .map = &.{} });
    try p.store.bind(try std.fmt.allocPrint(a, "{s}/target", .{base}), real);
    const sib = try Entity.make(a, "system/test2", .{ .map = &.{} });
    try p.store.bind(try std.fmt.allocPrint(a, "{s}/keep", .{base}), sib);
    // before deletion: both listed
    var out1 = try buildListing(&p, a, try std.fmt.allocPrint(a, "{s}/", .{base}));
    try testing.expectEqual(@as(u64, 2), out1.result.uintField("count").?);
    // put a deletion-marker over target
    const marker = try Entity.make(a, "system/deletion-marker", .{ .map = &.{} });
    try p.store.bind(try std.fmt.allocPrint(a, "{s}/target", .{base}), marker);
    var out2 = try buildListing(&p, a, try std.fmt.allocPrint(a, "{s}/", .{base}));
    try testing.expectEqual(@as(u64, 1), out2.result.uintField("count").?); // only the sibling
}

test "§7a echo handler round-trips params verbatim (conformance build)" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{9} ** 32, .open_grants = true, .conformance = true });
    defer p.deinit();
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    // echo interface bootstrapped
    const iface = try std.fmt.allocPrint(a, "/{s}/system/handler/system/validate/echo", .{p.local_peer});
    try testing.expect(p.store.getAt(iface) != null);
    // direct handler-body call (the dispatch chain is exercised live in S4)
    var pp = try a.alloc(Value.Pair, 1);
    pp[0] = .{ .key = try model.textVal(a, "ping"), .value = .{ .uint = 42 } };
    const exec = try wire.makeExecute(a, .{ .request_id = "e1", .uri = "system/validate/echo", .operation = "echo", .params = try Entity.make(a, "primitive/any", .{ .map = pp }) });
    const out = try echoHandler(&p, a, exec);
    try testing.expectEqual(@as(u64, 200), out.status);
    try testing.expectEqual(@as(u64, 42), out.result.uintField("ping").?);
}
