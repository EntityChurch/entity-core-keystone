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
const hash = @import("hash.zig");
const varint = @import("varint.zig");
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

/// Mint a capability token granted by us to `grantee_hash` at a caller-supplied
/// instant; sign it. Both entities are allocated from `a`.
///
/// `expires_at` carries §5.6's MIN_DEFINED ceiling: null means no term was defined and
/// the token genuinely has no expiry (the ONLY "no bound" spelling), while a non-null
/// value is emitted verbatim — including one equal to `created_at`, which §5.6 rule 2
/// requires for ttl_ms == 0 and which means "already expired at every observable
/// instant", not "unbounded".
///
/// `created_at` is supplied rather than sampled here so a computed expiry is guaranteed
/// to be relative to the SAME instant that lands in the token; sampling the clock twice
/// skews the two.
fn mintTokenAt(p: *Peer, a: std.mem.Allocator, created_at: u64, grantee_hash: []const u8, parent: ?[]const u8, expires_at: ?u64, grants: []Value) Error!Minted {
    var list: std.ArrayList(Value.Pair) = .empty;
    try list.append(a, .{ .key = try model.textVal(a, "granter"), .value = try model.bytesVal(a, p.identity.identity_hash) });
    try list.append(a, .{ .key = try model.textVal(a, "grantee"), .value = try model.bytesVal(a, grantee_hash) });
    const grants_copy = try a.alloc(Value, grants.len);
    @memcpy(grants_copy, grants);
    try list.append(a, .{ .key = try model.textVal(a, "grants"), .value = .{ .array = grants_copy } });
    try list.append(a, .{ .key = try model.textVal(a, "created_at"), .value = .{ .uint = created_at } });
    if (expires_at) |ex| try list.append(a, .{ .key = try model.textVal(a, "expires_at"), .value = .{ .uint = ex } });
    if (parent) |ph| try list.append(a, .{ .key = try model.textVal(a, "parent"), .value = try model.bytesVal(a, ph) });
    const token = try Entity.make(a, "system/capability/token", .{ .map = try list.toOwnedSlice(a) });
    const signature = try identity_mod.signEntity(a, p.identity, token);
    return .{ .token = token, .signature = signature };
}

/// `mintTokenAt` at the current instant with no §5.6 ceiling. Used by the paths that
/// mint a self-issued grant from local authority (bootstrap, handler registration, the
/// §4.4 handshake), where no MIN_DEFINED term is in play.
fn mintToken(p: *Peer, a: std.mem.Allocator, grantee_hash: []const u8, parent: ?[]const u8, grants: []Value) Error!Minted {
    return mintTokenAt(p, a, nowMs(), grantee_hash, parent, null, grants);
}

// ── §5.6 temporal ceiling (CAP-5 / CAP-6) ────────────────────────────────────

/// Convert a DURATION term to an absolute timestamp, reporting whether it contributes
/// a ceiling at all.
///
/// §5.6 rule 3: a term whose conversion created_at+ttl is not representable is treated
/// as ABSENT, exactly as a null term is. It MUST NOT wrap and MUST NOT saturate to a
/// representable maximum — saturation encodes differently from absence and manufactures
/// expires_at == 2^64-1, a finite bound no reader can distinguish from a deliberate one.
///
/// ttl == 0 is NOT a special case here and deliberately so: §5.6 rule 2 makes 0 a
/// DEFINED value yielding created_at (expire immediately). The absent field is the only
/// "no bound" spelling, and falling out of the arithmetic is what keeps the two from
/// ever collapsing into each other.
fn addTtl(created_at: u64, ttl: u64) ?u64 {
    const sum = @addWithOverflow(created_at, ttl);
    if (sum[1] != 0) return null; // u64 wrap => not representable => drop the term
    return sum[0];
}

/// Fold one DEFINED term into the running MIN_DEFINED (§5.6). Callers pass each term
/// already shaped: absolute timestamps (parent.expires_at, caller_capability.
/// expires_at) enter directly; durations MUST be converted with `addTtl` first. Mixing
/// a duration in unconverted yields a timestamp near the epoch and silently clamps
/// every token to already-expired — the failure mode §5.6 calls out by name.
fn minDefined(acc: ?u64, term: ?u64) ?u64 {
    const t = term orelse return acc;
    const a = acc orelse return t;
    return @min(a, t);
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
        // §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
        // HALF-OPEN connection (hello done, authenticate not yet) is an operation we
        // implement arriving in a state that forbids it — the same class as
        // connection_already_established above, taking the same 409. A half-open
        // connection is NOT established, so the guard above cannot reach it; §4.7
        // names this gap explicitly because two adjacent rules each look like they
        // cover it and neither does.
        if (conn.issued_nonce != null) return errOut(a, 409, "connection_sequence_error", null);
        const params = try exec.entityField(a, "params");
        // §4.5 negotiation: reject disjoint hash_formats / key_types up front.
        if (params) |pe| {
            if (negotiationReject(pe, "hash_formats", "ecfv1-sha256")) return errOut(a, 400, "incompatible_hash_format", null);
            if (negotiationReject(pe, "key_types", "ed25519")) return errOut(a, 400, "unsupported_key_type", null);
            // §4.5 mutual verifiability, the direction that is NOT the array.
            // `key_types` is an ACCEPT-SET; the initiator's OWN key_type is not in it
            // — it rides in its `peer_id` — so a hello may advertise a perfectly good
            // accept-set and still name an identity we cannot verify. Checking only
            // the array leaves that MUST unenforced at hello, which is where §4.5
            // wants it; authenticate catches it one leg later, which is conformant
            // but non-canonical.
            //
            // An UNPARSEABLE peer_id is deliberately left alone: that is a malformed
            // field, not a key_type we lack, and authenticate already refuses it.
            if (pe.textField("peer_id")) |pid| {
                const parsed = peer_id.parse(a, pid) catch null;
                if (parsed) |pp| {
                    defer pp.deinit(a);
                    if (pp.key_type != 0x01) return errOut(a, 400, "unsupported_key_type", null);
                }
            }
        }
        // §4.5 `protocols` — the one negotiated field Required with NO default, so
        // there is no floor to fall back to, and its two failure modes carry
        // different codes on purpose (§4.5 table row / §4.7 row 1):
        //
        //   absent or empty     -> 400 invalid_request       (a malformed hello)
        //   non-empty, disjoint -> 400 incompatible_protocol (we compared)
        //
        // "a caller that named no version cannot be told the comparison failed" —
        // the remedies differ (send the field vs change the version) and §4.7 exists
        // so the code selects the remedy. The vocabulary is §8.4's protocol version
        // identifiers, today the single entity-core/1.0.
        //
        // ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
        // precedence between the three, so a hello disjoint in more than one
        // dimension may be refused on any of them — but the choice is OBSERVABLE, and
        // the reference peer refuses key_types first. Checking protocols first is
        // equally spec-legal and makes AGILITY-UNKNOWN-1 answer incompatible_protocol,
        // because that probe's own hello carries protocols ["entity-core/v7"] — a
        // spec-line name, not a §8.4 identifier (F56).
        if (!helloProtocolOk(params)) {
            if (helloProtocolsPresent(params)) return errOut(a, 400, "incompatible_protocol", null);
            return errOut(a, 400, "invalid_request", "hello: protocols absent or empty");
        }
        // The hello is accepted from here on, so the initiator's peer_id is recorded
        // only now — a refused hello must not leave state on the connection.
        if (params) |pe| {
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
        // RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
        // single-use nonce. The anti-replay property is the MUST and the
        // mechanism (established-state tracking) is impl-defined, but the
        // STATUS is pinned to 401 invalid_nonce — a 409 state-conflict
        // under-signals the replay.
        if (conn.established) return errOut(a, 401, "invalid_nonce", null);
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
    // §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
    // 400 invalid_request, not the 501 every other handler answers. The table
    // separates a STATE conflict from an UNKNOWN operation because they select
    // different remedies — "an unknown connect operation is not out of order at all;
    // it exists in no state", so connection_sequence_error would point the caller at
    // its ORDERING when the defect is its OPERATION NAME. Row 10 is scoped "in any
    // state", so this arm covers pre-handshake AND established; the genuine sequence
    // cases are refused in the two branches above, with 409.
    //
    // SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
    // (§3.3's 501 row, §6.2) is a different contract and is separately gated; moving
    // the other handlers' 501 would trade one green check for another.
    return errOut(a, 400, "invalid_request", "connect: unknown operation");
}

/// §4.5: is `protocols` present at all (a non-empty text array)? Separates the
/// malformed-hello case from the we-compared-and-disagreed case, which take
/// different §4.7 codes.
fn helloProtocolsPresent(params: ?Entity) bool {
    const pe = params orelse return false;
    const arr = switch (pe.field("protocols") orelse return false) {
        .array => |x| x,
        else => return false,
    };
    for (arr) |it| switch (it) {
        .text => return true,
        else => {},
    };
    return false;
}

/// §4.5: does `protocols` name a version we speak?
fn helloProtocolOk(params: ?Entity) bool {
    const pe = params orelse return false;
    const arr = switch (pe.field("protocols") orelse return false) {
        .array => |x| x,
        else => return false,
    };
    for (arr) |it| switch (it) {
        .text => |s| if (std.mem.eql(u8, s, "entity-core/1.0")) return true,
        else => {},
    };
    return false;
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

/// A §5.4 PATTERN rather than a concrete path. A resource-requiring operation takes a
/// CONCRETE path (0.8.2.20); a trailing "/" is a listing request rather than a pattern
/// — only a "*" makes it one.
fn isPatternPath(t: []const u8) bool {
    return std.mem.indexOfScalar(u8, t, '*') != null;
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

/// Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).
///
/// "When any handler returns a multi-entry result whose entries are tree paths, each
/// entry MUST be individually checked using `check_path_permission`. Entries for which
/// `check_path_permission` returns DENY MUST be omitted. The result's `count` field
/// MUST reflect the filtered entry count, not the source tree's total count."
///
/// This is the read path at its highest volume and it is the reason 0.8.2.21 refused to
/// carve reads out of the caller-specified-path rule: an unfiltered listing discloses
/// the EXISTENCE of every binding under a prefix to a caller whose capability covers
/// none of them.
///
/// The DIRECTORY itself is deliberately NOT checked — §6.3 makes each ENTRY the
/// subject, and testing the prefix would deny a listing to a caller whose grant covers
/// children but not the node above them, which is the ordinary shape of a narrowed
/// grant.
///
/// An UNAUTHENTICATED context (`caller_cap == null`) is NOT filtered: the filter's
/// subject is "the caller's verified capability", and where there is none there is no
/// caller to narrow. That is the bootstrap/internal path.
fn buildListing(p: *Peer, a: std.mem.Allocator, path: []const u8, caller_cap: ?Entity, pattern: []const u8) Error!Outcome {
    const entries = try p.store.listing(a, path);
    var entry_pairs: std.ArrayList(Value.Pair) = .empty;
    var emitted: u64 = 0;
    const dir = if (path.len > 0 and path[path.len - 1] == '/')
        path
    else
        try std.fmt.allocPrint(a, "{s}/", .{path});
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
        // §6.3's per-entry check (0.8.2.21/.22).
        if (caller_cap) |cc| {
            const child = try std.fmt.allocPrint(a, "{s}{s}", .{ dir, le.seg });
            if (!try cap.checkPathPermission(a, p.local_peer, "get", child, cc, pattern)) continue;
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

/// The `system/tree` handler (§6.3).
///
/// RESOLVE THE OPERATION FIRST; only then run the §3.3 resource ladder. The `op`
/// dispatch below is what makes that true: a handler that validates the resource first
/// answers a RESOURCE fault for an unknown-OPERATION request, so `system/tree:bogusop`
/// with no resource would report `ambiguous_resource` where §3.3 pins `501
/// unsupported_operation` (measured as X9/F52 on peers that had the arms the other way
/// round). Here every resource branch is INSIDE a known-operation arm, so the ladder is
/// unreachable for an unknown op.
fn treeHandler(p: *Peer, a: std.mem.Allocator, exec: Entity, caller_cap: ?Entity, pattern: []const u8) Error!Outcome {
    const op = exec.textField("operation") orelse "";

    if (std.mem.eql(u8, op, "get")) {
        // §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
        // `resource.targets`: a handler that counts the effective list and then indexes
        // `targets[0]` has implemented the arithmetic completely and is still reading a
        // path no authorization covered.
        const eff = try cap.effectiveTargets(a, p.local_peer, exec);
        if (!eff.had_resource) {
            // THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION
            // IS WHAT SAYS SO. §3.3's "an empty effective list IS the absent case" is
            // scoped "for an operation that REQUIRES a resource" (0.8.2.24, N7); `get`
            // does not. For a resource-OPTIONAL operation 0.8.2.25 (N10) decides the
            // present-but-empty case by whether the absent case is WIDER than the
            // request — BROAD-RESULT refuses it, OPTIONAL-FILTER answers it empty.
            //
            // EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
            // resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
            // listing", self-excluded case "400 path_required". Both arms are pinned by
            // text and neither is this peer's choice.
            const root_path = try std.fmt.allocPrint(a, "/{s}/", .{p.local_peer});
            return buildListing(p, a, root_path, caller_cap, pattern);
        }
        if (eff.survivors.len == 0) {
            // The self-excluded request: `resource` PRESENT, every target carved out by
            // the caller's own exclude. Serving it the absent case "answers a request
            // for one excluded path with a listing of the tree" (EXTENSION-TREE §2.2a)
            // — the root listing is WIDER than what was asked for, which is what
            // BROAD-RESULT means.
            return errOut(a, 400, "path_required", "tree: effective target list is empty");
        }
        if (eff.survivors.len > 1)
            return errOut(a, 400, "ambiguous_resource", "tree: more than one effective target");
        const tgt = eff.survivors[0];
        if (!pathFlexOk(tgt)) return errOut(a, 400, "invalid_path", tgt);
        if (tgt.len == 0 or tgt[tgt.len - 1] == '/') {
            return buildListing(p, a, try cap.canonicalize(a, p.local_peer, tgt), caller_cap, pattern);
        }
        if (isPatternPath(tgt)) return errOut(a, 400, "malformed_resource", tgt);
        const path = try cap.canonicalize(a, p.local_peer, tgt);
        // §6.3: the handler MUST verify the CALLER's capability covers the path it is
        // about to read. NOT a secondary check — the dispatch-level check never saw
        // this path if the caller excluded it.
        if (caller_cap) |cc| {
            if (!try cap.checkPathPermission(a, p.local_peer, "get", path, cc, pattern))
                return errOut(a, 403, "capability_denied", path);
        }
        const e = p.store.getAt(path) orelse return errOut(a, 404, "not_found", path);
        // mode=hash → return system/hash
        if (try exec.entityField(a, "params")) |pe| {
            if (pe.textField("mode")) |m| if (std.mem.eql(u8, m, "hash")) {
                return ok(try Entity.make(a, "system/hash", try model.bytesVal(a, e.hash)));
            };
        }
        return ok(try e.clone(a));
    } else if (std.mem.eql(u8, op, "put")) {
        // Same ladder as `get`, with the two empties COLLAPSED rather than split:
        // EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's "an
        // empty effective list IS the absent case" applies in its unscoped form and
        // both empties answer `path_required`.
        //
        // Note the code change 0.8.2.20 forced: this branch answered
        // `ambiguous_resource` for a MISSING target, which 0.8.2.20 names as the exact
        // inversion it forbids. The remedies differ — *supply a resource* is not
        // *disambiguate your request* — and the code is what selects between them.
        const eff = try cap.effectiveTargets(a, p.local_peer, exec);
        if (!eff.had_resource or eff.survivors.len == 0)
            return errOut(a, 400, "path_required", "tree: put requires a resource target");
        if (eff.survivors.len > 1)
            return errOut(a, 400, "ambiguous_resource", "tree: more than one effective target");
        const tgt = eff.survivors[0];
        if (!pathFlexOk(tgt)) return errOut(a, 400, "invalid_path", tgt);
        if (isPatternPath(tgt)) return errOut(a, 400, "malformed_resource", tgt);
        const path = try cap.canonicalize(a, p.local_peer, tgt);
        if (caller_cap) |cc| {
            if (!try cap.checkPathPermission(a, p.local_peer, "put", path, cc, pattern))
                return errOut(a, 403, "capability_denied", path);
        }
        const params = try exec.entityField(a, "params");
        const raw_entity = if (params) |pe| pe.field("entity") else null;
        const expected = if (params) |pe| pe.bytesField("expected_hash") else null;
        // §3.9 CAS
        const current = p.store.hashAt(path);
        const zero33 = [_]u8{0} ** 33;
        const cas_ok = if (expected) |h| (if (std.mem.eql(u8, h, &zero33)) current == null else (current != null and std.mem.eql(u8, current.?, h))) else true;
        if (!cas_ok) return errOut(a, 409, "hash_mismatch", path);
        if (raw_entity) |rv| {
            switch (try admitPut(a, rv)) {
                .refused => |r| return r,
                .admitted => |e| {
                    try p.store.bind(path, e);
                    return ok(try Entity.make(a, "system/hash", try model.bytesVal(a, e.hash)));
                },
            }
        }
        return errOut(a, 400, "unexpected_params", "put: missing entity");
    }
    return errOut(a, 501, "unsupported_operation", op);
}

/// Digest byte length for a `content_hash_format` code per the §1.2 seed table,
/// or null when this peer cannot VERIFY that code. The total wire length is this
/// plus the varint prefix, which is not a constant of the code (§7.3): codes
/// >= 0x80 occupy more than one byte.
fn hashDigestLen(format_code: u64) ?usize {
    return switch (format_code) {
        0x00 => 32,
        0x01 => 48,
        else => null,
    };
}

/// The outcome of §6.3's put admission ladder.
const PutAdmission = union(enum) { admitted: Entity, refused: Outcome };

/// §6.3's `put` admission ladder (normative, 0.8.2.11).
///
/// `put` is a RECEIPT path: the submitter authors the entity, the peer validates
/// what it received (§1.8 item 1) and MUST NOT author a submitted entity's
/// `content_hash` on the submitter's behalf. Two ordered steps:
///
///   1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any
///      CBOR value; null is a legal payload), and a `content_hash` that is a
///      well-formed system/hash whose total byte length matches its format code
///      (§1.2). Any failure -> 400 invalid_request. A well-formed hash naming a
///      format code this peer cannot verify is the separate §1.2 ingest-dispatch
///      case -> 400 unsupported_content_hash_format.
///   2. HASH — carried content_hash vs content_hash({type, data}). Disagreement ->
///      400 hash_mismatch.
///
/// Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
/// inputs are exactly what step 1 establishes, so a submission that is both
/// malformed and mis-hashed is step 1's and answers invalid_request.
///
/// Structural admission is not semantic validation: `data` is never checked
/// against the type named by `type`.
fn admitPut(a: std.mem.Allocator, v: Value) Error!PutAdmission {
    const refuse = struct {
        fn f(al: std.mem.Allocator, code: []const u8, msg: []const u8) Error!PutAdmission {
            return .{ .refused = try errOut(al, 400, code, msg) };
        }
    }.f;

    switch (v) {
        .map => {},
        else => return refuse(a, "invalid_request", "put: entity is not a map"),
    }
    const typ = switch (model.mapGet(v, "type") orelse Value{ .null = {} }) {
        .text => |s| s,
        else => return refuse(a, "invalid_request", "put: entity.type absent, empty or not a text string"),
    };
    if (typ.len == 0)
        return refuse(a, "invalid_request", "put: entity.type absent, empty or not a text string");
    // Presence, not truthiness: a CBOR null is a legal `data` payload.
    const data_src = model.mapGet(v, "data") orelse
        return refuse(a, "invalid_request", "put: entity.data absent");
    const carried = switch (model.mapGet(v, "content_hash") orelse Value{ .null = {} }) {
        .bytes => |b| b,
        else => return refuse(a, "invalid_request", "put: entity.content_hash absent or not a byte string"),
    };
    if (carried.len == 0)
        return refuse(a, "invalid_request", "put: entity.content_hash absent or not a byte string");
    const dec = varint.decode(carried, 0) catch
        return refuse(a, "invalid_request", "put: entity.content_hash is not a well-formed system/hash");
    // §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
    // invalid_request: the shape is fine, the algorithm is what we lack.
    const digest_len = hashDigestLen(dec.value) orelse
        return refuse(a, "unsupported_content_hash_format", "put: unsupported content_hash_format");
    if (carried.len != dec.len + digest_len)
        return refuse(a, "invalid_request", "put: content_hash length does not match its format code");

    const computed = try hash.contentHash(a, dec.value, typ, data_src);
    if (!std.mem.eql(u8, computed, carried))
        return refuse(a, "hash_mismatch", "put: content_hash does not match content_hash({type, data})");

    // The carried hash IS the entity's address; recomputing it into the store would
    // be the authoring arm §6.3 forbids. Built field-by-field rather than through
    // Entity.make, which hardcodes format 0x00.
    return .{ .admitted = .{
        .typ = try a.dupe(u8, typ),
        .data = try model.cloneValue(a, data_src),
        .hash = try a.dupe(u8, carried),
    } };
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
fn mintBounded(p: *Peer, a: std.mem.Allocator, env: model.Envelope, caller_cap: ?Entity, params: ?Entity, req_grants: []Value, grantee_hash: []const u8, parent: ?[]const u8) Error!Outcome {
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

    // §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and
    // convert the duration terms against that same instant.
    //
    // Note what this is NOT: an authorization decision. An over-long ttl_ms from a
    // bounded caller MINTS a clamped token and returns 200 — "rejecting it is
    // non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
    // (parent: null), so §5.6's parent-child attenuation never reaches it; without this
    // clamp, temporal attenuation is the one dimension a requester could escape, and
    // policy withdrawal would have no bounded latency.
    const created_at = nowMs();
    var ceiling: ?u64 = null;
    if (parent) |ph| { // absolute
        if (cap.resolve(env, &p.store, ph)) |pt| ceiling = minDefined(ceiling, pt.uintField("expires_at"));
    }
    if (caller_cap) |cc| ceiling = minDefined(ceiling, cc.uintField("expires_at")); // absolute
    if (params) |pe| { // duration
        if (pe.uintField("ttl_ms")) |ttl| ceiling = minDefined(ceiling, addTtl(created_at, ttl));
    }

    const minted = try mintTokenAt(p, a, created_at, grantee_hash, parent, ceiling, req_grants);
    var gpairs = try a.alloc(Value.Pair, 1);
    gpairs[0] = .{ .key = try model.textVal(a, "token"), .value = try model.bytesVal(a, minted.token.hash) };
    const grant_result = try Entity.make(a, "system/capability/grant", .{ .map = gpairs });
    var inc = try a.alloc(Inc, 3);
    inc[0] = .{ .key = minted.token.hash, .entity = minted.token };
    inc[1] = .{ .key = p.identity.identity_hash, .entity = p.identity.peer_entity };
    inc[2] = .{ .key = minted.signature.hash, .entity = minted.signature };
    return okInc(grant_result, inc);
}

fn capabilityHandler(p: *Peer, a: std.mem.Allocator, env: model.Envelope, exec: Entity, caller_cap: ?Entity) Error!Outcome {
    const op = exec.textField("operation") orelse "";
    const params = try exec.entityField(a, "params");
    const author = exec.bytesField("author");
    if (std.mem.eql(u8, op, "request")) {
        const grantee = author orelse return errOut(a, 403, "capability_denied", null);
        return mintBounded(p, a, env, caller_cap, params, try reqGrants(a, params), grantee, null);
    } else if (std.mem.eql(u8, op, "delegate")) {
        const parent = if (params) |pe| pe.bytesField("parent") else null;
        if (parent == null) return errOut(a, 400, "unexpected_params", "delegate: parent required");
        if (isZeroHash(parent.?)) return errOut(a, 400, "unexpected_params", "delegate: zero parent");
        // delegate is same-peer-only in v1
        if (author == null or !std.mem.eql(u8, author.?, p.identity.identity_hash))
            return errOut(a, 501, "unsupported_operation", "delegate: same-peer-only in v1");
        return mintBounded(p, a, env, caller_cap, params, try reqGrants(a, params), author.?, parent.?);
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

// §6.2: user-installed handlers MUST NOT register at reserved "system/" paths.
fn isReservedSystemPattern(pattern: []const u8) bool {
    return std.mem.eql(u8, pattern, "system") or cap.startsWith(pattern, "system/");
}

fn registerHandler(p: *Peer, a: std.mem.Allocator, exec: Entity) Error!Outcome {
    const rp = try registerPattern(a, exec);
    const pattern = switch (rp) {
        .err => |e| return e,
        .pattern => |s| s,
    };
    if (isReservedSystemPattern(pattern)) {
        const msg = try std.fmt.allocPrint(a, "\xc2\xa76.2: user-installed handlers MUST NOT register at system/* paths: {s}", .{pattern});
        return errOut(a, 403, "forbidden_pattern", msg);
    }
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
fn dispatchOutboundHandler(p: *Peer, a: std.mem.Allocator, conn: *Conn, env: Envelope, exec: Entity, handler_pattern: []const u8) Error!Outcome {
    const out_fn = conn.outbound orelse
        return errOut(a, 503, "no_outbound_seam", "dispatch-outbound requires a live §6.11 reentry connection");
    const params = (try exec.entityField(a, "params")) orelse
        return errOut(a, 400, "unexpected_params", "dispatch-outbound: missing params");
    const target = params.textField("target") orelse return errOut(a, 400, "unexpected_params", "missing target");
    const operation = params.textField("operation") orelse return errOut(a, 400, "unexpected_params", "missing operation");
    const value = params.field("value") orelse return errOut(a, 400, "unexpected_params", "missing value");

    // GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the single-granter
    // case is an array of ONE. They were singular, which made §1.4's multi-signature-root
    // rule ungateable on the wire: driving it needs two granter identities and two
    // signatures, and a single-credential carrier cannot express that input.
    //
    // TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one, because
    // THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle is what all 46
    // tracked reports are measured against and it sends the SINGULAR names; a plural-only
    // peer reads the triple as absent there, takes the ambient arm and refuses — measured
    // on the `go` vanguard as 2 of 778 severities moving PASS -> FAIL. REMOVE THIS
    // FALLBACK AT THE ORACLE RE-PIN, and not before.
    const cap_e = try params.entityField(a, "reentry_capability");
    const granters = try entityListField(a, params, "reentry_granters", "reentry_granter");
    const cap_sigs = try entityListField(a, params, "reentry_cap_signatures", "reentry_cap_signature");
    // The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED arm, all
    // three absent selects the AMBIENT arm, and a PARTIAL set is 400 invalid_params — a
    // partial credential is malformed, not ambient. An empty array is partial, not present.
    var n_present: u8 = 0;
    if (cap_e != null) n_present += 1;
    if (granters.len > 0) n_present += 1;
    if (cap_sigs.len > 0) n_present += 1;
    if (n_present != 0 and n_present != 3)
        return errOut(a, 400, "invalid_params", "dispatch-outbound reentry authority is all-or-none");
    const has_cred = n_present == 3;
    const cred: ?Entity = if (has_cred) cap_e else null;
    const granter_list: []const Entity = if (has_cred) granters else &.{};
    const sig_list: []const Entity = if (has_cred) cap_sigs else &.{};

    // §7a.1: the `value` field IS the outbound params entity data — pass it through
    // (the reference uses it directly). Re-wrapping as { value } double-wraps, so the
    // echo's result.value returns a map, not the sent value (keystone §7b t1_2).
    const inner = try Entity.make(a, "primitive/any", try model.cloneValue(a, value));

    // `target` arrives as any of §1.4's three spellings and the validator sends the
    // SCHEMED ABSOLUTE form. Both the handler-pattern dimension and the resource target
    // want the PEER-RELATIVE path — §1.4's PD-2 block says so for Dimension 1, and a
    // resource target carrying a scheme is not a path at all.
    const rel_target = try cap.peerRelativeOf(a, target);

    // §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer, all four
    // dimensions, on THIS handler's own grant — with a target-minted credential relaxing
    // Dimension 4 and nothing else. Consulting only the presented credential here is the
    // §6.8 confused-deputy bypass.
    const own_grant = p.store.getAt(try cap.grantPathFor(a, p.local_peer, handler_pattern)) orelse
        // §6.8: a handler with no valid grant does not run. Fail closed rather than
        // falling back to the credential, which is the substitution §6.8 forbids.
        return errOut(a, 403, "capability_denied", "no handler grant for this pattern");
    // §7a.2a: the credential, its granters and its signatures arrive NESTED IN PARAMS
    // (ratified shape (a), in-band), so they are NOT in `env` and a verifier handed that
    // alone cannot resolve a single link.
    const bundle = try mergeIncluded(a, env, cred, granter_list, sig_list);
    // §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends the
    // absolute form, so the URI names the target. Where the uri is PEER-RELATIVE there is
    // no peer in it and the §6.11 seam's destination is the connection's remote, so that
    // is the fallback — without it Dimension 4 passes vacuously.
    const uri_peer = try cap.extractPeer(a, p.local_peer, target);
    const target_peer = if (std.mem.eql(u8, uri_peer, p.local_peer))
        (conn.hello_peer_id orelse uri_peer)
    else
        uri_peer;
    var res_pairs = try a.alloc(Value.Pair, 1);
    res_pairs[0] = .{ .key = try model.textVal(a, "targets"), .value = blk: {
        const t = try a.alloc(Value, 1);
        t[0] = try model.textVal(a, try std.fmt.allocPrint(a, "system/handler/{s}", .{rel_target}));
        break :blk .{ .array = t };
    } };
    if (!try cap.checkOutboundSubDispatch(a, bundle, &p.store, p.local_peer, target_peer,
                                          rel_target, operation, own_grant,
                                          .{ .map = res_pairs }, cred)) {
        // §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic
        // transport- or gateway-class code would launder an authorization verdict into a
        // route fault, and the ambient and presented branches would then disagree about
        // what the same gate decided.
        return errOut(a, 403, "capability_denied",
                      "outbound sub-dispatch not authorized by the handler grant");
    }

    // Build a signed, authority-bearing outbound EXECUTE back to the caller.
    const req = try buildReentryExecute(p, a, conn, target, rel_target, operation, inner, cred, granter_list, sig_list);
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
/// `granters`/`cap_sigs` are PLURAL (GUIDE-CONFORMANCE §7a.1, 0.8.2.19) so a K-of-N root
/// can present every granter identity and every link signature. Every member goes into
/// `included` because §5.5's chain walk resolves granters and signers BY HASH out of that
/// map — a granter left out is a link the verifier cannot reach.
///
/// `cred == null` is the AMBIENT arm: the EXECUTE carries no `capability` field at all. An
/// empty hash would NOT do — that is a present field resolving to nothing, which §5.2
/// reads as an unresolvable capability rather than as its absence.
fn buildReentryExecute(p: *Peer, a: std.mem.Allocator, conn: *Conn, target: []const u8, rel_target: []const u8, operation: []const u8, inner: Entity, cred: ?Entity, granters: []const Entity, cap_sigs: []const Entity) Error!Envelope {
    conn.out_counter += 1;
    const rid = try std.fmt.allocPrint(a, "ro-{d}", .{conn.out_counter});
    var rpairs = try a.alloc(Value.Pair, 1);
    rpairs[0] = .{ .key = try model.textVal(a, "targets"), .value = blk: {
        const t = try a.alloc(Value, 1);
        t[0] = try model.textVal(a, try std.fmt.allocPrint(a, "system/handler/{s}", .{rel_target}));
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
        .capability = if (cred) |c| c.hash else null,
    });
    const exec_sig = try identity_mod.signEntity(a, p.identity, exec);
    const n_cred: usize = if (cred != null) 1 + granters.len + cap_sigs.len else 0;
    var included = try a.alloc(model.Included, n_cred + 1);
    var idx: usize = 0;
    if (cred) |c| {
        included[idx] = .{ .key = c.hash, .entity = c };
        idx += 1;
        for (granters) |g| { included[idx] = .{ .key = g.hash, .entity = g }; idx += 1; }
        for (cap_sigs) |sg| { included[idx] = .{ .key = sg.hash, .entity = sg }; idx += 1; }
    }
    included[idx] = .{ .key = exec_sig.hash, .entity = exec_sig };
    // Materialize into an Envelope (arena-owned; out_fn must NOT free our entities).
    return Envelope{ .root = exec, .included = included };
}

/// Decode an ARRAY of nested entities at `key`, falling back to the SINGULAR spelling as a
/// list of one (the §7a.1 transitional carriers).
///
/// An EMPTY slice means absent, not-a-list, or a MALFORMED array (a member that does not
/// decode) — never a silently shorter list, because the caller's all-or-none test would
/// then read a partial credential as a complete one.
fn entityListField(a: std.mem.Allocator, e: Entity, key: []const u8, singular: []const u8) Error![]const Entity {
    if (e.field(key)) |v| {
        switch (v) {
            .array => |items| {
                var out = try a.alloc(Entity, items.len);
                for (items, 0..) |item, i| {
                    out[i] = model.ofCbor(a, item) catch return &.{};
                }
                return out;
            },
            else => {},
        }
    }
    if (try e.entityField(a, singular)) |one| {
        var out = try a.alloc(Entity, 1);
        out[0] = one;
        return out;
    }
    return &.{};
}

/// The §7a.2a bundle: the parent envelope's `included` plus the in-band credential set.
fn mergeIncluded(a: std.mem.Allocator, env: Envelope, cred: ?Entity, granters: []const Entity, cap_sigs: []const Entity) Error!Envelope {
    const extra: usize = if (cred != null) 1 + granters.len + cap_sigs.len else 0;
    var included = try a.alloc(model.Included, env.included.len + extra);
    var idx: usize = 0;
    for (env.included) |inc| { included[idx] = inc; idx += 1; }
    if (cred) |c| {
        included[idx] = .{ .key = c.hash, .entity = c };
        idx += 1;
        for (granters) |g| { included[idx] = .{ .key = g.hash, .entity = g }; idx += 1; }
        for (cap_sigs) |sg| { included[idx] = .{ .key = sg.hash, .entity = sg }; idx += 1; }
    }
    return Envelope{ .root = env.root, .included = included };
}

fn conformanceHandler(p: *Peer, a: std.mem.Allocator, conn: *Conn, env: Envelope, exec: Entity, stripped: []const u8) Error!Outcome {
    if (std.mem.eql(u8, stripped, "system/validate/echo")) return echoHandler(p, a, exec);
    // §1.4 PD-2 needs the OWNING handler's peer-relative pattern (Dimension 1 is matched
    // peer-relative) and the parent envelope (the §7a.2a bundle base).
    if (std.mem.eql(u8, stripped, "system/validate/dispatch-outbound")) return dispatchOutboundHandler(p, a, conn, env, exec, stripped);
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
    // §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to
    // sit below the verdict, so a pre-establishment EXECUTE naming a FOREIGN namespace took
    // the 401 an unauthenticated request takes. §4.7's own reason: "a 401 directs the caller
    // to authenticate and retry, and for a foreign-namespace address that retry cannot
    // succeed at any authentication state — so the 401 names a remedy that does not exist."
    // §6.5 step 3 calls it "a gate, not an ordering preference" and §1.4 makes the downstream
    // permission check unreachable here.
    const norm = try cap.normalizeUri(a, uri);
    const path = try cap.canonicalize(a, p.local_peer, norm);
    {
        const atp = try cap.extractPeer(a, p.local_peer, path);
        if (!std.mem.eql(u8, atp, p.local_peer)) return errOut(a, 400, "invalid_request", "not local peer");
    }

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
    // (The §1.4 address gate that used to sit here has moved ABOVE the verdict — §4.7
    // 0.8.2.6 orders it before authentication. Reaching this line means the path is local.)
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
    // §6.3's checkPathPermission needs the caller's capability and the OWNING handler's
    // pattern, and the dispatch-level check above already computed both. They are
    // CARRIED rather than recomputed: recomputing invites the two to drift, and §6.8 is
    // explicit that the authority is selected by who named the path. `stripped` here is
    // the OWNER's pattern (§6.3, 0.8.2.23) — for the tree handler owner and runner
    // coincide, so the distinction is not observable, but the argument means the owner.
    if (std.mem.eql(u8, stripped, "system/tree")) return treeHandler(p, a, exec, caller_cap, stripped);
    if (std.mem.eql(u8, stripped, "system/capability")) return capabilityHandler(p, a, env, exec, caller_cap);
    if (std.mem.eql(u8, stripped, "system/handler")) return handlersHandler(p, a, exec);
    if (std.mem.eql(u8, stripped, "system/type")) return typesHandler(a, exec);
    // §7a conformance handlers (only bootstrapped when conformance=true)
    if (p.conformance and cap.startsWith(stripped, "system/validate/"))
        return conformanceHandler(p, a, conn, env, exec, stripped);
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
/// survives the arena reset. Always answers: every inbound root reaching here gets a
/// frame (§4.11), so the transport's write decision has one shape.
pub fn dispatch(p: *Peer, conn: *Conn, env: Envelope) Error!?Envelope {
    const exec = env.root;
    const request_id = exec.textField("request_id") orelse "";

    var arena_inst = std.heap.ArenaAllocator.init(p.gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    if (!std.mem.eql(u8, exec.typ, "system/protocol/execute")) {
        // §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
        // invalid_request, coded frame; MAY then close. NOT a bare close — that is
        // indistinguishable from a network fault."
        //
        // §3.3 read "the connection MUST be closed", assigning no code and requiring no
        // frame, and this peer did something weaker still: it returned null, the
        // transport wrote NOTHING, and the connection stayed open — which is §4.11's
        // OTHER non-conformant behaviour, the silent drop, "the weaker of the two
        // precisely because nothing surfaces it". This is a PRE-ADMISSION refusal: the
        // root is not an EXECUTE, so nothing was ever admitted and §4.9(c) does not
        // reach it. §9.1's floor row that used to MANDATE the bare close was REPLACED
        // at the same revision (N18).
        //
        // `request_id` is read best-effort — an arbitrary root type is under no
        // obligation to carry one, and §4.11 licenses the uncorrelated frame exactly
        // there. We do NOT close: on a multiplexed connection that would cost every
        // ADMITTED in-flight request its response, and §4.11 leaves the close to us.
        const er = try wire.errorResult(a, "invalid_request", "root entity is neither EXECUTE nor EXECUTE_RESPONSE");
        const gpa_er = try er.clone(p.gpa);
        const root = try wire.makeResponse(p.gpa, request_id, 400, gpa_er);
        errdefer root.deinit(p.gpa);
        return Envelope{ .root = root, .included = try p.gpa.alloc(model.Included, 0) };
    }

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
/// A handler's OWN grant (§6.8) — the authority it spends when it dispatches onward, as
/// distinct from any capability a caller presents. §6.8 row 1: an access in service of a
/// caller's request needs the caller's verified capability AND this grant, and BOTH must
/// pass. Narrow for `dispatch-outbound`; empty for everything else.
fn ownGrantsFor(a: std.mem.Allocator, pattern: []const u8) Error![]Value {
    if (!std.mem.eql(u8, pattern, "system/validate/dispatch-outbound")) return a.alloc(Value, 0);
    const scope = struct {
        fn one(al: std.mem.Allocator, v: []const u8) Error!Value {
            var items = try al.alloc(Value, 1);
            items[0] = try model.textVal(al, v);
            var pairs = try al.alloc(Value.Pair, 1);
            pairs[0] = .{ .key = try model.textVal(al, "include"), .value = .{ .array = items } };
            return Value{ .map = pairs };
        }
    };
    var gpairs = try a.alloc(Value.Pair, 3);
    gpairs[0] = .{ .key = try model.textVal(a, "handlers"), .value = try scope.one(a, "system/validate/echo") };
    gpairs[1] = .{ .key = try model.textVal(a, "operations"), .value = try scope.one(a, "echo") };
    gpairs[2] = .{ .key = try model.textVal(a, "resources"), .value = try scope.one(a, "system/handler/system/validate/echo") };
    var out = try a.alloc(Value, 1);
    out[0] = .{ .map = gpairs };
    return out;
}

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
    // §6.8: the grant MUST exist at `system/capability/grants/{pattern}` and a handler
    // with no valid grant does not run — so this bind is the ceiling row 1 intersects
    // against, not bookkeeping. NARROW for dispatch-outbound: with a wide grant,
    // consulting it and skipping it give the same answer on every input, so the
    // confused-deputy discriminator cannot fire (GUIDE-CONFORMANCE §7a.1).
    const minted = try mintToken(p, a, p.identity.identity_hash, null, try ownGrantsFor(a, bh.pattern));
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

/// Build a hello params entity naming `version` in `protocols`, or an empty params
/// entity when `version` is null — the two shapes §4.5 distinguishes.
fn testHelloParams(gpa: std.mem.Allocator, version: ?[]const u8) !Entity {
    const v = version orelse return wire.emptyParams(gpa);
    var list: std.ArrayList(Value.Pair) = .empty;
    const protos = try gpa.alloc(Value, 1);
    protos[0] = try model.textVal(gpa, v);
    try list.append(gpa, .{ .key = try model.textVal(gpa, "protocols"), .value = .{ .array = protos } });
    return Entity.make(gpa, "primitive/any", .{ .map = try list.toOwnedSlice(gpa) });
}

/// Dispatch one connect operation and return (status, code). `code` is empty on 200.
fn testConnect(gpa: std.mem.Allocator, p: *Peer, conn: *Conn, op: []const u8, params: Entity) !struct { status: u64, code: []const u8 } {
    const exec = try wire.makeExecute(gpa, .{ .request_id = "r1", .uri = "system/protocol/connect", .operation = op, .params = params });
    const env = Envelope{ .root = exec, .included = try gpa.alloc(model.Included, 0) };
    defer env.deinit(gpa);
    const resp = (try dispatch(p, conn, env)).?;
    defer resp.deinit(gpa);
    const status = resp.root.uintField("status").?;
    const result = try resp.root.entityField(gpa, "result");
    var code: []const u8 = "";
    if (result) |r| {
        defer r.deinit(gpa);
        if (r.textField("code")) |c| code = try gpa.dupe(u8, c);
    }
    return .{ .status = status, .code = code };
}

test "hello: the accept case, and the three §4.5/§4.7 refusals beside it" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{5} ** 32 });
    defer p.deinit();

    // The ACCEPT direction, and it is the one that validates the FIXTURE: a hello
    // MUST carry `protocols` (§4.5 — Required, no default), so this is what a
    // well-formed hello looks like and every deny case differs in exactly one field.
    var conn = Conn{};
    defer conn.deinit(gpa);
    const r1 = try testConnect(gpa, &p, &conn, "hello", try testHelloParams(gpa, "entity-core/1.0"));
    defer gpa.free(r1.code);
    try testing.expectEqual(@as(u64, 200), r1.status);

    // §4.7 out-of-order / 0.8.2.8 half-open: the connection is now half-open (nonce
    // issued, not established), so a SECOND hello is 409 — the guard `established`
    // alone cannot reach.
    const r2 = try testConnect(gpa, &p, &conn, "hello", try testHelloParams(gpa, "entity-core/1.0"));
    defer gpa.free(r2.code);
    try testing.expectEqual(@as(u64, 409), r2.status);

    // §4.5 / §4.7 row 1: absent `protocols` is a malformed hello (invalid_request),
    // NOT a failed comparison (incompatible_protocol). The two select different
    // remedies, so the CODE is asserted — 400 alone cannot tell them apart.
    var conn2 = Conn{};
    defer conn2.deinit(gpa);
    const r3 = try testConnect(gpa, &p, &conn2, "hello", try testHelloParams(gpa, null));
    defer gpa.free(r3.code);
    try testing.expectEqual(@as(u64, 400), r3.status);
    try testing.expectEqualStrings("invalid_request", r3.code);
    try testing.expect(conn2.issued_nonce == null);

    var conn3 = Conn{};
    defer conn3.deinit(gpa);
    const r4 = try testConnect(gpa, &p, &conn3, "hello", try testHelloParams(gpa, "entity-core/9.9"));
    defer gpa.free(r4.code);
    try testing.expectEqual(@as(u64, 400), r4.status);
    try testing.expectEqualStrings("incompatible_protocol", r4.code);
}

test "§4.7 row 10: unknown connect op is 400, unknown op elsewhere stays 501" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{7} ** 32 });
    defer p.deinit();
    var conn = Conn{};
    defer conn.deinit(gpa);
    const r = try testConnect(gpa, &p, &conn, "no_such_operation", try wire.emptyParams(gpa));
    defer gpa.free(r.code);
    try testing.expectEqual(@as(u64, 400), r.status);
    try testing.expectEqualStrings("invalid_request", r.code);

    // The differential. §4.7 row 10 and §3.3's 501 row are adjacent and opposite: a
    // peer can satisfy row 10 by making EVERY unknown operation 400, which trades one
    // contract for another and looks exactly like a fix. Measured together the trade
    // is visible; measured apart it is not.
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    const exec = try wire.makeExecute(a, .{ .request_id = "r2", .uri = "system/tree", .operation = "no_such_operation", .params = try wire.emptyParams(a) });
    const out = try treeHandler(&p, a, exec, null, "system/tree");
    try testing.expectEqual(@as(u64, 501), out.status);
    try testing.expectEqualStrings("unsupported_operation", out.result.textField("code").?);
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
    var out1 = try buildListing(&p, a, try std.fmt.allocPrint(a, "{s}/", .{base}), null, "system/tree");
    try testing.expectEqual(@as(u64, 2), out1.result.uintField("count").?);
    // put a deletion-marker over target
    const marker = try Entity.make(a, "system/deletion-marker", .{ .map = &.{} });
    try p.store.bind(try std.fmt.allocPrint(a, "{s}/target", .{base}), marker);
    var out2 = try buildListing(&p, a, try std.fmt.allocPrint(a, "{s}/", .{base}), null, "system/tree");
    try testing.expectEqual(@as(u64, 1), out2.result.uintField("count").?); // only the sibling
}

// ── §3.3 ladder + §6.3 listing filter (0.8.2.20/.21/.22/.24/.25) ─────────────

/// An arena-owned `resource` value. `targets == null` omits the key entirely (the
/// ABSENT case), which is a different input from an empty array.
fn testResource(a: std.mem.Allocator, targets: ?[]const []const u8, excl: ?[]const []const u8) !Value {
    var pairs: std.ArrayList(Value.Pair) = .empty;
    if (excl) |xs| {
        const arr = try a.alloc(Value, xs.len);
        for (xs, 0..) |s, i| arr[i] = try model.textVal(a, s);
        try pairs.append(a, .{ .key = try model.textVal(a, "exclude"), .value = .{ .array = arr } });
    }
    if (targets) |ts| {
        const arr = try a.alloc(Value, ts.len);
        for (ts, 0..) |s, i| arr[i] = try model.textVal(a, s);
        try pairs.append(a, .{ .key = try model.textVal(a, "targets"), .value = .{ .array = arr } });
    }
    return .{ .map = try pairs.toOwnedSlice(a) };
}

/// A capability token with one grant over `system/tree`, all operations, and the given
/// resource scope. Arena-owned.
fn testCapToken(a: std.mem.Allocator, res_incl: []const []const u8, res_excl: []const []const u8) !Entity {
    const lst = struct {
        fn f(al: std.mem.Allocator, items: []const []const u8) !Value {
            const arr = try al.alloc(Value, items.len);
            for (items, 0..) |s, i| arr[i] = try model.textVal(al, s);
            return .{ .array = arr };
        }
    }.f;
    const sc = struct {
        fn f(al: std.mem.Allocator, incl: []const []const u8, excl: []const []const u8) !Value {
            var pr = try al.alloc(Value.Pair, 2);
            pr[0] = .{ .key = try model.textVal(al, "exclude"), .value = try lst(al, excl) };
            pr[1] = .{ .key = try model.textVal(al, "include"), .value = try lst(al, incl) };
            return .{ .map = pr };
        }
    }.f;
    var g = try a.alloc(Value.Pair, 3);
    g[0] = .{ .key = try model.textVal(a, "handlers"), .value = try sc(a, &.{"system/tree"}, &.{}) };
    g[1] = .{ .key = try model.textVal(a, "operations"), .value = try sc(a, &.{"*"}, &.{}) };
    g[2] = .{ .key = try model.textVal(a, "resources"), .value = try sc(a, res_incl, res_excl) };
    const grants = try a.alloc(Value, 1);
    grants[0] = .{ .map = g };
    var top = try a.alloc(Value.Pair, 1);
    top[0] = .{ .key = try model.textVal(a, "grants"), .value = .{ .array = grants } };
    return Entity.make(a, "system/capability/token", .{ .map = top });
}

fn testTreeExec(a: std.mem.Allocator, op: []const u8, resource: ?Value) !Entity {
    return wire.makeExecute(a, .{
        .request_id = "rT",
        .uri = "system/tree",
        .operation = op,
        .params = try wire.emptyParams(a),
        .resource = resource,
    });
}

fn outCode(o: Outcome) []const u8 {
    return o.result.textField("code") orelse "";
}

test "§3.3 ladder dispositions on the EFFECTIVE list (0.8.2.20/.24/.25)" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{11} ** 32 });
    defer p.deinit();
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    // get, ABSENT resource -> the root listing. EXTENSION-TREE §2.2a (v4.11) declares
    // `get` resource-OPTIONAL and BROAD-RESULT with that absent-case answer; this is
    // the F86 arm, answered NO, and it is text rather than this peer's choice.
    var out = try treeHandler(&p, a, try testTreeExec(a, "get", null), null, "system/tree");
    try testing.expectEqual(@as(u64, 200), out.status);
    try testing.expectEqualStrings("system/tree/listing", out.result.typ);

    // get, PRESENT and self-excluded -> 400 path_required. Serving this the absent case
    // answers a request for one excluded path with a listing of the whole tree.
    out = try treeHandler(&p, a, try testTreeExec(a, "get", try testResource(a, &.{"app/qA"}, &.{"app/qA"})), null, "system/tree");
    try testing.expectEqual(@as(u64, 400), out.status);
    try testing.expectEqualStrings("path_required", outCode(out));

    // get, two survivors -> 400 ambiguous_resource. A peer indexing targets[0] answers
    // the first target instead.
    out = try treeHandler(&p, a, try testTreeExec(a, "get", try testResource(a, &.{ "app/qA", "app/qB" }, null)), null, "system/tree");
    try testing.expectEqual(@as(u64, 400), out.status);
    try testing.expectEqualStrings("ambiguous_resource", outCode(out));

    // get, a PATTERN subject -> 400 malformed_resource. A resource-requiring operation
    // takes a CONCRETE path (0.8.2.20).
    out = try treeHandler(&p, a, try testTreeExec(a, "get", try testResource(a, &.{"app/*"}, null)), null, "system/tree");
    try testing.expectEqual(@as(u64, 400), out.status);
    try testing.expectEqualStrings("malformed_resource", outCode(out));

    // put, ABSENT resource -> 400 path_required, NOT ambiguous_resource. 0.8.2.20 names
    // that inversion outright: *supply a resource* is not *disambiguate your request*,
    // and the code is what selects the remedy. This peer answered ambiguous_resource.
    out = try treeHandler(&p, a, try testTreeExec(a, "put", null), null, "system/tree");
    try testing.expectEqual(@as(u64, 400), out.status);
    try testing.expectEqualStrings("path_required", outCode(out));

    // put, PRESENT and self-excluded -> also path_required: §2.2a declares `put`
    // resource-REQUIRED, so §3.3's "an empty effective list IS the absent case" applies
    // in its unscoped form and the two empties COLLAPSE here.
    out = try treeHandler(&p, a, try testTreeExec(a, "put", try testResource(a, &.{"app/qA"}, &.{"app/qA"})), null, "system/tree");
    try testing.expectEqual(@as(u64, 400), out.status);
    try testing.expectEqualStrings("path_required", outCode(out));

    // RULE G control: an UNKNOWN operation with no resource is an OPERATION fault, not
    // a resource one. Resolve the operation first; only then run the ladder.
    out = try treeHandler(&p, a, try testTreeExec(a, "bogusop", null), null, "system/tree");
    try testing.expectEqual(@as(u64, 501), out.status);
    try testing.expectEqualStrings("unsupported_operation", outCode(out));
    // ... and with a resource present it must answer the same thing. That differential
    // is what says ORDERING rather than a missing 501 arm.
    out = try treeHandler(&p, a, try testTreeExec(a, "bogusop", try testResource(a, &.{"app/qA"}, null)), null, "system/tree");
    try testing.expectEqual(@as(u64, 501), out.status);
    try testing.expectEqualStrings("unsupported_operation", outCode(out));
}

test "§6.3 check_path_permission catches the vacated dispatch check (0.8.2.20)" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{12} ** 32 });
    defer p.deinit();
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    const qa = try std.fmt.allocPrint(a, "/{s}/app/qA", .{p.local_peer});
    const qb = try std.fmt.allocPrint(a, "/{s}/app/qB", .{p.local_peer});
    try p.store.bind(qa, try Entity.make(a, "system/test", .{ .map = &.{} }));
    try p.store.bind(qb, try Entity.make(a, "system/test", .{ .map = &.{} }));

    // A capability covering app/* EXCEPT qB. The caller then excludes qB from its own
    // request, which removes it from the dispatch-level check's view entirely — and a
    // handler that acts on it regardless has authorized nothing (F84: this was `no` on
    // 33 of 43 peers).
    const tok = try testCapToken(a, &.{"app/*"}, &.{"app/qB"});
    var out = try treeHandler(
        &p,
        a,
        try testTreeExec(a, "get", try testResource(a, &.{ "app/qA", "app/qB" }, &.{"app/qA"})),
        tok,
        "system/tree",
    );
    try testing.expectEqual(@as(u64, 403), out.status);
    try testing.expectEqualStrings("capability_denied", outCode(out));

    // THE ACCEPT CONTROL. Without it a permanently-denying check passes this test, and
    // the deny above says nothing.
    out = try treeHandler(
        &p,
        a,
        try testTreeExec(a, "get", try testResource(a, &.{ "app/qA", "app/qB" }, &.{"app/qB"})),
        tok,
        "system/tree",
    );
    try testing.expectEqual(@as(u64, 200), out.status);
    try testing.expectEqualStrings("system/test", out.result.typ);
}

test "§6.3 listing filter omits denied entries and count follows (0.8.2.21/.22)" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{13} ** 32 });
    defer p.deinit();
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    const dir = try std.fmt.allocPrint(a, "/{s}/app/", .{p.local_peer});
    try p.store.bind(try std.fmt.allocPrint(a, "{s}qA", .{dir}), try Entity.make(a, "system/test", .{ .map = &.{} }));
    try p.store.bind(try std.fmt.allocPrint(a, "{s}qB", .{dir}), try Entity.make(a, "system/test", .{ .map = &.{} }));

    // UNAUTHENTICATED: not filtered. The filter's subject is "the caller's verified
    // capability", and where there is none there is no caller to narrow (bootstrap).
    var out = try buildListing(&p, a, dir, null, "system/tree");
    try testing.expectEqual(@as(u64, 2), out.result.uintField("count").?);

    // Under a capability EXCLUDING qB: one entry, and `count` follows the FILTERED
    // total. A count still reporting the source total is the disclosure the rule exists
    // to prevent, so it is asserted separately from the entry map.
    const tok = try testCapToken(a, &.{"app/*"}, &.{"app/qB"});
    out = try buildListing(&p, a, dir, tok, "system/tree");
    try testing.expectEqual(@as(u64, 1), out.result.uintField("count").?);
    const entries = model.mapGet(out.result.data, "entries").?;
    try testing.expectEqual(@as(usize, 1), entries.map.len);
    try testing.expectEqualStrings("qA", entries.map[0].key.text);

    // ACCEPT CONTROL: a capability covering BOTH still lists both — otherwise a filter
    // that denies everything passes the assertion above.
    const wide = try testCapToken(a, &.{"app/*"}, &.{});
    out = try buildListing(&p, a, dir, wide, "system/tree");
    try testing.expectEqual(@as(u64, 2), out.result.uintField("count").?);
}

test "§4.11 pre-admission: a non-EXECUTE root is answered, not dropped (N12/N17)" {
    const gpa = testing.allocator;
    var p = try create(gpa, .{ .seed = [_]u8{14} ** 32 });
    defer p.deinit();
    var conn = Conn{};
    defer conn.deinit(gpa);

    // §3.3 used to read "the connection MUST be closed" and this peer did something
    // weaker still: it returned null, the transport wrote NOTHING, and the connection
    // stayed open — §4.11's silent-drop non-conformance, "the weaker of the two
    // precisely because nothing surfaces it".
    var pairs = try gpa.alloc(Value.Pair, 1);
    pairs[0] = .{ .key = try model.textVal(gpa, "request_id"), .value = try model.textVal(gpa, "rX") };
    const root = try Entity.make(gpa, "system/some-other-thing", .{ .map = pairs });
    const env = Envelope{ .root = root, .included = try gpa.alloc(model.Included, 0) };
    defer env.deinit(gpa);

    const resp = (try dispatch(&p, &conn, env)) orelse return error.TestExpectedFrame;
    defer resp.deinit(gpa);
    try testing.expectEqual(@as(u64, 400), resp.root.uintField("status").?);
    // Correlated where the id is available (§4.11).
    try testing.expectEqualStrings("rX", resp.root.textField("request_id").?);
    const result = (try resp.root.entityField(gpa, "result")).?;
    defer result.deinit(gpa);
    try testing.expectEqualStrings("invalid_request", result.textField("code").?);
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
