//! Capability system (L3) — the §5 verification core: pattern matching (§5.4),
//! request verification (§5.2 verify_request / check_permission), delegation-chain
//! verification (§5.5), attenuation (§5.6), delegation caveats (§5.7), revocation
//! (§5.1). Derived from the §5 pseudocode directly.
//!
//! Verdict is the §5.10 Layer-1 deterministic ALLOW/DENY; the dispatcher maps
//! DENY→403, with the §5.5 unresolvable-grantee carve-out surfaced as a distinct
//! verdict mapping to 401, and the §4.6/F20 authn(401)/authz(403) split surfaced
//! as a 3-way request verdict (A-ZIG-006, corroborating OCaml A-OC-008).
//!
//! No-GC idiom: parse helpers borrow into the entity's cbor tree (no allocation);
//! scope/grant parsing produces small slice-of-slices the caller frees, but the
//! verification path uses a scratch ARENA so the chain walk allocates freely and
//! is freed in one shot — the clean Zig answer to a recursive borrow graph.

const std = @import("std");
const model = @import("model.zig");
const identity = @import("identity.zig");
const peer_id = @import("peer_id.zig");
const base58 = @import("base58.zig");

const Entity = model.Entity;
const Value = model.Value;
const Store = @import("store.zig").Store;

pub const Verdict = enum { allow, deny };

/// 3-way request verdict (§5.2 / §4.6 / F20): authn-class failure → 401,
/// authz-class deny → 403, allow → dispatch.
pub const ReqVerdict = enum { allow, authn_fail, authz_deny, chain_too_deep };

pub const Error = error{ OutOfMemory, UnresolvableGrantee } || model.Error || identity.Error;

// ── parse helpers (borrow into the entity's cbor tree) ───────────────────────

const Scope = struct { incl: []const []const u8, excl: []const []const u8 };
const Grant = struct {
    handlers: Scope,
    resources: Scope,
    operations: Scope,
    peers: ?Scope,
};

fn textList(arena: std.mem.Allocator, v: ?Value) Error![]const []const u8 {
    const arr = switch (v orelse return &.{}) {
        .array => |a| a,
        else => return &.{},
    };
    var out: std.ArrayList([]const u8) = .empty;
    for (arr) |it| switch (it) {
        .text => |s| try out.append(arena, s),
        else => {},
    };
    return out.toOwnedSlice(arena);
}

fn parseScope(arena: std.mem.Allocator, c: Value) Error!Scope {
    return .{
        .incl = try textList(arena, model.mapGet(c, "include")),
        .excl = try textList(arena, model.mapGet(c, "exclude")),
    };
}

fn parseGrant(arena: std.mem.Allocator, c: Value) Error!Grant {
    const sc = struct {
        fn f(a: std.mem.Allocator, cc: Value, key: []const u8) Error!Scope {
            if (model.mapGet(cc, key)) |s| return parseScope(a, s);
            return .{ .incl = &.{}, .excl = &.{} };
        }
    }.f;
    return .{
        .handlers = try sc(arena, c, "handlers"),
        .resources = try sc(arena, c, "resources"),
        .operations = try sc(arena, c, "operations"),
        .peers = if (model.mapGet(c, "peers")) |s| try parseScope(arena, s) else null,
    };
}

fn grantsOfToken(arena: std.mem.Allocator, token: Entity) Error![]Grant {
    const arr = switch (token.field("grants") orelse return &.{}) {
        .array => |a| a,
        else => return &.{},
    };
    var out: std.ArrayList(Grant) = .empty;
    for (arr) |g| try out.append(arena, try parseGrant(arena, g));
    return out.toOwnedSlice(arena);
}

// ── §5.4 pattern matching ────────────────────────────────────────────────────

pub fn startsWith(s: []const u8, prefix: []const u8) bool {
    return s.len >= prefix.len and std.mem.eql(u8, s[0..prefix.len], prefix);
}

pub fn isPeerId(seg: []const u8) bool {
    if (seg.len < 46) return false;
    for (seg) |c| if (std.mem.indexOfScalar(u8, base58.alphabet, c) == null) return false;
    return true;
}

/// URI normalization (§1.4): strip entity:// scheme; peer-relative paths pass
/// through to canonicalize. Returns a slice into `uri` or an owned dup.
pub fn normalizeUri(arena: std.mem.Allocator, uri: []const u8) Error![]const u8 {
    if (startsWith(uri, "entity://")) {
        const rest = uri["entity://".len..];
        const out = try arena.alloc(u8, rest.len + 1);
        out[0] = '/';
        @memcpy(out[1..], rest);
        return out;
    }
    return uri;
}

/// Resolve peer-relative paths to absolute "/{local}/..." form. Returns owned.
pub fn canonicalize(arena: std.mem.Allocator, local_peer: []const u8, path: []const u8) Error![]const u8 {
    if (startsWith(path, "/")) return path;
    return std.fmt.allocPrint(arena, "/{s}/{s}", .{ local_peer, path });
}

/// Both path and pattern MUST already be canonical (absolute).
pub fn matchesPattern(path: []const u8, pattern: []const u8) bool {
    if (std.mem.eql(u8, pattern, "*")) return true;
    if (startsWith(pattern, "/*/")) {
        const remainder = pattern[3..];
        if (path.len < 1) return false;
        const i = std.mem.indexOfScalarPos(u8, path, 1, '/') orelse return false;
        return matchesPattern(path[i + 1 ..], remainder);
    }
    if (pattern.len >= 2 and std.mem.eql(u8, pattern[pattern.len - 2 ..], "/*")) {
        const prefix = pattern[0 .. pattern.len - 1]; // keep trailing /
        return startsWith(path, prefix);
    }
    return std.mem.eql(u8, path, pattern);
}

fn matchesScope(arena: std.mem.Allocator, local_peer: []const u8, value: []const u8, s: Scope) Error!bool {
    const cv = try canonicalize(arena, local_peer, value);
    const covered = struct {
        fn f(a: std.mem.Allocator, lp: []const u8, v: []const u8, pats: []const []const u8) Error!bool {
            for (pats) |p| {
                if (matchesPattern(v, try canonicalize(a, lp, p))) return true;
            }
            return false;
        }
    }.f;
    if (!try covered(arena, local_peer, cv, s.incl)) return false;
    return !try covered(arena, local_peer, cv, s.excl);
}

// ── §5.2 check_permission ────────────────────────────────────────────────────

fn firstSegment(uri: []const u8) []const u8 {
    const u = if (startsWith(uri, "/")) uri[1..] else uri;
    const i = std.mem.indexOfScalar(u8, u, '/') orelse return u;
    return u[0..i];
}

pub fn extractPeer(arena: std.mem.Allocator, local_peer: []const u8, uri: []const u8) Error![]const u8 {
    const first = firstSegment(try normalizeUri(arena, uri));
    return if (isPeerId(first)) first else local_peer;
}

fn resolveGranterPeerId(arena: std.mem.Allocator, env: model.Envelope, st: *Store, cap: Entity) Error!?[]const u8 {
    const gh = cap.bytesField("granter") orelse return null;
    const g = resolve(env, st, gh) orelse return null;
    const pk = g.bytesField("public_key") orelse return null;
    return try identity.peerIdOfPubkey(arena, pk);
}

fn checkResourceScope(arena: std.mem.Allocator, local_peer: []const u8, granter_peer: []const u8, resource: Value, s: Scope) Error!bool {
    const targets = try textList(arena, model.mapGet(resource, "targets"));
    const caller_excl = try textList(arena, model.mapGet(resource, "exclude"));
    if (targets.len == 0) return false;
    const covered = struct {
        fn f(a: std.mem.Allocator, frame: []const u8, pats: []const []const u8, v: []const u8) Error!bool {
            for (pats) |p| {
                if (matchesPattern(v, try canonicalize(a, frame, p))) return true;
            }
            return false;
        }
    }.f;
    for (targets) |tgt| {
        const ct = try canonicalize(arena, local_peer, tgt);
        if (try covered(arena, local_peer, caller_excl, ct)) continue; // caller excluded (local frame)
        if (!try covered(arena, granter_peer, s.incl, ct)) return false; // not in grant include (granter frame)
        if (try covered(arena, granter_peer, s.excl, ct)) return false; // in grant exclude → deny
    }
    return true;
}

/// check_permission gates the wire request at the dispatch authorization boundary
/// (§5.2 / §3.2.3). `granter_peer` is the §PR-8 canonicalization frame for the
/// cap's grant resource patterns; every other dimension stays on the local frame.
pub fn checkPermission(arena: std.mem.Allocator, local_peer: []const u8, granter_peer: []const u8, exec: Entity, token: Entity, handler_pattern: []const u8) Error!Verdict {
    const operation = exec.textField("operation") orelse "";
    const uri = exec.textField("uri") orelse "";
    const target_peer = try extractPeer(arena, local_peer, uri);
    const resource = exec.field("resource");
    const grants = try grantsOfToken(arena, token);
    for (grants) |g| {
        const op_ok = try matchesScope(arena, local_peer, operation, g.operations);
        if (!op_ok) continue;
        const h_ok = try matchesScope(arena, local_peer, handler_pattern, g.handlers);
        if (!h_ok) continue;
        const peers = g.peers orelse Scope{ .incl = &.{local_peer}, .excl = &.{} };
        const p_ok = try matchesScope(arena, local_peer, target_peer, peers);
        if (!p_ok) continue;
        const r_ok = if (resource) |r| try checkResourceScope(arena, local_peer, granter_peer, r, g.resources) else true;
        if (r_ok) return .allow;
    }
    return .deny;
}

// ── §5.5 / §5.6 chain verification + attenuation ─────────────────────────────

pub fn resolve(env: model.Envelope, st: *Store, h: []const u8) ?Entity {
    if (env.includedGet(h)) |e| return e;
    return st.getByHash(h);
}

pub fn findSignature(env: model.Envelope, target: []const u8) ?Entity {
    for (env.included) |inc| {
        const e = inc.entity;
        if (std.mem.eql(u8, e.typ, "system/signature")) {
            if (e.bytesField("target")) |t| {
                if (std.mem.eql(u8, t, target)) return e;
            }
        }
    }
    return null;
}

fn linkGranterPeer(arena: std.mem.Allocator, env: model.Envelope, st: *Store, local_peer: []const u8, cap: Entity) Error!?[]const u8 {
    const gh = cap.bytesField("granter") orelse return local_peer; // multi-sig root (M3) → local frame
    const g = resolve(env, st, gh) orelse return null; // unresolvable granter → deny
    const pk = g.bytesField("public_key") orelse return null; // present identity, no key → deny
    return try identity.peerIdOfPubkey(arena, pk);
}

fn scopeSubset(arena: std.mem.Allocator, child_peer: []const u8, parent_peer: []const u8, child: Scope, parent: Scope) Error!bool {
    for (child.incl) |cp| {
        const cc = try canonicalize(arena, child_peer, cp);
        var found = false;
        for (parent.incl) |pp| {
            if (matchesPattern(cc, try canonicalize(arena, parent_peer, pp))) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    for (parent.excl) |pe| {
        const cpe = try canonicalize(arena, parent_peer, pe);
        var found = false;
        for (child.excl) |ce| {
            if (matchesPattern(cpe, try canonicalize(arena, child_peer, ce))) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn grantSubset(arena: std.mem.Allocator, local_peer: []const u8, child_peer: []const u8, parent_peer: []const u8, child: Grant, parent: Grant) Error!bool {
    if (!try scopeSubset(arena, local_peer, local_peer, child.handlers, parent.handlers)) return false;
    if (!try scopeSubset(arena, local_peer, local_peer, child.operations, parent.operations)) return false;
    if (!try scopeSubset(arena, child_peer, parent_peer, child.resources, parent.resources)) return false;
    const cp = child.peers orelse Scope{ .incl = &.{local_peer}, .excl = &.{} };
    const pp = parent.peers orelse Scope{ .incl = &.{local_peer}, .excl = &.{} };
    return scopeSubset(arena, local_peer, local_peer, cp, pp);
}

fn isAttenuated(arena: std.mem.Allocator, local_peer: []const u8, child_peer: []const u8, parent_peer: []const u8, child: Entity, parent: Entity) Error!bool {
    const cg = try grantsOfToken(arena, child);
    const pg = try grantsOfToken(arena, parent);
    for (cg) |c| {
        var ok = false;
        for (pg) |p| {
            if (try grantSubset(arena, local_peer, child_peer, parent_peer, c, p)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }
    const pe = parent.uintField("expires_at");
    const ce = child.uintField("expires_at");
    if (pe != null and ce == null) return false; // child infinite, parent finite
    if (pe) |p| if (ce) |c| if (c > p) return false;
    return true;
}

fn checkDelegationCaveats(parent: Entity, child: Entity, depth: u64) bool {
    const caveats = parent.field("delegation_caveats") orelse return true;
    if (model.mapGet(caveats, "no_delegation")) |v| switch (v) {
        .boolean => |b| if (b) return false,
        else => {},
    };
    if (model.mapGet(caveats, "max_delegation_depth")) |v| switch (v) {
        .uint => |m| if (depth >= m) return false,
        else => {},
    };
    if (model.mapGet(caveats, "max_delegation_ttl")) |v| switch (v) {
        .uint => |maxttl| {
            const ex = child.uintField("expires_at");
            const cr = child.uintField("created_at");
            if (ex) |e| {
                if (cr) |c| {
                    if (e - c > maxttl) return false;
                }
            } else return false; // infinite child lifetime exceeds any finite limit
        },
        else => {},
    };
    return true;
}

fn nowMs() u64 {
    return @intCast(std.time.milliTimestamp());
}

const ChainError = error{ ChainTooDeep, ChainUnreachable } || Error;

fn collectChain(arena: std.mem.Allocator, env: model.Envelope, st: *Store, cap: Entity) ChainError![]Entity {
    var chain: std.ArrayList(Entity) = .empty;
    var current = cap;
    var depth: usize = 0;
    while (true) {
        if (depth > 64) return error.ChainTooDeep;
        try chain.append(arena, current);
        const ph = current.bytesField("parent") orelse return chain.toOwnedSlice(arena);
        current = resolve(env, st, ph) orelse return error.ChainUnreachable;
        depth += 1;
    }
}

/// §4.10(b) structural-bound pre-check: true if the authority chain rooted at
/// `cap` exceeds the max depth (64). Walks parent pointers without verifying
/// signatures — depth is a purely structural property, gated BEFORE the per-link
/// authz walk so an over-deep chain is reported as 400 chain_depth_exceeded
/// (structural excess), distinct from a 403 capability_denied authz failure (arch
/// ruling, v7.75 §4.10(b)). An unreachable parent is NOT a depth problem — it
/// returns false here and is left for verifyCapabilityChain to deny (403).
fn chainExceedsDepth(env: model.Envelope, st: *Store, cap: Entity) bool {
    var current = cap;
    var depth: usize = 0;
    while (true) {
        if (depth > 64) return true;
        const ph = current.bytesField("parent") orelse return false; // root within bound
        current = resolve(env, st, ph) orelse return false; // unreachable — not a depth problem
        depth += 1;
    }
}

// ── §3.6 M3 multi-signature granter ──────────────────────────────────────────
//
// The capability `granter` field is a UNION (§3.6): a single system/hash (bytes,
// single-sig) OR a {signers: [system/hash], threshold: uint} map (multi-sig,
// root-only). A multi-sig root is verified by verifyMultiSigRoot — M3 structure
// first, then §5.5 M6 (local peer ∈ signers) + M4 k-of-n quorum.

const MultiGranter = struct { signers: []const []const u8, threshold: u64 };

/// Parse the multi-granter descriptor iff `granter` is a map (not bytes).
/// Single-sig granters (bytes) and absent granters return null.
fn multiGranterOfEntity(arena: std.mem.Allocator, cap: Entity) Error!?MultiGranter {
    const g = cap.field("granter") orelse return null;
    switch (g) {
        .map => {}, // multi-sig descriptor
        else => return null, // bytes (single-sig) or other → not multi-sig
    }
    const signers = try bytesList(arena, model.mapGet(g, "signers"));
    const threshold = switch (model.mapGet(g, "threshold") orelse Value{ .uint = 0 }) {
        .uint => |t| t,
        else => 0,
    };
    return .{ .signers = signers, .threshold = threshold };
}

fn bytesList(arena: std.mem.Allocator, v: ?Value) Error![]const []const u8 {
    const arr = switch (v orelse return &.{}) {
        .array => |a| a,
        else => return &.{},
    };
    var out: std.ArrayList([]const u8) = .empty;
    for (arr) |it| switch (it) {
        .bytes => |b| try out.append(arena, b),
        else => {},
    };
    return out.toOwnedSlice(arena);
}

fn hasDuplicateSigners(signers: []const []const u8) bool {
    for (signers, 0..) |s, i| {
        for (signers[i + 1 ..]) |o| {
            if (std.mem.eql(u8, s, o)) return true;
        }
    }
    return false;
}

fn signerPeerId(arena: std.mem.Allocator, env: model.Envelope, st: *Store, h: []const u8) Error!?[]const u8 {
    const p = resolve(env, st, h) orelse return null;
    const pk = p.bytesField("public_key") orelse return null;
    return try identity.peerIdOfPubkey(arena, pk);
}

/// verify_multisig_root (§3.6 M3 / §5.5 M4·M6). ALLOW only if the quorum is
/// well-formed AND a threshold of DISTINCT signers signed the cap's content hash.
/// Structural validation (M3) precedes signature counting (§3.6 precedence 25): a
/// malformed quorum is denied on its structure, not on its signatures. Every path
/// returns deny → the dispatcher maps it to 403 capability_denied.
fn verifyMultiSigRoot(arena: std.mem.Allocator, env: model.Envelope, st: *Store, local_peer: []const u8, cap: Entity, mg: MultiGranter) Error!Verdict {
    const n = mg.signers.len;
    // §3.6 M3 structure (BEFORE signatures) — root-only; real quorum (n ≥ 2);
    // usable threshold (2 ≤ threshold ≤ n); distinct signers.
    if (cap.bytesField("parent") != null) return .deny; // multi-sig is root-only
    if (n < 2) return .deny;
    if (mg.threshold < 2 or mg.threshold > n) return .deny;
    if (hasDuplicateSigners(mg.signers)) return .deny;

    // §5.5 M6 root-at-local — the local peer MUST be a quorum member.
    var local_in_quorum = false;
    for (mg.signers) |s| {
        if (try signerPeerId(arena, env, st, s)) |pid| {
            if (std.mem.eql(u8, pid, local_peer)) {
                local_in_quorum = true;
                break;
            }
        }
    }
    if (!local_in_quorum) return .deny;

    // temporal validity + grantee resolution (as for any root).
    const t = nowMs();
    if (cap.uintField("not_before")) |nb| if (t < nb) return .deny;
    if (cap.uintField("expires_at")) |ex| if (ex < t) return .deny;
    const grantee = cap.bytesField("grantee") orelse return .deny;
    if (resolve(env, st, grantee) == null) return .deny;

    // §5.5 M4 k-of-n — count DISTINCT signers with a valid signature over the
    // cap's content hash; ≥ threshold ⇒ quorum. A duplicate signature from one
    // signer does NOT inflate the count.
    var valid: std.ArrayList([]const u8) = .empty;
    for (mg.signers) |s| {
        // skip if this signer already counted (distinct-signer count)
        var already = false;
        for (valid.items) |v| if (std.mem.eql(u8, v, s)) {
            already = true;
            break;
        };
        if (already) continue;
        const signer_peer = resolve(env, st, s) orelse continue;
        // find a signature targeting the cap whose `signer` == this signer hash
        // and which verifies under the signer peer's key.
        for (env.included) |inc| {
            const sgn = inc.entity;
            if (!std.mem.eql(u8, sgn.typ, "system/signature")) continue;
            const tgt = sgn.bytesField("target") orelse continue;
            if (!std.mem.eql(u8, tgt, cap.hash)) continue;
            const sg = sgn.bytesField("signer") orelse continue;
            if (!std.mem.eql(u8, sg, s)) continue;
            if (identity.verifySignature(sgn, signer_peer)) {
                try valid.append(arena, s);
                break;
            }
        }
    }
    return if (valid.items.len >= mg.threshold) .allow else .deny;
}

/// verify_capability_chain (§5.5). A single-sig root roots at the local peer; a
/// §3.6 M3 multi-sig root (root-only) passes k-of-n quorum via verifyMultiSigRoot.
/// Returns allow/deny; surfaces UnresolvableGrantee for the §5.5 401 carve-out.
fn verifyCapabilityChain(arena: std.mem.Allocator, env: model.Envelope, st: *Store, local_peer: []const u8, capability: Entity) Error!Verdict {
    const chain = collectChain(arena, env, st, capability) catch |e| switch (e) {
        error.ChainTooDeep, error.ChainUnreachable => return .deny,
        else => |x| return x,
    };
    const root = chain[chain.len - 1];
    // Root authority: a single-sig root must root at the local peer; a §3.6 M3
    // multi-sig root (root-only) must pass k-of-n quorum validation.
    const root_ok = blk: {
        if (try multiGranterOfEntity(arena, root)) |mg| {
            break :blk (try verifyMultiSigRoot(arena, env, st, local_peer, root, mg)) == .allow;
        }
        const gh = root.bytesField("granter") orelse break :blk false;
        const g = resolve(env, st, gh) orelse break :blk false;
        const pk = g.bytesField("public_key") orelse break :blk false;
        const pid = try identity.peerIdOfPubkey(arena, pk);
        break :blk std.mem.eql(u8, pid, local_peer);
    };
    if (!root_ok) return .deny;

    const n = chain.len;
    const t = nowMs();
    for (chain, 0..) |current, i| {
        // §3.6 M3 multi-sig is root-only and is fully verified above (structure,
        // quorum signatures, temporal, grantee). A multi-sig token anywhere but
        // the chain root is rejected; the root's per-link signature/grantee/
        // temporal checks below are skipped (already done in verifyMultiSigRoot).
        if ((try multiGranterOfEntity(arena, current)) != null) {
            if (i != n - 1) return .deny; // multi-sig off-root → deny
            continue;
        }
        // signature: signer == granter, verify against granter identity
        const gh = current.bytesField("granter") orelse return .deny;
        const sgn = findSignature(env, current.hash) orelse return .deny;
        const granter = resolve(env, st, gh) orelse return .deny;
        const signer_ok = if (sgn.bytesField("signer")) |s| std.mem.eql(u8, s, gh) else false;
        if (!(signer_ok and identity.verifySignature(sgn, granter))) return .deny;
        // grantee resolution → 401 carve-out
        const grantee = current.bytesField("grantee") orelse return error.UnresolvableGrantee;
        if (resolve(env, st, grantee) == null) return error.UnresolvableGrantee;
        // temporal validity
        if (current.uintField("not_before")) |nb| if (t < nb) return .deny;
        if (current.uintField("expires_at")) |ex| if (ex < t) return .deny;
        // delegation link
        if (i < n - 1) {
            const parent = chain[i + 1];
            const child_peer = (try linkGranterPeer(arena, env, st, local_peer, current)) orelse return .deny;
            const parent_peer = (try linkGranterPeer(arena, env, st, local_peer, parent)) orelse return .deny;
            const link_ok = blk: {
                const pg = parent.bytesField("grantee");
                const cg = current.bytesField("granter");
                if (pg == null or cg == null or !std.mem.eql(u8, pg.?, cg.?)) break :blk false;
                if (!try isAttenuated(arena, local_peer, child_peer, parent_peer, current, parent)) break :blk false;
                if (!checkDelegationCaveats(parent, current, @intCast(i))) break :blk false;
                break :blk true;
            };
            if (!link_ok) return .deny;
        }
    }
    return .allow;
}

/// is_revoked (§5.1) — marker check at the revocations path; covers leaf + root.
fn isRevoked(arena: std.mem.Allocator, env: model.Envelope, st: *Store, local_peer: []const u8, capability: Entity) Error!bool {
    const root_hash = blk: {
        const chain = collectChain(arena, env, st, capability) catch break :blk capability.hash;
        break :blk chain[chain.len - 1].hash;
    };
    const check = struct {
        fn f(a: std.mem.Allocator, s: *Store, lp: []const u8, h: []const u8) Error!bool {
            const hex = try model.hex(a, h);
            const path = try std.fmt.allocPrint(a, "/{s}/system/capability/revocations/{s}", .{ lp, hex });
            return s.getAt(path) != null;
        }
    }.f;
    return (try check(arena, st, local_peer, capability.hash)) or (try check(arena, st, local_peer, root_hash));
}

/// verify_request (§5.2) — 3-way authn/authz verdict (A-ZIG-006 / §4.6 / F20).
/// `arena` scopes all verification scratch; caller resets it after.
pub fn verifyRequest(arena: std.mem.Allocator, env: model.Envelope, st: *Store, local_peer: []const u8) Error!ReqVerdict {
    const exec = env.root;
    // 1. content hash already validated on parse (model.ofCbor).
    // 2. signature / author — authentication class (§4.6 boundary → 401).
    const sgn = findSignature(env, exec.hash) orelse return .authn_fail;
    const author_h = exec.bytesField("author");
    const signer_ok = blk: {
        const s = sgn.bytesField("signer") orelse break :blk false;
        const a = author_h orelse break :blk false;
        break :blk std.mem.eql(u8, s, a);
    };
    if (!signer_ok) return .authn_fail;
    const author = (if (author_h) |a| env.includedGet(a) else null) orelse return .authn_fail;
    if (!identity.verifySignature(sgn, author)) return .authn_fail;
    // 3. capability / chain — authorization class (→ 403).
    const cap_h = exec.bytesField("capability") orelse return .authz_deny;
    const capability = env.includedGet(cap_h) orelse return .authz_deny;
    // §4.10(b) resource bound: a chain exceeding max depth is rejected as 400
    // chain_depth_exceeded (structural excess) BEFORE the per-link authz walk —
    // distinct from 403 capability_denied. Arch v7.75 ruling: 400 lets the caller
    // distinguish "shorten your chain" from "you lack the capability".
    if (chainExceedsDepth(env, st, capability)) return .chain_too_deep;
    // chain first: a per-link unresolvable grantee (§5.5) → 401 takes precedence
    // over the §5.2 grantee==author mismatch → 403 (the single 401 carve-out).
    const chain_verdict = verifyCapabilityChain(arena, env, st, local_peer, capability) catch |e| switch (e) {
        error.UnresolvableGrantee => return error.UnresolvableGrantee,
        else => |x| return x,
    };
    if (chain_verdict == .deny) return .authz_deny;
    const grantee_ok = blk: {
        const g = capability.bytesField("grantee") orelse break :blk false;
        const a = author_h orelse break :blk false;
        break :blk std.mem.eql(u8, g, a);
    };
    if (!grantee_ok) return .authz_deny;
    if (try isRevoked(arena, env, st, local_peer, capability)) return .authz_deny;
    return .allow;
}

/// Resolve the §PR-8 granter frame for a leaf cap at the dispatch site; falls back
/// to the local peer for an unresolvable/multisig granter.
pub fn granterFrame(arena: std.mem.Allocator, env: model.Envelope, st: *Store, local_peer: []const u8, cap: Entity) Error![]const u8 {
    return (try resolveGranterPeerId(arena, env, st, cap)) orelse local_peer;
}

// ── public re-exports for the §6.2 mint-time subset check (peer.zig) ──────────
//
// The capability-handler's mint-time subset check (§6.2) is a distinct surface
// from the dispatch chain walk; it runs on the local frame (child=parent=local).
// Expose the grant parse + local-frame subset so peer.zig need not re-derive them.

pub const PubGrant = Grant;

pub fn parseGrantPublic(arena: std.mem.Allocator, v: Value) Error!PubGrant {
    return parseGrant(arena, v);
}

pub fn grantsOfTokenPublic(arena: std.mem.Allocator, token: Entity) Error![]PubGrant {
    return grantsOfToken(arena, token);
}

/// §6.2 local-frame subset (child=parent=local) — the mint-time check.
pub fn grantSubsetLocal(arena: std.mem.Allocator, local_peer: []const u8, child: PubGrant, parent: PubGrant) Error!bool {
    return grantSubset(arena, local_peer, local_peer, local_peer, child, parent);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "pattern matching §5.4" {
    try testing.expect(matchesPattern("/p/system/tree", "*"));
    try testing.expect(matchesPattern("/p/system/tree/x", "/p/system/tree/*"));
    try testing.expect(matchesPattern("/p/a/b", "/*/a/b"));
    try testing.expect(!matchesPattern("/p/a/b", "/p/a/c"));
}

test "canonicalize peer-relative" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    try testing.expectEqualStrings("/peerX/system/tree", try canonicalize(a, "peerX", "system/tree"));
    try testing.expectEqualStrings("/peerX/system/tree", try canonicalize(a, "peerX", "/peerX/system/tree"));
}

// ── §3.6 M3 multi-signature K-of-N — ACCEPT path ─────────────────────────────
//
// The validate-peer `multisig` category is 100% rejection tests (malformed
// quorum → 403), which a fail-closed peer passes vacuously. This is the
// direction the oracle does NOT cover: a real 2-of-3 root (one signer = local
// peer) with a threshold of valid signatures over the cap's content_hash MUST be
// ALLOWed — and each M3/M4/M6 invariant flip MUST deny. Mirrors the OCaml
// selftest accept-path block.

const Store_ = @import("store.zig").Store;

/// Build a system/capability/token with a multi-sig granter descriptor.
/// `signers` are the signer identity hashes (33-byte content hashes). Owned by gpa.
fn mkMultiCap(gpa: std.mem.Allocator, grantee_hash: []const u8, signers: []const []const u8, threshold: u64, parent: ?[]const u8) Error!Entity {
    const sig_arr = try gpa.alloc(Value, signers.len);
    var built: usize = 0;
    errdefer {
        for (sig_arr[0..built]) |v| v.deinit(gpa);
        gpa.free(sig_arr);
    }
    while (built < signers.len) : (built += 1) sig_arr[built] = try model.bytesVal(gpa, signers[built]);

    var granter_pairs = try gpa.alloc(Value.Pair, 2);
    granter_pairs[0] = .{ .key = try model.textVal(gpa, "signers"), .value = .{ .array = sig_arr } };
    granter_pairs[1] = .{ .key = try model.textVal(gpa, "threshold"), .value = .{ .uint = threshold } };

    const field_count: usize = if (parent != null) 4 else 3;
    var pairs = try gpa.alloc(Value.Pair, field_count);
    pairs[0] = .{ .key = try model.textVal(gpa, "granter"), .value = .{ .map = granter_pairs } };
    pairs[1] = .{ .key = try model.textVal(gpa, "grantee"), .value = try model.bytesVal(gpa, grantee_hash) };
    pairs[2] = .{ .key = try model.textVal(gpa, "grants"), .value = .{ .array = try gpa.alloc(Value, 0) } };
    if (parent) |p| pairs[3] = .{ .key = try model.textVal(gpa, "parent"), .value = try model.bytesVal(gpa, p) };
    return Entity.make(gpa, "system/capability/token", .{ .map = pairs });
}

/// Run verifyCapabilityChain over an envelope assembled from owned entities, then
/// free everything (leak-checked). `extra` entities (peers + signatures) go into
/// `included`; `cap` is the chain root. Returns the verdict (or surfaces errors).
fn allowsMultiSig(gpa: std.mem.Allocator, local_peer: []const u8, cap: Entity, extra: []const Entity) !Verdict {
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    var st = Store_.init(gpa);
    defer st.deinit();

    // Assemble the included set: the cap itself + all extra entities, each cloned
    // and owned by the envelope (which frees them on deinit).
    var included: std.ArrayList(model.Included) = .empty;
    defer {
        for (included.items) |inc| {
            gpa.free(inc.key);
            inc.entity.deinit(gpa);
        }
        included.deinit(gpa);
    }
    const cap_clone = try cap.clone(gpa);
    try included.append(gpa, .{ .key = try gpa.dupe(u8, cap_clone.hash), .entity = cap_clone });
    for (extra) |e| {
        const c = try e.clone(gpa);
        try included.append(gpa, .{ .key = try gpa.dupe(u8, c.hash), .entity = c });
    }
    const env = model.Envelope{
        .root = try cap.clone(gpa),
        .included = included.items,
    };
    defer env.root.deinit(gpa);

    return verifyCapabilityChain(arena_inst.allocator(), env, &st, local_peer, cap);
}

test "§3.6 multi-sig K-of-N accept path + M3/M4/M6 deny flips" {
    const gpa = testing.allocator;
    const id1 = try identity.ofSeed(gpa, [_]u8{1} ** 32);
    defer id1.deinit(gpa);
    const id2 = try identity.ofSeed(gpa, [_]u8{2} ** 32);
    defer id2.deinit(gpa);
    const id3 = try identity.ofSeed(gpa, [_]u8{3} ** 32);
    defer id3.deinit(gpa);
    const local = id1.peer_id;
    const signers = [_][]const u8{ id1.identity_hash, id2.identity_hash, id3.identity_hash };

    // valid 2-of-3, local in quorum, 2 valid sigs → Allow
    {
        const cap = try mkMultiCap(gpa, id1.identity_hash, &signers, 2, null);
        defer cap.deinit(gpa);
        const s1 = try identity.signEntity(gpa, id1, cap);
        defer s1.deinit(gpa);
        const s2 = try identity.signEntity(gpa, id2, cap);
        defer s2.deinit(gpa);
        const extra = [_]Entity{ id1.peer_entity, id2.peer_entity, id3.peer_entity, s1, s2 };
        try testing.expectEqual(Verdict.allow, try allowsMultiSig(gpa, local, cap, &extra));
    }

    // only 1 valid sig (< threshold) → Deny (M4)
    {
        const cap = try mkMultiCap(gpa, id1.identity_hash, &signers, 2, null);
        defer cap.deinit(gpa);
        const s1 = try identity.signEntity(gpa, id1, cap);
        defer s1.deinit(gpa);
        const extra = [_]Entity{ id1.peer_entity, id2.peer_entity, id3.peer_entity, s1 };
        try testing.expectEqual(Verdict.deny, try allowsMultiSig(gpa, local, cap, &extra));
    }

    // duplicate signature from one signer does NOT inflate the count → Deny (M4)
    {
        const cap = try mkMultiCap(gpa, id1.identity_hash, &signers, 2, null);
        defer cap.deinit(gpa);
        const s1 = try identity.signEntity(gpa, id1, cap);
        defer s1.deinit(gpa);
        const extra = [_]Entity{ id1.peer_entity, id2.peer_entity, id3.peer_entity, s1, s1 };
        try testing.expectEqual(Verdict.deny, try allowsMultiSig(gpa, local, cap, &extra));
    }

    // local peer not among the signers → Deny (M6)
    {
        const two = [_][]const u8{ id2.identity_hash, id3.identity_hash };
        const cap = try mkMultiCap(gpa, id1.identity_hash, &two, 2, null);
        defer cap.deinit(gpa);
        const n2 = try identity.signEntity(gpa, id2, cap);
        defer n2.deinit(gpa);
        const n3 = try identity.signEntity(gpa, id3, cap);
        defer n3.deinit(gpa);
        const extra = [_]Entity{ id2.peer_entity, id3.peer_entity, n2, n3 };
        try testing.expectEqual(Verdict.deny, try allowsMultiSig(gpa, local, cap, &extra));
    }

    // threshold = 1 (M3 structure) → Deny even with valid sigs (precedence)
    {
        const cap = try mkMultiCap(gpa, id1.identity_hash, &signers, 1, null);
        defer cap.deinit(gpa);
        const s1 = try identity.signEntity(gpa, id1, cap);
        defer s1.deinit(gpa);
        const s2 = try identity.signEntity(gpa, id2, cap);
        defer s2.deinit(gpa);
        const extra = [_]Entity{ id1.peer_entity, id2.peer_entity, id3.peer_entity, s1, s2 };
        try testing.expectEqual(Verdict.deny, try allowsMultiSig(gpa, local, cap, &extra));
    }

    // duplicate signers (M3 structure) → Deny
    {
        const dup = [_][]const u8{ id1.identity_hash, id1.identity_hash };
        const cap = try mkMultiCap(gpa, id1.identity_hash, &dup, 2, null);
        defer cap.deinit(gpa);
        const s1 = try identity.signEntity(gpa, id1, cap);
        defer s1.deinit(gpa);
        const extra = [_]Entity{ id1.peer_entity, s1 };
        try testing.expectEqual(Verdict.deny, try allowsMultiSig(gpa, local, cap, &extra));
    }

    // multi-sig off-root → Deny (root-only); use a single-sig root parent with a
    // multi-sig child. The chain walk rejects the multi-sig token off the root.
    {
        const parent = try mkMultiCap(gpa, id1.identity_hash, &signers, 2, null);
        defer parent.deinit(gpa);
        const child = try mkMultiCap(gpa, id1.identity_hash, &signers, 2, parent.hash);
        defer child.deinit(gpa);
        const ps1 = try identity.signEntity(gpa, id1, parent);
        defer ps1.deinit(gpa);
        const ps2 = try identity.signEntity(gpa, id2, parent);
        defer ps2.deinit(gpa);
        const cs1 = try identity.signEntity(gpa, id1, child);
        defer cs1.deinit(gpa);
        const cs2 = try identity.signEntity(gpa, id2, child);
        defer cs2.deinit(gpa);
        const extra = [_]Entity{ id1.peer_entity, id2.peer_entity, id3.peer_entity, parent, ps1, ps2, cs1, cs2 };
        try testing.expectEqual(Verdict.deny, try allowsMultiSig(gpa, local, child, &extra));
    }
}

test "single-sig root still verifies (strict superset)" {
    const gpa = testing.allocator;
    const id1 = try identity.ofSeed(gpa, [_]u8{1} ** 32);
    defer id1.deinit(gpa);
    const local = id1.peer_id;

    var pairs = try gpa.alloc(Value.Pair, 3);
    pairs[0] = .{ .key = try model.textVal(gpa, "granter"), .value = try model.bytesVal(gpa, id1.identity_hash) };
    pairs[1] = .{ .key = try model.textVal(gpa, "grantee"), .value = try model.bytesVal(gpa, id1.identity_hash) };
    pairs[2] = .{ .key = try model.textVal(gpa, "grants"), .value = .{ .array = try gpa.alloc(Value, 0) } };
    const cap = try Entity.make(gpa, "system/capability/token", .{ .map = pairs });
    defer cap.deinit(gpa);
    const ss = try identity.signEntity(gpa, id1, cap);
    defer ss.deinit(gpa);
    const extra = [_]Entity{ id1.peer_entity, ss };
    try testing.expectEqual(Verdict.allow, try allowsMultiSig(gpa, local, cap, &extra));
}
