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

/// The unmatchable value (0.8.2.20). Unreachable as a canonical path by
/// CONSTRUCTION: its first segment cannot be a peer_id, since isPeerId requires
/// >= 46 Base58 characters and '-' is outside the Base58 alphabet.
pub const never_match = "/never-match";

/// Resolve peer-relative paths to absolute "/{local}/..." form. Returns owned.
///
/// TOTAL (0.8.2.20): the return domain is "a canonical path OR never_match". The two
/// reserved arms were ABSENT here — "../x" came back as "/{local}/../x", which
/// matched nothing, so a grant exclude carrying it carved out nothing and the grant
/// was silently wider than its author wrote (measured on the wire 2026-09-14). A
/// non-match is the desired outcome in an INCLUDE and the opposite of it in an
/// EXCLUDE.
pub fn canonicalize(arena: std.mem.Allocator, local_peer: []const u8, path: []const u8) Error![]const u8 {
    if (startsWith(path, "./") or startsWith(path, "../")) return never_match;
    if (startsWith(path, "*/")) return never_match;
    if (startsWith(path, "/")) return path;
    return std.fmt.allocPrint(arena, "/{s}/{s}", .{ local_peer, path });
}

/// AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
/// in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an
/// exclude (carves out nothing), so the reading is chosen where the POSITION is known
/// and matchesPattern stays uniform over its operands.
///
/// PATH-SCOPE ONLY (0.8.2.24, N2/N3) — every caller must gate this on the dimension's
/// scope type. The two live callers do: `matchesScope` tests `kind == .path`, and
/// `checkResourceScope` is the RESOURCES dimension, which is path-scope by definition.
fn excludeIsUnmatchable(arena: std.mem.Allocator, frame: []const u8, excl: []const []const u8) Error!bool {
    for (excl) |p| {
        if (std.mem.eql(u8, try canonicalize(arena, frame, p), never_match)) return true;
    }
    return false;
}

/// Both path and pattern MUST already be canonical (absolute).
pub fn matchesPattern(path: []const u8, pattern: []const u8) bool {
    // never_match never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
    // rule rather than a property of the string: the line below returns true for a
    // bare "*", so safety must not rest on a value merely looking unmatchable.
    if (std.mem.eql(u8, path, never_match) or std.mem.eql(u8, pattern, never_match)) return false;
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

/// Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every
/// call site — no default — so a new one cannot inherit the wrong matcher silently,
/// which is exactly the F40 defect.
pub const ScopeKind = enum {
    id, // operations, peers   — system/capability/id-scope
    path, // handlers, resources — system/capability/path-scope
};

/// §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard forms
/// — bare "*" and a trailing slash-star segment-prefix. None of the §5.4 path transforms
/// apply, so a pattern carrying path syntax is matched as a literal string: a non-match,
/// never a fault.
pub fn matchesIdPattern(value: []const u8, pattern: []const u8) bool {
    if (std.mem.eql(u8, pattern, "*")) return true;
    if (pattern.len >= 2 and std.mem.eql(u8, pattern[pattern.len - 2 ..], "/*")) {
        return startsWith(value, pattern[0 .. pattern.len - 1]);
    }
    return std.mem.eql(u8, value, pattern);
}

fn coveredId(value: []const u8, pats: []const []const u8) bool {
    for (pats) |p| {
        if (matchesIdPattern(value, p)) return true;
    }
    return false;
}

fn matchesScope(arena: std.mem.Allocator, local_peer: []const u8, value: []const u8, s: Scope, kind: ScopeKind) Error!bool {
    // SCOPED TO PATH-SCOPE (0.8.2.24, N2/N3). §5.2's exclude loop now tests the
    // sentinel INSIDE `if dimension_type == "system/capability/path-scope"`, and
    // §5.4 says the same from the other side: "a capability carrying an unmatchable
    // PATH-SCOPE pattern is INVALID ... It does NOT reach `operations` or `peers`
    // [MUST]". This guard was UNCONDITIONAL until 0.8.2.24 — which was the text at
    // the time (F82 was our own ask, and the grant created this work) — and under it
    // an ordinary namespaced operation name like "*/apply" path-canonicalizes to the
    // sentinel and DENIES THE WHOLE DIMENSION. Over-denial, invisible on well-formed
    // grants.
    //
    // The two id-scope dimensions reach `coveredId`'s literal arm below unguarded,
    // which is correct: under §3.6's id-scope grammar every non-`*` pattern is a
    // literal and a literal is never structurally unmatchable, so there is nothing
    // here for the sentinel to detect. §5.4 says so outright and leaves the id-scope
    // form of the carves-out-nothing hazard deliberately open rather than minting a
    // second sentinel for it — a scope boundary, not an omission.
    if (kind == .path and try excludeIsUnmatchable(arena, local_peer, s.excl)) return false; // 0.8.2.21 — deny
    if (kind == .id) {
        return coveredId(value, s.incl) and !coveredId(value, s.excl);
    }
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
    // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
    // target: the coverage test below is correct in isolation and is simply never
    // reached on a sentinel, because matchesPattern answers false.
    if (try excludeIsUnmatchable(arena, granter_peer, s.excl)) return false;
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
        const op_ok = try matchesScope(arena, local_peer, operation, g.operations, .id);
        if (!op_ok) continue;
        const h_ok = try matchesScope(arena, local_peer, handler_pattern, g.handlers, .path);
        if (!h_ok) continue;
        const peers = g.peers orelse Scope{ .incl = &.{local_peer}, .excl = &.{} };
        const p_ok = try matchesScope(arena, local_peer, target_peer, peers, .id);
        if (!p_ok) continue;
        const r_ok = if (resource) |r| try checkResourceScope(arena, local_peer, granter_peer, r, g.resources) else true;
        if (r_ok) return .allow;
    }
    return .deny;
}

// ── §5.2 effective targets and §6.3 check_path_permission ────────────────────

/// The result of §5.2's effective-target derivation. The PAIR is the point: see
/// `effectiveTargets`.
pub const Effective = struct {
    /// Survivors in the CALLER'S OWN SPELLING, not canonicalized.
    survivors: []const []const u8,
    /// Was a `resource` carrying a `targets` key present at all?
    had_resource: bool,
};

/// effectiveTargets derives §5.2's effective target list (0.8.2.20): the caller's own
/// `resource.exclude` removes entries from the request BEFORE anything else looks at it.
///
/// The survivors come back in the caller's OWN SPELLING, not canonicalized — 0.8.2.21
/// is explicit that `effective_targets` yields raw survivors, and the distinction is
/// load-bearing here because the value flows on to `store.getAt`, which canonicalizes
/// for itself.
///
/// `had_resource` says whether a `resource` was present at all. An ABSENT resource and
/// a resource whose every target was excluded are different inputs to §3.3, and for a
/// resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT REQUESTS with
/// different answers rather than merely different inputs to one.
///
/// THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11): "where an
/// implementation projects resource.targets onto the effective set ahead of the handler,
/// that projection MUST NOT be lossy about its own emptiness — narrow when narrowing
/// leaves something, and retain the raw pair when narrowing would empty it." A function
/// returning only a list cannot satisfy that: collapsing `[qA] exclude [qA]` to `[]`
/// deletes the two-empties discriminator before any handler can read it.
///
/// "Every seam that narrows is exempted alike, inbound-wire and in-process
/// sub-dispatch." This peer has exactly ONE narrowing seam — this function, called by
/// the tree handler — and §6.5's dispatch chain does not project: `dispatchOutcome`
/// passes `exec` through untouched and `checkPermission` reads `resource` for itself.
/// So there is no second door to keep in step, and adding a projection at dispatch
/// would create one.
///
/// A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**: `textList` of a non-array yields an
/// empty survivor list rather than "absent", so `{"targets": 42}` answers the
/// present-but-empty disposition and never the WIDER absent-case one. That is N11's own
/// defect one field over, and it is the cell the two vanguards initially disagreed on.
pub fn effectiveTargets(arena: std.mem.Allocator, local_peer: []const u8, exec: Entity) Error!Effective {
    const absent = Effective{ .survivors = &.{}, .had_resource = false };
    const r = exec.field("resource") orelse return absent;
    switch (r) {
        .map => {},
        else => return absent,
    }
    if (model.mapGet(r, "targets") == null) return absent;
    const targets = try textList(arena, model.mapGet(r, "targets"));
    const caller_excl = try textList(arena, model.mapGet(r, "exclude"));
    var out: std.ArrayList([]const u8) = .empty;
    for (targets) |t| {
        const ct = try canonicalize(arena, local_peer, t);
        var dropped = false;
        for (caller_excl) |x| {
            // The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4's
            // table rules it separately from the grant arm): canonicalize answers
            // never_match and matchesPattern then answers false, so the target simply
            // SURVIVES. That asymmetry is 0.8.2.21's whole point and it is INHERITED
            // from the primitives here, never restated.
            if (matchesPattern(ct, try canonicalize(arena, local_peer, x))) {
                dropped = true;
                break;
            }
        }
        if (!dropped) try out.append(arena, t);
    }
    return .{ .survivors = try out.toOwnedSlice(arena), .had_resource = true };
}

/// checkPathPermission is §6.3's handler-level path check.
///
/// IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
/// subject is derived after dispatch, and the dispatch-level check can be made VACUOUS
/// by caller-controlled input: a caller who excludes the one target its capability does
/// not cover removes that target from `checkPermission`'s view entirely, and a handler
/// that then acts on it has authorized nothing.
///
/// THREE DIMENSIONS, NOT FOUR. `peers` is not consulted — the path is local by
/// construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
/// step 3, before any handler runs), and §6.3's signature names only handlers,
/// operations and resources.
///
/// THE FRAME IS `local_peer_id`, NOT THE GRANTER, and that is the spec's own signature
/// rather than a choice: §6.3's block reads `matches_scope(canonical_path,
/// grant.resources, "path-scope", local_peer_id)` — there is no granter parameter to
/// pass. §5.5a governs chain ATTENUATION, where the subject is a PATTERN compared
/// against a parent's pattern; this call site compares a CONCRETE LOCAL PATH the
/// handler is about to touch. Adding a frame here is the over-scoping defect this
/// cohort has recorded three times.
///
/// There is no caller-exclude set at this call site: the subject is a single concrete
/// path and the caller's exclusions have already been applied in deriving it. Every
/// grant exclude covering the subject therefore denies — which `matchesScope` already
/// implements, including 0.8.2.21's sentinel rule, so this function is three calls to
/// it and nothing else. An empty `resources.include` is a legal grant shape (§5.2:
/// handlers that touch no tree paths) and DENIES every path here, which is what that
/// note says it should: coverage over an empty include list is false.
pub fn checkPathPermission(
    arena: std.mem.Allocator,
    local_peer: []const u8,
    operation: []const u8,
    path: []const u8,
    token: Entity,
    handler_pattern: []const u8,
) Error!bool {
    // canonicalize is TOTAL and may answer never_match, which matches no grant (§5.4)
    // — so a malformed path falls through to DENY rather than being matched against
    // anything.
    const cp = try canonicalize(arena, local_peer, path);
    const grants = try grantsOfToken(arena, token);
    for (grants) |g| {
        if (!try matchesScope(arena, local_peer, handler_pattern, g.handlers, .path)) continue;
        if (!try matchesScope(arena, local_peer, operation, g.operations, .id)) continue;
        if (!try matchesScope(arena, local_peer, cp, g.resources, .path)) continue;
        return true;
    }
    return false;
}

// ── §5.5 / §5.6 chain verification + attenuation ─────────────────────────────

pub fn resolve(env: model.Envelope, st: *Store, h: []const u8) ?Entity {
    if (env.includedGet(h)) |e| return e;
    return st.getByHash(h);
}

/// §6.2 CAP-6a: true when every temporal field on a RECEIVED token is either absent
/// (legal) or representable as a u64.
///
/// This is the reader-side half of CAP-6 and it is where a peer fails OPEN. The
/// idiomatic accessor `uintField` answers null both when a field is ABSENT and when it
/// is PRESENT but not a `.uint` — a negative integer or a bignum — so a token carrying
/// expires_at:-1 silently skipped the expiry check and was honored with 200. §6.2
/// CAP-6a is explicit: such a token "is malformed. A verifier MUST refuse it and MUST
/// NOT treat the unrepresentable field as absent." An absent expires_at stays legal and
/// is deliberately NOT rejected here.
///
/// Refusal must be the §5.2 capability_denied disposition (a status-bearing response),
/// never a decode-layer silent drop or a transport close.
pub fn temporalFieldsRepresentable(tok: Entity) bool {
    for ([_][]const u8{ "expires_at", "not_before", "created_at" }) |key| {
        const v = tok.field(key) orelse continue; // absent is legal
        switch (v) {
            .uint => {},
            else => return false, // present but not a u64 => malformed
        }
    }
    return true;
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

/// §5.5a subset check: every child include must be covered by some parent include,
/// and every parent exclude must be inherited by some child exclude.
///
/// TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; `entity-core-formalization` K-7).
/// §3.6's id-scope grammar binds the scope TYPE, not one function — "An implementation
/// on the canonicalizing reading is non-conformant and MUST adopt the literal matcher"
/// — so the rule F40 landed on `matchesScope` reaches here too, with delegation-chain
/// WIDENING named as the reason: on the canonicalizing reading `/tree/get` is covered
/// by `*` in one direction and `*/apply` is not, so a child grant can come out WIDER
/// than its parent. `lean`'s differential put it at 2 of 64 include pairs and 2 of 64
/// exclude pairs, fail-closed, with a 16-pair control alphabet reporting 0 — which is
/// why every hand-tried example missed it.
///
/// `kind` has NO DEFAULT and is named at every call site, because a default is how the
/// next dimension inherits the wrong matcher silently — the original F40 defect.
/// handlers/resources -> .path; operations/peers -> .id. The per-link granter frames
/// are meaningless on the .id arm (an id pattern is never canonicalized) and are simply
/// unread there rather than being a second parameter to get wrong.
fn scopeSubset(arena: std.mem.Allocator, child_peer: []const u8, parent_peer: []const u8, child: Scope, parent: Scope, kind: ScopeKind) Error!bool {
    const frame = struct {
        fn f(a: std.mem.Allocator, peer: []const u8, p: []const u8, k: ScopeKind) Error![]const u8 {
            return switch (k) {
                .path => canonicalize(a, peer, p),
                .id => p,
            };
        }
    }.f;
    // `covers(pattern, value)` — matchesPattern for path-scope, the §3.6 literal
    // matcher for id-scope. matchesPattern already refuses the §5.4 sentinel in
    // EITHER operand (RULE F: the guard is a property of the matcher here, so every
    // path reaching a decision inherits it), and an id pattern never canonicalizes,
    // so the sentinel cannot arise on that arm at all.
    const covers = struct {
        fn f(pattern_side: []const u8, value_side: []const u8, k: ScopeKind) bool {
            return switch (k) {
                .path => matchesPattern(value_side, pattern_side),
                .id => matchesIdPattern(value_side, pattern_side),
            };
        }
    }.f;
    for (child.incl) |cp| {
        const cc = try frame(arena, child_peer, cp, kind);
        var found = false;
        for (parent.incl) |pp| {
            if (covers(try frame(arena, parent_peer, pp, kind), cc, kind)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    for (parent.excl) |pe| {
        const cpe = try frame(arena, parent_peer, pe, kind);
        var found = false;
        for (child.excl) |ce| {
            if (covers(try frame(arena, child_peer, ce, kind), cpe, kind)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn grantSubset(arena: std.mem.Allocator, local_peer: []const u8, child_peer: []const u8, parent_peer: []const u8, child: Grant, parent: Grant) Error!bool {
    // The scope KIND is a property of the DIMENSION, named here, never defaulted
    // (F50 / 0.8.2.16). Only RESOURCES takes the §5.5a per-link granter frames;
    // handlers stays local, and the two id dimensions do not canonicalize at all.
    if (!try scopeSubset(arena, local_peer, local_peer, child.handlers, parent.handlers, .path)) return false;
    if (!try scopeSubset(arena, local_peer, local_peer, child.operations, parent.operations, .id)) return false;
    if (!try scopeSubset(arena, child_peer, parent_peer, child.resources, parent.resources, .path)) return false;
    const cp = child.peers orelse Scope{ .incl = &.{local_peer}, .excl = &.{} };
    const pp = parent.peers orelse Scope{ .incl = &.{local_peer}, .excl = &.{} };
    return scopeSubset(arena, local_peer, local_peer, cp, pp, .id);
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
    return verifyCapabilityChainRootedAt(arena, env, st, local_peer, local_peer, capability);
}

/// `verifyCapabilityChain` with the expected ROOT granter named separately from the
/// verifying peer.
///
/// §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is minted
/// by the TARGET peer, so root-trust is relaxed away from the local peer — and every other
/// clause (per-link signatures, grantee resolution, temporal validity, attenuation,
/// caveats) is unchanged. Parameterized rather than forked because a second copy of a
/// chain walk is a second copy that drifts.
///
/// A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When `root_peer`
/// differs from `local_peer` the quorum arm is REFUSED outright rather than verified:
/// *minted by the target* means the target SOLELY minted it, and a K-of-N root is a
/// GROUP's authority — its co-signers authorized it too. Accepting it would let any one
/// signer's target confer the whole group's grant, which is E3/F66's over-acceptance.
/// §5.5's M6 also requires the LOCAL peer in the signer set, so the quorum arm has no
/// meaning in a foreign frame even on its own terms.
fn verifyCapabilityChainRootedAt(arena: std.mem.Allocator, env: model.Envelope, st: *Store, local_peer: []const u8, root_peer: []const u8, capability: Entity) Error!Verdict {
    const chain = collectChain(arena, env, st, capability) catch |e| switch (e) {
        error.ChainTooDeep, error.ChainUnreachable => return .deny,
        else => |x| return x,
    };
    const root = chain[chain.len - 1];
    // Root authority: a single-sig root must root at `root_peer`; a §3.6 M3 multi-sig root
    // (root-only) must pass k-of-n quorum validation, and only in the LOCAL frame.
    const root_ok = blk: {
        if (try multiGranterOfEntity(arena, root)) |mg| {
            if (!std.mem.eql(u8, root_peer, local_peer)) break :blk false;
            break :blk (try verifyMultiSigRoot(arena, env, st, local_peer, root, mg)) == .allow;
        }
        const gh = root.bytesField("granter") orelse break :blk false;
        const g = resolve(env, st, gh) orelse break :blk false;
        const pk = g.bytesField("public_key") orelse break :blk false;
        const pid = try identity.peerIdOfPubkey(arena, pk);
        break :blk std.mem.eql(u8, pid, root_peer);
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
        // temporal validity.
        //
        // CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
        // created_at is MALFORMED and must be refused outright. This has to run BEFORE
        // the two range checks below, because those use `uintField`, which cannot tell
        // "absent" from "present but not a u64" — so on its own it would skip the check
        // and honor the token (fail-open).
        if (!temporalFieldsRepresentable(current)) return .deny;
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

// ── RULE B / RULE E / RULE A unit surface ────────────────────────────────────
//
// These drive the three §5 primitives directly rather than through the wire, which is
// what lets each one carry its own ACCEPT case. arc-probe measures the same rules end
// to end; a probe row and a unit assertion answer different questions and neither
// substitutes for the other.

test "§5.4 sentinel is scoped to PATH-SCOPE (0.8.2.24 N2/N3)" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    // The DEFECT the scoping removes. `*/apply` is an ordinary namespaced OPERATION
    // name; it path-canonicalizes to the sentinel, and under the unconditional guard
    // this whole dimension denied — over-denial, invisible on well-formed grants.
    const ops = Scope{ .incl = &.{"*"}, .excl = &.{"*/apply"} };
    try testing.expect(try matchesScope(a, "peerX", "get", ops, .id));
    // ... and the id-scope exclude still EXCLUDES its own literal, which is the control
    // that says the dimension is being evaluated rather than waved through.
    try testing.expect(!try matchesScope(a, "peerX", "*/apply", ops, .id));

    // PATH-SCOPE keeps the guard: an unmatchable exclude there denies everything
    // (0.8.2.21), because a path exclude that carves out nothing is a grant silently
    // wider than its author wrote.
    const res = Scope{ .incl = &.{"*"}, .excl = &.{"../nope"} };
    try testing.expect(!try matchesScope(a, "peerX", "app/q", res, .path));
    // Control: the same dimension with a MATCHABLE exclude still grants elsewhere.
    const res_ok = Scope{ .incl = &.{"*"}, .excl = &.{"app/secret"} };
    try testing.expect(try matchesScope(a, "peerX", "app/q", res_ok, .path));
    try testing.expect(!try matchesScope(a, "peerX", "app/secret", res_ok, .path));
}

test "scope_subset is typed by scope kind (F50, 0.8.2.16)" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    // THE INCLUDE PAIR THAT DISAGREES. Child operations include `*/apply`, parent `*`.
    // Under §3.6's literal matcher `*` covers it and the child is a subset. Under the
    // canonicalizing reading `*/apply` becomes the sentinel, matches nothing, and the
    // pair is refused — fail-CLOSED, which is why no hand-tried example found it.
    const child_ops = Scope{ .incl = &.{"*/apply"}, .excl = &.{} };
    const parent_ops = Scope{ .incl = &.{"*"}, .excl = &.{} };
    try testing.expect(try scopeSubset(a, "peerX", "peerX", child_ops, parent_ops, .id));

    // THE EXCLUDE PAIR. A parent exclude must be INHERITED by some child exclude; under
    // the canonicalizing reading an unmatchable exclude is not even inherited by an
    // identical copy of itself, so a scope stops being a subset of ITSELF.
    const both = Scope{ .incl = &.{"*"}, .excl = &.{"*/apply"} };
    try testing.expect(try scopeSubset(a, "peerX", "peerX", both, both, .id));

    // THE CONTROL, and it is what makes the two above measurements rather than a claim
    // that the function says yes: a genuinely WIDER child is still refused on the id
    // arm. `*` is not covered by the literal `get`.
    const wider = Scope{ .incl = &.{"*"}, .excl = &.{} };
    const narrow = Scope{ .incl = &.{"get"}, .excl = &.{} };
    try testing.expect(!try scopeSubset(a, "peerX", "peerX", wider, narrow, .id));

    // And the PATH arm is unchanged — it must still canonicalize, or §5.5a's per-link
    // granter frames stop working.
    const cpath = Scope{ .incl = &.{"app/q"}, .excl = &.{} };
    const ppath = Scope{ .incl = &.{"app/*"}, .excl = &.{} };
    try testing.expect(try scopeSubset(a, "peerX", "peerX", cpath, ppath, .path));
    try testing.expect(!try scopeSubset(a, "peerX", "peerX", ppath, cpath, .path));
}

/// A capability token carrying exactly one grant, for the two tests below. Arena-owned.
fn mkTokenOneGrant(
    a: std.mem.Allocator,
    handlers: []const u8,
    operations: []const u8,
    res_incl: []const []const u8,
    res_excl: []const []const u8,
) Error!Entity {
    const lst = struct {
        fn f(al: std.mem.Allocator, items: []const []const u8) Error!Value {
            const arr = try al.alloc(Value, items.len);
            for (items, 0..) |s, i| arr[i] = try model.textVal(al, s);
            return .{ .array = arr };
        }
    }.f;
    const sc = struct {
        fn f(al: std.mem.Allocator, incl: []const []const u8, excl: []const []const u8) Error!Value {
            var pr = try al.alloc(Value.Pair, 2);
            pr[0] = .{ .key = try model.textVal(al, "exclude"), .value = try lst(al, excl) };
            pr[1] = .{ .key = try model.textVal(al, "include"), .value = try lst(al, incl) };
            return .{ .map = pr };
        }
    }.f;
    var g = try a.alloc(Value.Pair, 3);
    g[0] = .{ .key = try model.textVal(a, "handlers"), .value = try sc(a, &.{handlers}, &.{}) };
    g[1] = .{ .key = try model.textVal(a, "operations"), .value = try sc(a, &.{operations}, &.{}) };
    g[2] = .{ .key = try model.textVal(a, "resources"), .value = try sc(a, res_incl, res_excl) };
    const grants = try a.alloc(Value, 1);
    grants[0] = .{ .map = g };
    var top = try a.alloc(Value.Pair, 1);
    top[0] = .{ .key = try model.textVal(a, "grants"), .value = .{ .array = grants } };
    return Entity.make(a, "system/capability/token", .{ .map = top });
}

test "§6.3 check_path_permission: three dimensions, local frame, empty include denies" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    const lp = "peerX";

    // THE ACCEPT CASE, AND IT IS THE ONE THAT VALIDATES THE FIXTURE. A predicate test
    // built only from deny cases is indistinguishable from one asserting false == false
    // — a fixture that parses to an empty scope denies everything and every deny case
    // passes for free.
    const tok = try mkTokenOneGrant(a, "system/tree", "*", &.{"app/*"}, &.{"app/secret"});
    try testing.expect(try checkPathPermission(a, lp, "get", "/peerX/app/q", tok, "system/tree"));

    // One deny per DIMENSION, because a single deny cannot distinguish "the predicate
    // checks the dimension I care about" from "the predicate denies".
    try testing.expect(!try checkPathPermission(a, lp, "get", "/peerX/app/secret", tok, "system/tree")); // resources exclude
    try testing.expect(!try checkPathPermission(a, lp, "get", "/peerX/other/q", tok, "system/tree")); // resources include
    try testing.expect(!try checkPathPermission(a, lp, "get", "/peerX/app/q", tok, "system/handler")); // handlers
    const ops_only = try mkTokenOneGrant(a, "system/tree", "put", &.{"app/*"}, &.{});
    try testing.expect(!try checkPathPermission(a, lp, "get", "/peerX/app/q", ops_only, "system/tree")); // operations

    // An empty `resources.include` is a legal grant shape (§5.2) and DENIES every path.
    const empty_res = try mkTokenOneGrant(a, "system/tree", "*", &.{}, &.{});
    try testing.expect(!try checkPathPermission(a, lp, "get", "/peerX/app/q", empty_res, "system/tree"));

    // A malformed path canonicalizes to the sentinel, which matches no grant — so it
    // falls through to DENY rather than being matched against anything.
    try testing.expect(!try checkPathPermission(a, lp, "get", "../escape", tok, "system/tree"));
}

test "§5.2 effective_targets: the two empties are distinguishable (0.8.2.25 N11)" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    const lp = "peerX";

    const mkexec = struct {
        fn f(al: std.mem.Allocator, resource: ?Value) Error!Entity {
            var pairs: std.ArrayList(Value.Pair) = .empty;
            try pairs.append(al, .{ .key = try model.textVal(al, "operation"), .value = try model.textVal(al, "get") });
            if (resource) |r| try pairs.append(al, .{ .key = try model.textVal(al, "resource"), .value = r });
            return Entity.make(al, "system/protocol/execute", .{ .map = try pairs.toOwnedSlice(al) });
        }
    }.f;
    const resmap = struct {
        fn f(al: std.mem.Allocator, targets: ?[]const []const u8, excl: ?[]const []const u8) Error!Value {
            var pairs: std.ArrayList(Value.Pair) = .empty;
            if (excl) |xs| {
                const arr = try al.alloc(Value, xs.len);
                for (xs, 0..) |s, i| arr[i] = try model.textVal(al, s);
                try pairs.append(al, .{ .key = try model.textVal(al, "exclude"), .value = .{ .array = arr } });
            }
            if (targets) |ts| {
                const arr = try al.alloc(Value, ts.len);
                for (ts, 0..) |s, i| arr[i] = try model.textVal(al, s);
                try pairs.append(al, .{ .key = try model.textVal(al, "targets"), .value = .{ .array = arr } });
            }
            return .{ .map = try pairs.toOwnedSlice(al) };
        }
    }.f;

    // ABSENT: no `resource` at all.
    const e0 = try effectiveTargets(a, lp, try mkexec(a, null));
    try testing.expect(!e0.had_resource);

    // PRESENT with survivors — the accept case, and the only one that says the exclude
    // loop is being run rather than short-circuited.
    const e1 = try effectiveTargets(a, lp, try mkexec(a, try resmap(a, &.{ "app/qA", "app/qB" }, &.{"app/qA"})));
    try testing.expect(e1.had_resource);
    try testing.expectEqual(@as(usize, 1), e1.survivors.len);
    // RAW survivor, not canonicalized (0.8.2.21).
    try testing.expectEqualStrings("app/qB", e1.survivors[0]);

    // PRESENT and SELF-EXCLUDED: every target carved out. This is the cell N11 is about
    // — a projection returning only a list collapses it into the absent case above, and
    // the handler's refusal arm becomes dead code.
    const e2 = try effectiveTargets(a, lp, try mkexec(a, try resmap(a, &.{"app/qA"}, &.{"app/qA"})));
    try testing.expect(e2.had_resource);
    try testing.expectEqual(@as(usize, 0), e2.survivors.len);

    // A `resource` map with NO `targets` key is ABSENT. (This case ran GREEN against
    // the pre-change peer on both vanguards — an inert control — so it is asserted
    // rather than assumed.)
    const e3 = try effectiveTargets(a, lp, try mkexec(a, try resmap(a, null, &.{"app/qA"})));
    try testing.expect(!e3.had_resource);

    // A PRESENT-BUT-ILL-TYPED `targets` is PRESENT, never absent: answering the absent
    // case here would be WIDER than the request, which §3.3 forbids.
    var illpairs = try a.alloc(Value.Pair, 1);
    illpairs[0] = .{ .key = try model.textVal(a, "targets"), .value = .{ .uint = 42 } };
    const e4 = try effectiveTargets(a, lp, try mkexec(a, .{ .map = illpairs }));
    try testing.expect(e4.had_resource);
    try testing.expectEqual(@as(usize, 0), e4.survivors.len);

    // The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4): the target
    // SURVIVES. The opposite of the grant arm, deliberately.
    const e5 = try effectiveTargets(a, lp, try mkexec(a, try resmap(a, &.{"app/qA"}, &.{"../nope"})));
    try testing.expect(e5.had_resource);
    try testing.expectEqual(@as(usize, 1), e5.survivors.len);
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


// ── §1.4 PD-2: outbound sub-dispatch authorization ───────────────────────────

/// Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
///
/// §1.4 admits three spellings of one address — `system/tree`, `/{peer}/system/tree` and
/// `entity://{peer}/system/tree` — and §1.4's PD-2 block requires Dimension 1's handler
/// pattern to be the target uri's peer-relative path, because a grant names HANDLERS and
/// a handler pattern never carries a peer segment. Matching a grant against the absolute
/// or schemed form matches nothing, silently, which reads at the wire as an authority
/// refusal.
///
/// The first segment is dropped ONLY when it is a peer_id. A peer-relative
/// `system/protocol/connect` must not lose `system` — the standing defect on `smalltalk`
/// and `forth`, where an unconditional strip made every self-minted grant unusable while
/// the handshake stayed green.
pub fn peerRelativeOf(arena: std.mem.Allocator, uri: []const u8) Error![]const u8 {
    const p = try normalizeUri(arena, uri);
    if (p.len == 0 or p[0] != '/') return p;
    const body = p[1..];
    const slash = std.mem.indexOfScalar(u8, body, '/');
    const first = if (slash) |i| body[0..i] else body;
    if (isPeerId(first)) return if (slash) |i| body[i + 1 ..] else "";
    return body;
}

/// Store key of a handler's OWN grant (§6.8: `system/capability/grants/{pattern}`),
/// tolerant of the pattern arriving absolute or peer-relative.
///
/// §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while
/// the grant path is built from the PEER-RELATIVE one. The two are one segment apart and
/// concatenating the wrong one yields a doubled peer segment whose lookup misses — which
/// fails closed as "no handler grant" and is indistinguishable, at the wire, from a
/// genuine authority refusal.
pub fn grantPathFor(arena: std.mem.Allocator, local_peer: []const u8, pattern: []const u8) Error![]const u8 {
    const prefix = try std.fmt.allocPrint(arena, "/{s}/", .{local_peer});
    const rel = if (startsWith(pattern, prefix)) pattern[prefix.len..] else pattern;
    return std.fmt.allocPrint(arena, "/{s}/system/capability/grants/{s}", .{ local_peer, rel });
}

/// Verify a presented reentry credential against §1.4's clauses. Answers the `peers`
/// scope Dimension 4 relaxes to, wrapped so that a credential which VERIFIES but carries
/// NO `peers` dimension is distinguishable from one that relaxes nothing.
///
/// THE OPTIONAL-OF-OPTIONAL IS THE POINT. An absent `peers` on the credential relaxes to
/// the TARGET — the ordinary reentry shape, "you may dispatch back to me" — so a plain
/// `?Scope` would collapse that legitimate result into "no relaxation", which is the
/// absent-vs-present conflation §6.2's CAP-6a records for temporal accessors, one layer
/// up and in the direction that REFUSES a valid reentry.
///
/// Every clause is required and failing any relaxes nothing: the chain ROOT granter
/// resolves to the TARGET peer and is NOT a multi-signature root; the LEAF grantee is the
/// local peer; the chain is valid and not revoked.
fn targetMintedPeersRelaxation(arena: std.mem.Allocator, env: model.Envelope, st: *Store, local_peer: []const u8, target_peer: []const u8, cred: Entity) Error!??Scope {
    // Nothing to relax — the default already covers this peer.
    if (std.mem.eql(u8, target_peer, local_peer)) return null;
    const v = verifyCapabilityChainRootedAt(arena, env, st, local_peer, target_peer, cred) catch |e| switch (e) {
        // An unresolvable grantee inside the credential belongs to SOMEBODY ELSE'S chain:
        // it must relax nothing, not turn the sub-dispatch into a 401 about a token the
        // caller presented in params.
        error.UnresolvableGrantee => return null,
        else => |x| return x,
    };
    if (v != .allow) return null;
    if (try isRevoked(arena, env, st, local_peer, cred)) return null;
    const gh = cred.bytesField("grantee") orelse return null;
    const ge = resolve(env, st, gh) orelse return null;
    const pk = ge.bytesField("public_key") orelse return null;
    const pid = try identity.peerIdOfPubkey(arena, pk);
    if (!std.mem.eql(u8, pid, local_peer)) return null;
    const gs = try grantsOfToken(arena, cred);
    if (gs.len == 0) return null;
    return gs[0].peers;   // null INSIDE the outer optional => the target itself
}

/// §1.4's PD-2 gate: `check_permission` run before a locally-originated sub-dispatch
/// LEAVES the peer, with all four dimensions applied.
///
/// ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT decides
/// all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's pattern
/// the target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE TARGET PEER
/// naming this peer as `grantee` relaxes Dimension 4 (`peers`) AND ONLY DIMENSION 4.
///
/// *"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT a
/// grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
/// sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
/// BYPASS it is distinguished from is a peer that treats the credential as a standalone
/// authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
/// obvious vectors agree under either reading, so the only input that separates them is a
/// VALID credential presented to a handler whose own grant does NOT cover the request.
///
/// `cred == null` is the ambient arm: Dimension 4 is decided by the handler's grant alone.
pub fn checkOutboundSubDispatch(arena: std.mem.Allocator, env: model.Envelope, st: *Store, local_peer: []const u8, target_peer: []const u8, handler_pattern: []const u8, operation: []const u8, handler_grant: Entity, resource: Value, cred: ?Entity) Error!bool {
    // Computed FIRST and consulted LAST, so no credential can stand in for 1-3.
    const relax: ??Scope = if (cred) |c|
        try targetMintedPeersRelaxation(arena, env, st, local_peer, target_peer, c)
    else
        null;
    for (try grantsOfToken(arena, handler_grant)) |g| {
        if (!try matchesScope(arena, local_peer, handler_pattern, g.handlers, .path)) continue;
        if (!try matchesScope(arena, local_peer, operation, g.operations, .id)) continue;
        if (!try checkResourceScope(arena, local_peer, local_peer, resource, g.resources)) continue;
        // Dimension 4. §5.2's default for an absent `peers` scope is
        // {include: [local_peer_id]}, so a foreign target fails unless this grant names it
        // or a target-minted credential relaxes it.
        const peers = g.peers orelse Scope{ .incl = &.{local_peer}, .excl = &.{} };
        if (try matchesScope(arena, local_peer, target_peer, peers, .id)) return true;
        if (relax) |maybe_scope| {
            if (maybe_scope) |rs| {
                if (try matchesScope(arena, local_peer, target_peer, rs, .id)) return true;
            } else {
                return true;   // absent `peers` on the credential relaxes to the granter
            }
        }
    }
    return false;
}
