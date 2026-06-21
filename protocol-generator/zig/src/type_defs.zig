//! Core type floor (V7 §9.5) — render-from-model (S4, A-ZIG-008 resolved).
//!
//! The peer publishes its 53 core `system/type/<name>` entities at
//! `/{peer}/system/type/{name}`. Each type's data is rendered NATIVELY from an
//! in-code declaration (the single source of truth — the FSpec/TypeDef builder
//! below) through the byte-green S2 codec; the resulting content_hash is
//! byte-identical to the Go-rendered `type-registry-vectors-v1.cbor` set (the S8
//! drift target). This is the render-from-model design every peer follows
//! (memory: type-registry-render-design; mirrors C# CoreTypeRegistry / TS
//! core-type-registry.ts / OCaml type_defs_data.ml).
//!
//! Scope is core + operational + type-system bootstrap ONLY — the 53 types of
//! `status/S4-TYPE-SCOPE.txt`. Extension vocabularies (compute/*, content/*,
//! subscription/*, …) are NOT published by a core peer (refined G4 / F17). The
//! oracle's type_system category matches the 53 floor as a hard FAIL gate and
//! WARNs (matched-if-present) on the non-floor types it also probes.
//!
//! Omit-empty semantics: an absent/false/zero field drops the key, so the
//! rendered ECF map is byte-identical to the Go reference encoder. The codec
//! sorts map keys canonically (RFC 8949 §4.2.1), so declaration order here is
//! irrelevant to the bytes — only the present key/value set matters.

const std = @import("std");
const model = @import("model.zig");
const Store = @import("store.zig").Store;
const Entity = model.Entity;
const Value = model.Value;

// ── FSpec — a field spec inside a TypeDef (system/type/field-spec shape) ──────
//
// Exactly one structural carrier is set: a type_ref, an array_of, a map_of, or
// a union_of. Rendered omit-empty into the field-spec ECF map.

const FSpec = struct {
    type_ref: ?[]const u8 = null,
    optional: bool = false,
    array_of: ?*const FSpec = null,
    map_of: ?*const FSpec = null,
    union_of: ?[]const FSpec = null,
    key_type: ?[]const u8 = null,
    byte_size: ?u64 = null,

    fn ref(type_ref: []const u8) FSpec {
        return .{ .type_ref = type_ref };
    }

    /// Render this spec to an ECF data map (omit-empty). Arena-allocated.
    fn toData(self: FSpec, a: std.mem.Allocator) !Value {
        var list: std.ArrayList(Value.Pair) = .empty;
        if (self.type_ref) |t| try list.append(a, .{ .key = try model.textVal(a, "type_ref"), .value = try model.textVal(a, t) });
        if (self.optional) try list.append(a, .{ .key = try model.textVal(a, "optional"), .value = .{ .boolean = true } });
        if (self.array_of) |inner| try list.append(a, .{ .key = try model.textVal(a, "array_of"), .value = try inner.toData(a) });
        if (self.map_of) |inner| try list.append(a, .{ .key = try model.textVal(a, "map_of"), .value = try inner.toData(a) });
        if (self.union_of) |variants| {
            const items = try a.alloc(Value, variants.len);
            for (variants, 0..) |v, i| items[i] = try v.toData(a);
            try list.append(a, .{ .key = try model.textVal(a, "union_of"), .value = .{ .array = items } });
        }
        if (self.key_type) |kt| try list.append(a, .{ .key = try model.textVal(a, "key_type"), .value = try model.textVal(a, kt) });
        if (self.byte_size) |bs| try list.append(a, .{ .key = try model.textVal(a, "byte_size"), .value = .{ .uint = bs } });
        return .{ .map = try list.toOwnedSlice(a) };
    }
};

fn fref(type_ref: []const u8) FSpec {
    return FSpec.ref(type_ref);
}
fn opt(s: FSpec) FSpec {
    var c = s;
    c.optional = true;
    return c;
}
fn sized(s: FSpec, n: u64) FSpec {
    var c = s;
    c.byte_size = n;
    return c;
}
fn farray(elem: *const FSpec) FSpec {
    return .{ .array_of = elem };
}
fn fmap(value: *const FSpec, key_type: ?[]const u8) FSpec {
    return .{ .map_of = value, .key_type = key_type };
}

// ── TypeDef — a core type definition (system/type entity data) ────────────────

const Field = struct { key: []const u8, spec: FSpec };

const TypeDef = struct {
    name: []const u8,
    extends: ?[]const u8 = null,
    fields: []const Field = &.{},
    layout: []const []const u8 = &.{},

    /// Render the `system/type` data map (omit-empty), declaration order of fields
    /// preserved within the `fields` sub-map (the codec re-sorts keys canonically).
    fn toData(self: TypeDef, a: std.mem.Allocator) !Value {
        var list: std.ArrayList(Value.Pair) = .empty;
        try list.append(a, .{ .key = try model.textVal(a, "name"), .value = try model.textVal(a, self.name) });
        if (self.extends) |e| try list.append(a, .{ .key = try model.textVal(a, "extends"), .value = try model.textVal(a, e) });
        if (self.fields.len > 0) {
            const pairs = try a.alloc(Value.Pair, self.fields.len);
            for (self.fields, 0..) |f, i| {
                pairs[i] = .{ .key = try model.textVal(a, f.key), .value = try f.spec.toData(a) };
            }
            try list.append(a, .{ .key = try model.textVal(a, "fields"), .value = .{ .map = pairs } });
        }
        if (self.layout.len > 0) {
            const items = try a.alloc(Value, self.layout.len);
            for (self.layout, 0..) |s, i| items[i] = try model.textVal(a, s);
            try list.append(a, .{ .key = try model.textVal(a, "layout"), .value = .{ .array = items } });
        }
        return .{ .map = try list.toOwnedSlice(a) };
    }

    fn toEntity(self: TypeDef, a: std.mem.Allocator) !Entity {
        return Entity.make(a, "system/type", try self.toData(a));
    }
};

// Helpers to build &const FSpec for nested array_of/map_of/union_of carriers.
// These live in a comptime-evaluated registry so pointers are stable.

fn field(comptime key: []const u8, comptime spec: FSpec) Field {
    return .{ .key = key, .spec = spec };
}

// ── the 53 core type definitions ──────────────────────────────────────────────
//
// Faithful port of the cross-blessed C#/TS/OCaml registry (byte-identical to the
// Go oracle). Nested specs use comptime const pointers (stable addresses).

// reused nested specs
const sp_string = FSpec.ref("primitive/string");
const sp_any = FSpec.ref("primitive/any");
const sp_bytes = FSpec.ref("primitive/bytes");
const sp_uint = FSpec.ref("primitive/uint");
const sp_hash = FSpec.ref("system/hash");
const sp_core_entity = FSpec.ref("core/entity");
const sp_tree_path = FSpec.ref("system/tree/path");
const sp_type_name = FSpec.ref("system/type/name");
const sp_grant_entry = FSpec.ref("system/capability/grant-entry");
const sp_field_spec = FSpec.ref("system/type/field-spec");
const sp_op_spec = FSpec.ref("system/handler/operation-spec");
const sp_listing_entry = FSpec.ref("system/tree/listing-entry");
const sp_type = FSpec.ref("system/type");
const sp_multi_granter = FSpec.ref("system/capability/multi-granter");

fn def(comptime name: []const u8) TypeDef {
    return .{ .name = name };
}

const all_types = blk: {
    @setEvalBranchQuota(20000);
    break :blk [_]TypeDef{
        // primitives (8)
        .{ .name = "primitive/any" },
        .{ .name = "primitive/bool" },
        .{ .name = "primitive/bytes" },
        .{ .name = "primitive/float" },
        .{ .name = "primitive/int" },
        .{ .name = "primitive/null" },
        .{ .name = "primitive/string" },
        .{ .name = "primitive/uint" },

        // structural roots + envelopes (5)
        .{ .name = "entity", .fields = &.{
            field("type", fref("primitive/string")),
            field("data", fref("primitive/any")),
        } },
        .{ .name = "core/entity", .fields = &.{
            field("type", fref("primitive/string")),
            field("data", fref("primitive/any")),
            field("content_hash", fref("system/hash")),
        } },
        .{ .name = "core/envelope", .fields = &.{
            field("root", fref("core/entity")),
            field("included", opt(fmap(&sp_core_entity, "system/hash"))),
        } },
        .{ .name = "system/envelope", .extends = "core/envelope" },
        .{ .name = "system/protocol/envelope", .extends = "core/envelope" },

        // identity / hash / signature (4)
        .{ .name = "system/hash", .extends = "primitive/bytes", .fields = &.{
            field("format_code", sized(fref("primitive/uint"), 1)),
            field("digest", fref("primitive/bytes")),
        }, .layout = &.{ "format_code", "digest" } },
        .{ .name = "system/peer", .fields = &.{
            field("key_type", fref("primitive/string")),
            field("peer_id", fref("system/peer-id")),
            field("public_key", fref("primitive/bytes")),
        } },
        .{ .name = "system/peer-id", .extends = "primitive/string" },
        .{ .name = "system/signature", .fields = &.{
            field("algorithm", fref("primitive/string")),
            field("signature", fref("primitive/bytes")),
            field("signer", fref("system/hash")),
            field("target", fref("system/hash")),
        } },

        // protocol surface (6)
        .{ .name = "system/protocol/connect/authenticate", .fields = &.{
            field("key_type", fref("primitive/string")),
            field("nonce", fref("primitive/bytes")),
            field("peer_id", fref("system/peer-id")),
            field("public_key", fref("primitive/bytes")),
        } },
        .{ .name = "system/protocol/connect/hello", .fields = &.{
            field("protocols", farray(&sp_string)),
            field("nonce", fref("primitive/bytes")),
            field("peer_id", fref("system/peer-id")),
            field("timestamp", fref("primitive/uint")),
            field("compression", opt(farray(&sp_string))),
            field("encryption", opt(farray(&sp_string))),
            field("hash_formats", opt(farray(&sp_string))),
            field("key_types", opt(farray(&sp_string))),
        } },
        .{ .name = "system/protocol/error", .fields = &.{
            field("code", fref("primitive/string")),
            field("message", opt(fref("primitive/string"))),
            field("rejected_marker", opt(fref("system/hash"))),
        } },
        .{ .name = "system/protocol/execute", .fields = &.{
            field("operation", fref("primitive/string")),
            field("params", fref("core/entity")),
            field("request_id", fref("primitive/string")),
            field("uri", fref("system/tree/path")),
            field("author", opt(fref("system/hash"))),
            field("bounds", opt(fref("system/bounds"))),
            field("capability", opt(fref("system/hash"))),
            field("deliver_to", opt(fref("system/delivery-spec"))),
            field("deliver_token", opt(fref("system/hash"))),
            field("durability_request", opt(fref("system/durability-request"))),
            field("resource", opt(fref("system/protocol/resource-target"))),
        } },
        .{ .name = "system/protocol/execute/response", .fields = &.{
            field("request_id", fref("primitive/string")),
            field("result", fref("core/entity")),
            field("status", fref("primitive/uint")),
            field("durability", opt(fref("system/durability-result"))),
        } },
        .{ .name = "system/protocol/resource-target", .fields = &.{
            field("targets", farray(&sp_tree_path)),
            field("exclude", opt(farray(&sp_tree_path))),
        } },

        // capability (12)
        .{ .name = "system/capability/grant", .fields = &.{
            field("token", fref("system/hash")),
        } },
        .{ .name = "system/capability/grant-entry", .fields = &.{
            field("handlers", fref("system/capability/path-scope")),
            field("operations", fref("system/capability/id-scope")),
            field("resources", fref("system/capability/path-scope")),
            field("allowances", opt(fmap(&sp_any, null))),
            field("constraints", opt(fmap(&sp_any, null))),
            field("peers", opt(fref("system/capability/id-scope"))),
        } },
        .{ .name = "system/capability/id-scope", .fields = &.{
            field("include", farray(&sp_string)),
            field("exclude", opt(farray(&sp_string))),
        } },
        .{ .name = "system/capability/path-scope", .fields = &.{
            field("include", farray(&sp_tree_path)),
            field("exclude", opt(farray(&sp_tree_path))),
        } },
        .{ .name = "system/capability/request", .fields = &.{
            field("grants", farray(&sp_grant_entry)),
            field("ttl_ms", opt(fref("primitive/uint"))),
        } },
        .{ .name = "system/capability/revocation", .fields = &.{
            field("token", fref("system/hash")),
            field("revoked_at", fref("primitive/uint")),
            field("reason", opt(fref("primitive/string"))),
        } },
        .{ .name = "system/capability/revoke-request", .fields = &.{
            field("token", fref("system/hash")),
            field("reason", opt(fref("primitive/string"))),
        } },
        .{ .name = "system/capability/delegate-request", .fields = &.{
            field("grants", farray(&sp_grant_entry)),
            field("parent", fref("system/hash")),
            field("ttl_ms", opt(fref("primitive/uint"))),
        } },
        .{ .name = "system/capability/delegation-caveats", .fields = &.{
            field("max_delegation_depth", opt(fref("primitive/uint"))),
            field("max_delegation_ttl", opt(fref("primitive/uint"))),
            field("no_delegation", opt(fref("primitive/bool"))),
        } },
        .{ .name = "system/capability/policy-entry", .fields = &.{
            field("grants", farray(&sp_grant_entry)),
            field("peer_pattern", fref("primitive/string")),
            field("notes", opt(fref("primitive/string"))),
            field("ttl_ms", opt(fref("primitive/uint"))),
        } },
        .{ .name = "system/capability/token", .fields = &.{
            field("created_at", fref("primitive/uint")),
            field("grantee", fref("system/hash")),
            field("granter", .{ .union_of = &.{ sp_hash, sp_multi_granter } }),
            field("grants", farray(&sp_grant_entry)),
            field("delegation_caveats", opt(fref("system/capability/delegation-caveats"))),
            field("expires_at", opt(fref("primitive/uint"))),
            field("not_before", opt(fref("primitive/uint"))),
            field("parent", opt(fref("system/hash"))),
            field("resource_limits", opt(fref("system/resource-limits"))),
        } },
        .{ .name = "system/capability/multi-granter", .fields = &.{
            field("signers", farray(&sp_hash)),
            field("threshold", fref("primitive/uint")),
        } },

        // handler machinery (6)
        .{ .name = "system/handler", .fields = &.{
            field("interface", fref("system/tree/path")),
            field("expression_path", opt(fref("system/tree/path"))),
            field("internal_scope", opt(farray(&sp_grant_entry))),
            field("max_scope", opt(farray(&sp_grant_entry))),
        } },
        .{ .name = "system/handler/interface", .fields = &.{
            field("name", fref("primitive/string")),
            field("operations", fmap(&sp_op_spec, null)),
            field("pattern", fref("system/tree/path")),
        } },
        .{ .name = "system/handler/manifest", .extends = "system/handler/interface", .fields = &.{
            field("name", fref("primitive/string")),
            field("operations", fmap(&sp_op_spec, null)),
            field("pattern", fref("system/tree/path")),
            field("expression_path", opt(fref("system/tree/path"))),
            field("internal_scope", opt(farray(&sp_grant_entry))),
            field("max_scope", opt(farray(&sp_grant_entry))),
        } },
        .{ .name = "system/handler/operation-spec", .fields = &.{
            field("input_type", opt(fref("system/type/name"))),
            field("output_type", opt(fref("system/type/name"))),
        } },
        .{ .name = "system/handler/register-request", .fields = &.{
            field("manifest", fref("system/handler/manifest")),
            field("requested_scope", opt(farray(&sp_grant_entry))),
            field("types", opt(fmap(&sp_type, null))),
        } },
        .{ .name = "system/handler/register-result", .fields = &.{
            field("grant", fref("system/capability/token")),
            field("pattern", fref("system/tree/path")),
        } },

        // tree (5)
        .{ .name = "system/tree/get-request", .fields = &.{
            field("limit", opt(fref("primitive/uint"))),
            field("mode", opt(fref("primitive/string"))),
            field("offset", opt(fref("primitive/uint"))),
            field("tree_id", opt(fref("primitive/string"))),
        } },
        .{ .name = "system/tree/put-request", .fields = &.{
            field("entity", opt(fref("core/entity"))),
            field("expected_hash", opt(fref("system/hash"))),
            field("tree_id", opt(fref("primitive/string"))),
        } },
        .{ .name = "system/tree/listing", .fields = &.{
            field("count", fref("primitive/uint")),
            field("entries", fmap(&sp_listing_entry, null)),
            field("offset", fref("primitive/uint")),
            field("path", fref("system/tree/path")),
            field("next_page", opt(fref("system/hash"))),
        } },
        .{ .name = "system/tree/listing-entry", .fields = &.{
            field("has_children", fref("primitive/bool")),
            field("hash", opt(fref("system/hash"))),
        } },
        .{ .name = "system/tree/path", .extends = "primitive/string" },

        // type-system bootstrap (3)
        .{ .name = "system/type", .fields = &.{
            field("name", fref("system/type/name")),
            field("extends", opt(fref("system/type/name"))),
            field("fields", opt(fmap(&sp_field_spec, null))),
            field("layout", opt(farray(&sp_string))),
            field("type_args", opt(fmap(&sp_type_name, null))),
            field("type_params", opt(farray(&sp_string))),
        } },
        .{ .name = "system/type/field-spec", .fields = &.{
            field("type_ref", opt(fref("system/type/name"))),
            field("optional", opt(fref("primitive/bool"))),
            field("array_of", opt(fref("system/type/field-spec"))),
            field("map_of", opt(fref("system/type/field-spec"))),
            field("union_of", opt(farray(&sp_field_spec))),
            field("key_type", opt(fref("system/type/name"))),
            field("byte_size", opt(fref("primitive/uint"))),
            field("type_param", opt(fref("primitive/string"))),
            field("type_args", opt(fmap(&sp_type_name, null))),
            field("default", opt(fref("primitive/any"))),
            field("constraints", opt(farray(&sp_core_entity))),
        } },
        .{ .name = "system/type/name", .extends = "primitive/string" },

        // operational (4)
        .{ .name = "system/bounds", .fields = &.{
            field("budget", opt(fref("primitive/uint"))),
            field("cascade_depth", opt(fref("primitive/uint"))),
            field("chain_id", opt(fref("primitive/string"))),
            field("parent_chain_id", opt(fref("primitive/string"))),
            field("ttl", opt(fref("primitive/uint"))),
            field("visited", opt(farray(&sp_tree_path))),
        } },
        .{ .name = "system/resource-limits", .fields = &.{
            field("max_budget", opt(fref("primitive/uint"))),
            field("max_ttl", opt(fref("primitive/uint"))),
            field("max_visited_length", opt(fref("primitive/uint"))),
        } },
        .{ .name = "system/delivery-spec", .fields = &.{
            field("operation", fref("primitive/string")),
            field("uri", fref("system/tree/path")),
        } },
        .{ .name = "system/deletion-marker" },
    };
};

/// Number of core types published (53).
pub const core_type_count = all_types.len;

/// Seed every core type entity into the store at `system/type/<name>`. Uses a
/// scratch arena (each entity is duped into the store, scratch freed at end).
pub fn publish(gpa: std.mem.Allocator, st: *Store, local_peer: []const u8) !void {
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();
    for (all_types) |td| {
        const e = try td.toEntity(a);
        const path = try std.fmt.allocPrint(a, "/{s}/system/type/{s}", .{ local_peer, td.name });
        try st.bind(path, e);
    }
}

// ── A-ZIG-008 byte-diff test: every core type's content_hash matches the Go
//    vector set (the S8 drift target). Mirrors TS test/type-registry.test.ts.

const testing = std.testing;

test "A-ZIG-008: 53 core types render byte-identical to the Go vector set" {
    const gpa = testing.allocator;

    // Load the vector file: array of { name, content_hash, ... }.
    const path = "../shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor";
    const file = std.fs.cwd().openFile(path, .{}) catch |e| {
        std.debug.print("skip: cannot open {s}: {}\n", .{ path, e });
        return error.SkipZigTest;
    };
    defer file.close();
    const bytes = try file.readToEndAlloc(gpa, 1 << 24);
    defer gpa.free(bytes);

    const cbor = @import("cbor.zig");
    const fixture = try cbor.decode(gpa, bytes);
    defer fixture.deinit(gpa);
    const vectors = switch (fixture) {
        .array => |arr| arr,
        else => return error.SkipZigTest,
    };

    // name -> 64-char digest hex (after the "ecf-sha256:" prefix).
    var want = std.StringHashMapUnmanaged([]const u8){};
    defer want.deinit(gpa);
    for (vectors) |v| {
        const name = switch (model.mapGet(v, "name") orelse continue) {
            .text => |s| s,
            else => continue,
        };
        const ch = switch (model.mapGet(v, "content_hash") orelse continue) {
            .text => |s| s,
            else => continue,
        };
        const prefix = "ecf-sha256:";
        if (!std.mem.startsWith(u8, ch, prefix)) continue;
        try want.put(gpa, name, ch[prefix.len..]);
    }

    try testing.expect(want.count() >= core_type_count);

    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const a = arena_inst.allocator();

    var mismatches: usize = 0;
    var matched: usize = 0;
    for (all_types) |td| {
        const e = try td.toEntity(a);
        // e.hash is 33 bytes: 0x00 format byte ‖ 32-byte digest. Compare the digest.
        const digest = e.hash[1..];
        const got_hex = try model.hex(a, digest);
        const expect_hex = want.get(td.name) orelse {
            std.debug.print("MISSING from vectors: {s}\n", .{td.name});
            mismatches += 1;
            continue;
        };
        if (std.mem.eql(u8, got_hex, expect_hex)) {
            matched += 1;
        } else {
            std.debug.print("MISMATCH {s}\n    want {s}\n    got  {s}\n", .{ td.name, expect_hex, got_hex });
            mismatches += 1;
        }
    }
    if (mismatches > 0) std.debug.print("type-registry: {d}/{d} byte-identical, {d} mismatch\n", .{ matched, core_type_count, mismatches });
    try testing.expectEqual(@as(usize, 0), mismatches);
    try testing.expectEqual(core_type_count, matched);
}
