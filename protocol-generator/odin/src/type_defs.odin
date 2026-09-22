package entity_core

import "core:mem"
import "core:strings"

// Core type floor (§9.5) — render-from-model. The peer publishes its core
// `system/type/<name>` entities at `/{peer}/system/type/{name}`. Each type's
// data is rendered NATIVELY from an in-code declaration (the single source of
// truth) through the byte-green S2 codec; the resulting content_hash is
// byte-identical to the Go-rendered `type-registry-vectors` set (the drift
// target). Scope is core + operational + type-system bootstrap ONLY — the 53
// floor types (matching the C#/TS/OCaml/Zig cross-blessed registry). Extension
// vocabularies are NOT published by a core peer.
//
// Omit-empty semantics: an absent/false/zero field drops the key, so the rendered
// ECF map is byte-identical to the Go reference encoder. The codec sorts map keys
// canonically, so declaration order is irrelevant to the bytes.
//
// FSpec — a field spec (system/type/field-spec shape). Exactly one structural
// carrier is set: a type_ref, an array_of, a map_of, or a union_of. Rendered
// omit-empty into the field-spec ECF map. Nested carriers are pointers into a
// small static table.

FSpec :: struct {
	type_ref:  string,
	optional:  bool,
	array_of:  ^FSpec,
	map_of:    ^FSpec,
	union_of:  []FSpec,
	key_type:  string,
	byte_size: u64,
}

@(private = "file")
fspec_to_data :: proc(s: FSpec, allocator := context.allocator) -> Ec_Value {
	list := make([dynamic]Ec_Pair, allocator)
	if s.type_ref != "" {
		append(&list, Ec_Pair{text_val("type_ref", allocator), text_val(s.type_ref, allocator)})
	}
	if s.optional {
		append(&list, Ec_Pair{text_val("optional", allocator), Ec_Bool(true)})
	}
	if s.array_of != nil {
		append(&list, Ec_Pair{text_val("array_of", allocator), fspec_to_data(s.array_of^, allocator)})
	}
	if s.map_of != nil {
		append(&list, Ec_Pair{text_val("map_of", allocator), fspec_to_data(s.map_of^, allocator)})
	}
	if s.union_of != nil {
		items := make([]Ec_Value, len(s.union_of), allocator)
		for v, i in s.union_of {
			items[i] = fspec_to_data(v, allocator)
		}
		append(&list, Ec_Pair{text_val("union_of", allocator), Ec_Array(items)})
	}
	if s.key_type != "" {
		append(&list, Ec_Pair{text_val("key_type", allocator), text_val(s.key_type, allocator)})
	}
	if s.byte_size != 0 {
		append(&list, Ec_Pair{text_val("byte_size", allocator), Ec_Uint(s.byte_size)})
	}
	return Ec_Map(list[:])
}

// ── FSpec constructors ────────────────────────────────────────────────────────

@(private = "file")
fref :: proc(t: string) -> FSpec {return FSpec{type_ref = t}}

@(private = "file")
opt :: proc(s: FSpec) -> FSpec {c := s; c.optional = true; return c}

@(private = "file")
sized :: proc(s: FSpec, n: u64) -> FSpec {c := s; c.byte_size = n; return c}

Field :: struct {
	key:  string,
	spec: FSpec,
}

Type_Def :: struct {
	name:    string,
	extends: string,
	fields:  []Field,
	layout:  []string,
}

@(private = "file")
typedef_to_data :: proc(td: Type_Def, allocator := context.allocator) -> Ec_Value {
	list := make([dynamic]Ec_Pair, allocator)
	append(&list, Ec_Pair{text_val("name", allocator), text_val(td.name, allocator)})
	if td.extends != "" {
		append(&list, Ec_Pair{text_val("extends", allocator), text_val(td.extends, allocator)})
	}
	if len(td.fields) > 0 {
		pairs := make([]Ec_Pair, len(td.fields), allocator)
		for f, i in td.fields {
			pairs[i] = Ec_Pair{text_val(f.key, allocator), fspec_to_data(f.spec, allocator)}
		}
		append(&list, Ec_Pair{text_val("fields", allocator), Ec_Map(pairs)})
	}
	if len(td.layout) > 0 {
		items := make([]Ec_Value, len(td.layout), allocator)
		for s, i in td.layout {
			items[i] = text_val(s, allocator)
		}
		append(&list, Ec_Pair{text_val("layout", allocator), Ec_Array(items)})
	}
	return Ec_Map(list[:])
}

// nested spec table — pointers must be stable across the whole run, so these are
// package-level statics (their addresses are taken by array_of/map_of below).
@(private = "file") sp_string := FSpec{type_ref = "primitive/string"}
@(private = "file") sp_any := FSpec{type_ref = "primitive/any"}
@(private = "file") sp_hash := FSpec{type_ref = "system/hash"}
@(private = "file") sp_core_entity := FSpec{type_ref = "core/entity"}
@(private = "file") sp_tree_path := FSpec{type_ref = "system/tree/path"}
@(private = "file") sp_type_name := FSpec{type_ref = "system/type/name"}
@(private = "file") sp_grant_entry := FSpec{type_ref = "system/capability/grant-entry"}
@(private = "file") sp_field_spec := FSpec{type_ref = "system/type/field-spec"}
@(private = "file") sp_op_spec := FSpec{type_ref = "system/handler/operation-spec"}
@(private = "file") sp_listing_entry := FSpec{type_ref = "system/tree/listing-entry"}
@(private = "file") sp_type := FSpec{type_ref = "system/type"}
@(private = "file") sp_multi_granter := FSpec{type_ref = "system/capability/multi-granter"}

@(private = "file")
farray :: proc(elem: ^FSpec) -> FSpec {return FSpec{array_of = elem}}

@(private = "file")
fmap :: proc(value: ^FSpec, key_type: string) -> FSpec {return FSpec{map_of = value, key_type = key_type}}

// Emit_Ctx carries the store + local_peer so each type def is rendered and bound
// IMMEDIATELY within its declaring statement — a Type_Def's `fields`/`layout`
// slice literals are stack-temporaries that dangle if collected into a
// [dynamic] and read later, so we render-and-bind in place.
@(private = "file")
Emit_Ctx :: struct {
	st:         ^Store,
	local_peer: string,
	gpa:        mem.Allocator,
	count:      int,
}

@(private = "file")
emit_type :: proc(ctx: ^Emit_Ctx, td: Type_Def) {
	a := context.temp_allocator
	data := typedef_to_data(td, a)
	e, err := entity_make("system/type", data, a)
	if err != .None {
		return
	}
	path := strings.concatenate({"/", ctx.local_peer, "/system/type/", td.name}, a)
	store_bind(ctx.st, path, e, ctx.gpa)
	ctx.count += 1
}

// core_type_defs renders + binds the 53 core type definitions directly.
@(private = "file")
core_type_defs :: proc(ctx: ^Emit_Ctx) {
	granter_union := make([]FSpec, 2, context.temp_allocator)
	granter_union[0] = sp_hash
	granter_union[1] = sp_multi_granter

	F :: proc(k: string, s: FSpec) -> Field {return Field{key = k, spec = s}}
	add :: proc(ctx: ^Emit_Ctx, td: Type_Def) {emit_type(ctx, td)}

	// primitives (8)
	add(ctx, {name = "primitive/any"})
	add(ctx, {name = "primitive/bool"})
	add(ctx, {name = "primitive/bytes"})
	add(ctx, {name = "primitive/float"})
	add(ctx, {name = "primitive/int"})
	add(ctx, {name = "primitive/null"})
	add(ctx, {name = "primitive/string"})
	add(ctx, {name = "primitive/uint"})

	// structural roots + envelopes (5)
	add(ctx, {name = "entity", fields = {
		F("type", fref("primitive/string")),
		F("data", fref("primitive/any")),
	}})
	add(ctx, {name = "core/entity", fields = {
		F("type", fref("primitive/string")),
		F("data", fref("primitive/any")),
		F("content_hash", fref("system/hash")),
	}})
	add(ctx, {name = "core/envelope", fields = {
		F("root", fref("core/entity")),
		F("included", opt(fmap(&sp_core_entity, "system/hash"))),
	}})
	add(ctx, {name = "system/envelope", extends = "core/envelope"})
	add(ctx, {name = "system/protocol/envelope", extends = "core/envelope"})

	// identity / hash / signature (4)
	add(ctx, {name = "system/hash", extends = "primitive/bytes", fields = {
		F("format_code", sized(fref("primitive/uint"), 1)),
		F("digest", fref("primitive/bytes")),
	}, layout = {"format_code", "digest"}})
	add(ctx, {name = "system/peer", fields = {
		F("key_type", fref("primitive/string")),
		F("peer_id", fref("system/peer-id")),
		F("public_key", fref("primitive/bytes")),
	}})
	add(ctx, {name = "system/peer-id", extends = "primitive/string"})
	add(ctx, {name = "system/signature", fields = {
		F("algorithm", fref("primitive/string")),
		F("signature", fref("primitive/bytes")),
		F("signer", fref("system/hash")),
		F("target", fref("system/hash")),
	}})

	// protocol surface (6)
	add(ctx, {name = "system/protocol/connect/authenticate", fields = {
		F("key_type", fref("primitive/string")),
		F("nonce", fref("primitive/bytes")),
		F("peer_id", fref("system/peer-id")),
		F("public_key", fref("primitive/bytes")),
	}})
	add(ctx, {name = "system/protocol/connect/hello", fields = {
		F("protocols", farray(&sp_string)),
		F("nonce", fref("primitive/bytes")),
		F("peer_id", fref("system/peer-id")),
		F("timestamp", fref("primitive/uint")),
		F("compression", opt(farray(&sp_string))),
		F("encryption", opt(farray(&sp_string))),
		F("hash_formats", opt(farray(&sp_string))),
		F("key_types", opt(farray(&sp_string))),
	}})
	add(ctx, {name = "system/protocol/error", fields = {
		F("code", fref("primitive/string")),
		F("message", opt(fref("primitive/string"))),
		F("rejected_marker", opt(fref("system/hash"))),
	}})
	add(ctx, {name = "system/protocol/execute", fields = {
		F("operation", fref("primitive/string")),
		F("params", fref("core/entity")),
		F("request_id", fref("primitive/string")),
		F("uri", fref("system/tree/path")),
		F("author", opt(fref("system/hash"))),
		F("bounds", opt(fref("system/bounds"))),
		F("capability", opt(fref("system/hash"))),
		F("deliver_to", opt(fref("system/delivery-spec"))),
		F("deliver_token", opt(fref("system/hash"))),
		F("durability_request", opt(fref("system/durability-request"))),
		F("resource", opt(fref("system/protocol/resource-target"))),
	}})
	add(ctx, {name = "system/protocol/execute/response", fields = {
		F("request_id", fref("primitive/string")),
		F("result", fref("core/entity")),
		F("status", fref("primitive/uint")),
		F("durability", opt(fref("system/durability-result"))),
	}})
	add(ctx, {name = "system/protocol/resource-target", fields = {
		F("targets", farray(&sp_tree_path)),
		F("exclude", opt(farray(&sp_tree_path))),
	}})

	// capability (12)
	add(ctx, {name = "system/capability/grant", fields = {
		F("token", fref("system/hash")),
	}})
	add(ctx, {name = "system/capability/grant-entry", fields = {
		F("handlers", fref("system/capability/path-scope")),
		F("operations", fref("system/capability/id-scope")),
		F("resources", fref("system/capability/path-scope")),
		F("allowances", opt(fmap(&sp_any, ""))),
		F("constraints", opt(fmap(&sp_any, ""))),
		F("peers", opt(fref("system/capability/id-scope"))),
	}})
	add(ctx, {name = "system/capability/id-scope", fields = {
		F("include", farray(&sp_string)),
		F("exclude", opt(farray(&sp_string))),
	}})
	add(ctx, {name = "system/capability/path-scope", fields = {
		F("include", farray(&sp_tree_path)),
		F("exclude", opt(farray(&sp_tree_path))),
	}})
	add(ctx, {name = "system/capability/request", fields = {
		F("grants", farray(&sp_grant_entry)),
		F("ttl_ms", opt(fref("primitive/uint"))),
	}})
	add(ctx, {name = "system/capability/revocation", fields = {
		F("token", fref("system/hash")),
		F("revoked_at", fref("primitive/uint")),
		F("reason", opt(fref("primitive/string"))),
	}})
	add(ctx, {name = "system/capability/revoke-request", fields = {
		F("token", fref("system/hash")),
		F("reason", opt(fref("primitive/string"))),
	}})
	add(ctx, {name = "system/capability/delegate-request", fields = {
		F("grants", farray(&sp_grant_entry)),
		F("parent", fref("system/hash")),
		F("ttl_ms", opt(fref("primitive/uint"))),
	}})
	add(ctx, {name = "system/capability/delegation-caveats", fields = {
		F("max_delegation_depth", opt(fref("primitive/uint"))),
		F("max_delegation_ttl", opt(fref("primitive/uint"))),
		F("no_delegation", opt(fref("primitive/bool"))),
	}})
	add(ctx, {name = "system/capability/policy-entry", fields = {
		F("grants", farray(&sp_grant_entry)),
		F("peer_pattern", fref("primitive/string")),
		F("notes", opt(fref("primitive/string"))),
		F("ttl_ms", opt(fref("primitive/uint"))),
	}})
	add(ctx, {name = "system/capability/token", fields = {
		F("created_at", fref("primitive/uint")),
		F("grantee", fref("system/hash")),
		F("granter", FSpec{union_of = granter_union}),
		F("grants", farray(&sp_grant_entry)),
		F("delegation_caveats", opt(fref("system/capability/delegation-caveats"))),
		F("expires_at", opt(fref("primitive/uint"))),
		F("not_before", opt(fref("primitive/uint"))),
		F("parent", opt(fref("system/hash"))),
		F("resource_limits", opt(fref("system/resource-limits"))),
	}})
	add(ctx, {name = "system/capability/multi-granter", fields = {
		F("signers", farray(&sp_hash)),
		F("threshold", fref("primitive/uint")),
	}})

	// handler machinery (6)
	add(ctx, {name = "system/handler", fields = {
		F("interface", fref("system/tree/path")),
		F("expression_path", opt(fref("system/tree/path"))),
		F("internal_scope", opt(farray(&sp_grant_entry))),
		F("max_scope", opt(farray(&sp_grant_entry))),
	}})
	add(ctx, {name = "system/handler/interface", fields = {
		F("name", fref("primitive/string")),
		F("operations", fmap(&sp_op_spec, "")),
		F("pattern", fref("system/tree/path")),
	}})
	add(ctx, {name = "system/handler/manifest", extends = "system/handler/interface", fields = {
		F("name", fref("primitive/string")),
		F("operations", fmap(&sp_op_spec, "")),
		F("pattern", fref("system/tree/path")),
		F("expression_path", opt(fref("system/tree/path"))),
		F("internal_scope", opt(farray(&sp_grant_entry))),
		F("max_scope", opt(farray(&sp_grant_entry))),
	}})
	add(ctx, {name = "system/handler/operation-spec", fields = {
		F("input_type", opt(fref("system/type/name"))),
		F("output_type", opt(fref("system/type/name"))),
	}})
	add(ctx, {name = "system/handler/register-request", fields = {
		F("manifest", fref("system/handler/manifest")),
		F("requested_scope", opt(farray(&sp_grant_entry))),
		F("types", opt(fmap(&sp_type, ""))),
	}})
	add(ctx, {name = "system/handler/register-result", fields = {
		F("grant", fref("system/capability/token")),
		F("pattern", fref("system/tree/path")),
	}})

	// tree (5)
	add(ctx, {name = "system/tree/get-request", fields = {
		F("limit", opt(fref("primitive/uint"))),
		F("mode", opt(fref("primitive/string"))),
		F("offset", opt(fref("primitive/uint"))),
		F("tree_id", opt(fref("primitive/string"))),
	}})
	add(ctx, {name = "system/tree/put-request", fields = {
		F("entity", opt(fref("core/entity"))),
		F("expected_hash", opt(fref("system/hash"))),
		F("tree_id", opt(fref("primitive/string"))),
	}})
	add(ctx, {name = "system/tree/listing", fields = {
		F("count", fref("primitive/uint")),
		F("entries", fmap(&sp_listing_entry, "")),
		F("offset", fref("primitive/uint")),
		F("path", fref("system/tree/path")),
		F("next_page", opt(fref("system/hash"))),
	}})
	add(ctx, {name = "system/tree/listing-entry", fields = {
		F("has_children", fref("primitive/bool")),
		F("hash", opt(fref("system/hash"))),
	}})
	add(ctx, {name = "system/tree/path", extends = "primitive/string"})

	// type-system bootstrap (3)
	add(ctx, {name = "system/type", fields = {
		F("name", fref("system/type/name")),
		F("extends", opt(fref("system/type/name"))),
		F("fields", opt(fmap(&sp_field_spec, ""))),
		F("layout", opt(farray(&sp_string))),
		F("type_args", opt(fmap(&sp_type_name, ""))),
		F("type_params", opt(farray(&sp_string))),
	}})
	add(ctx, {name = "system/type/field-spec", fields = {
		F("type_ref", opt(fref("system/type/name"))),
		F("optional", opt(fref("primitive/bool"))),
		F("array_of", opt(fref("system/type/field-spec"))),
		F("map_of", opt(fref("system/type/field-spec"))),
		F("union_of", opt(farray(&sp_field_spec))),
		F("key_type", opt(fref("system/type/name"))),
		F("byte_size", opt(fref("primitive/uint"))),
		F("type_param", opt(fref("primitive/string"))),
		F("type_args", opt(fmap(&sp_type_name, ""))),
		F("default", opt(fref("primitive/any"))),
		F("constraints", opt(farray(&sp_core_entity))),
	}})
	add(ctx, {name = "system/type/name", extends = "primitive/string"})

	// operational (4)
	add(ctx, {name = "system/bounds", fields = {
		F("budget", opt(fref("primitive/uint"))),
		F("cascade_depth", opt(fref("primitive/uint"))),
		F("chain_id", opt(fref("primitive/string"))),
		F("parent_chain_id", opt(fref("primitive/string"))),
		F("ttl", opt(fref("primitive/uint"))),
		F("visited", opt(farray(&sp_tree_path))),
	}})
	add(ctx, {name = "system/resource-limits", fields = {
		F("max_budget", opt(fref("primitive/uint"))),
		F("max_ttl", opt(fref("primitive/uint"))),
		F("max_visited_length", opt(fref("primitive/uint"))),
	}})
	add(ctx, {name = "system/delivery-spec", fields = {
		F("operation", fref("primitive/string")),
		F("uri", fref("system/tree/path")),
	}})
	add(ctx, {name = "system/deletion-marker"})
}

CORE_TYPE_COUNT :: 53

// type_defs_publish seeds every core type entity into the store at
// system/type/<name>. Each type is rendered + bound in place (a Type_Def's field
// slice literals dangle if collected). Cloned into the store via `allocator`;
// scratch on context.temp_allocator (caller resets it after).
type_defs_publish :: proc(st: ^Store, local_peer: string, allocator := context.allocator) -> int {
	ctx := Emit_Ctx{st = st, local_peer = local_peer, gpa = allocator}
	core_type_defs(&ctx)
	return ctx.count
}
