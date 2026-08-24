package entity_core

import "core:mem"
import "core:slice"
import "core:strings"

// Entity model (L-foundation) — the materialized `{type, data, content_hash}`
// form (§1.1, §3.4) and the protocol envelope (§3.1), lifted onto the S2
// `Ec_Value` tree.
//
// No-GC ownership contract (profile [memory]): an `Entity` OWNS its `typ`
// string, its `data` Ec_Value tree, and its 33-byte `hash`. `entity_destroy`
// frees all three. An `Envelope` owns its `root` Entity and every `included`
// Entity plus the duped key bytes. This is the documented caller-frees seam the
// GC'd peers never had to author. Tests run under mem.Tracking_Allocator so any
// un-freed entity is a failure.
//
// N4 original-byte forwarding: at the peer surface a decoded inbound entity is
// re-materialized through our own codec (recomputing the hash from {type,data})
// — §5.2 validate-before-trust. We trust our recomputed hash, not the wire
// bytes, so a forwarded entity is canonical by construction.

Entity :: struct {
	typ:  string, // owned
	data: Ec_Value, // owned tree
	hash: []u8, // owned, 33 bytes (format byte 0x00 ‖ 32-byte SHA-256)
}

// entity_make constructs a materialized entity, computing the content_hash under
// the ecfv1-sha256 floor (format_code 0). Takes ownership of `data`; dupes `typ`
// (caller keeps ownership of the passed slice).
entity_make :: proc(
	typ: string,
	data: Ec_Value,
	allocator := context.allocator,
) -> (Entity, Codec_Error) {
	owned_typ := strings.clone(typ, allocator)
	// content_hash extracts {type, data} from the map it is handed; build the
	// preimage {type: typ, data: data} on a stack array borrowing `typ`+`data`
	// (no clone — the hash path only reads it and re-encodes into temp scratch).
	preimage_pairs := [2]Ec_Pair{
		{Ec_Text(typ), data},
		{Ec_Text("data"), data},
	}
	preimage_pairs[0].key = Ec_Text("type")
	preimage_pairs[0].value = Ec_Text(typ)
	h, herr := content_hash(Ec_Map(preimage_pairs[:]), 0, allocator)
	if herr != .None {
		delete(owned_typ, allocator)
		return Entity{}, herr
	}
	return Entity{typ = owned_typ, data = data, hash = h}, .None
}

entity_destroy :: proc(e: Entity, allocator := context.allocator) {
	delete(e.typ, allocator)
	value_destroy(e.data, allocator)
	delete(e.hash, allocator)
}

// entity_clone produces a deep, independently-owned copy (used when an entity
// must live in both the store and an outgoing envelope's `included`).
entity_clone :: proc(e: Entity, allocator := context.allocator) -> (Entity, Codec_Error) {
	owned_typ := strings.clone(e.typ, allocator)
	data := value_clone(e.data, allocator)
	h := make([]u8, len(e.hash), allocator)
	copy(h, e.hash)
	return Entity{typ = owned_typ, data = data, hash = h}, .None
}

// ── field accessors (data is a map) ──────────────────────────────────────────

entity_field :: proc(e: Entity, key: string) -> (Ec_Value, bool) {
	return map_get(e.data, key)
}

entity_text :: proc(e: Entity, key: string) -> (string, bool) {
	v, ok := map_get(e.data, key)
	if !ok {
		return "", false
	}
	t, is_text := v.(Ec_Text)
	return string(t), is_text
}

entity_bytes :: proc(e: Entity, key: string) -> ([]u8, bool) {
	v, ok := map_get(e.data, key)
	if !ok {
		return nil, false
	}
	b, is_bytes := v.(Ec_Bytes)
	return ([]u8)(b), is_bytes
}

entity_uint :: proc(e: Entity, key: string) -> (u64, bool) {
	v, ok := map_get(e.data, key)
	if !ok {
		return 0, false
	}
	u, is_uint := v.(Ec_Uint)
	return u64(u), is_uint
}

// entity_field_entity parses a sub-entity carried as a CBOR map field (e.g.
// params, the inner entity in a put). Returns an owned Entity + true.
entity_field_entity :: proc(
	e: Entity,
	key: string,
	allocator := context.allocator,
) -> (Entity, bool, Codec_Error) {
	v, ok := map_get(e.data, key)
	if !ok {
		return Entity{}, false, .None
	}
	sub, err := entity_of_cbor(v, allocator)
	if err != .None {
		return Entity{}, false, err
	}
	return sub, true, .None
}

// entity_to_cbor produces the wire form: the entity carries its content_hash so
// it is self-describing across serialization (§3.1). Returns an owned Ec_Value.
entity_to_cbor :: proc(e: Entity, allocator := context.allocator) -> Ec_Value {
	pairs := make([]Ec_Pair, 3, allocator)
	pairs[0] = Ec_Pair{text_val("type", allocator), text_val(e.typ, allocator)}
	pairs[1] = Ec_Pair{text_val("data", allocator), value_clone(e.data, allocator)}
	pairs[2] = Ec_Pair{text_val("content_hash", allocator), bytes_val(e.hash, allocator)}
	return Ec_Map(pairs)
}

// entity_of_cbor parses a wire entity, recomputing the hash from {type,data} and
// validating it against the carried content_hash (§1.8 fidelity). Returns the
// recomputed canonical entity (we trust our hash, not the wire bytes — §5.2).
entity_of_cbor :: proc(
	c: Ec_Value,
	allocator := context.allocator,
) -> (Entity, Codec_Error) {
	tv, has_type := map_get(c, "type")
	if !has_type {
		return Entity{}, .Bad_Entity
	}
	typ, is_text := tv.(Ec_Text)
	if !is_text {
		return Entity{}, .Bad_Entity
	}
	data_src, has_data := map_get(c, "data")
	if !has_data {
		return Entity{}, .Bad_Entity
	}
	data := value_clone(data_src, allocator)
	e, err := entity_make(string(typ), data, allocator)
	if err != .None {
		value_destroy(data, allocator)
		return Entity{}, err
	}
	if ch, has_ch := map_get(c, "content_hash"); has_ch {
		if h, is_bytes := ch.(Ec_Bytes); is_bytes {
			if !slice.equal(([]u8)(h), e.hash) {
				entity_destroy(e, allocator)
				return Entity{}, .Content_Hash_Mismatch
			}
		}
	}
	return e, .None
}

// ── envelope (§3.1) ──────────────────────────────────────────────────────────

Included :: struct {
	key:    []u8, // owned: the entity's content_hash bytes
	entity: Entity, // owned
}

Envelope :: struct {
	root:     Entity,
	included: []Included,
}

envelope_destroy :: proc(env: Envelope, allocator := context.allocator) {
	entity_destroy(env.root, allocator)
	for inc in env.included {
		delete(inc.key, allocator)
		entity_destroy(inc.entity, allocator)
	}
	delete(env.included, allocator)
}

envelope_get :: proc(env: Envelope, h: []u8) -> (Entity, bool) {
	for inc in env.included {
		if slice.equal(inc.key, h) {
			return inc.entity, true
		}
	}
	return Entity{}, false
}

envelope_to_cbor :: proc(env: Envelope, allocator := context.allocator) -> Ec_Value {
	inc_pairs := make([]Ec_Pair, len(env.included), allocator)
	for inc, i in env.included {
		inc_pairs[i] = Ec_Pair{bytes_val(inc.key, allocator), entity_to_cbor(inc.entity, allocator)}
	}
	pairs := make([]Ec_Pair, 2, allocator)
	pairs[0] = Ec_Pair{text_val("root", allocator), entity_to_cbor(env.root, allocator)}
	pairs[1] = Ec_Pair{text_val("included", allocator), Ec_Map(inc_pairs)}
	return Ec_Map(pairs)
}

// envelope_encode serializes the envelope to canonical ECF frame bytes (owned).
envelope_encode :: proc(env: Envelope, allocator := context.allocator) -> ([]u8, Codec_Error) {
	v := envelope_to_cbor(env, allocator)
	defer value_destroy(v, allocator)
	return cbor_encode(v, allocator)
}

// envelope_of_cbor builds an owned Envelope from a (just-decoded) Ec_Value.
// Validates each included key matches its entity hash (§3.1).
envelope_of_cbor :: proc(c: Ec_Value, allocator := context.allocator) -> (Envelope, Codec_Error) {
	root_src, has_root := map_get(c, "root")
	if !has_root {
		return Envelope{}, .Bad_Entity
	}
	root, rerr := entity_of_cbor(root_src, allocator)
	if rerr != .None {
		return Envelope{}, rerr
	}

	list := make([dynamic]Included, allocator)
	cleanup :: proc(root: Entity, list: [dynamic]Included, allocator: mem.Allocator) {
		entity_destroy(root, allocator)
		for inc in list {
			delete(inc.key, allocator)
			entity_destroy(inc.entity, allocator)
		}
		delete(list)
	}

	if inc_v, has_inc := map_get(c, "included"); has_inc {
		m, is_map := inc_v.(Ec_Map)
		if !is_map {
			cleanup(root, list, allocator)
			return Envelope{}, .Bad_Entity
		}
		for pair in ([]Ec_Pair)(m) {
			kb, is_bytes := pair.key.(Ec_Bytes)
			if !is_bytes {
				cleanup(root, list, allocator)
				return Envelope{}, .Bad_Entity
			}
			e, eerr := entity_of_cbor(pair.value, allocator)
			if eerr != .None {
				cleanup(root, list, allocator)
				return Envelope{}, eerr
			}
			if !slice.equal(([]u8)(kb), e.hash) {
				entity_destroy(e, allocator)
				cleanup(root, list, allocator)
				return Envelope{}, .Included_Key_Mismatch
			}
			key := make([]u8, len(kb), allocator)
			copy(key, ([]u8)(kb))
			append(&list, Included{key = key, entity = e})
		}
	}
	return Envelope{root = root, included = list[:]}, .None
}

envelope_of_frame :: proc(payload: []u8, allocator := context.allocator) -> (Envelope, Codec_Error) {
	v, err := cbor_decode(payload, allocator)
	if err != .None {
		return Envelope{}, err
	}
	defer value_destroy(v, allocator)
	return envelope_of_cbor(v, allocator)
}

// ── small Ec_Value helpers (owned allocations) ───────────────────────────────

text_val :: proc(s: string, allocator := context.allocator) -> Ec_Value {
	return Ec_Text(strings.clone(s, allocator))
}

bytes_val :: proc(b: []u8, allocator := context.allocator) -> Ec_Value {
	out := make([]u8, len(b), allocator)
	copy(out, b)
	return Ec_Bytes(out)
}

uint_val :: proc(n: u64) -> Ec_Value {
	return Ec_Uint(n)
}

bool_val :: proc(b: bool) -> Ec_Value {
	return Ec_Bool(b)
}

// value_clone deep-clones an Ec_Value tree (borrowed-in → owned-out).
value_clone :: proc(v: Ec_Value, allocator := context.allocator) -> Ec_Value {
	switch t in v {
	case Ec_Uint:
		return t
	case Ec_Nint:
		return t
	case Ec_Bool:
		return t
	case Ec_Null:
		return t
	case Ec_Float:
		return t
	case Ec_Bytes:
		out := make([]u8, len(([]u8)(t)), allocator)
		copy(out, ([]u8)(t))
		return Ec_Bytes(out)
	case Ec_Text:
		return Ec_Text(strings.clone(string(t), allocator))
	case Ec_Array:
		items := ([]Ec_Value)(t)
		out := make([]Ec_Value, len(items), allocator)
		for item, i in items {
			out[i] = value_clone(item, allocator)
		}
		return Ec_Array(out)
	case Ec_Map:
		pairs := ([]Ec_Pair)(t)
		out := make([]Ec_Pair, len(pairs), allocator)
		for pair, i in pairs {
			out[i] = Ec_Pair{value_clone(pair.key, allocator), value_clone(pair.value, allocator)}
		}
		return Ec_Map(out)
	}
	return Ec_Null{}
}

// map_get_val is like map_get but takes a raw Ec_Value (for nested maps).
map_get_val :: proc(v: Ec_Value, key: string) -> (Ec_Value, bool) {
	return map_get(v, key)
}

// hex_of returns lowercase hex of a byte slice (for tree-path hash segments).
hex_of :: proc(s: []u8, allocator := context.allocator) -> string {
	digits := "0123456789abcdef"
	out := make([]u8, len(s) * 2, allocator)
	for b, i in s {
		out[i * 2] = digits[b >> 4]
		out[i * 2 + 1] = digits[b & 0xf]
	}
	return string(out)
}
