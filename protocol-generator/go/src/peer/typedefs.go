package peer

// typedefs.go — the V7 §9.5 core type-registry floor (53 types).
//
// CLEAN-ROOM: the type definitions below are an in-code MODEL rendered through
// the peer's own S2 codec; the served entity's content_hash is computed by our
// own encoder over the model, not ingested from oracle bytes. The shapes follow
// the V7 §9.5 floor + the cross-peer render-from-model ruling (single source of
// truth in code, omit-empty so the canonical ECF map is byte-stable regardless
// of field declaration order — the codec re-sorts map keys length-then-lex).
//
// A *core* peer publishes EXACTLY the §9.5 floor (core + operational + the
// type-system bootstrap). Extension vocabularies (compute/*, content/*, …) are
// NOT pre-published by a core peer (refined G4 / F17): the oracle's type_system
// category matches the floor as a hard FAIL gate and WARNs (matched-if-present)
// on the non-floor types it also probes.

import "github.com/entity-core/entity-core-protocol-go/internal/cbor"

// fspec is a field spec inside a typeDef (the system/type/field-spec shape).
// Exactly one structural carrier is normally set: a typeRef, an arrayOf, a
// mapOf, or a unionOf. Rendered omit-empty into the field-spec ECF map.
type fspec struct {
	typeRef  string
	optional bool
	arrayOf  *fspec
	mapOf    *fspec
	unionOf  []fspec
	keyType  string
	byteSize uint64
	hasSize  bool
}

// fref → a type_ref to a named type.
func fref(t string) fspec { return fspec{typeRef: t} }

// opt marks a field-spec optional.
func opt(s fspec) fspec { s.optional = true; return s }

// sized adds a byte_size carrier.
func sized(n uint64, s fspec) fspec { s.byteSize = n; s.hasSize = true; return s }

// farray → an array_of the given element spec.
func farray(elem fspec) fspec { e := elem; return fspec{arrayOf: &e} }

// fmapOf → a map_of the given value spec, with an optional key_type ("" = none).
func fmapOf(keyType string, val fspec) fspec {
	v := val
	return fspec{mapOf: &v, keyType: keyType}
}

// funion → a union_of the given variant specs.
func funion(vs ...fspec) fspec { return fspec{unionOf: vs} }

// data renders a field-spec to its ECF data map (omit-empty). The codec sorts
// keys canonically; only the present key/value set affects the bytes.
func (s fspec) data() cbor.Value {
	var p []cbor.Pair
	if s.typeRef != "" {
		p = append(p, cbor.Entry("type_ref", cbor.Text(s.typeRef)))
	}
	if s.optional {
		p = append(p, cbor.Entry("optional", cbor.Bool(true)))
	}
	if s.arrayOf != nil {
		p = append(p, cbor.Entry("array_of", s.arrayOf.data()))
	}
	if s.mapOf != nil {
		p = append(p, cbor.Entry("map_of", s.mapOf.data()))
	}
	if s.unionOf != nil {
		variants := make([]cbor.Value, len(s.unionOf))
		for i, v := range s.unionOf {
			variants[i] = v.data()
		}
		p = append(p, cbor.Entry("union_of", valList(variants...)))
	}
	if s.keyType != "" {
		p = append(p, cbor.Entry("key_type", cbor.Text(s.keyType)))
	}
	if s.hasSize {
		p = append(p, cbor.Entry("byte_size", cbor.Uint(s.byteSize)))
	}
	return cbor.NewMap(p...)
}

// field is one named field of a typeDef (declaration order preserved within the
// fields sub-map; the codec re-sorts it canonically on encode).
type field struct {
	name string
	spec fspec
}

func f(name string, spec fspec) field { return field{name, spec} }

// typeDef is a core type definition (the system/type entity data).
type typeDef struct {
	name    string
	extends string
	fields  []field
	layout  []string
}

func def(name string) typeDef { return typeDef{name: name} }

func (t typeDef) withExtends(e string) typeDef { t.extends = e; return t }
func (t typeDef) withFields(fs ...field) typeDef {
	t.fields = fs
	return t
}
func (t typeDef) withLayout(ls ...string) typeDef { t.layout = ls; return t }

// data renders the system/type data map (omit-empty).
func (t typeDef) data() cbor.Value {
	var p []cbor.Pair
	p = append(p, cbor.Entry("name", cbor.Text(t.name)))
	if t.extends != "" {
		p = append(p, cbor.Entry("extends", cbor.Text(t.extends)))
	}
	if len(t.fields) > 0 {
		fp := make([]cbor.Pair, len(t.fields))
		for i, fl := range t.fields {
			fp[i] = cbor.Pair{Key: cbor.Text(fl.name), Val: fl.spec.data()}
		}
		p = append(p, cbor.Entry("fields", cbor.NewMap(fp...)))
	}
	if len(t.layout) > 0 {
		p = append(p, cbor.Entry("layout", strList(t.layout...)))
	}
	return cbor.NewMap(p...)
}

// entity materializes the type as a system/type entity (content_hash computed by
// our own encoder over the model).
func (t typeDef) entity() Entity { return mustEntity("system/type", t.data()) }

// reused nested specs.
var (
	spString       = fref("primitive/string")
	spAny          = fref("primitive/any")
	spHash         = fref("system/hash")
	spCoreEntity   = fref("core/entity")
	spTreePath     = fref("system/tree/path")
	spGrantEntry   = fref("system/capability/grant-entry")
	spMultiGranter = fref("system/capability/multi-granter")
	spFieldSpec    = fref("system/type/field-spec")
	spOpSpec       = fref("system/handler/operation-spec")
	spListingEntry = fref("system/tree/listing-entry")
	spType         = fref("system/type")
	spTypeName     = fref("system/type/name")
)

// coreTypeDefs is the V7 §9.5 core type floor (53 definitions).
func coreTypeDefs() []typeDef {
	return []typeDef{
		// primitives (8)
		def("primitive/any"),
		def("primitive/bool"),
		def("primitive/bytes"),
		def("primitive/float"),
		def("primitive/int"),
		def("primitive/null"),
		def("primitive/string"),
		def("primitive/uint"),

		// structural roots + envelopes (5)
		def("entity").withFields(
			f("type", fref("primitive/string")),
			f("data", fref("primitive/any")),
		),
		def("core/entity").withFields(
			f("type", fref("primitive/string")),
			f("data", fref("primitive/any")),
			f("content_hash", fref("system/hash")),
		),
		def("core/envelope").withFields(
			f("root", fref("core/entity")),
			f("included", opt(fmapOf("system/hash", spCoreEntity))),
		),
		def("system/envelope").withExtends("core/envelope"),
		def("system/protocol/envelope").withExtends("core/envelope"),

		// identity / hash / signature (4)
		def("system/hash").withExtends("primitive/bytes").withFields(
			f("format_code", sized(1, fref("primitive/uint"))),
			f("digest", fref("primitive/bytes")),
		).withLayout("format_code", "digest"),
		def("system/peer").withFields(
			f("key_type", fref("primitive/string")),
			f("peer_id", fref("system/peer-id")),
			f("public_key", fref("primitive/bytes")),
		),
		def("system/peer-id").withExtends("primitive/string"),
		def("system/signature").withFields(
			f("algorithm", fref("primitive/string")),
			f("signature", fref("primitive/bytes")),
			f("signer", fref("system/hash")),
			f("target", fref("system/hash")),
		),

		// protocol surface (6)
		def("system/protocol/connect/authenticate").withFields(
			f("key_type", fref("primitive/string")),
			f("nonce", fref("primitive/bytes")),
			f("peer_id", fref("system/peer-id")),
			f("public_key", fref("primitive/bytes")),
		),
		def("system/protocol/connect/hello").withFields(
			f("protocols", farray(spString)),
			f("nonce", fref("primitive/bytes")),
			f("peer_id", fref("system/peer-id")),
			f("timestamp", fref("primitive/uint")),
			f("compression", opt(farray(spString))),
			f("encryption", opt(farray(spString))),
			f("hash_formats", opt(farray(spString))),
			f("key_types", opt(farray(spString))),
		),
		def("system/protocol/error").withFields(
			f("code", fref("primitive/string")),
			f("message", opt(fref("primitive/string"))),
			f("rejected_marker", opt(fref("system/hash"))),
		),
		def("system/protocol/execute").withFields(
			f("operation", fref("primitive/string")),
			f("params", fref("core/entity")),
			f("request_id", fref("primitive/string")),
			f("uri", fref("system/tree/path")),
			f("author", opt(fref("system/hash"))),
			f("bounds", opt(fref("system/bounds"))),
			f("capability", opt(fref("system/hash"))),
			f("deliver_to", opt(fref("system/delivery-spec"))),
			f("deliver_token", opt(fref("system/hash"))),
			f("durability_request", opt(fref("system/durability-request"))),
			f("resource", opt(fref("system/protocol/resource-target"))),
		),
		def("system/protocol/execute/response").withFields(
			f("request_id", fref("primitive/string")),
			f("result", fref("core/entity")),
			f("status", fref("primitive/uint")),
			f("durability", opt(fref("system/durability-result"))),
		),
		def("system/protocol/resource-target").withFields(
			f("targets", farray(spTreePath)),
			f("exclude", opt(farray(spTreePath))),
		),

		// capability (12)
		def("system/capability/grant").withFields(
			f("token", fref("system/hash")),
		),
		def("system/capability/grant-entry").withFields(
			f("handlers", fref("system/capability/path-scope")),
			f("operations", fref("system/capability/id-scope")),
			f("resources", fref("system/capability/path-scope")),
			f("allowances", opt(fmapOf("", spAny))),
			f("constraints", opt(fmapOf("", spAny))),
			f("peers", opt(fref("system/capability/id-scope"))),
		),
		def("system/capability/id-scope").withFields(
			f("include", farray(spString)),
			f("exclude", opt(farray(spString))),
		),
		def("system/capability/path-scope").withFields(
			f("include", farray(spTreePath)),
			f("exclude", opt(farray(spTreePath))),
		),
		def("system/capability/request").withFields(
			f("grants", farray(spGrantEntry)),
			f("ttl_ms", opt(fref("primitive/uint"))),
		),
		def("system/capability/revocation").withFields(
			f("token", fref("system/hash")),
			f("revoked_at", fref("primitive/uint")),
			f("reason", opt(fref("primitive/string"))),
		),
		def("system/capability/revoke-request").withFields(
			f("token", fref("system/hash")),
			f("reason", opt(fref("primitive/string"))),
		),
		def("system/capability/delegate-request").withFields(
			f("grants", farray(spGrantEntry)),
			f("parent", fref("system/hash")),
			f("ttl_ms", opt(fref("primitive/uint"))),
		),
		def("system/capability/delegation-caveats").withFields(
			f("max_delegation_depth", opt(fref("primitive/uint"))),
			f("max_delegation_ttl", opt(fref("primitive/uint"))),
			f("no_delegation", opt(fref("primitive/bool"))),
		),
		def("system/capability/policy-entry").withFields(
			f("grants", farray(spGrantEntry)),
			f("peer_pattern", fref("primitive/string")),
			f("notes", opt(fref("primitive/string"))),
			f("ttl_ms", opt(fref("primitive/uint"))),
		),
		def("system/capability/token").withFields(
			f("created_at", fref("primitive/uint")),
			f("grantee", fref("system/hash")),
			f("granter", funion(spHash, spMultiGranter)),
			f("grants", farray(spGrantEntry)),
			f("delegation_caveats", opt(fref("system/capability/delegation-caveats"))),
			f("expires_at", opt(fref("primitive/uint"))),
			f("not_before", opt(fref("primitive/uint"))),
			f("parent", opt(fref("system/hash"))),
			f("resource_limits", opt(fref("system/resource-limits"))),
		),
		def("system/capability/multi-granter").withFields(
			f("signers", farray(spHash)),
			f("threshold", fref("primitive/uint")),
		),

		// handler machinery (6)
		def("system/handler").withFields(
			f("interface", fref("system/tree/path")),
			f("expression_path", opt(fref("system/tree/path"))),
			f("internal_scope", opt(farray(spGrantEntry))),
			f("max_scope", opt(farray(spGrantEntry))),
		),
		def("system/handler/interface").withFields(
			f("name", fref("primitive/string")),
			f("operations", fmapOf("", spOpSpec)),
			f("pattern", fref("system/tree/path")),
		),
		def("system/handler/manifest").withExtends("system/handler/interface").withFields(
			f("name", fref("primitive/string")),
			f("operations", fmapOf("", spOpSpec)),
			f("pattern", fref("system/tree/path")),
			f("expression_path", opt(fref("system/tree/path"))),
			f("internal_scope", opt(farray(spGrantEntry))),
			f("max_scope", opt(farray(spGrantEntry))),
		),
		def("system/handler/operation-spec").withFields(
			f("input_type", opt(fref("system/type/name"))),
			f("output_type", opt(fref("system/type/name"))),
		),
		def("system/handler/register-request").withFields(
			f("manifest", fref("system/handler/manifest")),
			f("requested_scope", opt(farray(spGrantEntry))),
			f("types", opt(fmapOf("", spType))),
		),
		def("system/handler/register-result").withFields(
			f("grant", fref("system/capability/token")),
			f("pattern", fref("system/tree/path")),
		),

		// tree (5)
		def("system/tree/get-request").withFields(
			f("limit", opt(fref("primitive/uint"))),
			f("mode", opt(fref("primitive/string"))),
			f("offset", opt(fref("primitive/uint"))),
			f("tree_id", opt(fref("primitive/string"))),
		),
		def("system/tree/put-request").withFields(
			f("entity", opt(fref("core/entity"))),
			f("expected_hash", opt(fref("system/hash"))),
			f("tree_id", opt(fref("primitive/string"))),
		),
		def("system/tree/listing").withFields(
			f("count", fref("primitive/uint")),
			f("entries", fmapOf("", spListingEntry)),
			f("offset", fref("primitive/uint")),
			f("path", fref("system/tree/path")),
			f("next_page", opt(fref("system/hash"))),
		),
		def("system/tree/listing-entry").withFields(
			f("has_children", fref("primitive/bool")),
			f("hash", opt(fref("system/hash"))),
		),
		def("system/tree/path").withExtends("primitive/string"),

		// type-system bootstrap (3)
		def("system/type").withFields(
			f("name", fref("system/type/name")),
			f("extends", opt(fref("system/type/name"))),
			f("fields", opt(fmapOf("", spFieldSpec))),
			f("layout", opt(farray(spString))),
			f("type_args", opt(fmapOf("", spTypeName))),
			f("type_params", opt(farray(spString))),
		),
		def("system/type/field-spec").withFields(
			f("type_ref", opt(fref("system/type/name"))),
			f("optional", opt(fref("primitive/bool"))),
			f("array_of", opt(fref("system/type/field-spec"))),
			f("map_of", opt(fref("system/type/field-spec"))),
			f("union_of", opt(farray(spFieldSpec))),
			f("key_type", opt(fref("system/type/name"))),
			f("byte_size", opt(fref("primitive/uint"))),
			f("type_param", opt(fref("primitive/string"))),
			f("type_args", opt(fmapOf("", spTypeName))),
			f("default", opt(fref("primitive/any"))),
			f("constraints", opt(farray(spCoreEntity))),
		),
		def("system/type/name").withExtends("primitive/string"),

		// operational (4)
		def("system/bounds").withFields(
			f("budget", opt(fref("primitive/uint"))),
			f("cascade_depth", opt(fref("primitive/uint"))),
			f("chain_id", opt(fref("primitive/string"))),
			f("parent_chain_id", opt(fref("primitive/string"))),
			f("ttl", opt(fref("primitive/uint"))),
			f("visited", opt(farray(spTreePath))),
		),
		def("system/resource-limits").withFields(
			f("max_budget", opt(fref("primitive/uint"))),
			f("max_ttl", opt(fref("primitive/uint"))),
			f("max_visited_length", opt(fref("primitive/uint"))),
		),
		def("system/delivery-spec").withFields(
			f("operation", fref("primitive/string")),
			f("uri", fref("system/tree/path")),
		),
		def("system/deletion-marker"),
	}
}

// publishCoreTypes writes the §9.5 floor at /{peer}/system/type/{name}.
func (p *Peer) publishCoreTypes() {
	for _, td := range coreTypeDefs() {
		p.store.Bind("/"+p.localPeer+"/system/type/"+td.name, td.entity())
	}
}
