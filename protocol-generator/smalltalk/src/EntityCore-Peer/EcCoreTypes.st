"entity-core-protocol-smalltalk — the §9.5 core type floor (render-from-model). Publishes the
FULL 53-type core floor as system/type entities under the local namespace at
/{peer}/system/type/{name}. Each per-type `data` map is the in-code override table (the cross-
impl type model, ported field-for-field from the cohort shape — forth src/coretypes.fs); each
entity''s content_hash is computed by THIS peer''s S2-green codec over {type, data}
(render-from-model, NOT ingest-bytes) — the surface the oracle''s type_system category fetches at
system/type/<name>. Non-floor vocabularies are extension-owned and intentionally absent.

THE PURE-OBJECT REP (A-ST-000): a type descriptor is built with EcVal map/array cascades; the
field-spec helpers (ref:/refo:/arr:/arro:/map:/mapo:) answer EcValue objects. Canonical map-key
ORDER is irrelevant (the codec sorts on encode, §4.2.1), so the field maps below are built in any
order; only the logical content must match.

LIVE-IMAGE NOTE: EcVal / EcEntity / EcStore resolve at send-time."

| pkg cls |
pkg := 'EntityCore-Peer'.
cls := (Object << #EcCoreTypes package: pkg) install.

"── field-spec value helpers (each answers an EcValue = one field''s type descriptor) ──"
cls class compile: 'ref: aName  ^ EcVal map: { ''type_ref'' -> (EcVal text: aName) }'.
cls class compile: 'refo: aName
	^ EcVal map: { ''type_ref'' -> (EcVal text: aName). ''optional'' -> (EcVal bool: true) }'.
cls class compile: 'arr: aName  ^ EcVal map: { ''array_of'' -> (self ref: aName) }'.
cls class compile: 'arro: aName
	^ EcVal map: { ''optional'' -> (EcVal bool: true). ''array_of'' -> (self ref: aName) }'.
cls class compile: 'map: aName  ^ EcVal map: { ''map_of'' -> (self ref: aName) }'.
cls class compile: 'mapo: aName
	^ EcVal map: { ''optional'' -> (EcVal bool: true). ''map_of'' -> (self ref: aName) }'.

"── the bind path + entity make + store bind ──"
"bindType:data: — make a system/type entity from a data EcValue + bind at /{local}/system/type/{name}."
cls class compile: 'bindType: aName data: aDataValue local: aLocal store: aStore
	| ent path |
	ent := EcEntity type: ''system/type'' data: aDataValue.
	path := ''/'', aLocal, ''/system/type/'', aName.
	aStore bind: path to: ent'.

"nm: — {name: X}."
cls class compile: 'nm: aName local: aLocal store: aStore
	self bindType: aName data: (EcVal map: { ''name'' -> (EcVal text: aName) }) local: aLocal store: aStore'.
"ext:base: — {name: X, extends: Y}."
cls class compile: 'ext: aName base: aBase local: aLocal store: aStore
	self bindType: aName data: (EcVal map: {
		''name'' -> (EcVal text: aName). ''extends'' -> (EcVal text: aBase) }) local: aLocal store: aStore'.
"flds:fields: — {name: X, fields: {...}}. aFields is an Array of stringKey -> field-descriptor."
cls class compile: 'flds: aName fields: aFieldsArray local: aLocal store: aStore
	self bindType: aName data: (EcVal map: {
		''name'' -> (EcVal text: aName).
		''fields'' -> (EcVal map: aFieldsArray) }) local: aLocal store: aStore'.

"── the publisher — publish: local store: ──"
cls class compile: 'publishFor: aLocal store: aStore
	| l s r a o m mo |
	l := aLocal. s := aStore.
	"convenience block aliases (single-doit temp-capture safe: all declared at top)."
	r := [ :n | self ref: n ]. a := [ :n | self arr: n ]. o := [ :n | self refo: n ].
	m := [ :n | self map: n ]. mo := [ :n | self mapo: n ].

	"── primitives (8) ──"
	#(''primitive/any'' ''primitive/bool'' ''primitive/bytes'' ''primitive/float''
	  ''primitive/int'' ''primitive/null'' ''primitive/string'' ''primitive/uint'')
		do: [ :n | self nm: n local: l store: s ].

	"── entity / envelope (5) ──"
	self flds: ''entity'' fields: {
		''data'' -> (r value: ''primitive/any''). ''type'' -> (r value: ''primitive/string'') } local: l store: s.
	self flds: ''core/entity'' fields: {
		''content_hash'' -> (r value: ''system/hash'').
		''data'' -> (r value: ''primitive/any''). ''type'' -> (r value: ''primitive/string'') } local: l store: s.
	self flds: ''core/envelope'' fields: {
		''included'' -> (EcVal map: {
			''optional'' -> (EcVal bool: true). ''map_of'' -> (r value: ''core/entity''). ''key_type'' -> (EcVal text: ''system/hash'') }).
		''root'' -> (r value: ''core/entity'') } local: l store: s.
	self ext: ''system/envelope'' base: ''core/envelope'' local: l store: s.
	self ext: ''system/protocol/envelope'' base: ''core/envelope'' local: l store: s.

	"── hash / peer / signature (5) ──"
	self bindType: ''system/hash'' data: (EcVal map: {
		''name'' -> (EcVal text: ''system/hash'').
		''fields'' -> (EcVal map: {
			''digest'' -> (r value: ''primitive/bytes'').
			''format_code'' -> (EcVal map: { ''type_ref'' -> (EcVal text: ''primitive/uint''). ''byte_size'' -> (EcVal uint: 1) }) }).
		''extends'' -> (EcVal text: ''primitive/bytes'').
		''layout'' -> (EcVal array: { EcVal text: ''format_code''. EcVal text: ''digest'' }) }) local: l store: s.
	self flds: ''system/peer'' fields: {
		''key_type'' -> (r value: ''primitive/string''). ''peer_id'' -> (r value: ''system/peer-id''). ''public_key'' -> (r value: ''primitive/bytes'') } local: l store: s.
	self ext: ''system/peer-id'' base: ''primitive/string'' local: l store: s.
	self flds: ''system/signature'' fields: {
		''algorithm'' -> (r value: ''primitive/string''). ''signature'' -> (r value: ''primitive/bytes'').
		''signer'' -> (r value: ''system/hash''). ''target'' -> (r value: ''system/hash'') } local: l store: s.

	"── connect (2) ──"
	self flds: ''system/protocol/connect/authenticate'' fields: {
		''key_type'' -> (r value: ''primitive/string''). ''nonce'' -> (r value: ''primitive/bytes'').
		''peer_id'' -> (r value: ''system/peer-id''). ''public_key'' -> (r value: ''primitive/bytes'') } local: l store: s.
	self flds: ''system/protocol/connect/hello'' fields: {
		''compression'' -> (self arro: ''primitive/string''). ''encryption'' -> (self arro: ''primitive/string'').
		''hash_formats'' -> (self arro: ''primitive/string''). ''key_types'' -> (self arro: ''primitive/string'').
		''nonce'' -> (r value: ''primitive/bytes''). ''peer_id'' -> (r value: ''system/peer-id'').
		''protocols'' -> (a value: ''primitive/string''). ''timestamp'' -> (r value: ''primitive/uint'') } local: l store: s.

	"── protocol error / execute / response / resource-target (4) ──"
	self flds: ''system/protocol/error'' fields: {
		''code'' -> (r value: ''primitive/string''). ''message'' -> (o value: ''primitive/string''). ''rejected_marker'' -> (o value: ''system/hash'') } local: l store: s.
	self flds: ''system/protocol/execute'' fields: {
		''author'' -> (o value: ''system/hash''). ''bounds'' -> (o value: ''system/bounds''). ''capability'' -> (o value: ''system/hash'').
		''deliver_to'' -> (o value: ''system/delivery-spec''). ''deliver_token'' -> (o value: ''system/hash''). ''durability_request'' -> (o value: ''system/durability-request'').
		''operation'' -> (r value: ''primitive/string''). ''params'' -> (r value: ''core/entity''). ''request_id'' -> (r value: ''primitive/string'').
		''resource'' -> (o value: ''system/protocol/resource-target''). ''uri'' -> (r value: ''system/tree/path'') } local: l store: s.
	self flds: ''system/protocol/execute/response'' fields: {
		''durability'' -> (o value: ''system/durability-result''). ''request_id'' -> (r value: ''primitive/string'').
		''result'' -> (r value: ''core/entity''). ''status'' -> (r value: ''primitive/uint'') } local: l store: s.
	self flds: ''system/protocol/resource-target'' fields: {
		''exclude'' -> (self arro: ''system/tree/path''). ''targets'' -> (a value: ''system/tree/path'') } local: l store: s.

	"── capability (11) ──"
	self flds: ''system/capability/grant'' fields: { ''token'' -> (r value: ''system/hash'') } local: l store: s.
	self flds: ''system/capability/grant-entry'' fields: {
		''allowances'' -> (mo value: ''primitive/any''). ''constraints'' -> (mo value: ''primitive/any'').
		''handlers'' -> (r value: ''system/capability/path-scope''). ''operations'' -> (r value: ''system/capability/id-scope'').
		''peers'' -> (o value: ''system/capability/id-scope''). ''resources'' -> (r value: ''system/capability/path-scope'') } local: l store: s.
	self flds: ''system/capability/id-scope'' fields: {
		''exclude'' -> (self arro: ''primitive/string''). ''include'' -> (a value: ''primitive/string'') } local: l store: s.
	self flds: ''system/capability/path-scope'' fields: {
		''exclude'' -> (self arro: ''system/tree/path''). ''include'' -> (a value: ''system/tree/path'') } local: l store: s.
	self flds: ''system/capability/request'' fields: {
		''grants'' -> (a value: ''system/capability/grant-entry''). ''ttl_ms'' -> (o value: ''primitive/uint'') } local: l store: s.
	self flds: ''system/capability/revocation'' fields: {
		''reason'' -> (o value: ''primitive/string''). ''revoked_at'' -> (r value: ''primitive/uint''). ''token'' -> (r value: ''system/hash'') } local: l store: s.
	self flds: ''system/capability/revoke-request'' fields: {
		''reason'' -> (o value: ''primitive/string''). ''token'' -> (r value: ''system/hash'') } local: l store: s.
	self flds: ''system/capability/delegate-request'' fields: {
		''grants'' -> (a value: ''system/capability/grant-entry''). ''parent'' -> (r value: ''system/hash''). ''ttl_ms'' -> (o value: ''primitive/uint'') } local: l store: s.
	self flds: ''system/capability/delegation-caveats'' fields: {
		''max_delegation_depth'' -> (o value: ''primitive/uint''). ''max_delegation_ttl'' -> (o value: ''primitive/uint''). ''no_delegation'' -> (o value: ''primitive/bool'') } local: l store: s.
	self flds: ''system/capability/policy-entry'' fields: {
		''grants'' -> (a value: ''system/capability/grant-entry''). ''notes'' -> (o value: ''primitive/string'').
		''peer_pattern'' -> (r value: ''primitive/string''). ''ttl_ms'' -> (o value: ''primitive/uint'') } local: l store: s.
	self flds: ''system/capability/token'' fields: {
		''created_at'' -> (r value: ''primitive/uint''). ''delegation_caveats'' -> (o value: ''system/capability/delegation-caveats'').
		''expires_at'' -> (o value: ''primitive/uint''). ''grantee'' -> (r value: ''system/hash'').
		''granter'' -> (EcVal map: { ''union_of'' -> (EcVal array: { r value: ''system/hash''. r value: ''system/capability/multi-granter'' }) }).
		''grants'' -> (a value: ''system/capability/grant-entry''). ''not_before'' -> (o value: ''primitive/uint'').
		''parent'' -> (o value: ''system/hash''). ''resource_limits'' -> (o value: ''system/resource-limits'') } local: l store: s.
	self flds: ''system/capability/multi-granter'' fields: {
		''signers'' -> (a value: ''system/hash''). ''threshold'' -> (r value: ''primitive/uint'') } local: l store: s.

	"── handler (6) ──"
	self flds: ''system/handler'' fields: {
		''expression_path'' -> (o value: ''system/tree/path''). ''interface'' -> (r value: ''system/tree/path'').
		''internal_scope'' -> (self arro: ''system/capability/grant-entry''). ''max_scope'' -> (self arro: ''system/capability/grant-entry'') } local: l store: s.
	self flds: ''system/handler/interface'' fields: {
		''name'' -> (r value: ''primitive/string''). ''operations'' -> (m value: ''system/handler/operation-spec''). ''pattern'' -> (r value: ''system/tree/path'') } local: l store: s.
	self bindType: ''system/handler/manifest'' data: (EcVal map: {
		''name'' -> (EcVal text: ''system/handler/manifest'').
		''fields'' -> (EcVal map: {
			''expression_path'' -> (o value: ''system/tree/path''). ''internal_scope'' -> (self arro: ''system/capability/grant-entry'').
			''max_scope'' -> (self arro: ''system/capability/grant-entry''). ''name'' -> (r value: ''primitive/string'').
			''operations'' -> (m value: ''system/handler/operation-spec''). ''pattern'' -> (r value: ''system/tree/path'') }).
		''extends'' -> (EcVal text: ''system/handler/interface'') }) local: l store: s.
	self flds: ''system/handler/operation-spec'' fields: {
		''input_type'' -> (o value: ''system/type/name''). ''output_type'' -> (o value: ''system/type/name'') } local: l store: s.
	self flds: ''system/handler/register-request'' fields: {
		''manifest'' -> (r value: ''system/handler/manifest''). ''requested_scope'' -> (self arro: ''system/capability/grant-entry''). ''types'' -> (mo value: ''system/type'') } local: l store: s.
	self flds: ''system/handler/register-result'' fields: {
		''grant'' -> (r value: ''system/capability/token''). ''pattern'' -> (r value: ''system/tree/path'') } local: l store: s.

	"── tree (5) ──"
	self flds: ''system/tree/get-request'' fields: {
		''limit'' -> (o value: ''primitive/uint''). ''mode'' -> (o value: ''primitive/string''). ''offset'' -> (o value: ''primitive/uint''). ''tree_id'' -> (o value: ''primitive/string'') } local: l store: s.
	self flds: ''system/tree/put-request'' fields: {
		''entity'' -> (o value: ''core/entity''). ''expected_hash'' -> (o value: ''system/hash''). ''tree_id'' -> (o value: ''primitive/string'') } local: l store: s.
	self flds: ''system/tree/listing'' fields: {
		''count'' -> (r value: ''primitive/uint''). ''entries'' -> (m value: ''system/tree/listing-entry''). ''next_page'' -> (o value: ''system/hash'').
		''offset'' -> (r value: ''primitive/uint''). ''path'' -> (r value: ''system/tree/path'') } local: l store: s.
	self flds: ''system/tree/listing-entry'' fields: {
		''has_children'' -> (r value: ''primitive/bool''). ''hash'' -> (o value: ''system/hash'') } local: l store: s.
	self ext: ''system/tree/path'' base: ''primitive/string'' local: l store: s.

	"── type system (3) ──"
	self flds: ''system/type'' fields: {
		''extends'' -> (o value: ''system/type/name''). ''fields'' -> (mo value: ''system/type/field-spec''). ''layout'' -> (self arro: ''primitive/string'').
		''name'' -> (r value: ''system/type/name''). ''type_args'' -> (mo value: ''system/type/name''). ''type_params'' -> (self arro: ''primitive/string'') } local: l store: s.
	self flds: ''system/type/field-spec'' fields: {
		''array_of'' -> (o value: ''system/type/field-spec''). ''byte_size'' -> (o value: ''primitive/uint''). ''constraints'' -> (self arro: ''core/entity'').
		''default'' -> (o value: ''primitive/any''). ''key_type'' -> (o value: ''system/type/name''). ''map_of'' -> (o value: ''system/type/field-spec'').
		''optional'' -> (o value: ''primitive/bool''). ''type_args'' -> (mo value: ''system/type/name''). ''type_param'' -> (o value: ''primitive/string'').
		''type_ref'' -> (o value: ''system/type/name''). ''union_of'' -> (self arro: ''system/type/field-spec'') } local: l store: s.
	self ext: ''system/type/name'' base: ''primitive/string'' local: l store: s.

	"── bounds / limits / delivery / deletion (4) ──"
	self flds: ''system/bounds'' fields: {
		''budget'' -> (o value: ''primitive/uint''). ''cascade_depth'' -> (o value: ''primitive/uint''). ''chain_id'' -> (o value: ''primitive/string'').
		''parent_chain_id'' -> (o value: ''primitive/string''). ''ttl'' -> (o value: ''primitive/uint''). ''visited'' -> (self arro: ''system/tree/path'') } local: l store: s.
	self flds: ''system/resource-limits'' fields: {
		''max_budget'' -> (o value: ''primitive/uint''). ''max_ttl'' -> (o value: ''primitive/uint''). ''max_visited_length'' -> (o value: ''primitive/uint'') } local: l store: s.
	self flds: ''system/delivery-spec'' fields: {
		''operation'' -> (r value: ''primitive/string''). ''uri'' -> (r value: ''system/tree/path'') } local: l store: s.
	self nm: ''system/deletion-marker'' local: l store: s'.

'EntityCore-Peer:EcCoreTypes installed'
