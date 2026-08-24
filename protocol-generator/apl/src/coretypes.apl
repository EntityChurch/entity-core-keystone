⍝ entity-core-protocol-apl — src/coretypes.apl (§9.5 core-type floor — render-from-model).
⍝
⍝ Publishes the 53-type §9.5 core floor as system/type entities under the local namespace.
⍝ Each per-type `data` map is the in-code override table (the cross-impl type model, ported
⍝ from the cohort shapes); each entity's content_hash is computed by THIS peer's own
⍝ S2-green codec over {type,data} — render-from-model, NOT ingest-bytes (the durable
⍝ "render natively" lesson). Non-floor vocabularies are extension-owned and absent.
⍝ Canonical map-key ORDER is irrelevant (the codec sorts on encode, §4.2.1).
⍝ →-branch tradfns; gCtLocal carries the peer_id (single image).

CtCount←{53}

⍝ ── field-spec helpers ──
Ref←{VMapEmpty VmPut('type_ref')(VText ⍵)}
Refo←{(VMapEmpty VmPut('type_ref')(VText ⍵))VmPut('optional')(VBool 1)}
Arr←{VMapEmpty VmPut('array_of')(Ref ⍵)}
Arro←{(VMapEmpty VmPut('optional')(VBool 1))VmPut('array_of')(Ref ⍵)}
Mp←{VMapEmpty VmPut('map_of')(Ref ⍵)}
Mpo←{(VMapEmpty VmPut('optional')(VBool 1))VmPut('map_of')(Ref ⍵)}

⍝ ── bind helpers (use gCtLocal) ──
∇name BindType data
 ('/',gCtLocal,'/system/type/',name)StoreBind('system/type'EntMake data)
∇
∇Nm name
 name BindType(VMapEmpty VmPut('name')(VText name))
∇
∇base Ext name;d
 d←VMapEmpty VmPut('name')(VText name)
 d←d VmPut('extends')(VText base)
 name BindType d
∇
∇fields Flds name;d
 d←VMapEmpty VmPut('name')(VText name)
 d←d VmPut('fields')fields
 name BindType d
∇

∇CtPublish local;m;d;lay
 gCtLocal←local
 ⍝ primitives (8)
 Nm'primitive/any' ⋄ Nm'primitive/bool' ⋄ Nm'primitive/bytes' ⋄ Nm'primitive/float'
 Nm'primitive/int' ⋄ Nm'primitive/null' ⋄ Nm'primitive/string' ⋄ Nm'primitive/uint'
 ⍝ entity / envelope (5)
 m←VMapEmpty VmPut('data')(Ref'primitive/any') ⋄ m←m VmPut('type')(Ref'primitive/string')
 m Flds'entity'
 m←VMapEmpty VmPut('content_hash')(Ref'system/hash')
 m←m VmPut('data')(Ref'primitive/any') ⋄ m←m VmPut('type')(Ref'primitive/string')
 m Flds'core/entity'
 d←VMapEmpty VmPut('optional')(VBool 1) ⋄ d←d VmPut('map_of')(Ref'core/entity')
 d←d VmPut('key_type')(VText'system/hash')
 m←VMapEmpty VmPut('included')d ⋄ m←m VmPut('root')(Ref'core/entity')
 m Flds'core/envelope'
 'core/envelope'Ext'system/envelope'
 'core/envelope'Ext'system/protocol/envelope'
 ⍝ hash / peer / signature (4)
 d←VMapEmpty VmPut('type_ref')(VText'primitive/uint') ⋄ d←d VmPut('byte_size')(VUint 1)
 m←VMapEmpty VmPut('digest')(Ref'primitive/bytes') ⋄ m←m VmPut('format_code')d
 lay←(VArrEmpty VArrAdd VText'format_code')VArrAdd VText'digest'
 d←VMapEmpty VmPut('name')(VText'system/hash') ⋄ d←d VmPut('fields')m
 d←d VmPut('extends')(VText'primitive/bytes') ⋄ d←d VmPut('layout')lay
 'system/hash'BindType d
 m←VMapEmpty VmPut('key_type')(Ref'primitive/string') ⋄ m←m VmPut('peer_id')(Ref'system/peer-id')
 m←m VmPut('public_key')(Ref'primitive/bytes')
 m Flds'system/peer'
 'primitive/string'Ext'system/peer-id'
 m←VMapEmpty VmPut('algorithm')(Ref'primitive/string') ⋄ m←m VmPut('signature')(Ref'primitive/bytes')
 m←m VmPut('signer')(Ref'system/hash') ⋄ m←m VmPut('target')(Ref'system/hash')
 m Flds'system/signature'
 ⍝ connect (2)
 m←VMapEmpty VmPut('key_type')(Ref'primitive/string') ⋄ m←m VmPut('nonce')(Ref'primitive/bytes')
 m←m VmPut('peer_id')(Ref'system/peer-id') ⋄ m←m VmPut('public_key')(Ref'primitive/bytes')
 m Flds'system/protocol/connect/authenticate'
 m←VMapEmpty VmPut('compression')(Arro'primitive/string') ⋄ m←m VmPut('encryption')(Arro'primitive/string')
 m←m VmPut('hash_formats')(Arro'primitive/string') ⋄ m←m VmPut('key_types')(Arro'primitive/string')
 m←m VmPut('nonce')(Ref'primitive/bytes') ⋄ m←m VmPut('peer_id')(Ref'system/peer-id')
 m←m VmPut('protocols')(Arr'primitive/string') ⋄ m←m VmPut('timestamp')(Ref'primitive/uint')
 m Flds'system/protocol/connect/hello'
 ⍝ protocol error / execute / response / resource-target (4)
 m←VMapEmpty VmPut('code')(Ref'primitive/string') ⋄ m←m VmPut('message')(Refo'primitive/string')
 m←m VmPut('rejected_marker')(Refo'system/hash')
 m Flds'system/protocol/error'
 m←VMapEmpty VmPut('author')(Refo'system/hash') ⋄ m←m VmPut('bounds')(Refo'system/bounds')
 m←m VmPut('capability')(Refo'system/hash') ⋄ m←m VmPut('deliver_to')(Refo'system/delivery-spec')
 m←m VmPut('deliver_token')(Refo'system/hash') ⋄ m←m VmPut('durability_request')(Refo'system/durability-request')
 m←m VmPut('operation')(Ref'primitive/string') ⋄ m←m VmPut('params')(Ref'core/entity')
 m←m VmPut('request_id')(Ref'primitive/string') ⋄ m←m VmPut('resource')(Refo'system/protocol/resource-target')
 m←m VmPut('uri')(Ref'system/tree/path')
 m Flds'system/protocol/execute'
 m←VMapEmpty VmPut('durability')(Refo'system/durability-result') ⋄ m←m VmPut('request_id')(Ref'primitive/string')
 m←m VmPut('result')(Ref'core/entity') ⋄ m←m VmPut('status')(Ref'primitive/uint')
 m Flds'system/protocol/execute/response'
 m←VMapEmpty VmPut('exclude')(Arro'system/tree/path') ⋄ m←m VmPut('targets')(Arr'system/tree/path')
 m Flds'system/protocol/resource-target'
 ⍝ capability (11)
 (VMapEmpty VmPut('token')(Ref'system/hash'))Flds'system/capability/grant'
 m←VMapEmpty VmPut('allowances')(Mpo'primitive/any') ⋄ m←m VmPut('constraints')(Mpo'primitive/any')
 m←m VmPut('handlers')(Ref'system/capability/path-scope') ⋄ m←m VmPut('operations')(Ref'system/capability/id-scope')
 m←m VmPut('peers')(Refo'system/capability/id-scope') ⋄ m←m VmPut('resources')(Ref'system/capability/path-scope')
 m Flds'system/capability/grant-entry'
 m←VMapEmpty VmPut('exclude')(Arro'primitive/string') ⋄ m←m VmPut('include')(Arr'primitive/string')
 m Flds'system/capability/id-scope'
 m←VMapEmpty VmPut('exclude')(Arro'system/tree/path') ⋄ m←m VmPut('include')(Arr'system/tree/path')
 m Flds'system/capability/path-scope'
 m←VMapEmpty VmPut('grants')(Arr'system/capability/grant-entry') ⋄ m←m VmPut('ttl_ms')(Refo'primitive/uint')
 m Flds'system/capability/request'
 m←VMapEmpty VmPut('reason')(Refo'primitive/string') ⋄ m←m VmPut('revoked_at')(Ref'primitive/uint')
 m←m VmPut('token')(Ref'system/hash')
 m Flds'system/capability/revocation'
 m←VMapEmpty VmPut('reason')(Refo'primitive/string') ⋄ m←m VmPut('token')(Ref'system/hash')
 m Flds'system/capability/revoke-request'
 m←VMapEmpty VmPut('grants')(Arr'system/capability/grant-entry') ⋄ m←m VmPut('parent')(Ref'system/hash')
 m←m VmPut('ttl_ms')(Refo'primitive/uint')
 m Flds'system/capability/delegate-request'
 m←VMapEmpty VmPut('max_delegation_depth')(Refo'primitive/uint') ⋄ m←m VmPut('max_delegation_ttl')(Refo'primitive/uint')
 m←m VmPut('no_delegation')(Refo'primitive/bool')
 m Flds'system/capability/delegation-caveats'
 m←VMapEmpty VmPut('grants')(Arr'system/capability/grant-entry') ⋄ m←m VmPut('notes')(Refo'primitive/string')
 m←m VmPut('peer_pattern')(Ref'primitive/string') ⋄ m←m VmPut('ttl_ms')(Refo'primitive/uint')
 m Flds'system/capability/policy-entry'
 d←VMapEmpty VmPut('union_of')((VArrEmpty VArrAdd Ref'system/hash')VArrAdd Ref'system/capability/multi-granter')
 m←VMapEmpty VmPut('created_at')(Ref'primitive/uint') ⋄ m←m VmPut('delegation_caveats')(Refo'system/capability/delegation-caveats')
 m←m VmPut('expires_at')(Refo'primitive/uint') ⋄ m←m VmPut('grantee')(Ref'system/hash')
 m←m VmPut('granter')d ⋄ m←m VmPut('grants')(Arr'system/capability/grant-entry')
 m←m VmPut('not_before')(Refo'primitive/uint') ⋄ m←m VmPut('parent')(Refo'system/hash')
 m←m VmPut('resource_limits')(Refo'system/resource-limits')
 m Flds'system/capability/token'
 m←VMapEmpty VmPut('signers')(Arr'system/hash') ⋄ m←m VmPut('threshold')(Ref'primitive/uint')
 m Flds'system/capability/multi-granter'
 ⍝ handler (6)
 m←VMapEmpty VmPut('expression_path')(Refo'system/tree/path') ⋄ m←m VmPut('interface')(Ref'system/tree/path')
 m←m VmPut('internal_scope')(Arro'system/capability/grant-entry') ⋄ m←m VmPut('max_scope')(Arro'system/capability/grant-entry')
 m Flds'system/handler'
 m←VMapEmpty VmPut('name')(Ref'primitive/string') ⋄ m←m VmPut('operations')(Mp'system/handler/operation-spec')
 m←m VmPut('pattern')(Ref'system/tree/path')
 m Flds'system/handler/interface'
 m←VMapEmpty VmPut('expression_path')(Refo'system/tree/path') ⋄ m←m VmPut('internal_scope')(Arro'system/capability/grant-entry')
 m←m VmPut('max_scope')(Arro'system/capability/grant-entry') ⋄ m←m VmPut('name')(Ref'primitive/string')
 m←m VmPut('operations')(Mp'system/handler/operation-spec') ⋄ m←m VmPut('pattern')(Ref'system/tree/path')
 d←VMapEmpty VmPut('name')(VText'system/handler/manifest') ⋄ d←d VmPut('fields')m
 d←d VmPut('extends')(VText'system/handler/interface')
 'system/handler/manifest'BindType d
 m←VMapEmpty VmPut('input_type')(Refo'system/type/name') ⋄ m←m VmPut('output_type')(Refo'system/type/name')
 m Flds'system/handler/operation-spec'
 m←VMapEmpty VmPut('manifest')(Ref'system/handler/manifest') ⋄ m←m VmPut('requested_scope')(Arro'system/capability/grant-entry')
 m←m VmPut('types')(Mpo'system/type')
 m Flds'system/handler/register-request'
 m←VMapEmpty VmPut('grant')(Ref'system/capability/token') ⋄ m←m VmPut('pattern')(Ref'system/tree/path')
 m Flds'system/handler/register-result'
 ⍝ tree (5)
 m←VMapEmpty VmPut('limit')(Refo'primitive/uint') ⋄ m←m VmPut('mode')(Refo'primitive/string')
 m←m VmPut('offset')(Refo'primitive/uint') ⋄ m←m VmPut('tree_id')(Refo'primitive/string')
 m Flds'system/tree/get-request'
 m←VMapEmpty VmPut('entity')(Refo'core/entity') ⋄ m←m VmPut('expected_hash')(Refo'system/hash')
 m←m VmPut('tree_id')(Refo'primitive/string')
 m Flds'system/tree/put-request'
 m←VMapEmpty VmPut('count')(Ref'primitive/uint') ⋄ m←m VmPut('entries')(Mp'system/tree/listing-entry')
 m←m VmPut('next_page')(Refo'system/hash') ⋄ m←m VmPut('offset')(Ref'primitive/uint')
 m←m VmPut('path')(Ref'system/tree/path')
 m Flds'system/tree/listing'
 m←VMapEmpty VmPut('has_children')(Ref'primitive/bool') ⋄ m←m VmPut('hash')(Refo'system/hash')
 m Flds'system/tree/listing-entry'
 'primitive/string'Ext'system/tree/path'
 ⍝ type system (3)
 m←VMapEmpty VmPut('extends')(Refo'system/type/name') ⋄ m←m VmPut('fields')(Mpo'system/type/field-spec')
 m←m VmPut('layout')(Arro'primitive/string') ⋄ m←m VmPut('name')(Ref'system/type/name')
 m←m VmPut('type_args')(Mpo'system/type/name') ⋄ m←m VmPut('type_params')(Arro'primitive/string')
 m Flds'system/type'
 m←VMapEmpty VmPut('array_of')(Refo'system/type/field-spec') ⋄ m←m VmPut('byte_size')(Refo'primitive/uint')
 m←m VmPut('constraints')(Arro'core/entity') ⋄ m←m VmPut('default')(Refo'primitive/any')
 m←m VmPut('key_type')(Refo'system/type/name') ⋄ m←m VmPut('map_of')(Refo'system/type/field-spec')
 m←m VmPut('optional')(Refo'primitive/bool') ⋄ m←m VmPut('type_args')(Mpo'system/type/name')
 m←m VmPut('type_param')(Refo'primitive/string') ⋄ m←m VmPut('type_ref')(Refo'system/type/name')
 m←m VmPut('union_of')(Arro'system/type/field-spec')
 m Flds'system/type/field-spec'
 'primitive/string'Ext'system/type/name'
 ⍝ bounds / limits / delivery / deletion (5)
 m←VMapEmpty VmPut('budget')(Refo'primitive/uint') ⋄ m←m VmPut('cascade_depth')(Refo'primitive/uint')
 m←m VmPut('chain_id')(Refo'primitive/string') ⋄ m←m VmPut('parent_chain_id')(Refo'primitive/string')
 m←m VmPut('ttl')(Refo'primitive/uint') ⋄ m←m VmPut('visited')(Arro'system/tree/path')
 m Flds'system/bounds'
 m←VMapEmpty VmPut('max_budget')(Refo'primitive/uint') ⋄ m←m VmPut('max_ttl')(Refo'primitive/uint')
 m←m VmPut('max_visited_length')(Refo'primitive/uint')
 m Flds'system/resource-limits'
 m←VMapEmpty VmPut('operation')(Ref'primitive/string') ⋄ m←m VmPut('uri')(Ref'system/tree/path')
 m Flds'system/delivery-spec'
 Nm'system/deletion-marker'
∇
