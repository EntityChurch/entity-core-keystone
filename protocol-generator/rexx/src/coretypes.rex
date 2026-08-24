/* entity-core-protocol-rexx — core type floor (§9.5) — render-from-model.
 *
 * Publishes the FULL 53-type §9.5 core floor as system/type entities under the local
 * namespace. The per-type `data` maps are the in-code override table (the cross-impl
 * type model, ported field-for-field from the cohort shapes); each entity's
 * content_hash is computed by THIS peer's S2-green codec over {type, data}
 * (render-from-model, NOT ingest-bytes) — the surface the oracle's type_system
 * category fetches at system/type/<name>. Non-floor vocabularies are extension-owned
 * and intentionally absent.
 *
 * The canonical map-key ORDER is irrelevant here (the codec sorts on encode, §4.2.1),
 * so field-spec maps are built in any order; only the logical content must match.
 * Field-spec helpers keep the 53 definitions terse and unambiguous (no auto-classify).
 */

/* ── field-spec helpers ── */
CtRef: procedure expose EC.                    /* {type_ref: X} */
  parse arg x
  return Ecf_Map('type_ref', Ecf_Str(x))
CtRefO: procedure expose EC.                   /* {type_ref: X, optional: true} */
  parse arg x
  return Ecf_Map('type_ref', Ecf_Str(x), 'optional', 'R')
CtArrO: procedure expose EC.                   /* {optional: true, array_of: {type_ref: X}} */
  parse arg x
  return Ecf_Map('optional', 'R', 'array_of', CtRef(x))
CtArr: procedure expose EC.                    /* {array_of: {type_ref: X}} */
  parse arg x
  return Ecf_Map('array_of', CtRef(x))
CtMapO: procedure expose EC.                   /* {optional: true, map_of: {type_ref: X}} */
  parse arg x
  return Ecf_Map('optional', 'R', 'map_of', CtRef(x))
CtMap: procedure expose EC.                    /* {map_of: {type_ref: X}} */
  parse arg x
  return Ecf_Map('map_of', CtRef(x))

/* bind one system/type entity for name+data at /{peer}/system/type/{name}. */
_ct_bind: procedure expose EC.
  parse arg store_h, local, name, data
  call Store_Bind store_h, '/' || local || '/system/type/' || name, Ent_Make('system/type', data)
  return

/* the trivial `{name: X}` model (a primitive / string-newtype). */
_ct_nm: procedure expose EC.
  parse arg store_h, local, name
  call _ct_bind store_h, local, name, Ecf_Map('name', Ecf_Str(name))
  return
/* `{name: X, extends: Y}`. */
_ct_ext: procedure expose EC.
  parse arg store_h, local, name, base
  call _ct_bind store_h, local, name, Ecf_Map('name', Ecf_Str(name), 'extends', Ecf_Str(base))
  return
/* `{name: X, fields: F}`. */
_ct_flds: procedure expose EC.
  parse arg store_h, local, name, fields
  call _ct_bind store_h, local, name, Ecf_Map('name', Ecf_Str(name), 'fields', fields)
  return

Ct_Count: procedure
  return 53

/* publish every core type at /{peer}/system/type/{name}. */
Ct_Publish: procedure expose EC.
  parse arg store_h, local
  s = store_h; L = local

  /* primitives */
  call _ct_nm s, L, 'primitive/any'
  call _ct_nm s, L, 'primitive/bool'
  call _ct_nm s, L, 'primitive/bytes'
  call _ct_nm s, L, 'primitive/float'
  call _ct_nm s, L, 'primitive/int'
  call _ct_nm s, L, 'primitive/null'
  call _ct_nm s, L, 'primitive/string'
  call _ct_nm s, L, 'primitive/uint'

  /* entity / envelope */
  call _ct_flds s, L, 'entity', Ecf_Map('data', CtRef('primitive/any'), 'type', CtRef('primitive/string'))
  call _ct_flds s, L, 'core/entity', Ecf_Map('content_hash', CtRef('system/hash'), 'data', CtRef('primitive/any'), 'type', CtRef('primitive/string'))
  call _ct_flds s, L, 'core/envelope', Ecf_Map('included', Ecf_Map('optional', 'R', 'map_of', CtRef('core/entity'), 'key_type', Ecf_Str('system/hash')), 'root', CtRef('core/entity'))
  call _ct_ext s, L, 'system/envelope', 'core/envelope'
  call _ct_ext s, L, 'system/protocol/envelope', 'core/envelope'

  /* hash / peer / signature */
  d = Ecf_Map('digest', CtRef('primitive/bytes'), 'format_code', Ecf_Map('type_ref', Ecf_Str('primitive/uint'), 'byte_size', Ecf_Int(1)))
  lay = Lst_Add(Lst_Add('', 'format_code'), 'digest')
  call _ct_bind s, L, 'system/hash', Ecf_Map('name', Ecf_Str('system/hash'), 'fields', d, 'extends', Ecf_Str('primitive/bytes'), 'layout', Ecf_TextArray(lay))
  call _ct_flds s, L, 'system/peer', Ecf_Map('key_type', CtRef('primitive/string'), 'peer_id', CtRef('system/peer-id'), 'public_key', CtRef('primitive/bytes'))
  call _ct_ext s, L, 'system/peer-id', 'primitive/string'
  call _ct_flds s, L, 'system/signature', Ecf_Map('algorithm', CtRef('primitive/string'), 'signature', CtRef('primitive/bytes'), 'signer', CtRef('system/hash'), 'target', CtRef('system/hash'))

  /* connect */
  call _ct_flds s, L, 'system/protocol/connect/authenticate', Ecf_Map('key_type', CtRef('primitive/string'), 'nonce', CtRef('primitive/bytes'), 'peer_id', CtRef('system/peer-id'), 'public_key', CtRef('primitive/bytes'))
  hf = Ecf_Map('compression', CtArrO('primitive/string'), 'encryption', CtArrO('primitive/string'), 'hash_formats', CtArrO('primitive/string'), 'key_types', CtArrO('primitive/string'))
  hf = Ecf_MapPut(hf, 'nonce', CtRef('primitive/bytes'))
  hf = Ecf_MapPut(hf, 'peer_id', CtRef('system/peer-id'))
  hf = Ecf_MapPut(hf, 'protocols', CtArr('primitive/string'))
  hf = Ecf_MapPut(hf, 'timestamp', CtRef('primitive/uint'))
  call _ct_flds s, L, 'system/protocol/connect/hello', hf

  /* protocol error / execute / response / resource-target */
  call _ct_flds s, L, 'system/protocol/error', Ecf_Map('code', CtRef('primitive/string'), 'message', CtRefO('primitive/string'), 'rejected_marker', CtRefO('system/hash'))
  ex = Ecf_Map('author', CtRefO('system/hash'), 'bounds', CtRefO('system/bounds'), 'capability', CtRefO('system/hash'), 'deliver_to', CtRefO('system/delivery-spec'))
  ex = Ecf_MapPut(ex, 'deliver_token', CtRefO('system/hash'))
  ex = Ecf_MapPut(ex, 'durability_request', CtRefO('system/durability-request'))
  ex = Ecf_MapPut(ex, 'operation', CtRef('primitive/string'))
  ex = Ecf_MapPut(ex, 'params', CtRef('core/entity'))
  ex = Ecf_MapPut(ex, 'request_id', CtRef('primitive/string'))
  ex = Ecf_MapPut(ex, 'resource', CtRefO('system/protocol/resource-target'))
  ex = Ecf_MapPut(ex, 'uri', CtRef('system/tree/path'))
  call _ct_flds s, L, 'system/protocol/execute', ex
  call _ct_flds s, L, 'system/protocol/execute/response', Ecf_Map('durability', CtRefO('system/durability-result'), 'request_id', CtRef('primitive/string'), 'result', CtRef('core/entity'), 'status', CtRef('primitive/uint'))
  call _ct_flds s, L, 'system/protocol/resource-target', Ecf_Map('exclude', CtArrO('system/tree/path'), 'targets', CtArr('system/tree/path'))

  /* capability */
  call _ct_flds s, L, 'system/capability/grant', Ecf_Map('token', CtRef('system/hash'))
  ge = Ecf_Map('allowances', CtMapO('primitive/any'), 'constraints', CtMapO('primitive/any'), 'handlers', CtRef('system/capability/path-scope'), 'operations', CtRef('system/capability/id-scope'))
  ge = Ecf_MapPut(ge, 'peers', CtRefO('system/capability/id-scope'))
  ge = Ecf_MapPut(ge, 'resources', CtRef('system/capability/path-scope'))
  call _ct_flds s, L, 'system/capability/grant-entry', ge
  call _ct_flds s, L, 'system/capability/id-scope', Ecf_Map('exclude', CtArrO('primitive/string'), 'include', CtArr('primitive/string'))
  call _ct_flds s, L, 'system/capability/path-scope', Ecf_Map('exclude', CtArrO('system/tree/path'), 'include', CtArr('system/tree/path'))
  call _ct_flds s, L, 'system/capability/request', Ecf_Map('grants', CtArr('system/capability/grant-entry'), 'ttl_ms', CtRefO('primitive/uint'))
  call _ct_flds s, L, 'system/capability/revocation', Ecf_Map('reason', CtRefO('primitive/string'), 'revoked_at', CtRef('primitive/uint'), 'token', CtRef('system/hash'))
  call _ct_flds s, L, 'system/capability/revoke-request', Ecf_Map('reason', CtRefO('primitive/string'), 'token', CtRef('system/hash'))
  call _ct_flds s, L, 'system/capability/delegate-request', Ecf_Map('grants', CtArr('system/capability/grant-entry'), 'parent', CtRef('system/hash'), 'ttl_ms', CtRefO('primitive/uint'))
  call _ct_flds s, L, 'system/capability/delegation-caveats', Ecf_Map('max_delegation_depth', CtRefO('primitive/uint'), 'max_delegation_ttl', CtRefO('primitive/uint'), 'no_delegation', CtRefO('primitive/bool'))
  call _ct_flds s, L, 'system/capability/policy-entry', Ecf_Map('grants', CtArr('system/capability/grant-entry'), 'notes', CtRefO('primitive/string'), 'peer_pattern', CtRef('primitive/string'), 'ttl_ms', CtRefO('primitive/uint'))
  gr_union = Ecf_Map('union_of', Ecf_Array(Lst_Add(Lst_Add('', CtRef('system/hash')), CtRef('system/capability/multi-granter'))))
  tk = Ecf_Map('created_at', CtRef('primitive/uint'), 'delegation_caveats', CtRefO('system/capability/delegation-caveats'), 'expires_at', CtRefO('primitive/uint'), 'grantee', CtRef('system/hash'))
  tk = Ecf_MapPut(tk, 'granter', gr_union)
  tk = Ecf_MapPut(tk, 'grants', CtArr('system/capability/grant-entry'))
  tk = Ecf_MapPut(tk, 'not_before', CtRefO('primitive/uint'))
  tk = Ecf_MapPut(tk, 'parent', CtRefO('system/hash'))
  tk = Ecf_MapPut(tk, 'resource_limits', CtRefO('system/resource-limits'))
  call _ct_flds s, L, 'system/capability/token', tk
  call _ct_flds s, L, 'system/capability/multi-granter', Ecf_Map('signers', CtArr('system/hash'), 'threshold', CtRef('primitive/uint'))

  /* handler */
  call _ct_flds s, L, 'system/handler', Ecf_Map('expression_path', CtRefO('system/tree/path'), 'interface', CtRef('system/tree/path'), 'internal_scope', CtArrO('system/capability/grant-entry'), 'max_scope', CtArrO('system/capability/grant-entry'))
  call _ct_flds s, L, 'system/handler/interface', Ecf_Map('name', CtRef('primitive/string'), 'operations', CtMap('system/handler/operation-spec'), 'pattern', CtRef('system/tree/path'))
  mf = Ecf_Map('expression_path', CtRefO('system/tree/path'), 'internal_scope', CtArrO('system/capability/grant-entry'), 'max_scope', CtArrO('system/capability/grant-entry'), 'name', CtRef('primitive/string'))
  mf = Ecf_MapPut(mf, 'operations', CtMap('system/handler/operation-spec'))
  mf = Ecf_MapPut(mf, 'pattern', CtRef('system/tree/path'))
  call _ct_bind s, L, 'system/handler/manifest', Ecf_Map('name', Ecf_Str('system/handler/manifest'), 'fields', mf, 'extends', Ecf_Str('system/handler/interface'))
  call _ct_flds s, L, 'system/handler/operation-spec', Ecf_Map('input_type', CtRefO('system/type/name'), 'output_type', CtRefO('system/type/name'))
  call _ct_flds s, L, 'system/handler/register-request', Ecf_Map('manifest', CtRef('system/handler/manifest'), 'requested_scope', CtArrO('system/capability/grant-entry'), 'types', CtMapO('system/type'))
  call _ct_flds s, L, 'system/handler/register-result', Ecf_Map('grant', CtRef('system/capability/token'), 'pattern', CtRef('system/tree/path'))

  /* tree */
  call _ct_flds s, L, 'system/tree/get-request', Ecf_Map('limit', CtRefO('primitive/uint'), 'mode', CtRefO('primitive/string'), 'offset', CtRefO('primitive/uint'), 'tree_id', CtRefO('primitive/string'))
  call _ct_flds s, L, 'system/tree/put-request', Ecf_Map('entity', CtRefO('core/entity'), 'expected_hash', CtRefO('system/hash'), 'tree_id', CtRefO('primitive/string'))
  call _ct_flds s, L, 'system/tree/listing', Ecf_Map('count', CtRef('primitive/uint'), 'entries', CtMap('system/tree/listing-entry'), 'next_page', CtRefO('system/hash'), 'offset', CtRef('primitive/uint'), 'path', CtRef('system/tree/path'))
  call _ct_flds s, L, 'system/tree/listing-entry', Ecf_Map('has_children', CtRef('primitive/bool'), 'hash', CtRefO('system/hash'))
  call _ct_ext s, L, 'system/tree/path', 'primitive/string'

  /* type system */
  ty = Ecf_Map('extends', CtRefO('system/type/name'), 'fields', CtMapO('system/type/field-spec'), 'layout', CtArrO('primitive/string'), 'name', CtRef('system/type/name'))
  ty = Ecf_MapPut(ty, 'type_args', CtMapO('system/type/name'))
  ty = Ecf_MapPut(ty, 'type_params', CtArrO('primitive/string'))
  call _ct_flds s, L, 'system/type', ty
  fs = Ecf_Map('array_of', CtRefO('system/type/field-spec'), 'byte_size', CtRefO('primitive/uint'), 'constraints', CtArrO('core/entity'), 'default', CtRefO('primitive/any'))
  fs = Ecf_MapPut(fs, 'key_type', CtRefO('system/type/name'))
  fs = Ecf_MapPut(fs, 'map_of', CtRefO('system/type/field-spec'))
  fs = Ecf_MapPut(fs, 'optional', CtRefO('primitive/bool'))
  fs = Ecf_MapPut(fs, 'type_args', CtMapO('system/type/name'))
  fs = Ecf_MapPut(fs, 'type_param', CtRefO('primitive/string'))
  fs = Ecf_MapPut(fs, 'type_ref', CtRefO('system/type/name'))
  fs = Ecf_MapPut(fs, 'union_of', CtArrO('system/type/field-spec'))
  call _ct_flds s, L, 'system/type/field-spec', fs
  call _ct_ext s, L, 'system/type/name', 'primitive/string'

  /* bounds / limits / delivery / deletion */
  bd = Ecf_Map('budget', CtRefO('primitive/uint'), 'cascade_depth', CtRefO('primitive/uint'), 'chain_id', CtRefO('primitive/string'), 'parent_chain_id', CtRefO('primitive/string'))
  bd = Ecf_MapPut(bd, 'ttl', CtRefO('primitive/uint'))
  bd = Ecf_MapPut(bd, 'visited', CtArrO('system/tree/path'))
  call _ct_flds s, L, 'system/bounds', bd
  call _ct_flds s, L, 'system/resource-limits', Ecf_Map('max_budget', CtRefO('primitive/uint'), 'max_ttl', CtRefO('primitive/uint'), 'max_visited_length', CtRefO('primitive/uint'))
  call _ct_flds s, L, 'system/delivery-spec', Ecf_Map('operation', CtRef('primitive/string'), 'uri', CtRef('system/tree/path'))
  call _ct_nm s, L, 'system/deletion-marker'
  return
