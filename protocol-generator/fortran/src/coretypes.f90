! entity-core-protocol-fortran — src/coretypes.f90 (§9.5 core type floor — render-from-model).
!
! Publishes the full 53-type §9.5 core floor as system/type entities under the local
! namespace. The per-type `data` maps are the in-code override table (the cross-impl type
! model, ported field-for-field from the cohort shapes); each entity's content_hash is
! computed by THIS peer's own S2-green codec over {type, data} (render-from-model, NOT
! ingest-bytes — the durable "render natively" lesson), so the surface the oracle's
! type_system category fetches at system/type/<name> is single-sourced in code. Non-floor
! vocabularies are extension-owned and intentionally absent. Canonical map-key ORDER is
! irrelevant (the codec sorts on encode, §4.2.1), so field-spec maps are built in any order.
module entity_core_coretypes
  use, intrinsic :: iso_fortran_env, only : int64
  use entity_core_cbor, only : ecf_value_t
  use entity_core_val
  use entity_core_ent
  use entity_core_store
  implicit none
  private

  public :: ct_publish, ct_count

contains

  integer function ct_count(); ct_count = 53; end function ct_count

  ! ── field-spec helpers ──
  function ref(x) result(v)
    character(len=*), intent(in) :: x
    type(ecf_value_t) :: v
    v = v_map_put(v_map_empty(), 'type_ref', v_text(x))
  end function ref
  function refo(x) result(v)
    character(len=*), intent(in) :: x
    type(ecf_value_t) :: v
    v = v_map_put(v_map_put(v_map_empty(), 'type_ref', v_text(x)), 'optional', v_bool(.true.))
  end function refo
  function arr(x) result(v)
    character(len=*), intent(in) :: x
    type(ecf_value_t) :: v
    v = v_map_put(v_map_empty(), 'array_of', ref(x))
  end function arr
  function arro(x) result(v)
    character(len=*), intent(in) :: x
    type(ecf_value_t) :: v
    v = v_map_put(v_map_put(v_map_empty(), 'optional', v_bool(.true.)), 'array_of', ref(x))
  end function arro
  function mp(x) result(v)
    character(len=*), intent(in) :: x
    type(ecf_value_t) :: v
    v = v_map_put(v_map_empty(), 'map_of', ref(x))
  end function mp
  function mpo(x) result(v)
    character(len=*), intent(in) :: x
    type(ecf_value_t) :: v
    v = v_map_put(v_map_put(v_map_empty(), 'optional', v_bool(.true.)), 'map_of', ref(x))
  end function mpo

  ! ── bind helpers ──
  subroutine bind_type(s, local, name, data)
    type(store_t),     intent(inout) :: s
    character(len=*),  intent(in)    :: local, name
    type(ecf_value_t), intent(in)    :: data
    call store_bind(s, '/' // trim(local) // '/system/type/' // name, ent_make('system/type', data))
  end subroutine bind_type

  subroutine nm(s, local, name)             ! {name: X}
    type(store_t),    intent(inout) :: s
    character(len=*), intent(in)    :: local, name
    call bind_type(s, local, name, v_map_put(v_map_empty(), 'name', v_text(name)))
  end subroutine nm
  subroutine ext(s, local, name, base)      ! {name, extends}
    type(store_t),    intent(inout) :: s
    character(len=*), intent(in)    :: local, name, base
    type(ecf_value_t) :: d
    d = v_map_put(v_map_put(v_map_empty(), 'name', v_text(name)), 'extends', v_text(base))
    call bind_type(s, local, name, d)
  end subroutine ext
  subroutine flds(s, local, name, fields)   ! {name, fields}
    type(store_t),     intent(inout) :: s
    character(len=*),  intent(in)    :: local, name
    type(ecf_value_t), intent(in)    :: fields
    type(ecf_value_t) :: d
    d = v_map_put(v_map_put(v_map_empty(), 'name', v_text(name)), 'fields', fields)
    call bind_type(s, local, name, d)
  end subroutine flds

  subroutine ct_publish(s, local)
    type(store_t),    intent(inout) :: s
    character(len=*), intent(in)    :: local
    type(ecf_value_t) :: m, d, lay

    ! primitives (8)
    call nm(s, local, 'primitive/any')
    call nm(s, local, 'primitive/bool')
    call nm(s, local, 'primitive/bytes')
    call nm(s, local, 'primitive/float')
    call nm(s, local, 'primitive/int')
    call nm(s, local, 'primitive/null')
    call nm(s, local, 'primitive/string')
    call nm(s, local, 'primitive/uint')

    ! entity / envelope (5)
    m = v_map_put(v_map_put(v_map_empty(), 'data', ref('primitive/any')), 'type', ref('primitive/string'))
    call flds(s, local, 'entity', m)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'content_hash', ref('system/hash')), &
        'data', ref('primitive/any')), 'type', ref('primitive/string'))
    call flds(s, local, 'core/entity', m)
    d = v_map_put(v_map_put(v_map_put(v_map_empty(), 'optional', v_bool(.true.)), 'map_of', ref('core/entity')), &
        'key_type', v_text('system/hash'))
    m = v_map_put(v_map_put(v_map_empty(), 'included', d), 'root', ref('core/entity'))
    call flds(s, local, 'core/envelope', m)
    call ext(s, local, 'system/envelope', 'core/envelope')
    call ext(s, local, 'system/protocol/envelope', 'core/envelope')

    ! hash / peer / signature (4)
    d = v_map_put(v_map_put(v_map_empty(), 'type_ref', v_text('primitive/uint')), 'byte_size', v_uint(1_int64))
    m = v_map_put(v_map_empty(), 'digest', ref('primitive/bytes'))
    m = v_map_put(m, 'format_code', d)
    lay = v_arr_add(v_arr_add(v_arr_empty(), v_text('format_code')), v_text('digest'))
    d = v_map_put(v_map_put(v_map_put(v_map_put(v_map_empty(), 'name', v_text('system/hash')), &
        'fields', m), 'extends', v_text('primitive/bytes')), 'layout', lay)
    call bind_type(s, local, 'system/hash', d)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'key_type', ref('primitive/string')), &
        'peer_id', ref('system/peer-id')), 'public_key', ref('primitive/bytes'))
    call flds(s, local, 'system/peer', m)
    call ext(s, local, 'system/peer-id', 'primitive/string')
    m = v_map_put(v_map_put(v_map_put(v_map_put(v_map_empty(), 'algorithm', ref('primitive/string')), &
        'signature', ref('primitive/bytes')), 'signer', ref('system/hash')), 'target', ref('system/hash'))
    call flds(s, local, 'system/signature', m)

    ! connect (2)
    m = v_map_put(v_map_put(v_map_put(v_map_put(v_map_empty(), 'key_type', ref('primitive/string')), &
        'nonce', ref('primitive/bytes')), 'peer_id', ref('system/peer-id')), 'public_key', ref('primitive/bytes'))
    call flds(s, local, 'system/protocol/connect/authenticate', m)
    m = v_map_put(v_map_empty(), 'compression', arro('primitive/string'))
    m = v_map_put(m, 'encryption', arro('primitive/string'))
    m = v_map_put(m, 'hash_formats', arro('primitive/string'))
    m = v_map_put(m, 'key_types', arro('primitive/string'))
    m = v_map_put(m, 'nonce', ref('primitive/bytes'))
    m = v_map_put(m, 'peer_id', ref('system/peer-id'))
    m = v_map_put(m, 'protocols', arr('primitive/string'))
    m = v_map_put(m, 'timestamp', ref('primitive/uint'))
    call flds(s, local, 'system/protocol/connect/hello', m)

    ! protocol error / execute / response / resource-target (4)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'code', ref('primitive/string')), &
        'message', refo('primitive/string')), 'rejected_marker', refo('system/hash'))
    call flds(s, local, 'system/protocol/error', m)
    m = v_map_put(v_map_empty(), 'author', refo('system/hash'))
    m = v_map_put(m, 'bounds', refo('system/bounds'))
    m = v_map_put(m, 'capability', refo('system/hash'))
    m = v_map_put(m, 'deliver_to', refo('system/delivery-spec'))
    m = v_map_put(m, 'deliver_token', refo('system/hash'))
    m = v_map_put(m, 'durability_request', refo('system/durability-request'))
    m = v_map_put(m, 'operation', ref('primitive/string'))
    m = v_map_put(m, 'params', ref('core/entity'))
    m = v_map_put(m, 'request_id', ref('primitive/string'))
    m = v_map_put(m, 'resource', refo('system/protocol/resource-target'))
    m = v_map_put(m, 'uri', ref('system/tree/path'))
    call flds(s, local, 'system/protocol/execute', m)
    m = v_map_put(v_map_put(v_map_put(v_map_put(v_map_empty(), 'durability', refo('system/durability-result')), &
        'request_id', ref('primitive/string')), 'result', ref('core/entity')), 'status', ref('primitive/uint'))
    call flds(s, local, 'system/protocol/execute/response', m)
    m = v_map_put(v_map_put(v_map_empty(), 'exclude', arro('system/tree/path')), 'targets', arr('system/tree/path'))
    call flds(s, local, 'system/protocol/resource-target', m)

    ! capability (11)
    call flds(s, local, 'system/capability/grant', v_map_put(v_map_empty(), 'token', ref('system/hash')))
    m = v_map_put(v_map_empty(), 'allowances', mpo('primitive/any'))
    m = v_map_put(m, 'constraints', mpo('primitive/any'))
    m = v_map_put(m, 'handlers', ref('system/capability/path-scope'))
    m = v_map_put(m, 'operations', ref('system/capability/id-scope'))
    m = v_map_put(m, 'peers', refo('system/capability/id-scope'))
    m = v_map_put(m, 'resources', ref('system/capability/path-scope'))
    call flds(s, local, 'system/capability/grant-entry', m)
    m = v_map_put(v_map_put(v_map_empty(), 'exclude', arro('primitive/string')), 'include', arr('primitive/string'))
    call flds(s, local, 'system/capability/id-scope', m)
    m = v_map_put(v_map_put(v_map_empty(), 'exclude', arro('system/tree/path')), 'include', arr('system/tree/path'))
    call flds(s, local, 'system/capability/path-scope', m)
    m = v_map_put(v_map_put(v_map_empty(), 'grants', arr('system/capability/grant-entry')), 'ttl_ms', refo('primitive/uint'))
    call flds(s, local, 'system/capability/request', m)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'reason', refo('primitive/string')), &
        'revoked_at', ref('primitive/uint')), 'token', ref('system/hash'))
    call flds(s, local, 'system/capability/revocation', m)
    m = v_map_put(v_map_put(v_map_empty(), 'reason', refo('primitive/string')), 'token', ref('system/hash'))
    call flds(s, local, 'system/capability/revoke-request', m)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'grants', arr('system/capability/grant-entry')), &
        'parent', ref('system/hash')), 'ttl_ms', refo('primitive/uint'))
    call flds(s, local, 'system/capability/delegate-request', m)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'max_delegation_depth', refo('primitive/uint')), &
        'max_delegation_ttl', refo('primitive/uint')), 'no_delegation', refo('primitive/bool'))
    call flds(s, local, 'system/capability/delegation-caveats', m)
    m = v_map_put(v_map_empty(), 'grants', arr('system/capability/grant-entry'))
    m = v_map_put(m, 'notes', refo('primitive/string'))
    m = v_map_put(m, 'peer_pattern', ref('primitive/string'))
    m = v_map_put(m, 'ttl_ms', refo('primitive/uint'))
    call flds(s, local, 'system/capability/policy-entry', m)
    d = v_map_put(v_map_empty(), 'union_of', v_arr_add(v_arr_add(v_arr_empty(), ref('system/hash')), ref('system/capability/multi-granter')))
    m = v_map_put(v_map_empty(), 'created_at', ref('primitive/uint'))
    m = v_map_put(m, 'delegation_caveats', refo('system/capability/delegation-caveats'))
    m = v_map_put(m, 'expires_at', refo('primitive/uint'))
    m = v_map_put(m, 'grantee', ref('system/hash'))
    m = v_map_put(m, 'granter', d)
    m = v_map_put(m, 'grants', arr('system/capability/grant-entry'))
    m = v_map_put(m, 'not_before', refo('primitive/uint'))
    m = v_map_put(m, 'parent', refo('system/hash'))
    m = v_map_put(m, 'resource_limits', refo('system/resource-limits'))
    call flds(s, local, 'system/capability/token', m)
    m = v_map_put(v_map_put(v_map_empty(), 'signers', arr('system/hash')), 'threshold', ref('primitive/uint'))
    call flds(s, local, 'system/capability/multi-granter', m)

    ! handler (6)
    m = v_map_put(v_map_put(v_map_put(v_map_put(v_map_empty(), 'expression_path', refo('system/tree/path')), &
        'interface', ref('system/tree/path')), 'internal_scope', arro('system/capability/grant-entry')), &
        'max_scope', arro('system/capability/grant-entry'))
    call flds(s, local, 'system/handler', m)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'name', ref('primitive/string')), &
        'operations', mp('system/handler/operation-spec')), 'pattern', ref('system/tree/path'))
    call flds(s, local, 'system/handler/interface', m)
    m = v_map_put(v_map_empty(), 'expression_path', refo('system/tree/path'))
    m = v_map_put(m, 'internal_scope', arro('system/capability/grant-entry'))
    m = v_map_put(m, 'max_scope', arro('system/capability/grant-entry'))
    m = v_map_put(m, 'name', ref('primitive/string'))
    m = v_map_put(m, 'operations', mp('system/handler/operation-spec'))
    m = v_map_put(m, 'pattern', ref('system/tree/path'))
    d = v_map_put(v_map_put(v_map_put(v_map_empty(), 'name', v_text('system/handler/manifest')), &
        'fields', m), 'extends', v_text('system/handler/interface'))
    call bind_type(s, local, 'system/handler/manifest', d)
    m = v_map_put(v_map_put(v_map_empty(), 'input_type', refo('system/type/name')), 'output_type', refo('system/type/name'))
    call flds(s, local, 'system/handler/operation-spec', m)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'manifest', ref('system/handler/manifest')), &
        'requested_scope', arro('system/capability/grant-entry')), 'types', mpo('system/type'))
    call flds(s, local, 'system/handler/register-request', m)
    m = v_map_put(v_map_put(v_map_empty(), 'grant', ref('system/capability/token')), 'pattern', ref('system/tree/path'))
    call flds(s, local, 'system/handler/register-result', m)

    ! tree (5)
    m = v_map_put(v_map_put(v_map_put(v_map_put(v_map_empty(), 'limit', refo('primitive/uint')), &
        'mode', refo('primitive/string')), 'offset', refo('primitive/uint')), 'tree_id', refo('primitive/string'))
    call flds(s, local, 'system/tree/get-request', m)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'entity', refo('core/entity')), &
        'expected_hash', refo('system/hash')), 'tree_id', refo('primitive/string'))
    call flds(s, local, 'system/tree/put-request', m)
    m = v_map_put(v_map_empty(), 'count', ref('primitive/uint'))
    m = v_map_put(m, 'entries', mp('system/tree/listing-entry'))
    m = v_map_put(m, 'next_page', refo('system/hash'))
    m = v_map_put(m, 'offset', ref('primitive/uint'))
    m = v_map_put(m, 'path', ref('system/tree/path'))
    call flds(s, local, 'system/tree/listing', m)
    m = v_map_put(v_map_put(v_map_empty(), 'has_children', ref('primitive/bool')), 'hash', refo('system/hash'))
    call flds(s, local, 'system/tree/listing-entry', m)
    call ext(s, local, 'system/tree/path', 'primitive/string')

    ! type system (3)
    m = v_map_put(v_map_empty(), 'extends', refo('system/type/name'))
    m = v_map_put(m, 'fields', mpo('system/type/field-spec'))
    m = v_map_put(m, 'layout', arro('primitive/string'))
    m = v_map_put(m, 'name', ref('system/type/name'))
    m = v_map_put(m, 'type_args', mpo('system/type/name'))
    m = v_map_put(m, 'type_params', arro('primitive/string'))
    call flds(s, local, 'system/type', m)
    m = v_map_put(v_map_empty(), 'array_of', refo('system/type/field-spec'))
    m = v_map_put(m, 'byte_size', refo('primitive/uint'))
    m = v_map_put(m, 'constraints', arro('core/entity'))
    m = v_map_put(m, 'default', refo('primitive/any'))
    m = v_map_put(m, 'key_type', refo('system/type/name'))
    m = v_map_put(m, 'map_of', refo('system/type/field-spec'))
    m = v_map_put(m, 'optional', refo('primitive/bool'))
    m = v_map_put(m, 'type_args', mpo('system/type/name'))
    m = v_map_put(m, 'type_param', refo('primitive/string'))
    m = v_map_put(m, 'type_ref', refo('system/type/name'))
    m = v_map_put(m, 'union_of', arro('system/type/field-spec'))
    call flds(s, local, 'system/type/field-spec', m)
    call ext(s, local, 'system/type/name', 'primitive/string')

    ! bounds / limits / delivery / deletion (5)
    m = v_map_put(v_map_empty(), 'budget', refo('primitive/uint'))
    m = v_map_put(m, 'cascade_depth', refo('primitive/uint'))
    m = v_map_put(m, 'chain_id', refo('primitive/string'))
    m = v_map_put(m, 'parent_chain_id', refo('primitive/string'))
    m = v_map_put(m, 'ttl', refo('primitive/uint'))
    m = v_map_put(m, 'visited', arro('system/tree/path'))
    call flds(s, local, 'system/bounds', m)
    m = v_map_put(v_map_put(v_map_put(v_map_empty(), 'max_budget', refo('primitive/uint')), &
        'max_ttl', refo('primitive/uint')), 'max_visited_length', refo('primitive/uint'))
    call flds(s, local, 'system/resource-limits', m)
    m = v_map_put(v_map_put(v_map_empty(), 'operation', ref('primitive/string')), 'uri', ref('system/tree/path'))
    call flds(s, local, 'system/delivery-spec', m)
    call nm(s, local, 'system/deletion-marker')
  end subroutine ct_publish

end module entity_core_coretypes
