! entity-core-protocol-fortran — src/wire.f90 (§1.6 framing + §3.1 envelope + the two
! message builders §3.2 EXECUTE / §3.3 EXECUTE_RESPONSE).
!
! Frame := [4-byte BE length][canonical-ECF payload]; the length prefix + de-framing live
! in the C net-shim (net_shim.c), so the Fortran layer never sees a partial or oversize
! frame. The payload is a canonical-ECF system/protocol/envelope (§3.1): a `root` entity
! plus an `included` content_hash -> entity map (BYTE-string keys — the §3.1 major-2 seam,
! NOT text keys). `included` is the §5.8 authority carrier (capabilities, peer identities,
! signatures travel here).
!
! ONLY EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello / authenticate
! are OPERATIONS on system/protocol/connect, NOT message types — any other root type is
! ignored (the dispatcher returns no response).
module entity_core_wire
  use, intrinsic :: iso_fortran_env, only : int8, int64
  use entity_core_status
  use entity_core_cbor
  use entity_core_val
  use entity_core_ent
  implicit none
  private

  type, public :: envelope_t
    type(entity_t)              :: root
    type(entity_t), allocatable :: inc(:)
  end type envelope_t

  public :: env_make, env_included_get, env_to_cbor, env_of_cbor
  public :: wire_frame_of_envelope, wire_envelope_of_frame, wire_peek
  public :: wire_make_execute, wire_make_response, wire_error_result
  public :: wire_empty_params, wire_resource_target
  public :: wire_response_status, wire_response_result

contains

  function env_make(root, inc) result(env)
    type(entity_t), intent(in) :: root
    type(entity_t), intent(in) :: inc(:)
    type(envelope_t) :: env
    env%root = root
    env%inc = inc
  end function env_make

  function env_included_get(env, h) result(e)
    type(envelope_t), intent(in) :: env
    integer(int8),    intent(in) :: h(:)
    type(entity_t) :: e
    integer :: i
    e%present = .false.
    if (size(h) == 0) return
    if (.not. allocated(env%inc)) return
    do i = 1, size(env%inc)
      if (hash_eq(ent_hash(env%inc(i)), h)) then; e = env%inc(i); return; end if
    end do
  end function env_included_get

  ! wire envelope map {root, included}; dedup `included` by content_hash, first-seen
  ! (a repeated hash would emit a duplicate byte key the canonical codec rejects).
  function env_to_cbor(env) result(top)
    type(envelope_t), intent(in) :: env
    type(ecf_value_t) :: top, incmap
    integer :: i, j, cnt, ni
    logical :: dup
    integer(int8), allocatable :: hi(:)
    ni = 0
    if (allocated(env%inc)) ni = size(env%inc)
    incmap%vkind = EV_MAP
    incmap%items => null()
    if (ni > 0) then
      allocate(incmap%items(2*ni))     ! upper bound; trim after dedup
      cnt = 0
      do i = 1, ni
        hi = ent_hash(env%inc(i))
        dup = .false.
        do j = 1, cnt
          if (hash_eq(hi, val_bytes(incmap%items(2*j-1)))) then; dup = .true.; exit; end if
        end do
        if (dup) cycle
        cnt = cnt + 1
        incmap%items(2*cnt-1) = v_bytes(hi)
        incmap%items(2*cnt)   = ent_to_cbor(env%inc(i))
      end do
      if (2*cnt /= size(incmap%items)) call trim_items(incmap, 2*cnt)
    end if
    top = v_map_empty()
    top = v_map_put(top, 'root', ent_to_cbor(env%root))
    top = v_map_put(top, 'included', incmap)
  end function env_to_cbor

  subroutine trim_items(m, n)
    type(ecf_value_t), intent(inout) :: m
    integer,           intent(in)    :: n
    type(ecf_value_t), pointer :: nw(:)
    integer :: i
    allocate(nw(n))
    do i = 1, n
      nw(i) = m%items(i)
    end do
    m%items => nw
  end subroutine trim_items

  ! parse a wire envelope map; verify each included content_hash == its map key (§3.1)
  ! and dedup first-seen. stat/=EC_OK on a bad shape.
  subroutine env_of_cbor(top, env, stat)
    type(ecf_value_t), intent(in)  :: top
    type(envelope_t),  intent(out) :: env
    integer,           intent(out) :: stat
    type(ecf_value_t) :: rootv, incm, kv, vv
    type(entity_t), allocatable :: acc(:), tmp(:)
    type(entity_t)    :: e
    integer :: i, npair, s2
    logical :: dup
    integer(int8), allocatable :: kb(:)
    stat = EC_OK
    if (top%vkind /= EV_MAP) then; stat = EC_DECODE_ERROR; return; end if
    rootv = m_get(top, 'root')
    if (rootv%vkind /= EV_MAP) then; stat = EC_DECODE_ERROR; return; end if
    call ent_of_cbor(rootv, env%root, stat)
    if (stat /= EC_OK) return
    allocate(acc(0))
    incm = m_submap(top, 'included')
    if (incm%vkind == EV_MAP .and. associated(incm%items)) then
      npair = size(incm%items) / 2
      do i = 1, npair
        kv = incm%items(2*i-1)
        vv = incm%items(2*i)
        if (kv%vkind /= EV_BYTES) then; stat = EC_DECODE_ERROR; return; end if
        if (vv%vkind /= EV_MAP) then; stat = EC_DECODE_ERROR; return; end if
        call ent_of_cbor(vv, e, s2)
        if (s2 /= EC_OK) then; stat = s2; return; end if
        kb = val_bytes(kv)
        if (.not. hash_eq(kb, ent_hash(e))) then; stat = EC_HASH_MISMATCH; return; end if
        dup = .false.
        do s2 = 1, size(acc)
          if (hash_eq(ent_hash(acc(s2)), kb)) then; dup = .true.; exit; end if
        end do
        if (dup) cycle
        allocate(tmp(size(acc) + 1))
        if (size(acc) > 0) tmp(1:size(acc)) = acc
        tmp(size(tmp)) = e
        call move_alloc(tmp, acc)
      end do
    end if
    env%inc = acc
  end subroutine env_of_cbor

  function wire_frame_of_envelope(env) result(bytes)
    type(envelope_t), intent(in) :: env
    integer(int8), allocatable :: bytes(:)
    integer :: stat
    call cbor_encode(env_to_cbor(env), bytes, stat)
    if (stat /= EC_OK) allocate(bytes(0))
  end function wire_frame_of_envelope

  subroutine wire_envelope_of_frame(payload, env, ok)
    integer(int8),    intent(in)  :: payload(:)
    type(envelope_t), intent(out) :: env
    logical,          intent(out) :: ok
    type(ecf_value_t) :: v
    integer :: consumed, stat
    ok = .false.
    call cbor_decode(payload, v, consumed, stat)
    if (stat /= EC_OK) return
    if (consumed /= size(payload)) return       ! §6.3 full-consumption reject (A-FTN-012)
    call env_of_cbor(v, env, stat)
    ok = (stat == EC_OK)
  end subroutine wire_envelope_of_frame

  ! peek the root type + request_id from a raw payload WITHOUT hash validation — the §6.11
  ! demux needs only these to route a reply vs an inbound EXECUTE. Robust to a malformed
  ! `included` (decodes just the top map's root sub-map).
  subroutine wire_peek(payload, root_type, request_id, is_response, ok)
    integer(int8),                 intent(in)  :: payload(:)
    character(len=:), allocatable, intent(out) :: root_type, request_id
    logical,                       intent(out) :: is_response, ok
    type(ecf_value_t) :: top, rootv, datav
    integer :: consumed, stat
    root_type = ''; request_id = ''; is_response = .false.; ok = .false.
    call cbor_decode(payload, top, consumed, stat)
    if (stat /= EC_OK .or. top%vkind /= EV_MAP) return
    rootv = m_submap(top, 'root')
    if (rootv%vkind /= EV_MAP) return
    root_type = m_text(rootv, 'type')
    datav = m_submap(rootv, 'data')
    if (datav%vkind == EV_MAP) request_id = m_text(datav, 'request_id')
    is_response = (root_type == 'system/protocol/execute/response')
    ok = .true.
  end subroutine wire_peek

  ! ── EXECUTE builder (§3.2): author/capability are raw 33-byte hashes (0-len to omit);
  ! resource is a map value (EV_ABSENT to omit); params is a materialized entity. ──
  function wire_make_execute(request_id, uri, operation, params, author, capability, resource) result(e)
    character(len=*),  intent(in) :: request_id, uri, operation
    type(entity_t),    intent(in) :: params
    integer(int8),     intent(in) :: author(:), capability(:)
    type(ecf_value_t), intent(in) :: resource
    type(entity_t) :: e
    type(ecf_value_t) :: m
    m = v_map_empty()
    m = v_map_put(m, 'request_id', v_text(request_id))
    m = v_map_put(m, 'uri', v_text(uri))
    m = v_map_put(m, 'operation', v_text(operation))
    m = v_map_put(m, 'params', ent_to_cbor(params))
    if (size(author) > 0)     m = v_map_put(m, 'author', v_bytes(author))
    if (size(capability) > 0) m = v_map_put(m, 'capability', v_bytes(capability))
    if (resource%vkind == EV_MAP) m = v_map_put(m, 'resource', resource)
    e = ent_make('system/protocol/execute', m)
  end function wire_make_execute

  function wire_make_response(request_id, status, result) result(e)
    character(len=*), intent(in) :: request_id
    integer,          intent(in) :: status
    type(entity_t),   intent(in) :: result
    type(entity_t) :: e
    type(ecf_value_t) :: m
    m = v_map_empty()
    m = v_map_put(m, 'request_id', v_text(request_id))
    m = v_map_put(m, 'status', v_uint(int(status, int64)))
    m = v_map_put(m, 'result', ent_to_cbor(result))
    e = ent_make('system/protocol/execute/response', m)
  end function wire_make_response

  function wire_error_result(code, message) result(e)
    character(len=*), intent(in) :: code, message
    type(entity_t) :: e
    type(ecf_value_t) :: m
    m = v_map_empty()
    m = v_map_put(m, 'code', v_text(code))
    if (len_trim(message) > 0) m = v_map_put(m, 'message', v_text(message))
    e = ent_make('system/protocol/error', m)
  end function wire_error_result

  function wire_empty_params() result(e)
    type(entity_t) :: e
    e = ent_make('primitive/any', v_map_empty())
  end function wire_empty_params

  ! a resource map {targets: [target]} for a single target path string.
  function wire_resource_target(target) result(m)
    character(len=*), intent(in) :: target
    type(ecf_value_t) :: m
    m = v_map_empty()
    m = v_map_put(m, 'targets', v_arr_add(v_arr_empty(), v_text(target)))
  end function wire_resource_target

  ! ── response decode helpers (initiator side) ──
  integer function wire_response_status(env)
    type(envelope_t), intent(in) :: env
    integer(int64) :: v
    logical :: present
    call ent_uint(env%root, 'status', v, present)
    if (present) then; wire_response_status = int(v); else; wire_response_status = 0; end if
  end function wire_response_status

  function wire_response_result(env) result(r)
    type(envelope_t), intent(in) :: env
    type(entity_t) :: r
    r = ent_entity_field(env%root, 'result')
  end function wire_response_result

end module entity_core_wire
