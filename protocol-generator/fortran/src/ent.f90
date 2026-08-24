! entity-core-protocol-fortran — src/ent.f90
!
! A materialized entity {type, data, content_hash} (§1.1, §3.4) on top of the S2 codec
! value model. Unlike the Rexx peer (which packs an entity into a self-delimiting byte
! STRING because classic Rexx has no record type), Fortran has derived types — so an
! entity is a first-class `entity_t` with a `data` ecf_value_t and a 33-byte content_hash.
!
! content_hash covers ONLY {type, data} (§1.1) and is computed by the audited C-ABI floor
! (ec_content_hash = varint(0x00) ‖ SHA-256(ECF({type,data}))); the WIRE form (ent_to_cbor)
! carries it as a third field so entities are self-describing (§3.1). On decode
! (ent_of_cbor) the hash is RECOMPUTED from {type,data} and checked against the carried
! value (§1.8 fidelity — trust the recompute, not the wire bytes).
!
! `data` is an ARBITRARY ecf value (§1.1 / A-JAVA-010): a map for every core-protocol
! entity, a scalar for e.g. primitive/string. Field-read helpers take the map VIEW (an
! empty map for scalar data) so reads never fault. entity_t has NO self-referential
! allocatable component, so it is dtor-safe (the A-FTN-011 bug is confined to cbor.f90's
! ecf_value_t, whose `data` we hold by value — a shallow pointer copy of an arena tree).
module entity_core_ent
  use, intrinsic :: iso_fortran_env, only : int8, int64
  use entity_core_status
  use entity_core_cbor
  use entity_core_val
  use entity_core_ffi
  implicit none
  private

  integer, parameter, public :: HASH_LEN = 33

  type, public :: entity_t
    logical                       :: present = .false.
    character(len=:), allocatable :: etype
    type(ecf_value_t)             :: data
    integer(int8)                 :: hash(HASH_LEN) = 0_int8
  end type entity_t

  public :: ent_make, ent_absent, ent_type, ent_hash, ent_data, ent_data_map
  public :: ent_to_cbor, ent_of_cbor
  public :: ent_text, ent_bytes, ent_uint, ent_field, ent_map_field, ent_entity_field
  public :: hash_eq, hash_is_zero

contains

  function ent_absent() result(e)
    type(entity_t) :: e
    e%present = .false.
  end function ent_absent

  ! construct a materialized entity, computing the §1.1 content_hash via the C-ABI floor.
  function ent_make(etype, data) result(e)
    character(len=*),  intent(in) :: etype
    type(ecf_value_t), intent(in) :: data
    type(entity_t) :: e
    integer(int8), allocatable :: dbytes(:)
    integer :: stat
    e%present = .true.
    e%etype = etype
    e%data = data
    call cbor_encode(data, dbytes, stat)
    if (stat == EC_OK) then
      call ffi_content_hash(str_bytes(etype), dbytes, e%hash, stat)
    end if
  end function ent_make

  function ent_type(e) result(s)
    type(entity_t), intent(in) :: e
    character(len=:), allocatable :: s
    if (allocated(e%etype)) then; s = e%etype; else; s = ''; end if
  end function ent_type

  function ent_hash(e) result(h)
    type(entity_t), intent(in) :: e
    integer(int8) :: h(HASH_LEN)
    h = e%hash
  end function ent_hash

  function ent_data(e) result(v)
    type(entity_t), intent(in) :: e
    type(ecf_value_t) :: v
    v = e%data
  end function ent_data

  ! the data as a map VIEW: itself if a map, else an empty map (so field reads never fault).
  function ent_data_map(e) result(v)
    type(entity_t), intent(in) :: e
    type(ecf_value_t) :: v
    if (e%data%vkind == EV_MAP) then
      v = e%data
    else
      v = v_map_empty()
    end if
  end function ent_data_map

  ! the wire entity map {type, data, content_hash}.
  function ent_to_cbor(e) result(v)
    type(entity_t), intent(in) :: e
    type(ecf_value_t) :: v
    v = v_map_empty()
    v = v_map_put(v, 'type', v_text(ent_type(e)))
    v = v_map_put(v, 'data', e%data)
    v = v_map_put(v, 'content_hash', v_bytes(e%hash))
  end function ent_to_cbor

  ! parse a wire entity map; recompute + verify the hash (§1.8). stat/=EC_OK on bad shape.
  subroutine ent_of_cbor(mtv, e, stat)
    type(ecf_value_t), intent(in)  :: mtv
    type(entity_t),    intent(out) :: e
    integer,           intent(out) :: stat
    character(len=:), allocatable :: etype
    type(ecf_value_t)             :: data
    integer(int8), allocatable    :: carried(:)
    stat = EC_OK
    e%present = .false.
    if (mtv%vkind /= EV_MAP) then; stat = EC_DECODE_ERROR; return; end if
    if (.not. m_has(mtv, 'type')) then; stat = EC_DECODE_ERROR; return; end if
    if (.not. m_has(mtv, 'data')) then; stat = EC_DECODE_ERROR; return; end if
    etype = m_text(mtv, 'type')
    data  = m_get(mtv, 'data')
    e = ent_make(etype, data)
    carried = m_bytes(mtv, 'content_hash')
    if (size(carried) > 0) then
      if (size(carried) /= HASH_LEN .or. .not. all(carried == e%hash)) then
        e%present = .false.
        stat = EC_HASH_MISMATCH
      end if
    end if
  end subroutine ent_of_cbor

  ! ── field reads off the data map view ──
  function ent_text(e, key) result(s)
    type(entity_t),   intent(in) :: e
    character(len=*), intent(in) :: key
    character(len=:), allocatable :: s
    s = m_text(ent_data_map(e), key)
  end function ent_text

  function ent_bytes(e, key) result(b)
    type(entity_t),   intent(in) :: e
    character(len=*), intent(in) :: key
    integer(int8), allocatable :: b(:)
    b = m_bytes(ent_data_map(e), key)
  end function ent_bytes

  subroutine ent_uint(e, key, val, present)
    type(entity_t),   intent(in)  :: e
    character(len=*), intent(in)  :: key
    integer(int64),   intent(out) :: val
    logical,          intent(out) :: present
    call m_uint(ent_data_map(e), key, val, present)
  end subroutine ent_uint

  function ent_field(e, key) result(v)
    type(entity_t),   intent(in) :: e
    character(len=*), intent(in) :: key
    type(ecf_value_t) :: v
    v = m_get(ent_data_map(e), key)
  end function ent_field

  function ent_map_field(e, key) result(v)
    type(entity_t),   intent(in) :: e
    character(len=*), intent(in) :: key
    type(ecf_value_t) :: v
    v = m_submap(ent_data_map(e), key)
  end function ent_map_field

  ! decode a nested entity carried at `key` (a wire entity map), or absent.
  function ent_entity_field(e, key) result(r)
    type(entity_t),   intent(in) :: e
    character(len=*), intent(in) :: key
    type(entity_t) :: r
    type(ecf_value_t) :: m
    integer :: stat
    m = ent_map_field(e, key)
    if (m%vkind /= EV_MAP) then; r%present = .false.; return; end if
    call ent_of_cbor(m, r, stat)
    if (stat /= EC_OK) r%present = .false.
  end function ent_entity_field

  ! ── hash helpers ──
  logical function hash_eq(a, b)
    integer(int8), intent(in) :: a(:), b(:)
    hash_eq = (size(a) == size(b) .and. size(a) > 0)
    if (hash_eq) hash_eq = all(a == b)
  end function hash_eq

  logical function hash_is_zero(h)
    integer(int8), intent(in) :: h(:)
    hash_is_zero = (size(h) == 0 .or. all(h == 0_int8))
  end function hash_is_zero

end module entity_core_ent
