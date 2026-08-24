! entity-core-protocol-fortran — src/val.f90
!
! Peer-altitude value helpers over the S2 codec value model (ecf_value_t, cbor.f90).
! The codec speaks the tagged-union ecf_value_t (int/bytes/text/float/bool/null/array/
! map with an explicit major-type discriminant — A-FTN-003); this module is the
! protocol-altitude analogue: map/array BUILDERS + typed field READS, so the peer code
! reads as `v_map_put(m,'peer_id', v_text(pid))` and `m_text(map,'peer_id')` rather than
! restating the ecf_value_t layout at every call site (the Rexx ecf.rex / Tcl ::ecf::
! layer, in Fortran idiom).
!
! MEMORY (A-FTN-011 / A-FTN-013): built map/array `items(:)` are POINTER-allocated on the
! heap and never freed by the codec (the gfortran recursive-dtor bug forces pointer items,
! S2). The decoded tree is arena-like — reclaimed at process exit; the store retains
! entities it needs (S3 owns lifetime). Transient response values leak per dispatch; under
! a §4.9 sustained flood a bump-arena is the hardening path (A-FTN-013, S4 note). For the
! S3 gate and a bounded validate-peer run this is well within the resource cap.
!
! Absent sentinel (A-FTN-007): a field read returns an EV_ABSENT value / a zero-length
! byte array IFF the key is truly absent. Present-empty vs absent (the §4.5 negotiation
! seam) uses m_has.
module entity_core_val
  use, intrinsic :: iso_fortran_env, only : int8, int32, int64
  use entity_core_status
  use entity_core_cbor
  implicit none
  private

  ! a deferred-length string cell — the element type for the string lists the peer passes
  ! around (pattern lists, listing segments); Fortran has no native list-of-strings.
  type, public :: str_t
    character(len=:), allocatable :: s
  end type str_t

  public :: v_uint, v_text, v_textb, v_bytes, v_bool, v_null, v_float
  public :: v_map_empty, v_map_put, v_arr_empty, v_arr_add, v_text_array, v_scope
  public :: m_get, m_has, m_text, m_bytes, m_uint, m_submap, m_bool, m_array
  public :: val_text, val_bytes, val_is_map, val_is_array, val_is_bytes, val_is_text
  public :: arr_count, arr_item, str_of_bytes, bytes_of_str
  public :: text_list, hexlc, hex_to_bytes, sl_count, sl_of_words

contains

  ! ── constructors ──
  function v_uint(n) result(v)
    integer(int64), intent(in) :: n
    type(ecf_value_t) :: v
    v%vkind = EV_UINT; v%ival = n
  end function v_uint

  function v_text(s) result(v)
    character(len=*), intent(in) :: s
    type(ecf_value_t) :: v
    v%vkind = EV_TEXT
    v%bytes = str_bytes(s)
  end function v_text

  function v_textb(b) result(v)          ! text from raw utf-8 octets
    integer(int8), intent(in) :: b(:)
    type(ecf_value_t) :: v
    v%vkind = EV_TEXT; v%bytes = b
  end function v_textb

  function v_bytes(b) result(v)
    integer(int8), intent(in) :: b(:)
    type(ecf_value_t) :: v
    v%vkind = EV_BYTES; v%bytes = b
  end function v_bytes

  function v_bool(l) result(v)
    logical, intent(in) :: l
    type(ecf_value_t) :: v
    v%vkind = EV_BOOL; v%bval = l
  end function v_bool

  function v_null() result(v)
    type(ecf_value_t) :: v
    v%vkind = EV_NULL
  end function v_null

  function v_float(x) result(v)
    real(kind=8), intent(in) :: x
    type(ecf_value_t) :: v
    v%vkind = EV_FLOAT; v%fval = x
  end function v_float

  function v_map_empty() result(v)
    type(ecf_value_t) :: v
    v%vkind = EV_MAP
    v%items => null()
  end function v_map_empty

  ! append (text key, value) to a map -> a NEW map (heap items). The encoder re-sorts to
  ! canonical order, so build order is irrelevant.
  function v_map_put(m, key, val) result(r)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    type(ecf_value_t), intent(in) :: val
    type(ecf_value_t) :: r
    integer :: old
    r%vkind = EV_MAP
    if (associated(m%items)) then; old = size(m%items); else; old = 0; end if
    allocate(r%items(old + 2))
    if (old > 0) r%items(1:old) = m%items(1:old)
    r%items(old + 1) = v_text(key)
    r%items(old + 2) = val
  end function v_map_put

  function v_arr_empty() result(v)
    type(ecf_value_t) :: v
    v%vkind = EV_ARRAY
    v%items => null()
  end function v_arr_empty

  function v_arr_add(a, val) result(r)
    type(ecf_value_t), intent(in) :: a, val
    type(ecf_value_t) :: r
    integer :: old
    r%vkind = EV_ARRAY
    if (associated(a%items)) then; old = size(a%items); else; old = 0; end if
    allocate(r%items(old + 1))
    if (old > 0) r%items(1:old) = a%items(1:old)
    r%items(old + 1) = val
  end function v_arr_add

  ! a text array from a blank-separated word string (the §4.4 helper list shape).
  function v_text_array(words) result(v)
    character(len=*), intent(in) :: words
    type(ecf_value_t) :: v
    integer :: i, n, s
    v = v_arr_empty()
    n = len_trim(words)
    i = 1
    do while (i <= n)
      do
        if (i > n) exit
        if (words(i:i) /= ' ') exit
        i = i + 1
      end do
      s = i
      do
        if (i > n) exit
        if (words(i:i) == ' ') exit
        i = i + 1
      end do
      if (i > s) v = v_arr_add(v, v_text(words(s:i-1)))
    end do
  end function v_text_array

  ! a §5.4 scope map {include: [patterns...]} from a blank-separated pattern string.
  function v_scope(patterns) result(v)
    character(len=*), intent(in) :: patterns
    type(ecf_value_t) :: v
    v = v_map_put(v_map_empty(), 'include', v_text_array(patterns))
  end function v_scope

  ! ── readers over a map value ──
  function m_get(m, key) result(v)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    type(ecf_value_t) :: v
    v = ev_map_get(m, key)
  end function m_get

  logical function m_has(m, key)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    m_has = ev_has(m, key)
  end function m_has

  ! text field as a Fortran string; '' if absent or not text.
  function m_text(m, key) result(s)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    character(len=:), allocatable :: s
    type(ecf_value_t) :: v
    v = ev_map_get(m, key)
    s = val_text(v)
  end function m_text

  ! byte field as raw octets; zero-length if absent or not bytes.
  function m_bytes(m, key) result(b)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    integer(int8), allocatable :: b(:)
    type(ecf_value_t) :: v
    v = ev_map_get(m, key)
    if (v%vkind == EV_BYTES .and. allocated(v%bytes)) then
      b = v%bytes
    else
      allocate(b(0))
    end if
  end function m_bytes

  ! uint field (bit pattern); present=.false. if absent or not a uint.
  subroutine m_uint(m, key, val, present)
    type(ecf_value_t), intent(in)  :: m
    character(len=*),  intent(in)  :: key
    integer(int64),    intent(out) :: val
    logical,           intent(out) :: present
    type(ecf_value_t) :: v
    val = 0_int64; present = .false.
    v = ev_map_get(m, key)
    if (v%vkind == EV_UINT) then; val = v%ival; present = .true.; end if
  end subroutine m_uint

  logical function m_bool(m, key)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    type(ecf_value_t) :: v
    v = ev_map_get(m, key)
    m_bool = (v%vkind == EV_BOOL .and. v%bval)
  end function m_bool

  ! sub-map field; EV_ABSENT if absent or not a map.
  function m_submap(m, key) result(v)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    type(ecf_value_t) :: v
    v = ev_map_get(m, key)
    if (v%vkind /= EV_MAP) v%vkind = EV_ABSENT
  end function m_submap

  ! array field; EV_ABSENT if absent or not an array.
  function m_array(m, key) result(v)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    type(ecf_value_t) :: v
    v = ev_map_get(m, key)
    if (v%vkind /= EV_ARRAY) v%vkind = EV_ABSENT
  end function m_array

  ! ── value inspectors ──
  function val_text(v) result(s)
    type(ecf_value_t), intent(in) :: v
    character(len=:), allocatable :: s
    if (v%vkind == EV_TEXT .and. allocated(v%bytes)) then
      s = str_of_bytes(v%bytes)
    else
      s = ''
    end if
  end function val_text

  function val_bytes(v) result(b)
    type(ecf_value_t), intent(in) :: v
    integer(int8), allocatable :: b(:)
    if ((v%vkind == EV_BYTES .or. v%vkind == EV_TEXT) .and. allocated(v%bytes)) then
      b = v%bytes
    else
      allocate(b(0))
    end if
  end function val_bytes

  logical function val_is_map(v);   type(ecf_value_t), intent(in) :: v; val_is_map = (v%vkind == EV_MAP);   end function
  logical function val_is_array(v); type(ecf_value_t), intent(in) :: v; val_is_array = (v%vkind == EV_ARRAY); end function
  logical function val_is_bytes(v); type(ecf_value_t), intent(in) :: v; val_is_bytes = (v%vkind == EV_BYTES); end function
  logical function val_is_text(v);  type(ecf_value_t), intent(in) :: v; val_is_text = (v%vkind == EV_TEXT);  end function

  integer function arr_count(a)
    type(ecf_value_t), intent(in) :: a
    if (a%vkind == EV_ARRAY .and. associated(a%items)) then
      arr_count = size(a%items)
    else
      arr_count = 0
    end if
  end function arr_count

  function arr_item(a, i) result(v)
    type(ecf_value_t), intent(in) :: a
    integer,           intent(in) :: i
    type(ecf_value_t) :: v
    v%vkind = EV_ABSENT
    if (a%vkind == EV_ARRAY .and. associated(a%items)) then
      if (i >= 1 .and. i <= size(a%items)) v = a%items(i)
    end if
  end function arr_item

  ! ── byte <-> character bridges ──
  function str_of_bytes(b) result(s)
    integer(int8), intent(in) :: b(:)
    character(len=:), allocatable :: s
    integer :: i
    allocate(character(len=size(b)) :: s)
    do i = 1, size(b)
      s(i:i) = achar(iand(int(b(i)), 255))
    end do
  end function str_of_bytes

  function bytes_of_str(s) result(b)
    character(len=*), intent(in) :: s
    integer(int8) :: b(len(s))
    b = str_bytes(s)
  end function bytes_of_str

  ! the TEXT items of an array value as a str_t list (non-text items skipped); length-0
  ! for an absent / non-array / present-empty value (present-vs-absent uses m_has).
  function text_list(a) result(out)
    type(ecf_value_t), intent(in) :: a
    type(str_t), allocatable :: out(:)
    type(str_t), allocatable :: tmp(:)
    type(ecf_value_t) :: it
    integer :: i, n
    allocate(out(0))
    n = arr_count(a)
    do i = 1, n
      it = arr_item(a, i)
      if (it%vkind == EV_TEXT) then
        allocate(tmp(size(out) + 1))
        if (size(out) > 0) tmp(1:size(out)) = out
        tmp(size(tmp))%s = val_text(it)
        call move_alloc(tmp, out)
      end if
    end do
  end function text_list

  ! blank-separated words -> a str_t list (the §4.4 pattern-list helper).
  function sl_of_words(words) result(out)
    character(len=*), intent(in) :: words
    type(str_t), allocatable :: out(:)
    type(str_t), allocatable :: tmp(:)
    integer :: i, n, s
    allocate(out(0))
    n = len_trim(words); i = 1
    do while (i <= n)
      do
        if (i > n) exit
        if (words(i:i) /= ' ') exit
        i = i + 1
      end do
      s = i
      do
        if (i > n) exit
        if (words(i:i) == ' ') exit
        i = i + 1
      end do
      if (i > s) then
        allocate(tmp(size(out) + 1))
        if (size(out) > 0) tmp(1:size(out)) = out
        tmp(size(tmp))%s = words(s:i-1)
        call move_alloc(tmp, out)
      end if
    end do
  end function sl_of_words

  integer function sl_count(l)
    type(str_t), intent(in) :: l(:)
    sl_count = size(l)
  end function sl_count

  ! bytes from a lowercase/upper hex string (inverse of hexlc).
  function hex_to_bytes(s) result(b)
    character(len=*), intent(in) :: s
    integer(int8), allocatable :: b(:)
    integer :: i, n, hi, lo
    n = len(s) / 2
    allocate(b(n))
    do i = 1, n
      hi = hexdigit(s(2*i-1:2*i-1))
      lo = hexdigit(s(2*i:2*i))
      b(i) = int(ishft(hi, 4) + lo, int8)
    end do
  end function hex_to_bytes

  integer function hexdigit(c)
    character(len=1), intent(in) :: c
    if (c >= '0' .and. c <= '9') then; hexdigit = ichar(c) - ichar('0')
    else if (c >= 'a' .and. c <= 'f') then; hexdigit = ichar(c) - ichar('a') + 10
    else if (c >= 'A' .and. c <= 'F') then; hexdigit = ichar(c) - ichar('A') + 10
    else; hexdigit = 0; end if
  end function hexdigit

  ! lowercase hex of a byte array (A-CL-009: §3.4/§3.5 tree-paths use lowercase hex).
  function hexlc(b) result(s)
    integer(int8), intent(in) :: b(:)
    character(len=:), allocatable :: s
    character(len=16), parameter :: H = '0123456789abcdef'
    integer :: i, u
    allocate(character(len=2*size(b)) :: s)
    do i = 1, size(b)
      u = iand(int(b(i)), 255)
      s(2*i-1:2*i-1) = H(ishft(u,-4)+1 : ishft(u,-4)+1)
      s(2*i:2*i)     = H(iand(u,15)+1 : iand(u,15)+1)
    end do
  end function hexlc

end module entity_core_val
