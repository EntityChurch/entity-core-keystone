! entity-core-protocol-fortran — src/store.f90 (foundation storage, §1.7).
!
!   Content Store: hash -> entity   (immutable, content-addressed, dedup)
!   Entity Tree:   path -> hash      (mutable location index)
!
! In-memory minimal impl over module-idiomatic allocatable arrays inside a `store_t`
! derived type (so a process may hold several stores — the peer's + the foundation
! self-test's second store — without a class system). Keys are lowercase-hex content
! hashes (A-CL-009) and NUL-free paths.
!
! == §4.8 store data-race safety — STRUCTURAL. The peer is ONE OS process driven by a
! single-threaded select-pump (one frame dispatched to completion before the next event
! is polled — see transport.f90), so these arrays are never accessed concurrently: the
! §4.8 MUST holds by construction, with no lock and no possible race. This is the profile
! [async] single-thread-select model; the C net-shim's one select() loop is the only I/O
! waiter and it hands each frame to the Fortran side serially.
!
! The store owns entity LIFETIME explicitly (A-FTN-011): it holds entity_t records by
! value (each with its own allocatable etype + data), so it never depends on a decoded
! arena tree surviving. Lookups are linear scans — fine at the core-profile scale
! (dozens–low-hundreds of bindings); the listing walk is bounded per call (no accreting
! O(n^2), the A-RX-014 lesson).
module entity_core_store
  use, intrinsic :: iso_fortran_env, only : int8
  use entity_core_val
  use entity_core_ent
  implicit none
  private

  type, public :: store_t
    ! content store (parallel arrays)
    type(str_t),    allocatable :: c_hex(:)
    type(entity_t), allocatable :: c_ent(:)
    integer :: c_n = 0
    ! entity tree
    type(str_t), allocatable :: t_path(:)
    type(str_t), allocatable :: t_hex(:)     ! '' == unbound
    integer :: t_n = 0
  end type store_t

  ! a listing row: segment + bound-hash-hex (or '') + has_children.
  type, public :: listing_row_t
    character(len=:), allocatable :: seg
    character(len=:), allocatable :: hashhex
    logical :: has_children = .false.
  end type listing_row_t

  public :: store_new, store_put_entity, store_get_by_hash
  public :: store_bind, store_unbind, store_hash_at, store_get_at
  public :: store_listing

contains

  function store_new() result(s)
    type(store_t) :: s
    allocate(s%c_hex(0), s%c_ent(0), s%t_path(0), s%t_hex(0))
    s%c_n = 0; s%t_n = 0
  end function store_new

  ! ── content store ──
  subroutine store_put_entity(s, e)
    type(store_t),  intent(inout) :: s
    type(entity_t), intent(in)    :: e
    character(len=:), allocatable :: hex
    type(str_t),    allocatable   :: nh(:)
    type(entity_t), allocatable   :: ne(:)
    integer :: i
    hex = hexlc(ent_hash(e))
    do i = 1, s%c_n
      if (s%c_hex(i)%s == hex) return          ! dedup: already stored
    end do
    allocate(nh(s%c_n + 1), ne(s%c_n + 1))
    if (s%c_n > 0) then; nh(1:s%c_n) = s%c_hex(1:s%c_n); ne(1:s%c_n) = s%c_ent(1:s%c_n); end if
    nh(s%c_n + 1)%s = hex
    ne(s%c_n + 1)   = e
    call move_alloc(nh, s%c_hex)
    call move_alloc(ne, s%c_ent)
    s%c_n = s%c_n + 1
  end subroutine store_put_entity

  function store_get_by_hash(s, hbytes) result(e)
    type(store_t), intent(in) :: s
    integer(int8), intent(in) :: hbytes(:)
    type(entity_t) :: e
    character(len=:), allocatable :: hex
    integer :: i
    e%present = .false.
    if (size(hbytes) == 0) return
    hex = hexlc(hbytes)
    do i = 1, s%c_n
      if (s%c_hex(i)%s == hex) then; e = s%c_ent(i); return; end if
    end do
  end function store_get_by_hash

  ! ── entity tree ──
  integer function tree_index(s, path)
    type(store_t),    intent(in) :: s
    character(len=*), intent(in) :: path
    integer :: i
    tree_index = 0
    do i = 1, s%t_n
      if (s%t_path(i)%s == path) then; tree_index = i; return; end if
    end do
  end function tree_index

  subroutine store_bind(s, path, e)
    type(store_t),    intent(inout) :: s
    character(len=*), intent(in)    :: path
    type(entity_t),   intent(in)    :: e
    character(len=:), allocatable :: hex
    type(str_t), allocatable :: np(:), nh(:)
    integer :: idx
    call store_put_entity(s, e)
    hex = hexlc(ent_hash(e))
    idx = tree_index(s, path)
    if (idx > 0) then
      s%t_hex(idx)%s = hex
    else
      allocate(np(s%t_n + 1), nh(s%t_n + 1))
      if (s%t_n > 0) then; np(1:s%t_n) = s%t_path(1:s%t_n); nh(1:s%t_n) = s%t_hex(1:s%t_n); end if
      np(s%t_n + 1)%s = path
      nh(s%t_n + 1)%s = hex
      call move_alloc(np, s%t_path)
      call move_alloc(nh, s%t_hex)
      s%t_n = s%t_n + 1
    end if
  end subroutine store_bind

  subroutine store_unbind(s, path)
    type(store_t),    intent(inout) :: s
    character(len=*), intent(in)    :: path
    integer :: idx
    idx = tree_index(s, path)
    if (idx > 0) s%t_hex(idx)%s = ''
  end subroutine store_unbind

  function store_hash_at(s, path) result(hex)
    type(store_t),    intent(in) :: s
    character(len=*), intent(in) :: path
    character(len=:), allocatable :: hex
    integer :: idx
    hex = ''
    idx = tree_index(s, path)
    if (idx > 0) hex = s%t_hex(idx)%s
  end function store_hash_at

  function store_get_at(s, path) result(e)
    type(store_t),    intent(in) :: s
    character(len=*), intent(in) :: path
    type(entity_t) :: e
    integer :: idx, j
    e%present = .false.
    idx = tree_index(s, path)
    if (idx == 0) return
    if (len(s%t_hex(idx)%s) == 0) return
    do j = 1, s%c_n
      if (s%c_hex(j)%s == s%t_hex(idx)%s) then; e = s%c_ent(j); return; end if
    end do
  end function store_get_at

  ! one-level listing under `prefix` (trailing slash added if absent): a list of
  ! listing_row_t (segment, bound-hash-hex-or-'', has_children), sorted by segment (§3.9).
  function store_listing(s, prefix) result(rows)
    type(store_t),    intent(in) :: s
    character(len=*), intent(in) :: prefix
    type(listing_row_t), allocatable :: rows(:)
    character(len=:), allocatable :: p, path, rest, seg
    type(listing_row_t), allocatable :: tmp(:)
    integer :: i, plen, slash, k, m
    type(listing_row_t) :: swap
    logical :: found
    if (len(prefix) > 0) then
      if (prefix(len(prefix):len(prefix)) == '/') then; p = prefix; else; p = prefix // '/'; end if
    else
      p = '/'
    end if
    plen = len(p)
    allocate(rows(0))
    do i = 1, s%t_n
      if (len(s%t_hex(i)%s) == 0) cycle          ! unbound
      path = s%t_path(i)%s
      if (len(path) <= plen) cycle
      if (path(1:plen) /= p) cycle
      rest = path(plen+1:)
      slash = index(rest, '/')
      if (slash > 0) then
        seg = rest(1:slash-1)
        call acc_row(rows, seg, '', .true.)
      else
        call acc_row(rows, rest, s%t_hex(i)%s, .false.)
      end if
    end do
    ! insertion sort by segment
    m = size(rows)
    do k = 2, m
      swap = rows(k)
      i = k - 1
      do while (i >= 1)
        if (rows(i)%seg > swap%seg) then; rows(i+1) = rows(i); i = i - 1; else; exit; end if
      end do
      rows(i+1) = swap
    end do
  contains
    subroutine acc_row(rr, sg, hh, child)
      type(listing_row_t), allocatable, intent(inout) :: rr(:)
      character(len=*), intent(in) :: sg, hh
      logical,          intent(in) :: child
      integer :: j
      found = .false.
      do j = 1, size(rr)
        if (rr(j)%seg == sg) then
          if (child) rr(j)%has_children = .true.
          if (len(hh) > 0) rr(j)%hashhex = hh
          found = .true.
          return
        end if
      end do
      allocate(tmp(size(rr) + 1))
      if (size(rr) > 0) tmp(1:size(rr)) = rr
      tmp(size(tmp))%seg = sg
      tmp(size(tmp))%hashhex = hh
      tmp(size(tmp))%has_children = child
      call move_alloc(tmp, rr)
    end subroutine acc_row
  end function store_listing

end module entity_core_store
