! entity-core-protocol-fortran — src/transport.f90 (L4 transport plumbing).
!
! Thin, protocol-agnostic layer between the peer brain (peer.f90) and the C net-shim
! (net.f90 -> net_shim.c): the listener/dialer/send wrappers, and the §6.11 request_id
! DEMUX table (a reply's request_id -> its delivered response payload). The peer owns the
! event PUMP and all dispatch/handshake logic (so there is no peer<->transport module
! cycle — peer `use`s transport one-way); this module only holds the mechanical send +
! the correlation rendezvous.
!
! §6.11 / §4.8 / §7b: one process, one select loop (in the shim), one pump (in the peer)
! -> an inbound frame is dispatched to completion before the next event is polled, and an
! out-of-order reply is matched here by request_id. No thread, no lock: store-safety is
! structural (the profile [async] single-thread-select model).
module entity_core_transport
  use, intrinsic :: iso_fortran_env, only : int8
  use entity_core_net
  implicit none
  private

  type :: pend_t
    character(len=:), allocatable :: rid
    integer(int8),    allocatable :: payload(:)
    logical :: done = .false.
    logical :: used = .false.
  end type pend_t

  type(pend_t), allocatable, save :: pends(:)

  public :: tr_listen, tr_dial, tr_send_frame, tr_close, tr_shutdown, tr_poll
  public :: tr_pending_register, tr_pending_deliver, tr_pending_done, tr_pending_take
  public :: EV_NONE, EV_ACCEPT, EV_FRAME, EV_CLOSED, EV_OVERSIZE

contains

  integer function tr_listen(port)
    integer, intent(in) :: port
    if (.not. allocated(pends)) allocate(pends(0))
    tr_listen = net_listen(port)
  end function tr_listen

  integer function tr_dial(port)
    integer, intent(in) :: port
    if (.not. allocated(pends)) allocate(pends(0))
    tr_dial = net_connect(port)
  end function tr_dial

  subroutine tr_send_frame(io, payload)
    integer,       intent(in) :: io
    integer(int8), intent(in) :: payload(:)
    call net_send(io, payload)
  end subroutine tr_send_frame

  subroutine tr_close(io)
    integer, intent(in) :: io
    call net_close(io)
  end subroutine tr_close

  subroutine tr_shutdown()
    call net_shutdown()
  end subroutine tr_shutdown

  ! one raw event from the shim (blocking up to timeout_ms; <0 infinite).
  subroutine tr_poll(timeout_ms, kind, id, payload, plen)
    integer,                    intent(in)  :: timeout_ms
    integer,                    intent(out) :: kind, id, plen
    integer(int8), allocatable, intent(out) :: payload(:)
    call net_poll(timeout_ms, kind, id, payload, plen)
  end subroutine tr_poll

  ! ── §6.11 demux table ──
  integer function pend_index(rid)
    character(len=*), intent(in) :: rid
    integer :: i
    pend_index = 0
    if (.not. allocated(pends)) return
    do i = 1, size(pends)
      if (pends(i)%used .and. pends(i)%rid == rid) then; pend_index = i; return; end if
    end do
  end function pend_index

  ! register interest in a request_id (before sending it), so an early reply is captured.
  subroutine tr_pending_register(rid)
    character(len=*), intent(in) :: rid
    type(pend_t), allocatable :: tmp(:)
    integer :: idx, free, i
    if (.not. allocated(pends)) allocate(pends(0))
    idx = pend_index(rid)
    if (idx > 0) then; pends(idx)%done = .false.; return; end if
    free = 0
    do i = 1, size(pends)
      if (.not. pends(i)%used) then; free = i; exit; end if
    end do
    if (free == 0) then
      allocate(tmp(size(pends) + 1))
      if (size(pends) > 0) tmp(1:size(pends)) = pends
      call move_alloc(tmp, pends)
      free = size(pends)
    end if
    pends(free)%used = .true.
    pends(free)%done = .false.
    pends(free)%rid = rid
    if (allocated(pends(free)%payload)) deallocate(pends(free)%payload)
  end subroutine tr_pending_register

  ! deliver a reply payload for request_id (marks it done). No-op if not registered.
  subroutine tr_pending_deliver(rid, payload)
    character(len=*), intent(in) :: rid
    integer(int8),    intent(in) :: payload(:)
    integer :: idx
    idx = pend_index(rid)
    if (idx == 0) return
    pends(idx)%payload = payload
    pends(idx)%done = .true.
  end subroutine tr_pending_deliver

  logical function tr_pending_done(rid)
    character(len=*), intent(in) :: rid
    integer :: idx
    idx = pend_index(rid)
    tr_pending_done = .false.
    if (idx > 0) tr_pending_done = pends(idx)%done
  end function tr_pending_done

  ! take + clear the delivered payload for request_id (found=.false. if none).
  subroutine tr_pending_take(rid, payload, found)
    character(len=*),           intent(in)  :: rid
    integer(int8), allocatable, intent(out) :: payload(:)
    logical,                    intent(out) :: found
    integer :: idx
    found = .false.
    allocate(payload(0))
    idx = pend_index(rid)
    if (idx == 0) return
    if (.not. pends(idx)%done) return
    if (allocated(pends(idx)%payload)) payload = pends(idx)%payload
    found = .true.
    pends(idx)%used = .false.
    pends(idx)%done = .false.
    if (allocated(pends(idx)%payload)) deallocate(pends(idx)%payload)
  end subroutine tr_pending_take

end module entity_core_transport
