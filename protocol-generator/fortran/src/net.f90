! entity-core-protocol-fortran — src/net.f90
!
! iso_c_binding interface to the C net-shim (src/ext/net_shim.c) — the ONLY C wrapper in
! the peer (crypto/framing/base58 bind libentitycore_codec directly, no wrapper). Fortran
! has no native sockets, so the shim owns the real BSD sockets + the single select() loop
! + §1.6 de-framing, and the Fortran peer drives it by symbol (linked directly — unlike
! the Rexx peer's co-process-over-FIFOs, since Regina cannot dlopen a C extension).
! Also binds the wall-clock + CSPRNG helpers (§4.4 timestamps, §4.6 nonce).
module entity_core_net
  use, intrinsic :: iso_c_binding, only : c_int, c_int8_t, c_long_long
  use, intrinsic :: iso_fortran_env, only : int8, int64
  implicit none
  private

  ! event kinds returned by ec_net_poll (must match net_shim.c).
  integer, parameter, public :: EV_NONE = 0, EV_ACCEPT = 1, EV_FRAME = 2, &
                                EV_CLOSED = 3, EV_OVERSIZE = 4, &
                                EV_TRUNCATED = 5   ! §4.11: FIN with a partial frame buffered

  public :: net_listen, net_connect, net_send, net_close, net_shutdown, net_poll
  public :: now_ms, random_bytes

  integer, parameter :: POLL_CAP = 16*1024*1024 + 64     ! §4.10 max payload + slack
  ! module-level receive scratch (single-thread pump -> no reentrancy on it); heap-backed
  ! via SAVE so it never lands on the stack (a 16-MiB automatic array would overflow).
  integer(int8), save :: rxbuf(POLL_CAP)

  interface
    function ec_net_listen(port) bind(c, name='ec_net_listen') result(r)
      import :: c_int
      integer(c_int), value :: port
      integer(c_int)        :: r
    end function ec_net_listen

    function ec_net_connect(port) bind(c, name='ec_net_connect') result(r)
      import :: c_int
      integer(c_int), value :: port
      integer(c_int)        :: r
    end function ec_net_connect

    subroutine ec_net_send(id, buf, length) bind(c, name='ec_net_send')
      import :: c_int, c_int8_t
      integer(c_int),    value      :: id
      integer(c_int8_t), intent(in) :: buf(*)
      integer(c_int),    value      :: length
    end subroutine ec_net_send

    subroutine ec_net_close(id) bind(c, name='ec_net_close')
      import :: c_int
      integer(c_int), value :: id
    end subroutine ec_net_close

    subroutine ec_net_shutdown() bind(c, name='ec_net_shutdown')
    end subroutine ec_net_shutdown

    function ec_net_poll(timeout_ms, out_id, out_buf, out_cap, out_len) &
        bind(c, name='ec_net_poll') result(kind)
      import :: c_int, c_int8_t
      integer(c_int),    value       :: timeout_ms
      integer(c_int),    intent(out) :: out_id
      integer(c_int8_t), intent(out) :: out_buf(*)
      integer(c_int),    value       :: out_cap
      integer(c_int),    intent(out) :: out_len
      integer(c_int)                 :: kind
    end function ec_net_poll

    function ec_now_ms() bind(c, name='ec_now_ms') result(r)
      import :: c_long_long
      integer(c_long_long) :: r
    end function ec_now_ms

    subroutine ec_random(buf, n) bind(c, name='ec_random')
      import :: c_int, c_int8_t
      integer(c_int8_t), intent(out) :: buf(*)
      integer(c_int),    value       :: n
    end subroutine ec_random
  end interface

contains

  integer function net_listen(port)
    integer, intent(in) :: port
    net_listen = int(ec_net_listen(int(port, c_int)))
  end function net_listen

  integer function net_connect(port)
    integer, intent(in) :: port
    net_connect = int(ec_net_connect(int(port, c_int)))
  end function net_connect

  subroutine net_send(id, buf)
    integer,       intent(in) :: id
    integer(int8), intent(in) :: buf(:)
    if (size(buf) > 0) then
      call ec_net_send(int(id, c_int), buf, int(size(buf), c_int))
    else
      call ec_net_send(int(id, c_int), buf, 0_c_int)
    end if
  end subroutine net_send

  subroutine net_close(id)
    integer, intent(in) :: id
    call ec_net_close(int(id, c_int))
  end subroutine net_close

  subroutine net_shutdown()
    call ec_net_shutdown()
  end subroutine net_shutdown

  ! poll one event. kind is EV_*; for FRAME/OVERSIZE payload(1:plen) is filled.
  subroutine net_poll(timeout_ms, kind, id, payload, plen)
    integer,                    intent(in)  :: timeout_ms
    integer,                    intent(out) :: kind
    integer,                    intent(out) :: id
    integer(int8), allocatable, intent(out) :: payload(:)
    integer,                    intent(out) :: plen
    integer(c_int) :: cid, clen
    kind = int(ec_net_poll(int(timeout_ms, c_int), cid, rxbuf, int(POLL_CAP, c_int), clen))
    id = int(cid); plen = int(clen)
    if (plen > 0) then
      payload = rxbuf(1:plen)
    else
      allocate(payload(0))
    end if
  end subroutine net_poll

  integer(int64) function now_ms()
    now_ms = int(ec_now_ms(), int64)
  end function now_ms

  function random_bytes(n) result(b)
    integer, intent(in) :: n
    integer(int8) :: b(n)
    call ec_random(b, int(n, c_int))
  end function random_bytes

end module entity_core_net
