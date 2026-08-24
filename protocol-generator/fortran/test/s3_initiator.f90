! entity-core-protocol-fortran — test/s3_initiator.f90 (the S3 phase-exit gate).
!
! Boots a second peer, dials the responder over REAL loopback TCP through the full §6.5
! dispatch chain (both peers on their own single-threaded select-pump), drives the §4.1
! forward handshake (hello -> authenticate), then:
!   - handshake both directions established (a capability was minted server-side);
!   - remote peer_id is a base58 peer id and matches the responder;
!   - 404 on an unregistered path (no handler resolved, chain-verify still ALLOWs);
!   - 8-way request_id demux of concurrently-issued replies (N7, §6.11) — 8 EXECUTEs in
!     flight on the one connection, resolved out of order by the pump.
program s3_initiator
  use, intrinsic :: iso_fortran_env, only : int8, output_unit
  use entity_core_cbor, only : ecf_value_t, EV_ABSENT
  use entity_core_val
  use entity_core_ent
  use entity_core_wire
  use entity_core_capability, only : cap_is_peer_id
  use entity_core_peer
  use entity_core_keystore
  implicit none

  integer :: nargs, i, port, npass, nfail, k
  character(len=:), allocatable :: expected, seedhex, remote, rid
  character(len=256) :: arg
  integer(int8) :: seed(32)
  type(session_t) :: sess
  type(envelope_t) :: resp
  type(ecf_value_t) :: absent
  logical :: ok
  type(str_t), allocatable :: rids(:)

  port = 0; expected = ''; seedhex = '22'
  nargs = command_argument_count()
  i = 1
  do while (i <= nargs)
    call get_command_argument(i, arg)
    select case (trim(arg))
    case ('--port');   i = i + 1; call get_command_argument(i, arg); read(arg,*) port
    case ('--peerid'); i = i + 1; call get_command_argument(i, arg); expected = trim(arg)
    case ('--seed');   i = i + 1; call get_command_argument(i, arg); seedhex = trim(arg)
    end select
    i = i + 1
  end do

  absent%vkind = EV_ABSENT
  npass = 0; nfail = 0
  seed = keystore_seed_of_hexbyte(seedhex)
  call peer_create(seed, .false., .false.)

  sess = peer_dial(port)
  if (.not. sess%ok) then
    write(output_unit, '(a)') 'SMOKE: DIAL/handshake FAILED'
    stop 1
  end if
  remote = sess%remote_peer_id
  call check('session established both ways (capability minted)', sess%cap%present)
  call check('remote peer_id is a base58 peer id', cap_is_peer_id(remote))
  if (len(expected) > 0) call check('remote peer_id matches responder', remote == expected)

  ! 404 on an unregistered path
  call sess_execute(sess, '/' // remote // '/does/not/exist', 'noop', wire_empty_params(), absent, resp, ok)
  call check('unregistered path -> 404', ok .and. wire_response_status(resp) == 404)

  ! 8-way request_id demux (N7, §6.11) — 8 EXECUTEs in flight at once
  allocate(rids(0))
  do k = 1, 8
    rid = sess_execute_async(sess, '/' // remote // '/does/not/exist', 'noop', wire_empty_params(), absent)
    call push(rids, rid)
  end do
  do k = 1, 8
    call sess_await(rids(k)%s, ok)
  end do
  block
    integer :: correlated
    logical :: found
    correlated = 0
    do k = 1, 8
      call sess_response(rids(k)%s, resp, found)
      if (.not. found) cycle
      if (wire_response_status(resp) /= 404) cycle
      if (ent_text(resp%root, 'request_id') == rids(k)%s) correlated = correlated + 1
    end do
    call check('8 interleaved requests each correlated by request_id', correlated == 8)
  end block

  call peer_shutdown()
  write(output_unit, '(a)') ''
  if (nfail > 0) then
    write(output_unit, '(a,i0,a,i0,a)') 'SMOKE: FAIL (', npass, '/', npass+nfail, ')'
    stop 1
  end if
  write(output_unit, '(a,i0,a,i0,a)') 'SMOKE: PASS (', npass, '/', npass+nfail, ')'

contains
  subroutine check(name, cond)
    character(len=*), intent(in) :: name
    logical,          intent(in) :: cond
    if (cond) then; npass = npass + 1; write(output_unit,'(a,a)') '  [PASS] ', name
    else; nfail = nfail + 1; write(output_unit,'(a,a)') '  [FAIL] ', name; end if
  end subroutine check

  subroutine push(l, s)
    type(str_t), allocatable, intent(inout) :: l(:)
    character(len=*),         intent(in)    :: s
    type(str_t), allocatable :: tmp(:)
    allocate(tmp(size(l)+1))
    if (size(l) > 0) tmp(1:size(l)) = l
    tmp(size(tmp))%s = s
    call move_alloc(tmp, l)
  end subroutine push
end program s3_initiator
