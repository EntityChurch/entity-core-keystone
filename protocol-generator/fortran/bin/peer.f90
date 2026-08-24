! entity-core-protocol-fortran — bin/peer.f90 (the standalone S4-ready host).
!
! Boots ONE peer on a localhost port, prints a `LISTENING <port>` readiness line (so a
! harness — run-s4.sh — can scrape the bound port), then runs the single-threaded select-
! pump forever (peer_serve, the §4.9 serve loop). Compiled binary linking the C net-shim
! + libentitycore_codec directly (no co-process — Fortran's first-class C interop).
!
! Flags:
!   --port N               bind port (0 = ephemeral, the default)
!   --name NAME            load/create the Ed25519 identity at ~/.entity/peers/NAME/keypair
!                          (the Go entity-peer / peer-manager convention; lets the
!                          validator's multisig accept-path probe co-sign AS the peer)
!   --seed HH              fallback: one hex byte repeated 32x (deterministic seed)
!   --port-file PATH       write "<bound_port>\n<peer_id>\n" (the two-peer smoke handshake)
!   --debug-open-grants    degenerate [default -> *] admin seed policy (deprecated; §6.9a)
!   --validate             bootstrap the §7a system-validate conformance handlers (off by
!                          default — a standing dispatch-outbound originator must not ship)
program peer_main
  use, intrinsic :: iso_fortran_env, only : int8, output_unit
  use entity_core_peer
  use entity_core_keystore
  implicit none

  integer :: nargs, i, port, bound, u, ios
  character(len=:), allocatable :: name, seedhex, portfile
  logical :: open_grants, validate
  integer(int8) :: seed(32)
  character(len=256) :: arg

  port = 0; name = ''; seedhex = ''; portfile = ''
  open_grants = .false.; validate = .false.

  nargs = command_argument_count()
  i = 1
  do while (i <= nargs)
    call get_command_argument(i, arg)
    select case (trim(arg))
    case ('--port');              i = i + 1; call get_command_argument(i, arg); read(arg,*) port
    case ('--name');              i = i + 1; call get_command_argument(i, arg); name = trim(arg)
    case ('--seed');              i = i + 1; call get_command_argument(i, arg); seedhex = trim(arg)
    case ('--port-file');         i = i + 1; call get_command_argument(i, arg); portfile = trim(arg)
    case ('--debug-open-grants'); open_grants = .true.
    case ('--validate');          validate = .true.
    case ('--net', '--base');     i = i + 1     ! accepted + ignored (no co-process)
    case default;                 continue
    end select
    i = i + 1
  end do

  if (len(name) > 0) then
    seed = keystore_seed_of_name(name)
  else if (len(seedhex) > 0) then
    seed = keystore_seed_of_hexbyte(seedhex)
  else
    seed = keystore_seed_of_hexbyte('11')
  end if

  call peer_create(seed, open_grants, validate)
  bound = peer_listen(port)
  if (bound < 0) then
    write(0, '(a,i0)') 'peer: LISTEN failed on port ', port
    stop 1
  end if

  write(output_unit, '(a,i0)') 'LISTENING ', bound
  flush(output_unit)

  if (len(portfile) > 0) then
    open(newunit=u, file=portfile, status='replace', action='write', iostat=ios)
    if (ios == 0) then
      write(u, '(i0)') bound
      write(u, '(a)') peer_local()
      close(u)
    end if
  end if

  call peer_serve()
  call peer_shutdown()
end program peer_main
