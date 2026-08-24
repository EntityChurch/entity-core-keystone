! entity-core-protocol-fortran — src/keystore.f90 (L1 keystore primitive).
!
! Persistent Ed25519 identity at the peer-manager convention path
! ~/.entity/peers/NAME/keypair — an entity-core PEM = base64 of the 32-byte seed between
! `-----BEGIN ENTITY PRIVATE KEY-----` / `-----END ENTITY PRIVATE KEY-----` (the Go
! entity-peer `--name` / crypto.LookupKeypairByPeerID convention, so the validator's
! multisig accept-path probe can co-sign AS the peer at S4). Base64 is hand-rolled here
! (no native Fortran base64); the seed itself never crosses the C-ABI.
module entity_core_keystore
  use, intrinsic :: iso_fortran_env, only : int8
  use entity_core_net, only : random_bytes
  implicit none
  private

  public :: keystore_seed_of_name, keystore_seed_of_hexbyte, b64_encode, b64_decode

  character(len=*), parameter :: B64 = &
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

contains

  ! a deterministic 32-byte seed = one hex byte repeated 32x (the smoke/test convention).
  function keystore_seed_of_hexbyte(hh) result(seed)
    character(len=*), intent(in) :: hh
    integer(int8) :: seed(32)
    integer :: v, hi, lo
    hi = hexval(hh(1:1)); lo = hexval(hh(2:2))
    v = ishft(hi, 4) + lo
    seed = int(v, int8)
  end function keystore_seed_of_hexbyte

  ! load the seed for NAME from the keypair PEM, creating one (random) if absent.
  function keystore_seed_of_name(name) result(seed)
    character(len=*), intent(in) :: name
    integer(int8) :: seed(32)
    character(len=:), allocatable :: home, dir, path, b64line, line
    integer(int8), allocatable :: decoded(:)
    integer :: u, ios
    logical :: exists
    call get_environment_variable('HOME', length=ios)
    if (ios > 0) then
      allocate(character(len=ios) :: home); call get_environment_variable('HOME', home)
    else
      home = '/root'
    end if
    dir = trim(home) // '/.entity/peers/' // trim(name)
    path = dir // '/keypair'
    inquire(file=path, exist=exists)
    if (exists) then
      b64line = ''
      open(newunit=u, file=path, status='old', action='read', iostat=ios)
      if (ios == 0) then
        do
          call read_line(u, line, ios)
          if (ios /= 0) exit
          if (index(line, 'BEGIN') > 0 .or. index(line, 'END') > 0) cycle
          if (len_trim(line) > 0) b64line = b64line // trim(adjustl(line))
        end do
        close(u)
      end if
      decoded = b64_decode(b64line)
      if (size(decoded) >= 32) then; seed = decoded(1:32); return; end if
    end if
    ! create fresh
    seed = random_bytes(32)
    call execute_command_line('mkdir -p ' // dir, wait=.true.)
    open(newunit=u, file=path, status='replace', action='write', iostat=ios)
    if (ios == 0) then
      write(u, '(a)') '-----BEGIN ENTITY PRIVATE KEY-----'
      write(u, '(a)') b64_encode(seed)
      write(u, '(a)') '-----END ENTITY PRIVATE KEY-----'
      close(u)
    end if
  end function keystore_seed_of_name

  subroutine read_line(u, line, ios)
    integer,                       intent(in)  :: u
    character(len=:), allocatable, intent(out) :: line
    integer,                       intent(out) :: ios
    character(len=512) :: buf
    integer :: n
    read(u, '(a)', iostat=ios, size=n, advance='no') buf
    if (ios > 0) return
    if (is_iostat_eor(ios)) ios = 0
    line = buf(1:n)
  end subroutine read_line

  integer function hexval(c)
    character(len=1), intent(in) :: c
    if (c >= '0' .and. c <= '9') then; hexval = ichar(c) - ichar('0')
    else if (c >= 'a' .and. c <= 'f') then; hexval = ichar(c) - ichar('a') + 10
    else if (c >= 'A' .and. c <= 'F') then; hexval = ichar(c) - ichar('A') + 10
    else; hexval = 0; end if
  end function hexval

  function b64_encode(b) result(s)
    integer(int8), intent(in) :: b(:)
    character(len=:), allocatable :: s
    integer :: i, n, o, v
    n = size(b)
    allocate(character(len=4*((n+2)/3)) :: s)
    o = 0
    do i = 1, n, 3
      v = ishft(iand(int(b(i)), 255), 16)
      if (i+1 <= n) v = ior(v, ishft(iand(int(b(i+1)), 255), 8))
      if (i+2 <= n) v = ior(v, iand(int(b(i+2)), 255))
      s(o+1:o+1) = B64(iand(ishft(v,-18),63)+1:iand(ishft(v,-18),63)+1)
      s(o+2:o+2) = B64(iand(ishft(v,-12),63)+1:iand(ishft(v,-12),63)+1)
      if (i+1 <= n) then; s(o+3:o+3) = B64(iand(ishft(v,-6),63)+1:iand(ishft(v,-6),63)+1)
      else; s(o+3:o+3) = '='; end if
      if (i+2 <= n) then; s(o+4:o+4) = B64(iand(v,63)+1:iand(v,63)+1)
      else; s(o+4:o+4) = '='; end if
      o = o + 4
    end do
  end function b64_encode

  function b64_decode(s) result(b)
    character(len=*), intent(in) :: s
    integer(int8), allocatable :: b(:)
    integer(int8), allocatable :: tmp(:)
    integer :: i, v, bits, acc, c, n
    allocate(tmp(len(s)))
    n = 0; acc = 0; bits = 0
    do i = 1, len(s)
      if (s(i:i) == '=') exit
      c = index(B64, s(i:i)) - 1
      if (c < 0) cycle
      acc = ior(ishft(acc, 6), c)
      bits = bits + 6
      if (bits >= 8) then
        bits = bits - 8
        v = iand(ishft(acc, -bits), 255)
        n = n + 1; tmp(n) = int(v, int8)
      end if
    end do
    b = tmp(1:n)
  end function b64_decode

end module entity_core_keystore
