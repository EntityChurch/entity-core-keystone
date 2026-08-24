! entity-core-protocol-fortran — test/unit_tests.f90
!
! S2 codec unit tests. The profile's framework is test-drive (0.6.1), VENDORED as a
! single testdrive.F90 — but that file must be brought in offline and is not yet in the
! tree (A-FTN-010: deferred to when it can be vendored under --network=none). Until then
! these are plain-Fortran assertions with the same intent: a covering test for EACH of
! N1–N4 plus the accept-path directions the rejection-heavy corpus can't reach (the
! "always add an accept-path test" durable lesson).
program unit_tests
  use, intrinsic :: iso_fortran_env, only : int8, int64, output_unit, error_unit
  use, intrinsic :: ieee_arithmetic, only : ieee_value, ieee_positive_inf
  use entity_core_status
  use entity_core_cbor
  use entity_core_varint
  implicit none

  integer :: nfail
  nfail = 0

  call t_head_form_selftest(nfail)   ! A-FTN-002 signed-carrier uint64 tower
  call t_n1_varint_multibyte(nfail)  ! N1 LEB128 widening (>= 0x80)
  call t_n2_tag_reject(nfail)        ! N2 recursive major-type-6 reject
  call t_n3_empty_map(nfail)         ! N3 empty map == 0xA0
  call t_n4_fidelity(nfail)          ! N4 original-bytes span preserved
  call t_map_sort_accept(nfail)      ! accept-path: canonical key sort (length-then-lex)
  call t_float_ladder(nfail)         ! Rule 4 f16/f32/f64 spot checks
  call t_neg_ints(nfail)             ! mt1 minimal head
  call t_ult(nfail)                  ! unsigned-compare bias trick

  write(output_unit,'(a)') ''
  if (nfail == 0) then
    write(output_unit,'(a)') '=== unit_tests: ALL PASS ==='
    stop 0
  else
    write(output_unit,'(a,i0,a)') '=== unit_tests: ', nfail, ' FAIL ==='
    stop 1
  end if

contains

  subroutine check(cond, name, nfail)
    logical,          intent(in)    :: cond
    character(len=*), intent(in)    :: name
    integer,          intent(inout) :: nfail
    if (cond) then
      write(output_unit,'(a)') '  ok   '//name
    else
      write(output_unit,'(a)') '  FAIL '//name
      nfail = nfail + 1
    end if
  end subroutine check

  function h(b) result(s)
    integer(int8), intent(in) :: b(:)
    character(len=2*size(b)) :: s
    character(len=16), parameter :: HX = '0123456789abcdef'
    integer :: i, u
    do i = 1, size(b)
      u = iand(int(b(i)), 255)
      s(2*i-1:2*i-1) = HX(ishft(u,-4)+1 : ishft(u,-4)+1)
      s(2*i:2*i)     = HX(iand(u,15)+1 : iand(u,15)+1)
    end do
  end function h

  logical function enc_is(v, hexwant)
    type(ecf_value_t), intent(in) :: v
    character(len=*),  intent(in) :: hexwant
    integer(int8), allocatable :: out(:)
    integer :: stat
    call cbor_encode(v, out, stat)
    enc_is = (stat == EC_OK) .and. (h(out) == hexwant)
  end function enc_is

  subroutine t_head_form_selftest(nfail)
    integer, intent(inout) :: nfail
    logical :: ok
    character(len=256) :: rep
    call head_form_selftest(ok, rep)
    call check(ok, 'A-FTN-002 head-form self-test {0,2^63-1,2^63,2^64-2,2^64-1}', nfail)
  end subroutine t_head_form_selftest

  subroutine t_n1_varint_multibyte(nfail)
    integer, intent(inout) :: nfail
    integer(int8) :: out(10)
    integer :: vlen, stat, pos
    integer(int64) :: code
    ! 127 -> 0x7f (single byte); 128 -> 0x80 0x01 (widens — the N1 trap)
    call varint_encode(127_int64, out, vlen, stat)
    call check(stat==EC_OK .and. vlen==1 .and. out(1)==127_int8, 'N1 varint 127 = 7f', nfail)
    call varint_encode(128_int64, out, vlen, stat)
    call check(stat==EC_OK .and. vlen==2 .and. iand(int(out(1)),255)==128 .and. &
               out(2)==1_int8, 'N1 varint 128 = 80 01 (LEB128 widening)', nfail)
    ! round-trip decode
    pos = 1
    call varint_decode(out, pos, code, stat)
    call check(stat==EC_OK .and. code==128_int64 .and. pos==3, 'N1 varint 128 decode round-trip', nfail)
    ! 300 -> 0xac 0x02
    call varint_encode(300_int64, out, vlen, stat)
    call check(stat==EC_OK .and. vlen==2 .and. iand(int(out(1)),255)==172 .and. &
               out(2)==2_int8, 'N1 varint 300 = ac 02', nfail)
  end subroutine t_n1_varint_multibyte

  subroutine t_n2_tag_reject(nfail)
    integer, intent(inout) :: nfail
    type(ecf_value_t) :: v
    integer :: consumed, stat
    integer(int8) :: tag0(3)
    integer(int8), allocatable :: nested(:)
    ! tag 0 (0xc0) wrapping a text -> reject at top
    tag0 = [ int(z'C0',int8), int(z'61',int8), int(z'41',int8) ]   ! c0 61 'A'
    call cbor_decode(tag0, v, consumed, stat)
    call check(stat==EC_TAG_REJECTED, 'N2 top-level tag 0 (0xc0) rejected', nfail)
    ! tag 55799 (d9 d9 f7) then empty map -> reject
    nested = [ int(z'D9',int8), int(z'D9',int8), int(z'F7',int8), int(z'A0',int8) ]
    call cbor_decode(nested, v, consumed, stat)
    call check(stat==EC_TAG_REJECTED, 'N2 tag 55799 self-describe rejected', nfail)
    ! tag nested inside a map value: a1 61 'k' c0 00  -> reject (recursive scan)
    nested = [ int(z'A1',int8), int(z'61',int8), int(z'6B',int8), int(z'C0',int8), int(z'00',int8) ]
    call cbor_decode(nested, v, consumed, stat)
    call check(stat==EC_TAG_REJECTED, 'N2 tag nested in map value rejected (recursive)', nfail)
  end subroutine t_n2_tag_reject

  subroutine t_n3_empty_map(nfail)
    integer, intent(inout) :: nfail
    type(ecf_value_t) :: m, v
    integer :: consumed, stat
    integer(int8) :: a0(1)
    ! encode empty map -> single byte 0xA0
    m%vkind = EV_MAP                        ! no items allocated -> 0 pairs
    call check(enc_is(m, 'a0'), 'N3 empty map encodes to single byte 0xa0', nfail)
    ! decode 0xA0 -> empty map
    a0 = [ int(z'A0',int8) ]
    call cbor_decode(a0, v, consumed, stat)
    call check(stat==EC_OK .and. v%vkind==EV_MAP .and. consumed==1, 'N3 0xa0 decodes to empty map', nfail)
    ! empty array is 0x80, empty text 0x60, empty bytes 0x40 (boundary corroboration)
    call check(enc_is(ev_text_make_empty(), '60'), 'empty text -> 0x60', nfail)
  end subroutine t_n3_empty_map

  function ev_text_make_empty() result(v)
    type(ecf_value_t) :: v
    integer(int8) :: z(0)
    v = ev_text_make(z)
  end function ev_text_make_empty

  subroutine t_n4_fidelity(nfail)
    integer, intent(inout) :: nfail
    ! N4: after decode, the ORIGINAL wire span is recoverable (forward original bytes,
    ! never re-serialize). cbor_scan_len gives the exact node length WITHOUT decoding, so
    ! a peer can slice buf(pos:pos+len-1) — the original bytes — and forward them.
    integer(int8), allocatable :: entity(:)
    integer :: length, stat, consumed
    type(ecf_value_t) :: v
    ! {type:"a", data:{x:1}} : a2 64 64617461 a1 61 78 01 64 74797065 61 61
    entity = [ int(z'A2',int8), &
               int(z'64',int8), int(z'64',int8), int(z'61',int8), int(z'74',int8), int(z'61',int8), & ! "data"
               int(z'A1',int8), int(z'61',int8), int(z'78',int8), int(z'01',int8), &                  ! {x:1}
               int(z'64',int8), int(z'74',int8), int(z'79',int8), int(z'70',int8), int(z'65',int8), & ! "type"
               int(z'61',int8), int(z'61',int8) ]                                                     ! "a"
    call cbor_scan_len(entity, 1, length, stat)
    call check(stat==EC_OK .and. length==size(entity), &
               'N4 scan_len spans exactly the entity bytes (original-byte fidelity)', nfail)
    ! and a full decode consumes exactly the same span (no trailing re-interpretation)
    call cbor_decode(entity, v, consumed, stat)
    call check(stat==EC_OK .and. consumed==size(entity) .and. v%vkind==EV_MAP, &
               'N4 decode consumes exactly the original span', nfail)
  end subroutine t_n4_fidelity

  subroutine t_map_sort_accept(nfail)
    integer, intent(inout) :: nfail
    type(ecf_value_t) :: m
    ! Build {"aa":2, "z":1} in NON-canonical order (aa first). The encoder MUST reorder
    ! to length-then-lex: "z" (len1) before "aa" (len2) -> a2 617a01 62616102. The corpus
    ! decode->encode path never exercises the sort (input is already canonical), so this
    ! accept-path test is the only coverage of it.
    m%vkind = EV_MAP
    allocate(m%items(4))
    m%items(1) = ev_text_make(str_bytes('aa')); m%items(2) = ev_uint_make(2_int64)
    m%items(3) = ev_text_make(str_bytes('z'));  m%items(4) = ev_uint_make(1_int64)
    call check(enc_is(m, 'a2617a0162616102'), 'accept-path: map key sort length-then-lex', nfail)
  end subroutine t_map_sort_accept

  subroutine t_float_ladder(nfail)
    integer, intent(inout) :: nfail
    type(ecf_value_t) :: v
    v%vkind = EV_FLOAT
    v%fval = 1.0d0;      call check(enc_is(v, 'f93c00'),         'float 1.0 -> f16 f93c00', nfail)
    v%fval = 1.5d0;      call check(enc_is(v, 'f93e00'),         'float 1.5 -> f16 f93e00', nfail)
    v%fval = 65504.0d0;  call check(enc_is(v, 'f97bff'),         'float 65504 -> f16 max normal', nfail)
    v%fval = 65503.0d0;  call check(enc_is(v, 'fa477fdf00'),     'float 65503 -> f32 (not f16)', nfail)
    v%fval = 100000.0d0; call check(enc_is(v, 'fa47c35000'),     'float 100000 -> f32', nfail)
    v%fval = 1.1d0;      call check(enc_is(v, 'fb3ff199999999999a'), 'float 1.1 -> f64', nfail)
    v%fval = ieee_value(0.0d0, ieee_positive_inf)
    call check(enc_is(v, 'f97c00'), 'float +inf -> f16 f97c00', nfail)
  end subroutine t_float_ladder

  subroutine t_neg_ints(nfail)
    integer, intent(inout) :: nfail
    type(ecf_value_t) :: v
    v%vkind = EV_NINT
    v%ival = 0_int64;   call check(enc_is(v, '20'),   'nint -1 -> 0x20', nfail)   ! n=0
    v%ival = 24_int64;  call check(enc_is(v, '3818'), 'nint -25 -> 0x3818', nfail) ! n=24
    v%ival = 255_int64; call check(enc_is(v, '38ff'), 'nint -256 -> 0x38ff', nfail)
  end subroutine t_neg_ints

  subroutine t_ult(nfail)
    integer, intent(inout) :: nfail
    ! the bias-trick unsigned compare: 2^63 (negative signed) must be > 5 unsigned.
    call check(.not. ult(ishft(1_int64,63), 5_int64), 'ult(2^63, 5) is false (2^63 > 5 unsigned)', nfail)
    call check(ult(5_int64, ishft(1_int64,63)), 'ult(5, 2^63) is true', nfail)
    call check(ult(0_int64, 1_int64), 'ult(0,1) true', nfail)
    call check(.not. ult(-1_int64, -1_int64), 'ult(2^64-1, 2^64-1) false', nfail)
    call check(ult(-2_int64, -1_int64), 'ult(2^64-2, 2^64-1) true', nfail)
  end subroutine t_ult

end program unit_tests
