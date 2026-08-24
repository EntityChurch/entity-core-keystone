! entity-core-protocol-fortran — test/conformance.f90
!
! S2 FULL codec conformance driver (the gate). Walks the pinned v0.8.0 corpus
! (conformance-vectors-v1.cbor) decoded with OUR OWN decoder, and asserts per vector:
!   - encode_equal:   our re-encode of `input` == `canonical` bytes, byte-identical
!   - decode_reject:  our decoder REJECTS `canonical` (the N2 tag scanner et al.)
! Class B (content_hash / peer_id / signature) is reconstructed through the codec +
! the C-ABI crypto/base58 (bound DIRECTLY via iso_c_binding — no helper binary, unlike
! Rexx). A byte disagreement means OUR code is wrong (never the vector).
!
! Usage: conformance <corpus.cbor>
program conformance
  use, intrinsic :: iso_fortran_env, only : int8, int64, error_unit, output_unit
  use entity_core_status
  use entity_core_cbor
  use entity_core_varint
  use entity_core_entity
  implicit none

  character(len=4096) :: path
  integer(int8), allocatable :: filebuf(:)
  type(ecf_value_t) :: top, vec, idv, kindv, canonv, inputv
  integer :: consumed, stat, nvec, i
  integer :: npass, nfail, nskip
  character(len=64) :: id, kind, cat
  integer(int8), allocatable :: canon(:), got(:)
  logical :: ok
  character(len=256) :: st_report
  logical :: st_ok

  npass = 0; nfail = 0; nskip = 0

  ! ── head-form self-test first (A-FTN-002) — the signed-carrier uint64 tower must
  !    round-trip the full [2^63, 2^64-1] boundary byte-exact before we trust anything. ──
  call head_form_selftest(st_ok, st_report)
  if (.not. st_ok) then
    write(error_unit,'(a)') 'FATAL: head-form self-test FAILED: '//trim(st_report)
    stop 2
  end if
  write(output_unit,'(a)') 'head-form self-test: '//trim(st_report)

  call get_command_argument(1, path)
  if (len_trim(path) == 0) then
    write(error_unit,'(a)') 'usage: conformance <corpus.cbor>'
    stop 2
  end if

  call read_file(trim(path), filebuf, stat)
  if (stat /= 0) then
    write(error_unit,'(a)') 'FATAL: cannot read corpus '//trim(path)
    stop 2
  end if

  call cbor_decode(filebuf, top, consumed, stat)
  if (stat /= EC_OK) then
    write(error_unit,'(a,i0)') 'FATAL: corpus did not decode, stat=', stat
    stop 2
  end if
  if (top%vkind /= EV_ARRAY) then
    write(error_unit,'(a)') 'FATAL: corpus top-level is not an array'
    stop 2
  end if
  nvec = size(top%items)

  do i = 1, nvec
    vec   = top%items(i)
    idv   = ev_map_get(vec, 'id')
    kindv = ev_map_get(vec, 'kind')
    id    = bytes_to_str(ev_text_bytes(idv))
    kind  = bytes_to_str(ev_text_bytes(kindv))
    cat   = category(id)

    if (trim(kind) == 'decode_reject') then
      canonv = ev_map_get(vec, 'canonical')
      canon  = ev_get_bytes(canonv)
      call assert_reject(id, canon, npass, nfail)
      cycle
    end if

    ! encode_equal
    canonv = ev_map_get(vec, 'canonical')
    canon  = ev_get_bytes(canonv)
    inputv = ev_map_get(vec, 'input')

    select case (trim(cat))
    case ('peer_id')
      call build_peerid(inputv, got, ok)
    case ('content_hash')
      call build_content_hash(inputv, got, ok)
    case ('signature')
      call build_signature(inputv, got, ok)
    case default
      call cbor_encode(inputv, got, stat)
      ok = (stat == EC_OK)
    end select

    if (.not. ok) then
      call fail(id, 'unexpected build/encode reject', nfail)
      cycle
    end if
    if (bytes_eq(got, canon)) then
      npass = npass + 1
    else
      call fail(id, 'encode mismatch want='//hexs(canon)//' got='//hexs(got), nfail)
    end if
  end do

  write(output_unit,'(a)') ''
  write(output_unit,'(a,i0,a,i0,a,i0,a,i0,a)') &
      '=== conformance: ', nvec, ' vectors — ', npass, ' pass / ', nfail, &
      ' fail / ', nskip, ' skip ==='
  if (nfail > 0) stop 1
  stop 0

contains

  ! id up to the first '.' (e.g. "peer_id.3" -> "peer_id").
  function category(idstr) result(c)
    character(len=*), intent(in) :: idstr
    character(len=64) :: c
    integer :: p
    p = index(idstr, '.')
    if (p > 0) then; c = idstr(1:p-1); else; c = idstr; end if
  end function category

  subroutine build_peerid(inputv, got, ok)
    type(ecf_value_t), intent(in)               :: inputv
    integer(int8), allocatable, intent(out)     :: got(:)
    logical,                    intent(out)     :: ok
    integer(int64) :: kt, ht
    integer(int8), allocatable :: digest(:)
    integer(int8)  :: ascii(96)
    integer        :: alen, stat
    type(ecf_value_t) :: peerid_text
    kt     = ev_get_uint(ev_map_get(inputv, 'key_type'))
    ht     = ev_get_uint(ev_map_get(inputv, 'hash_type'))
    digest = ev_get_bytes(ev_map_get(inputv, 'digest'))
    call peerid_format_compute(kt, ht, digest, ascii, alen, stat)
    if (stat /= EC_OK) then; ok = .false.; allocate(got(0)); return; end if
    ! the canonical vector is the base58 string ECF-encoded as a CBOR text string.
    peerid_text = ev_text_make(ascii(1:alen))
    call cbor_encode(peerid_text, got, stat)
    ok = (stat == EC_OK)
  end subroutine build_peerid

  subroutine build_content_hash(inputv, got, ok)
    type(ecf_value_t), intent(in)               :: inputv
    integer(int8), allocatable, intent(out)     :: got(:)
    logical,                    intent(out)     :: ok
    type(ecf_value_t) :: typev, datav, fcv
    integer(int64)    :: code
    integer(int8)     :: out(48)
    integer           :: olen, stat
    typev = ev_map_get(inputv, 'type')
    datav = ev_map_get(inputv, 'data')
    fcv   = ev_map_get(inputv, 'format_code')
    if (fcv%vkind == EV_UINT) then; code = ev_get_uint(fcv); else; code = 0_int64; end if
    call content_hash_compute(typev, datav, code, out, olen, stat)
    if (stat /= EC_OK) then; ok = .false.; allocate(got(0)); return; end if
    got = out(1:olen)
    ok  = .true.
  end subroutine build_content_hash

  subroutine build_signature(inputv, got, ok)
    type(ecf_value_t), intent(in)               :: inputv
    integer(int8), allocatable, intent(out)     :: got(:)
    logical,                    intent(out)     :: ok
    integer(int8), allocatable :: seed(:)
    integer(int8)     :: seed32(32), sig(64)
    type(ecf_value_t) :: entity
    integer           :: stat
    seed = ev_get_bytes(ev_map_get(inputv, 'seed'))
    if (size(seed) /= 32) then; ok = .false.; allocate(got(0)); return; end if
    seed32 = seed(1:32)
    entity = ev_map_get(inputv, 'entity')
    call sign_compute(seed32, entity, sig, stat)
    if (stat /= EC_OK) then; ok = .false.; allocate(got(0)); return; end if
    got = sig
    ok  = .true.
  end subroutine build_signature

  ! A decode_reject vector passes iff decoding it as a COMPLETE message fails: either the
  ! decoder errors (e.g. the N2 major-type-6 tag scanner — tag_reject.4) OR the item does
  ! not consume the whole input (trailing bytes — the reference C codec's ecf.c:471
  ! `if (r.pos != len) return NULL /* trailing bytes */`, ecf.h:95 "malformed / trailing").
  ! FINDING (A-FTN-012): tag_reject.1/2/3/5's .cbor bytes do NOT contain the tags their
  ! .diag descriptions claim — they decode to a leading entity + trailing garbage, so they
  ! exercise ONLY trailing/malformed rejection, NOT the tag scanner. Only tag_reject.4
  ! actually covers N2. The real nested-tag coverage is our unit suite (t_n2_tag_reject).
  subroutine assert_reject(id, canon, npass, nfail)
    character(len=*), intent(in)    :: id
    integer(int8),    intent(in)    :: canon(:)
    integer,          intent(inout) :: npass, nfail
    type(ecf_value_t) :: v
    integer :: consumed, stat
    call cbor_decode(canon, v, consumed, stat)
    if (stat /= EC_OK .or. consumed /= size(canon)) then
      npass = npass + 1
    else
      call fail(id, 'expected decode reject, but decoded cleanly (full consumption)', nfail)
    end if
  end subroutine assert_reject

  subroutine fail(id, why, nfail)
    character(len=*), intent(in)    :: id, why
    integer,          intent(inout) :: nfail
    nfail = nfail + 1
    write(output_unit,'(a)') '  FAIL '//trim(id)//': '//trim(why)
  end subroutine fail

  logical function bytes_eq(a, b)
    integer(int8), intent(in) :: a(:), b(:)
    bytes_eq = .false.
    if (size(a) /= size(b)) return
    bytes_eq = all(a == b)
  end function bytes_eq

  function bytes_to_str(b) result(s)
    integer(int8), intent(in) :: b(:)
    character(len=64) :: s
    integer :: i
    s = ''
    do i = 1, min(size(b), 64)
      s(i:i) = achar(iand(int(b(i)), 255))
    end do
  end function bytes_to_str

  function hexs(b) result(s)
    integer(int8), intent(in) :: b(:)
    character(len=2*size(b)) :: s
    character(len=16), parameter :: H = '0123456789abcdef'
    integer :: i, u
    do i = 1, size(b)
      u = iand(int(b(i)), 255)
      s(2*i-1:2*i-1) = H(ishft(u,-4)+1 : ishft(u,-4)+1)
      s(2*i:2*i)     = H(iand(u,15)+1 : iand(u,15)+1)
    end do
  end function hexs

  subroutine read_file(fname, buf, stat)
    character(len=*),           intent(in)  :: fname
    integer(int8), allocatable, intent(out) :: buf(:)
    integer,                    intent(out) :: stat
    integer :: u, sz, ios
    stat = 0
    inquire(file=fname, size=sz, iostat=ios)
    if (ios /= 0 .or. sz < 0) then; stat = 1; return; end if
    allocate(buf(sz))
    open(newunit=u, file=fname, access='stream', form='unformatted', &
         status='old', action='read', iostat=ios)
    if (ios /= 0) then; stat = 1; return; end if
    read(u, iostat=ios) buf
    close(u)
    if (ios /= 0) stat = 1
  end subroutine read_file

end program conformance
