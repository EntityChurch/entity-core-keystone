! entity-core-protocol-fortran — src/cbor.f90
!
! THE NUMERIC PROBE. Canonical ECF (RFC 8949 §4.2 deterministic CBOR) VALUE codec in
! PURE FORTRAN. This is the file the peer exists to stress: a fixed-width SIGNED-ONLY
! integer substrate carrying the full uint64 tower [0, 2^64-1], plus a native-IEEE
! float tower with a hand-rolled f16 + shortest-float ladder.
!
! ── Value model (A-FTN-003) ──
! Fortran has NO native sum type. `ecf_value_t` is a derived type with an integer
! major-type discriminant (vkind) that carries int-vs-float AND byte-vs-text intent
! EXPLICITLY — the encoder NEVER infers the CBOR major type from the Fortran storage
! kind. The self-referential `items(:)` (a POINTER component of its own type — A-FTN-011,
! see the type def) is the array / map aggregate (the tagged-union analogue).
!
! ── The uint64 signed bit-carrier (A-FTN-002) ──
! A value in [2^63, 2^64-1] is held as a 64-bit BIT PATTERN in a SIGNED integer(int64)
! carrier (it reads as a negative signed value with the same 64 bits). Wire octets are
! extracted with ishft/iand (sign-agnostic) — NEVER signed arithmetic. The minimal-head
! decision needs an UNSIGNED compare, done via the bias trick ult() (xor the sign bit,
! then a signed compare) — NEVER a bare signed `<` on the carrier. A mandatory head-form
! self-test round-trips {0, 2^63-1, 2^63, 2^64-2, 2^64-1} byte-exact.
!
! ── The float tower (A-FTN-005) ──
! real(real64)/real(real32) are native IEEE binary64/binary32; transfer(x,0_int*) reads
! their bits (native-endian, so octets are extracted MSB-first from the INTEGER VALUE —
! host-endianness-independent). f16 (binary16, no native kind) is hand-rolled; the Rule 4
! shortest-float ladder (does the value round-trip through f16 then f32 exactly?) is
! hand-decided and VERIFIED by decoding back and comparing bits.
!
! ── N2 / N3 ──
! Decode runs an explicit recursive major-type-6 REJECT at every value head (N2); the
! empty map is the single byte 0xA0 (N3). Byte buffers are integer(int8) (SIGNED, 0xFF
! reads as -1) so octet uses mask iand(b,255) (A-FTN-004).
module entity_core_cbor
  use, intrinsic :: iso_fortran_env, only : int8, int32, int64, real32, real64
  use, intrinsic :: ieee_arithmetic, only : ieee_is_nan
  use entity_core_status
  implicit none
  private

  ! value-kind discriminant (the explicit major-type intent — A-FTN-003)
  integer, parameter, public :: EV_ABSENT = -1   ! not-present sentinel (A-FTN-007)
  integer, parameter, public :: EV_UINT   = 0    ! mt0 — ival is the bit pattern
  integer, parameter, public :: EV_NINT   = 1    ! mt1 — ival is n, value = -1 - n
  integer, parameter, public :: EV_BYTES  = 2    ! mt2 — bytes(:)
  integer, parameter, public :: EV_TEXT   = 3    ! mt3 — bytes(:) (UTF-8)
  integer, parameter, public :: EV_ARRAY  = 4    ! mt4 — items(1:n)
  integer, parameter, public :: EV_MAP    = 5    ! mt5 — items(1:2n) as k,v,k,v
  integer, parameter, public :: EV_FLOAT  = 7    ! mt7 f16/f32/f64 — fval
  integer, parameter, public :: EV_BOOL   = 20   ! mt7 0xf4/0xf5 — bval
  integer, parameter, public :: EV_NULL   = 22   ! mt7 0xf6

  integer, parameter :: MAX_DEPTH = 64           ! §4.10 nesting bound

  ! The self-referential `items` component is a POINTER, not allocatable, on purpose:
  ! gfortran's compiler-generated RECURSIVE auto-deallocator for a derived type with an
  ! allocatable component of its OWN type double-frees on deep/aliased nesting (observed
  ! here decoding the corpus). A pointer component is never auto-deallocated and never
  ! recursively followed by a dtor, so the bug can't fire. The decoded tree is arena-like:
  ! never freed, reclaimed at process exit (the codec is a one-shot per message; S3's
  ! store owns lifetime explicitly). Byte payloads stay allocatable (not self-referential,
  ! so safe + auto-freed). Default `=> null()` init means an intent(out) node is null on
  ! entry (so `associated()` is always well-defined). This is A-FTN-011.
  type, public :: ecf_value_t
    integer                     :: vkind = EV_ABSENT
    integer(int64)              :: ival  = 0_int64         ! uint/nint bit pattern
    real(real64)                :: fval  = 0.0_real64      ! float value
    logical                     :: bval  = .false.         ! bool
    integer(int8), allocatable  :: bytes(:)                ! bytes/text payload
    type(ecf_value_t), pointer  :: items(:) => null()      ! array elems / map k,v pairs
  end type ecf_value_t

  public :: cbor_encode, cbor_decode, cbor_scan_len
  public :: ev_map_get, ev_has, ev_get_uint, ev_get_bytes, ev_text_bytes, ev_text_equals
  public :: ev_uint_make, ev_text_make, ev_bytes_make, ev_map_make2
  public :: ult, str_bytes, head_form_selftest

contains

  ! ────────────────────────── unsigned helpers ──────────────────────────

  ! Unsigned less-than on int64 bit patterns (the bias trick — A-FTN-002). Flipping the
  ! sign bit of both operands turns a signed compare into an unsigned one.
  pure logical function ult(a, b)
    integer(int64), intent(in) :: a, b
    integer(int64), parameter  :: SIGNBIT = ishft(1_int64, 63)   ! 0x8000000000000000
    ult = ieor(a, SIGNBIT) < ieor(b, SIGNBIT)
  end function ult

  ! ASCII bytes of a Fortran character string (for key comparisons / literal keys).
  pure function str_bytes(s) result(b)
    character(len=*), intent(in) :: s
    integer(int8) :: b(len(s))
    integer :: i
    do i = 1, len(s)
      b(i) = int(iachar(s(i:i)), int8)
    end do
  end function str_bytes

  ! ────────────────────────── value constructors ──────────────────────────

  pure function ev_uint_make(bits) result(v)
    integer(int64), intent(in) :: bits
    type(ecf_value_t) :: v
    v%vkind = EV_UINT; v%ival = bits
  end function ev_uint_make

  pure function ev_text_make(s) result(v)
    integer(int8), intent(in) :: s(:)
    type(ecf_value_t) :: v
    v%vkind = EV_TEXT; v%bytes = s
  end function ev_text_make

  pure function ev_bytes_make(s) result(v)
    integer(int8), intent(in) :: s(:)
    type(ecf_value_t) :: v
    v%vkind = EV_BYTES; v%bytes = s
  end function ev_bytes_make

  ! build a 2-entry map {k1:v1, k2:v2} (encoder re-sorts to canonical order).
  function ev_map_make2(k1, v1, k2, v2) result(v)
    type(ecf_value_t), intent(in) :: k1, v1, k2, v2
    type(ecf_value_t) :: v
    v%vkind = EV_MAP
    allocate(v%items(4))
    v%items(1) = k1; v%items(2) = v1; v%items(3) = k2; v%items(4) = v2
  end function ev_map_make2

  ! ────────────────────────── navigation ──────────────────────────

  ! Value bound to TEXT key `key` in map value m, or an EV_ABSENT sentinel.
  function ev_map_get(m, key) result(v)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    type(ecf_value_t) :: v
    integer :: i, npair
    v%vkind = EV_ABSENT
    if (m%vkind /= EV_MAP) return
    if (.not. associated(m%items)) return
    npair = size(m%items) / 2
    do i = 1, npair
      if (ev_text_equals(m%items(2*i-1), key)) then
        v = m%items(2*i)
        return
      end if
    end do
  end function ev_map_get

  logical function ev_has(m, key)
    type(ecf_value_t), intent(in) :: m
    character(len=*),  intent(in) :: key
    type(ecf_value_t) :: v
    v = ev_map_get(m, key)
    ev_has = (v%vkind /= EV_ABSENT)
  end function ev_has

  logical function ev_text_equals(v, s)
    type(ecf_value_t), intent(in) :: v
    character(len=*),  intent(in) :: s
    ev_text_equals = .false.
    if (v%vkind /= EV_TEXT) return
    if (.not. allocated(v%bytes)) return
    if (size(v%bytes) /= len(s)) return
    ev_text_equals = all(v%bytes == str_bytes(s))
  end function ev_text_equals

  ! the uint bit pattern of a value (caller knows it is EV_UINT).
  pure integer(int64) function ev_get_uint(v)
    type(ecf_value_t), intent(in) :: v
    ev_get_uint = v%ival
  end function ev_get_uint

  function ev_get_bytes(v) result(b)
    type(ecf_value_t), intent(in) :: v
    integer(int8), allocatable :: b(:)
    if (allocated(v%bytes)) then
      b = v%bytes
    else
      allocate(b(0))
    end if
  end function ev_get_bytes

  function ev_text_bytes(v) result(b)
    type(ecf_value_t), intent(in) :: v
    integer(int8), allocatable :: b(:)
    b = ev_get_bytes(v)
  end function ev_text_bytes

  ! ────────────────────────── buffer append ──────────────────────────

  subroutine ap1(buf, n, b)
    integer(int8), allocatable, intent(inout) :: buf(:)
    integer,                    intent(inout) :: n
    integer(int8),              intent(in)    :: b
    integer(int8), allocatable :: tmp(:)
    if (.not. allocated(buf)) allocate(buf(64))
    if (n >= size(buf)) then
      allocate(tmp(2*size(buf))); tmp(1:n) = buf(1:n); call move_alloc(tmp, buf)
    end if
    n = n + 1; buf(n) = b
  end subroutine ap1

  subroutine apn(buf, n, bs)
    integer(int8), allocatable, intent(inout) :: buf(:)
    integer,                    intent(inout) :: n
    integer(int8),              intent(in)    :: bs(:)
    integer :: i
    do i = 1, size(bs)
      call ap1(buf, n, bs(i))
    end do
  end subroutine apn

  ! ────────────────────────── head emission ──────────────────────────

  ! Emit a CBOR head: major-type base byte (mt0=0x00, mt2=0x40, mt3=0x60, mt4=0x80,
  ! mt5=0xA0, mt1=0x20) plus the SHORTEST argument encoding of the bit pattern `arg`
  ! (unsigned). The ladder decision uses ult() (bias-trick unsigned compare) so a value
  ! in [2^63, 2^64-1] — negative in the signed carrier — still lands in the 8-byte arm.
  subroutine emit_head(buf, n, major_base, arg)
    integer(int8), allocatable, intent(inout) :: buf(:)
    integer,                    intent(inout) :: n
    integer,                    intent(in)    :: major_base
    integer(int64),             intent(in)    :: arg
    if (ult(arg, 24_int64)) then
      call ap1(buf, n, int(major_base + int(arg), int8))
    else if (ult(arg, 256_int64)) then
      call ap1(buf, n, int(major_base + 24, int8))
      call emit_be(buf, n, arg, 1)
    else if (ult(arg, 65536_int64)) then
      call ap1(buf, n, int(major_base + 25, int8))
      call emit_be(buf, n, arg, 2)
    else if (ult(arg, 4294967296_int64)) then     ! 2^32
      call ap1(buf, n, int(major_base + 26, int8))
      call emit_be(buf, n, arg, 4)
    else
      call ap1(buf, n, int(major_base + 27, int8))
      call emit_be(buf, n, arg, 8)
    end if
  end subroutine emit_head

  ! Big-endian emit of the low `nbytes` octets of the bit pattern v (sign-agnostic).
  subroutine emit_be(buf, n, v, nbytes)
    integer(int8), allocatable, intent(inout) :: buf(:)
    integer,                    intent(inout) :: n
    integer(int64),             intent(in)    :: v
    integer,                    intent(in)    :: nbytes
    integer :: k, octet
    do k = nbytes - 1, 0, -1
      octet = int(iand(ishft(v, -8*k), 255_int64))    ! byte k, MSB first
      call ap1(buf, n, int(octet, int8))              ! 128..255 wrap to signed image
    end do
  end subroutine emit_be

  ! ────────────────────────── ENCODE ──────────────────────────

  ! Canonical-encode a value into an allocatable byte buffer out(1:*). stat = EC_OK on
  ! success; the whole encoded value is out (trimmed).
  subroutine cbor_encode(v, out, stat)
    type(ecf_value_t), intent(in)               :: v
    integer(int8), allocatable, intent(out)     :: out(:)
    integer,                    intent(out)     :: stat
    integer(int8), allocatable :: buf(:)
    integer :: n
    n = 0
    stat = EC_OK
    call enc(v, buf, n, 0, stat)
    if (stat /= EC_OK) then
      if (allocated(out)) deallocate(out)
      allocate(out(0))
      return
    end if
    out = buf(1:n)
  end subroutine cbor_encode

  recursive subroutine enc(v, buf, n, depth, stat)
    type(ecf_value_t),          intent(in)    :: v
    integer(int8), allocatable, intent(inout) :: buf(:)
    integer,                    intent(inout) :: n
    integer,                    intent(in)    :: depth
    integer,                    intent(out)   :: stat
    integer :: i, npair
    stat = EC_OK
    if (depth > MAX_DEPTH) then; stat = EC_ENCODE_ERROR; return; end if
    select case (v%vkind)
    case (EV_UINT)
      call emit_head(buf, n, 0, v%ival)
    case (EV_NINT)
      call emit_head(buf, n, 32, v%ival)            ! mt1 base 0x20; arg = n
    case (EV_BYTES)
      call emit_head(buf, n, 64, int(payload_len(v), int64))
      if (allocated(v%bytes)) call apn(buf, n, v%bytes)
    case (EV_TEXT)
      call emit_head(buf, n, 96, int(payload_len(v), int64))
      if (allocated(v%bytes)) call apn(buf, n, v%bytes)
    case (EV_ARRAY)
      call emit_head(buf, n, 128, int(count_items(v), int64))
      if (associated(v%items)) then
        do i = 1, size(v%items)
          call enc(v%items(i), buf, n, depth+1, stat)
          if (stat /= EC_OK) return
        end do
      end if
    case (EV_MAP)
      npair = count_items(v)
      call emit_head(buf, n, 160, int(npair, int64))    ! N3: empty map -> 0xA0
      call enc_map_sorted(v, buf, n, depth, stat)
    case (EV_FLOAT)
      call enc_float(v%fval, buf, n)
    case (EV_BOOL)
      if (v%bval) then; call ap1(buf, n, int(-11, int8))   ! 0xf5
      else;             call ap1(buf, n, int(-12, int8)); end if  ! 0xf4
    case (EV_NULL)
      call ap1(buf, n, int(-10, int8))                     ! 0xf6
    case default
      stat = EC_ENCODE_ERROR
    end select
  end subroutine enc

  pure integer function payload_len(v)
    type(ecf_value_t), intent(in) :: v
    if (allocated(v%bytes)) then; payload_len = size(v%bytes); else; payload_len = 0; end if
  end function payload_len

  pure integer function count_items(v)
    type(ecf_value_t), intent(in) :: v
    if (associated(v%items)) then
      if (v%vkind == EV_MAP) then; count_items = size(v%items) / 2
      else;                        count_items = size(v%items); end if
    else
      count_items = 0
    end if
  end function count_items

  ! Emit a map's k,v pairs in RFC 8949 §4.2.1 deterministic order: sort by encoded-key
  ! bytes, length ascending then lexicographic (byte-wise, treating octets as unsigned).
  ! Keys are encoded once and reused. (For the corpus the input is already canonical, so
  ! this is a no-op there; the sort is exercised by an accept-path unit test — the
  ! "direction the oracle can't cover" lesson.)
  recursive subroutine enc_map_sorted(m, buf, n, depth, stat)
    type(ecf_value_t),          intent(in)    :: m
    integer(int8), allocatable, intent(inout) :: buf(:)
    integer,                    intent(inout) :: n
    integer,                    intent(in)    :: depth
    integer,                    intent(out)   :: stat
    integer :: npair, i, j, sel, tmp
    integer, allocatable :: order(:)
    type keybuf_t
      integer(int8), allocatable :: b(:)
    end type keybuf_t
    type(keybuf_t), allocatable :: keys(:)
    stat = EC_OK
    if (.not. associated(m%items)) return
    npair = size(m%items) / 2
    if (npair == 0) return
    allocate(keys(npair), order(npair))
    do i = 1, npair
      call cbor_encode(m%items(2*i-1), keys(i)%b, stat)
      if (stat /= EC_OK) return
      order(i) = i
    end do
    ! selection sort on order() by key-bytes (length-then-lex)
    do i = 1, npair - 1
      sel = i
      do j = i + 1, npair
        if (key_lt(keys(order(j))%b, keys(order(sel))%b)) sel = j
      end do
      if (sel /= i) then; tmp = order(i); order(i) = order(sel); order(sel) = tmp; end if
    end do
    do i = 1, npair
      j = order(i)
      call apn(buf, n, keys(j)%b)                          ! key (already encoded)
      call enc(m%items(2*j), buf, n, depth+1, stat)        ! value
      if (stat /= EC_OK) return
    end do
  end subroutine enc_map_sorted

  ! length-then-lex compare of two encoded-key byte arrays (unsigned octets).
  pure logical function key_lt(a, b)
    integer(int8), intent(in) :: a(:), b(:)
    integer :: i, ua, ub
    if (size(a) /= size(b)) then
      key_lt = size(a) < size(b)
      return
    end if
    do i = 1, size(a)
      ua = iand(int(a(i)), 255); ub = iand(int(b(i)), 255)
      if (ua /= ub) then; key_lt = ua < ub; return; end if
    end do
    key_lt = .false.
  end function key_lt

  ! ────────────────────────── float encode (Rule 4 ladder) ──────────────────────────

  subroutine enc_float(x, buf, n)
    real(real64),               intent(in)    :: x
    integer(int8), allocatable, intent(inout) :: buf(:)
    integer,                    intent(inout) :: n
    real(real32)   :: f32
    integer(int32) :: f32bits, h16
    integer(int64) :: f64bits
    logical        :: ok16

    if (ieee_is_nan(x)) then                       ! Rule 4a canonical NaN = f9 7e00
      call ap1(buf, n, int(-7, int8))              ! 0xf9
      call ap1(buf, n, int(126, int8))             ! 0x7e
      call ap1(buf, n, int(0, int8))               ! 0x00
      return
    end if

    f32 = real(x, real32)
    if (transfer(real(f32, real64), 0_int64) == transfer(x, 0_int64)) then
      ! value round-trips through f32 exactly (bit-exact — preserves -0.0 / Inf sign).
      call f32_to_f16(f32, h16, ok16)
      if (ok16) then
        call ap1(buf, n, int(-7, int8))            ! 0xf9  (f16)
        call emit_be(buf, n, int(iand(int(h16, int64), 65535_int64), int64), 2)
        return
      end if
      f32bits = transfer(f32, 0_int32)
      call ap1(buf, n, int(-6, int8))              ! 0xfa  (f32)
      call emit_be(buf, n, iand(int(f32bits, int64), int(z'FFFFFFFF', int64)), 4)
      return
    end if

    f64bits = transfer(x, 0_int64)                 ! 0xfb  (f64)
    call ap1(buf, n, int(-5, int8))
    call emit_be(buf, n, f64bits, 8)
  end subroutine enc_float

  ! Convert a binary32 to binary16 IF the value is EXACTLY representable (Rule 4). Returns
  ! ok=.true. + the 16 bits in h16(0..15) when the f16 round-trips back to the SAME f32
  ! bits; ok=.false. otherwise. Hand-rolled (no native binary16 kind — A-FTN-005),
  ! verified by decoding back and comparing bits (belt-and-suspenders exactness).
  subroutine f32_to_f16(f32, h16, ok)
    real(real32),   intent(in)  :: f32
    integer(int32), intent(out) :: h16
    logical,        intent(out) :: ok
    integer(int32) :: b, sign, exp8, man23, e
    real(real32)   :: back
    ok  = .false.
    h16 = 0
    b     = transfer(f32, 0_int32)
    sign  = iand(ishft(b, -31), 1)
    exp8  = iand(ishft(b, -23), 255)
    man23 = iand(b, int(z'7FFFFF', int32))
    if (exp8 == 255) then
      if (man23 == 0) then
        h16 = ior(ishft(sign, 15), int(z'7C00', int32))     ! Inf
        ok = .true.
      end if
      ! NaN handled by caller; fall through -> not f16 here
    else if (exp8 == 0) then
      if (man23 == 0) then
        h16 = ishft(sign, 15)                                ! +/-0
        ok = .true.
      end if
      ! f32 subnormal: too small for f16 normal — leave ok=.false.
    else
      e = exp8 - 127
      if (e >= -14 .and. e <= 15) then
        if (iand(man23, int(z'1FFF', int32)) == 0) then      ! low 13 mantissa bits zero
          h16 = ior(ior(ishft(sign, 15), ishft(e + 15, 10)), ishft(man23, -13))
          ok = .true.
        end if
      end if
    end if
    if (ok) then
      back = f16_to_f32(h16)
      if (transfer(back, 0_int32) /= b) ok = .false.         ! verify exact round-trip
    end if
  end subroutine f32_to_f16

  ! Decode a binary16 (in the low 16 bits of h) to binary32.
  function f16_to_f32(h) result(f32)
    integer(int32), intent(in) :: h
    real(real32) :: f32
    integer(int32) :: sign, exp5, man10, b, e, m, sh
    sign  = iand(ishft(h, -15), 1)
    exp5  = iand(ishft(h, -10), 31)
    man10 = iand(h, int(z'3FF', int32))
    if (exp5 == 0) then
      if (man10 == 0) then
        b = ishft(sign, 31)                                  ! +/-0
      else
        ! subnormal f16 -> normalized f32
        e = -14; m = man10
        do while (iand(m, int(z'400', int32)) == 0)
          m = ishft(m, 1); e = e - 1
        end do
        m = iand(m, int(z'3FF', int32))
        b = ior(ior(ishft(sign, 31), ishft(e + 127, 23)), ishft(m, 13))
      end if
    else if (exp5 == 31) then
      if (man10 == 0) then
        b = ior(ishft(sign, 31), int(z'7F800000', int32))    ! Inf
      else
        b = ior(ishft(sign, 31), int(z'7FC00000', int32))    ! NaN
      end if
    else
      sh = exp5 - 15 + 127
      b  = ior(ior(ishft(sign, 31), ishft(sh, 23)), ishft(man10, 13))
    end if
    f32 = transfer(b, 0.0_real32)
  end function f16_to_f32

  ! ────────────────────────── DECODE ──────────────────────────

  ! Decode ONE canonical value from buf starting at pos=1; returns the value, the number
  ! of bytes consumed, and stat. Runs the explicit recursive major-type-6 tag REJECT (N2)
  ! at every head and rejects indefinite-length forms.
  subroutine cbor_decode(buf, v, consumed, stat)
    integer(int8),     intent(in)  :: buf(:)
    type(ecf_value_t), intent(out) :: v
    integer,           intent(out) :: consumed
    integer,           intent(out) :: stat
    integer :: pos
    pos = 1
    call dec(buf, pos, v, 0, stat)
    consumed = pos - 1
  end subroutine cbor_decode

  recursive subroutine dec(buf, pos, v, depth, stat)
    integer(int8),     intent(in)    :: buf(:)
    integer,           intent(inout) :: pos
    type(ecf_value_t), intent(out)   :: v
    integer,           intent(in)    :: depth
    integer,           intent(out)   :: stat
    integer        :: b, major, ai, i, npair, nlen
    integer(int64) :: arg
    stat = EC_OK
    if (depth > MAX_DEPTH) then; stat = EC_NON_CANONICAL_ECF; return; end if
    if (pos > size(buf)) then; stat = EC_TRUNCATED_INPUT; return; end if
    b     = iand(int(buf(pos)), 255)               ! A-FTN-004 unsigned octet
    major = ishft(b, -5)
    ai    = iand(b, 31)
    pos   = pos + 1

    if (major == 6) then; stat = EC_TAG_REJECTED; return; end if   ! N2

    if (major == 7) then
      call dec_simple(buf, pos, ai, v, stat)
      return
    end if

    call read_arg(buf, pos, ai, arg, stat)
    if (stat /= EC_OK) return

    select case (major)
    case (0)
      v%vkind = EV_UINT; v%ival = arg
    case (1)
      v%vkind = EV_NINT; v%ival = arg
    case (2)
      nlen = int(arg)
      v%vkind = EV_BYTES
      call take_bytes(buf, pos, nlen, v%bytes, stat)
    case (3)
      nlen = int(arg)
      v%vkind = EV_TEXT
      call take_bytes(buf, pos, nlen, v%bytes, stat)
    case (4)
      v%vkind = EV_ARRAY
      nlen = int(arg)
      allocate(v%items(nlen))
      do i = 1, nlen
        call dec(buf, pos, v%items(i), depth+1, stat)
        if (stat /= EC_OK) return
      end do
    case (5)
      v%vkind = EV_MAP
      npair = int(arg)
      allocate(v%items(2*npair))
      do i = 1, 2*npair
        call dec(buf, pos, v%items(i), depth+1, stat)
        if (stat /= EC_OK) return
      end do
    case default
      stat = EC_NON_CANONICAL_ECF
    end select
  end subroutine dec

  subroutine dec_simple(buf, pos, ai, v, stat)
    integer(int8),     intent(in)    :: buf(:)
    integer,           intent(inout) :: pos
    integer,           intent(in)    :: ai
    type(ecf_value_t), intent(out)   :: v
    integer,           intent(out)   :: stat
    integer(int64) :: bits
    integer        :: k, octet
    stat = EC_OK
    select case (ai)
    case (20)
      v%vkind = EV_BOOL; v%bval = .false.
    case (21)
      v%vkind = EV_BOOL; v%bval = .true.
    case (22)
      v%vkind = EV_NULL
    case (25)                                       ! f16
      if (pos + 1 > size(buf)) then; stat = EC_TRUNCATED_INPUT; return; end if
      bits = ior(ishft(iand(int(buf(pos),  int64), 255_int64), 8), &
                      iand(int(buf(pos+1), int64), 255_int64))
      pos = pos + 2
      v%vkind = EV_FLOAT
      v%fval  = real(f16_to_f32(int(bits, int32)), real64)
    case (26)                                       ! f32
      if (pos + 3 > size(buf)) then; stat = EC_TRUNCATED_INPUT; return; end if
      bits = 0_int64
      do k = 0, 3
        octet = iand(int(buf(pos+k)), 255)
        bits  = ior(ishft(bits, 8), int(octet, int64))
      end do
      pos = pos + 4
      v%vkind = EV_FLOAT
      v%fval  = real(transfer(int(bits, int32), 0.0_real32), real64)
    case (27)                                       ! f64
      if (pos + 7 > size(buf)) then; stat = EC_TRUNCATED_INPUT; return; end if
      bits = 0_int64
      do k = 0, 7
        octet = iand(int(buf(pos+k)), 255)
        bits  = ior(ishft(bits, 8), int(octet, int64))
      end do
      pos = pos + 8
      v%vkind = EV_FLOAT
      v%fval  = transfer(bits, 0.0_real64)
    case default
      stat = EC_NON_CANONICAL_ECF                   ! 0xf7 undefined / 0xff break / etc.
    end select
  end subroutine dec_simple

  ! read a major-0..5 argument per the additional-info byte; reject indefinite (31) and
  ! the reserved 28..30. Big-endian accumulate into a bit-pattern carrier.
  subroutine read_arg(buf, pos, ai, arg, stat)
    integer(int8), intent(in)    :: buf(:)
    integer,       intent(inout) :: pos
    integer,       intent(in)    :: ai
    integer(int64),intent(out)   :: arg
    integer,       intent(out)   :: stat
    integer :: nb, k, octet
    stat = EC_OK
    arg  = 0_int64
    if (ai < 24) then
      arg = int(ai, int64)
      return
    end if
    select case (ai)
    case (24); nb = 1
    case (25); nb = 2
    case (26); nb = 4
    case (27); nb = 8
    case default
      stat = EC_NON_CANONICAL_ECF                   ! 28,29,30 reserved; 31 indefinite
      return
    end select
    if (pos + nb - 1 > size(buf)) then; stat = EC_TRUNCATED_INPUT; return; end if
    do k = 0, nb - 1
      octet = iand(int(buf(pos+k)), 255)
      arg   = ior(ishft(arg, 8), int(octet, int64))
    end do
    pos = pos + nb
  end subroutine read_arg

  subroutine take_bytes(buf, pos, nlen, out, stat)
    integer(int8),              intent(in)    :: buf(:)
    integer,                    intent(inout) :: pos
    integer,                    intent(in)    :: nlen
    integer(int8), allocatable, intent(out)   :: out(:)
    integer,                    intent(out)   :: stat
    stat = EC_OK
    if (nlen < 0 .or. pos + nlen - 1 > size(buf)) then; stat = EC_TRUNCATED_INPUT; return; end if
    allocate(out(nlen))
    if (nlen > 0) out = buf(pos:pos+nlen-1)
    pos = pos + nlen
  end subroutine take_bytes

  ! ────────────────────────── scan / fidelity (N4) ──────────────────────────

  ! Compute the byte length of the CBOR item at pos WITHOUT building a value — the
  ! entity-fidelity primitive (N4): after validating, a peer forwards the ORIGINAL byte
  ! span buf(pos : pos+len-1), never a re-encode. Also runs the N2 tag reject, so it is
  ! the cheap skip/validate path. Returns len (bytes) and stat.
  recursive subroutine cbor_scan_len(buf, pos, length, stat)
    integer(int8), intent(in)    :: buf(:)
    integer,       intent(in)    :: pos
    integer,       intent(out)   :: length
    integer,       intent(out)   :: stat
    integer :: p
    p = pos
    call scan(buf, p, 0, stat)
    length = p - pos
  end subroutine cbor_scan_len

  recursive subroutine scan(buf, pos, depth, stat)
    integer(int8), intent(in)    :: buf(:)
    integer,       intent(inout) :: pos
    integer,       intent(in)    :: depth
    integer,       intent(out)   :: stat
    integer        :: b, major, ai, i, nlen
    integer(int64) :: arg
    stat = EC_OK
    if (depth > MAX_DEPTH) then; stat = EC_NON_CANONICAL_ECF; return; end if
    if (pos > size(buf)) then; stat = EC_TRUNCATED_INPUT; return; end if
    b = iand(int(buf(pos)), 255); major = ishft(b, -5); ai = iand(b, 31); pos = pos + 1
    if (major == 6) then; stat = EC_TAG_REJECTED; return; end if
    if (major == 7) then
      select case (ai)
      case (20, 21, 22)
        ! 1 byte head only
      case (25); pos = pos + 2
      case (26); pos = pos + 4
      case (27); pos = pos + 8
      case default; stat = EC_NON_CANONICAL_ECF
      end select
      if (pos - 1 > size(buf)) stat = EC_TRUNCATED_INPUT
      return
    end if
    call read_arg(buf, pos, ai, arg, stat)
    if (stat /= EC_OK) return
    select case (major)
    case (0, 1)
      ! head only
    case (2, 3)
      nlen = int(arg)
      if (nlen < 0 .or. pos + nlen - 1 > size(buf)) then; stat = EC_TRUNCATED_INPUT; return; end if
      pos = pos + nlen
    case (4)
      do i = 1, int(arg); call scan(buf, pos, depth+1, stat); if (stat /= EC_OK) return; end do
    case (5)
      do i = 1, 2*int(arg); call scan(buf, pos, depth+1, stat); if (stat /= EC_OK) return; end do
    case default
      stat = EC_NON_CANONICAL_ECF
    end select
  end subroutine scan

  ! ────────────────────────── head-form self-test (A-FTN-002) ──────────────────────────

  ! MANDATORY fixed-width uint64-boundary self-test: encode + decode round-trip every
  ! value in {0, 2^63-1, 2^63, 2^64-2, 2^64-1} byte-exact. Proves the signed carrier
  ! emits and parses the FULL unsigned tower. Returns .true. iff all five pass, and (via
  ! report) the expected/actual hex for a human. ok=.false. blocks S2.
  subroutine head_form_selftest(ok, report)
    logical,          intent(out) :: ok
    character(len=*), intent(out) :: report
    integer(int64) :: vals(5), rt
    character(len=32) :: exp_hex(5)
    integer(int8), allocatable :: enc_bytes(:)
    type(ecf_value_t) :: val, dval
    integer :: i, consumed, stat
    character(len=64) :: got_hex
    ok = .true.
    report = ''
    vals(1) = 0_int64
    vals(2) = huge(0_int64)                           ! 2^63 - 1 (0x7FFFFFFFFFFFFFFF)
    vals(3) = ishft(1_int64, 63)                      ! 2^63  (== min signed = bit 63 set)
    vals(4) = -2_int64                                ! 2^64 - 2 (bit pattern)
    vals(5) = -1_int64                                ! 2^64 - 1 (bit pattern)
    exp_hex(1) = '00'
    exp_hex(2) = '1B7FFFFFFFFFFFFFFF'
    exp_hex(3) = '1B8000000000000000'
    exp_hex(4) = '1BFFFFFFFFFFFFFFFE'
    exp_hex(5) = '1BFFFFFFFFFFFFFFFF'
    do i = 1, 5
      val = ev_uint_make(vals(i))
      call cbor_encode(val, enc_bytes, stat)
      if (stat /= EC_OK) then; ok = .false.; report = 'encode failed'; return; end if
      got_hex = bytes_hex(enc_bytes)
      if (trim(got_hex) /= trim(exp_hex(i))) then
        ok = .false.
        report = 'value '//itoa(i)//' encode mismatch: want '//trim(exp_hex(i))// &
                 ' got '//trim(got_hex)
        return
      end if
      ! decode round-trip: bit pattern must survive exactly.
      call cbor_decode(enc_bytes, dval, consumed, stat)
      if (stat /= EC_OK .or. dval%vkind /= EV_UINT) then
        ok = .false.; report = 'value '//itoa(i)//' decode failed'; return
      end if
      rt = dval%ival
      if (rt /= vals(i)) then
        ok = .false.; report = 'value '//itoa(i)//' round-trip bit-pattern differs'; return
      end if
    end do
    report = 'all five {0, 2^63-1, 2^63, 2^64-2, 2^64-1} round-trip byte-exact'
  end subroutine head_form_selftest

  pure function bytes_hex(b) result(s)
    integer(int8), intent(in) :: b(:)
    character(len=2*size(b)) :: s
    character(len=16), parameter :: H = '0123456789ABCDEF'
    integer :: i, u
    do i = 1, size(b)
      u = iand(int(b(i)), 255)
      s(2*i-1:2*i-1) = H(ishft(u,-4)+1 : ishft(u,-4)+1)
      s(2*i:2*i)     = H(iand(u,15)+1 : iand(u,15)+1)
    end do
  end function bytes_hex

  pure function itoa(n) result(s)
    integer, intent(in) :: n
    character(len=12) :: s
    write(s, '(i0)') n
  end function itoa

end module entity_core_cbor
