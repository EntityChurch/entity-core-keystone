! entity-core-protocol-fortran — src/varint.f90
!
! Unsigned LEB128 varint (multicodec key_type / hash_type / content-hash format
! codes). N1: route ALL format-code / key-type / hash-type framing through a real
! LEB128 varint primitive, NEVER a fixed byte. The currently-allocated codes
! (0x00/0x01/0x02, key_type/hash_type 0x01) are all < 0x80 so today they encode as
! a single byte — byte-identical to a fixed field — but a code >= 0x80 widens to 2+
! bytes and a fixed-width impl breaks silently (content_hash.4 format_code=128,
! peer_id.3 key_type=128 exercise the widening; peer_id widening is inside the C-ABI,
! the content_hash prefix is THIS primitive).
!
! Pure Fortran over ishft/iand on an integer(int64) BIT PATTERN carrier: the value is
! held sign-agnostically, so a code with the high bit set (>= 2^63) would still emit
! correctly, though no such code exists. Byte buffer is integer(int8) (SIGNED — A-FTN-004).
module entity_core_varint
  use, intrinsic :: iso_fortran_env, only : int8, int32, int64
  use entity_core_status
  implicit none
  private
  public :: varint_encode, varint_decode

contains

  ! Encode a non-negative code (bit-pattern in a signed int64 carrier) as unsigned
  ! LEB128. `out(1:out_len)` receives the bytes; out must hold >= 10 bytes.
  subroutine varint_encode(code, out, out_len, stat)
    integer(int64), intent(in)  :: code
    integer(int8),  intent(out) :: out(:)
    integer,        intent(out) :: out_len
    integer,        intent(out) :: stat
    integer(int64) :: v
    integer        :: low7
    stat    = EC_OK
    out_len = 0
    v = code
    do
      ! low 7 bits, then logical-shift the carrier right by 7 (sign-agnostic).
      low7 = int(iand(v, 127_int64))
      v    = ishft(v, -7)                 ! ishft is a LOGICAL shift — no sign fill
      out_len = out_len + 1
      if (out_len > size(out)) then
        stat = EC_ENCODE_ERROR
        return
      end if
      if (v /= 0_int64) then
        out(out_len) = int(ior(low7, 128), int8)   ! continuation bit
      else
        out(out_len) = int(low7, int8)
        exit
      end if
    end do
  end subroutine varint_encode

  ! Decode an unsigned LEB128 varint from buf starting at pos (1-indexed). Returns
  ! the value (bit pattern) and advances pos past the varint. Rejects a truncated or
  ! non-minimal (trailing 0x00 continuation) form.
  subroutine varint_decode(buf, pos, code, stat)
    integer(int8),  intent(in)    :: buf(:)
    integer,        intent(inout) :: pos
    integer(int64), intent(out)   :: code
    integer,        intent(out)   :: stat
    integer(int64) :: result, low7
    integer        :: shift, nbytes
    integer(int8)  :: b
    stat   = EC_OK
    result = 0_int64
    shift  = 0
    nbytes = 0
    do
      if (pos > size(buf)) then
        stat = EC_TRUNCATED_INPUT
        return
      end if
      b      = buf(pos)
      pos    = pos + 1
      nbytes = nbytes + 1
      low7   = iand(int(b, int64), 127_int64)     ! mask to 7 bits (A-FTN-004 sign mask)
      result = ior(result, ishft(low7, shift))
      if (iand(int(b, int64), 128_int64) == 0_int64) then
        ! non-minimal guard: a >1-byte varint ending in 0x00 is not canonical
        if (nbytes > 1 .and. b == 0_int8) then
          stat = EC_NON_CANONICAL_ECF
          return
        end if
        exit
      end if
      shift = shift + 7
    end do
    code = result
  end subroutine varint_decode

end module entity_core_varint
