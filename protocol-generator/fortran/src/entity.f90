! entity-core-protocol-fortran — src/entity.f90
!
! Entity-framing surface composed from the pure-Fortran canonical codec (cbor.f90) + the
! C-ABI crypto/base58 floor (entity_core_ffi.f90). These are the core protocol codec
! operations the profile names for S2: content_hash, peer-id format/parse, Ed25519
! sign/verify. CORE TYPES ONLY — no TREE/CONTENT/IDENTITY/extension encoding.
!
! content_hash construction (§4.1): content_hash = varint(format_code) || DIGEST(ECF(E))
! where E = {type, data}. We build the {type,data} map with OUR encoder (canonical
! key sort: "data" < "type"), then SHA-256 it via the C-ABI — exercising the Fortran
! encoder end-to-end and reserving crypto for the audited floor. The varint(format_code)
! prefix is OUR LEB128 primitive (N1) — content_hash.4 (format 128 -> 0x80 0x01) proves
! the multibyte widening in Fortran.
module entity_core_entity
  use, intrinsic :: iso_fortran_env, only : int8, int64
  use entity_core_status
  use entity_core_cbor
  use entity_core_varint
  use entity_core_ffi
  implicit none
  private
  public :: content_hash_compute, peerid_format_compute, sign_compute, verify_compute

contains

  ! content_hash of entity {type,data} under an explicit format_code (0 = SHA-256).
  ! For the SHA-256 floor the digest is 32 bytes; a non-zero unsupported format (128)
  ! still exercises the varint prefix over the SHA-256 digest (the corpus construction).
  subroutine content_hash_compute(type_val, data_val, format_code, out, out_len, stat)
    type(ecf_value_t), intent(in)  :: type_val, data_val
    integer(int64),    intent(in)  :: format_code
    integer(int8),     intent(out) :: out(:)                ! >= 40 bytes
    integer,           intent(out) :: out_len
    integer,           intent(out) :: stat
    type(ecf_value_t)          :: entity
    integer(int8), allocatable :: ecf(:)
    integer(int8)              :: digest(32)
    integer(int8)              :: vbuf(10)
    integer                    :: vlen, i
    out_len = 0
    entity = ev_map_make2(ev_text_make(str_bytes('type')), type_val, &
                          ev_text_make(str_bytes('data')), data_val)
    call cbor_encode(entity, ecf, stat)
    if (stat /= EC_OK) return
    call ffi_sha256(ecf, digest, stat)
    if (stat /= EC_OK) return
    call varint_encode(format_code, vbuf, vlen, stat)
    if (stat /= EC_OK) return
    if (vlen + 32 > size(out)) then; stat = EC_OUT_OF_SPACE; return; end if
    do i = 1, vlen
      out(i) = vbuf(i)
    end do
    out(vlen+1:vlen+32) = digest
    out_len = vlen + 32
  end subroutine content_hash_compute

  ! peer-id: Base58(varint(key_type) || varint(hash_type) || digest) via the C-ABI
  ! (Fortran has NO bignum — A-FTN-006). Returns the base58 ASCII bytes.
  subroutine peerid_format_compute(key_type, hash_type, digest, out_ascii, out_len, stat)
    integer(int64), intent(in)  :: key_type, hash_type
    integer(int8),  intent(in)  :: digest(:)
    integer(int8),  intent(out) :: out_ascii(:)             ! >= 80 bytes
    integer,        intent(out) :: out_len
    integer,        intent(out) :: stat
    call ffi_peerid_format(key_type, hash_type, digest, out_ascii, out_len, stat)
  end subroutine peerid_format_compute

  ! deterministic Ed25519 signature over ECF(entity). seed IS the 32-byte private key.
  subroutine sign_compute(seed32, entity, out_sig64, stat)
    integer(int8),     intent(in)  :: seed32(32)
    type(ecf_value_t), intent(in)  :: entity
    integer(int8),     intent(out) :: out_sig64(64)
    integer,           intent(out) :: stat
    integer(int8), allocatable :: msg(:)
    call cbor_encode(entity, msg, stat)
    if (stat /= EC_OK) return
    call ffi_ed25519_sign(seed32, msg, out_sig64, stat)
  end subroutine sign_compute

  subroutine verify_compute(pub32, entity, sig64, ok, stat)
    integer(int8),     intent(in)  :: pub32(32)
    type(ecf_value_t), intent(in)  :: entity
    integer(int8),     intent(in)  :: sig64(64)
    logical,           intent(out) :: ok
    integer,           intent(out) :: stat
    integer(int8), allocatable :: msg(:)
    ok = .false.
    call cbor_encode(entity, msg, stat)
    if (stat /= EC_OK) return
    call ffi_ed25519_verify(pub32, msg, sig64, ok, stat)
  end subroutine verify_compute

end module entity_core_entity
