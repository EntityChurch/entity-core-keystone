! entity-core-protocol-fortran — src/entity_core_ffi.f90
!
! iso_c_binding interface blocks binding libentitycore_codec's ec_* symbols DIRECTLY
! (no C wrapper — Fortran's first-class C interop, cleaner than Rexx's SAA ext / Tcl's
! stubs shim). Every prototype below matches the VERBATIM header
! ffi-generator/c-abi/spec/entitycore_codec.h (C-ABI 1.1). The crypto floor (§9.1),
! SHA-256/384, entity framing, and base58 peer-id all cross here because there is no
! native audited Fortran crypto and Fortran has NO bignum type (base58 rides
! ec_peerid_{parse,format} — A-FTN-006).
!
! Buffer discipline: a C `const uint8_t *` binds to `integer(c_int8_t) :: p(*)`, which
! Fortran passes as the address of the first element — exactly a byte pointer. `size_t`
! binds to integer(c_size_t) by value; the int32_t EC_* return binds to c_int32_t. The
! signed int8 buffers are the wire octets (A-FTN-004); uint64 args (key_type/hash_type/
! format_code) pass as integer(c_int64_t) bit patterns by value.
!
! Only the crypto/hash/framing/peer-id surface is bound at S2. The pointer-to-pointer
! decode surface (ec_decode_entity / ec_entity_original_bytes, N4) is not needed here:
! the codec has its OWN pure-Fortran decoder + original-bytes span (cbor.f90); the
! borrowed-slice decode API is an S3 concern. The net-shim (ec_net_*) is S3.
module entity_core_ffi
  use, intrinsic :: iso_c_binding, only : c_int8_t, c_int32_t, c_int64_t, c_size_t
  use, intrinsic :: iso_fortran_env, only : int8, int32, int64
  use entity_core_status
  implicit none
  private

  public :: ffi_sha256, ffi_sha384, ffi_ed25519_sign, ffi_ed25519_verify, &
            ffi_ed25519_seed_to_pubkey, ffi_content_hash, ffi_encode_ecf, &
            ffi_peerid_format, ffi_peerid_parse

  ! ── verbatim entitycore_codec.h prototypes ──
  interface

    function ec_sha256(data_ptr, data_len, out_ptr) bind(c, name='ec_sha256') result(rc)
      import :: c_int8_t, c_size_t, c_int32_t
      integer(c_int8_t), intent(in)  :: data_ptr(*)
      integer(c_size_t), value       :: data_len
      integer(c_int8_t), intent(out) :: out_ptr(*)          ! 32
      integer(c_int32_t)             :: rc
    end function ec_sha256

    function ec_sha384(data_ptr, data_len, out_ptr) bind(c, name='ec_sha384') result(rc)
      import :: c_int8_t, c_size_t, c_int32_t
      integer(c_int8_t), intent(in)  :: data_ptr(*)
      integer(c_size_t), value       :: data_len
      integer(c_int8_t), intent(out) :: out_ptr(*)          ! 48
      integer(c_int32_t)             :: rc
    end function ec_sha384

    function ec_ed25519_sign(priv_ptr, msg_ptr, msg_len, out_sig) &
        bind(c, name='ec_ed25519_sign') result(rc)
      import :: c_int8_t, c_size_t, c_int32_t
      integer(c_int8_t), intent(in)  :: priv_ptr(*)         ! 32
      integer(c_int8_t), intent(in)  :: msg_ptr(*)
      integer(c_size_t), value       :: msg_len
      integer(c_int8_t), intent(out) :: out_sig(*)          ! 64
      integer(c_int32_t)             :: rc
    end function ec_ed25519_sign

    function ec_ed25519_verify(pub_ptr, msg_ptr, msg_len, sig_ptr) &
        bind(c, name='ec_ed25519_verify') result(rc)
      import :: c_int8_t, c_size_t, c_int32_t
      integer(c_int8_t), intent(in)  :: pub_ptr(*)          ! 32
      integer(c_int8_t), intent(in)  :: msg_ptr(*)
      integer(c_size_t), value       :: msg_len
      integer(c_int8_t), intent(in)  :: sig_ptr(*)          ! 64
      integer(c_int32_t)             :: rc
    end function ec_ed25519_verify

    function ec_ed25519_seed_to_pubkey(seed_ptr, out_pub) &
        bind(c, name='ec_ed25519_seed_to_pubkey') result(rc)
      import :: c_int8_t, c_int32_t
      integer(c_int8_t), intent(in)  :: seed_ptr(*)         ! 32
      integer(c_int8_t), intent(out) :: out_pub(*)          ! 32
      integer(c_int32_t)             :: rc
    end function ec_ed25519_seed_to_pubkey

    function ec_content_hash(type_ptr, type_len, data_ptr, data_len, out_ptr) &
        bind(c, name='ec_content_hash') result(rc)
      import :: c_int8_t, c_size_t, c_int32_t
      integer(c_int8_t), intent(in)  :: type_ptr(*)
      integer(c_size_t), value       :: type_len
      integer(c_int8_t), intent(in)  :: data_ptr(*)
      integer(c_size_t), value       :: data_len
      integer(c_int8_t), intent(out) :: out_ptr(*)          ! EC_CONTENT_HASH_LEN = 33
      integer(c_int32_t)             :: rc
    end function ec_content_hash

    function ec_encode_ecf(type_ptr, type_len, data_ptr, data_len, out_ptr, out_cap, out_len) &
        bind(c, name='ec_encode_ecf') result(rc)
      import :: c_int8_t, c_size_t, c_int32_t
      integer(c_int8_t), intent(in)  :: type_ptr(*)
      integer(c_size_t), value       :: type_len
      integer(c_int8_t), intent(in)  :: data_ptr(*)
      integer(c_size_t), value       :: data_len
      integer(c_int8_t), intent(out) :: out_ptr(*)
      integer(c_size_t), value       :: out_cap
      integer(c_size_t), intent(out) :: out_len
      integer(c_int32_t)             :: rc
    end function ec_encode_ecf

    function ec_peerid_format(key_type, hash_type, digest_ptr, digest_len, &
                              out_ptr, out_cap, out_len) &
        bind(c, name='ec_peerid_format') result(rc)
      import :: c_int8_t, c_int64_t, c_size_t, c_int32_t
      integer(c_int64_t), value      :: key_type            ! uint64 code
      integer(c_int64_t), value      :: hash_type           ! uint64 code
      integer(c_int8_t), intent(in)  :: digest_ptr(*)
      integer(c_size_t), value       :: digest_len
      integer(c_int8_t), intent(out) :: out_ptr(*)          ! base58 ASCII
      integer(c_size_t), value       :: out_cap
      integer(c_size_t), intent(out) :: out_len
      integer(c_int32_t)             :: rc
    end function ec_peerid_format

    function ec_peerid_parse(base58_ptr, base58_len, out_key_type, out_hash_type, &
                             out_digest_ptr, out_digest_len) &
        bind(c, name='ec_peerid_parse') result(rc)
      import :: c_int8_t, c_int64_t, c_size_t, c_int32_t
      integer(c_int8_t),  intent(in)  :: base58_ptr(*)
      integer(c_size_t),  value       :: base58_len
      integer(c_int64_t), intent(out) :: out_key_type
      integer(c_int64_t), intent(out) :: out_hash_type
      integer(c_int8_t),  intent(out) :: out_digest_ptr(*)
      integer(c_size_t),  intent(out) :: out_digest_len
      integer(c_int32_t)              :: rc
    end function ec_peerid_parse

  end interface

contains

  ! ── idiomatic Fortran wrappers (int8 array in / int8 array out + stat) ──

  subroutine ffi_sha256(data, out32, stat)
    integer(int8), intent(in)  :: data(:)
    integer(int8), intent(out) :: out32(32)
    integer,       intent(out) :: stat
    stat = int(ec_sha256(data, int(size(data), c_size_t), out32))
  end subroutine ffi_sha256

  subroutine ffi_sha384(data, out48, stat)
    integer(int8), intent(in)  :: data(:)
    integer(int8), intent(out) :: out48(48)
    integer,       intent(out) :: stat
    stat = int(ec_sha384(data, int(size(data), c_size_t), out48))
  end subroutine ffi_sha384

  subroutine ffi_ed25519_sign(priv32, msg, out_sig64, stat)
    integer(int8), intent(in)  :: priv32(32)
    integer(int8), intent(in)  :: msg(:)
    integer(int8), intent(out) :: out_sig64(64)
    integer,       intent(out) :: stat
    stat = int(ec_ed25519_sign(priv32, msg, int(size(msg), c_size_t), out_sig64))
  end subroutine ffi_ed25519_sign

  subroutine ffi_ed25519_verify(pub32, msg, sig64, ok, stat)
    integer(int8), intent(in)  :: pub32(32)
    integer(int8), intent(in)  :: msg(:)
    integer(int8), intent(in)  :: sig64(64)
    logical,       intent(out) :: ok
    integer,       intent(out) :: stat
    integer(c_int32_t) :: rc
    rc   = ec_ed25519_verify(pub32, msg, int(size(msg), c_size_t), sig64)
    stat = int(rc)
    ok   = (rc == EC_OK)
  end subroutine ffi_ed25519_verify

  subroutine ffi_ed25519_seed_to_pubkey(seed32, out_pub32, stat)
    integer(int8), intent(in)  :: seed32(32)
    integer(int8), intent(out) :: out_pub32(32)
    integer,       intent(out) :: stat
    stat = int(ec_ed25519_seed_to_pubkey(seed32, out_pub32))
  end subroutine ffi_ed25519_seed_to_pubkey

  ! content_hash = varint(0x00) || SHA-256(ECF({type,data})) as computed by the C-ABI
  ! over the type string bytes + the canonical-CBOR data value bytes (33 bytes out).
  subroutine ffi_content_hash(type_bytes, data_bytes, out33, stat)
    integer(int8), intent(in)  :: type_bytes(:)
    integer(int8), intent(in)  :: data_bytes(:)
    integer(int8), intent(out) :: out33(33)
    integer,       intent(out) :: stat
    stat = int(ec_content_hash(type_bytes, int(size(type_bytes), c_size_t), &
                               data_bytes, int(size(data_bytes), c_size_t), out33))
  end subroutine ffi_content_hash

  subroutine ffi_encode_ecf(type_bytes, data_bytes, out, out_len, stat)
    integer(int8), intent(in)  :: type_bytes(:)
    integer(int8), intent(in)  :: data_bytes(:)
    integer(int8), intent(out) :: out(:)
    integer,       intent(out) :: out_len
    integer,       intent(out) :: stat
    integer(c_size_t) :: n
    stat = int(ec_encode_ecf(type_bytes, int(size(type_bytes), c_size_t), &
                             data_bytes, int(size(data_bytes), c_size_t), &
                             out, int(size(out), c_size_t), n))
    out_len = int(n)
  end subroutine ffi_encode_ecf

  ! base58 peer-id: Base58(varint(key_type) || varint(hash_type) || digest). The varint
  ! framing (incl. the multibyte key_type=128 of peer_id.3) is done inside the C-ABI.
  subroutine ffi_peerid_format(key_type, hash_type, digest, out_ascii, out_len, stat)
    integer(int64), intent(in)  :: key_type, hash_type
    integer(int8),  intent(in)  :: digest(:)
    integer(int8),  intent(out) :: out_ascii(:)             ! caller-sized (>= ~64)
    integer,        intent(out) :: out_len
    integer,        intent(out) :: stat
    integer(c_size_t) :: n
    stat = int(ec_peerid_format(int(key_type, c_int64_t), int(hash_type, c_int64_t), &
                                digest, int(size(digest), c_size_t), &
                                out_ascii, int(size(out_ascii), c_size_t), n))
    out_len = int(n)
  end subroutine ffi_peerid_format

  subroutine ffi_peerid_parse(base58, key_type, hash_type, digest, digest_len, stat)
    integer(int8),  intent(in)  :: base58(:)
    integer(int64), intent(out) :: key_type, hash_type
    integer(int8),  intent(out) :: digest(:)                ! caller-sized (>= 64)
    integer,        intent(out) :: digest_len
    integer,        intent(out) :: stat
    integer(c_int64_t) :: kt, ht
    integer(c_size_t)  :: dl
    stat      = int(ec_peerid_parse(base58, int(size(base58), c_size_t), kt, ht, digest, dl))
    key_type  = int(kt, int64)
    hash_type = int(ht, int64)
    digest_len = int(dl)
  end subroutine ffi_peerid_parse

end module entity_core_ffi
