! entity-core-protocol-fortran — src/identity.f90 (L1 identity: §1.5, §3.5, §7.3).
!
! Everything derives from a 32-byte Ed25519 seed:
!   pub         = Ed25519 pubkey of seed                     (32 bytes, C-ABI floor)
!   peer_id     = §1.5 canonical-form identity-multihash      (Base58, via C-ABI — no
!                 Fortran bignum, A-FTN-006)
!   peer_entity = system/peer {public_key, key_type}          (§3.5; NO peer_id in basis)
!   id_hash     = content_hash(peer_entity)                   (33 bytes)
!
! peer_id is the §1.5 identity-multihash form (key_type 0x01 ed25519, hash_type 0x00
! identity, digest = the raw 32-byte pubkey), which the profile [spec] note bakes in as
! settled (superseding the stale §7.4 SHA-256 skeleton) to avoid the S4 handshake debug
! cycle. Signing is over the full 33-byte content_hash (§7.3). Ed25519 sign/verify + the
! base58 peer-id cross the C-ABI (entity_core_ffi); no native Fortran crypto/bignum.
module entity_core_identity
  use, intrinsic :: iso_fortran_env, only : int8, int64
  use entity_core_status
  use entity_core_cbor, only : ecf_value_t
  use entity_core_val
  use entity_core_ent
  use entity_core_ffi
  implicit none
  private

  integer(int64), parameter :: KEY_TYPE_ED25519 = 1_int64
  integer(int64), parameter :: HASH_TYPE_IDENTITY = 0_int64

  type, public :: id_t
    integer(int8)                 :: seed(32) = 0_int8
    integer(int8)                 :: pub(32)  = 0_int8
    character(len=:), allocatable :: peer_id
    type(entity_t)                :: peer_entity
    integer(int8)                 :: id_hash(HASH_LEN) = 0_int8
  end type id_t

  public :: id_of_seed, id_sign, id_verify_signature
  public :: peer_id_of_pubkey, peer_entity_of_pubkey, peer_id_key_type

contains

  function id_of_seed(seed) result(id)
    integer(int8), intent(in) :: seed(32)
    type(id_t) :: id
    integer :: stat
    id%seed = seed
    call ffi_ed25519_seed_to_pubkey(seed, id%pub, stat)
    id%peer_entity = peer_entity_of_pubkey(id%pub)
    id%id_hash = ent_hash(id%peer_entity)
    id%peer_id = peer_id_of_pubkey(id%pub)
  end function id_of_seed

  ! §1.5 identity-multihash peer_id from a raw Ed25519 pubkey (Base58 of
  ! varint(key_type) ‖ varint(hash_type) ‖ digest), via the C-ABI.
  function peer_id_of_pubkey(pub) result(s)
    integer(int8), intent(in) :: pub(:)
    character(len=:), allocatable :: s
    integer(int8) :: ascii(96)
    integer :: out_len, stat
    call ffi_peerid_format(KEY_TYPE_ED25519, HASH_TYPE_IDENTITY, pub, ascii, out_len, stat)
    if (stat == EC_OK .and. out_len > 0) then
      s = str_of_bytes(ascii(1:out_len))
    else
      s = ''
    end if
  end function peer_id_of_pubkey

  ! the §1.5 multihash key_type code carried by a base58 peer_id (-1 if unparseable).
  ! Lets the §4.6 authenticate step reject a peer_id encoding an unsupported key_type
  ! (e.g. 0xFD) with 400 unsupported_key_type instead of a downstream 401 identity_mismatch
  ! (AGILITY-UNKNOWN-1 / v7.66 §7.1).
  integer(int64) function peer_id_key_type(peer_id)
    character(len=*), intent(in) :: peer_id
    integer(int64) :: kt, ht
    integer(int8)  :: digest(64)
    integer :: dlen, stat
    peer_id_key_type = -1_int64
    if (len_trim(peer_id) == 0) return
    call ffi_peerid_parse(bytes_of_str(trim(peer_id)), kt, ht, digest, dlen, stat)
    if (stat == EC_OK) peer_id_key_type = kt
  end function peer_id_key_type

  ! the system/peer entity for a raw pubkey (no peer_id in the §3.5 basis).
  function peer_entity_of_pubkey(pub) result(e)
    integer(int8), intent(in) :: pub(:)
    type(entity_t) :: e
    type(ecf_value_t) :: m
    m = v_map_empty()
    m = v_map_put(m, 'public_key', v_bytes(pub))
    m = v_map_put(m, 'key_type', v_text('ed25519'))
    e = ent_make('system/peer', m)
  end function peer_entity_of_pubkey

  ! sign a target entity's 33-byte content_hash -> a system/signature entity (§3.5).
  function id_sign(id, target) result(sig_ent)
    type(id_t),     intent(in) :: id
    type(entity_t), intent(in) :: target
    type(entity_t) :: sig_ent
    integer(int8) :: th(HASH_LEN), sig(64)
    type(ecf_value_t) :: m
    integer :: stat
    th = ent_hash(target)
    call ffi_ed25519_sign(id%seed, th, sig, stat)
    m = v_map_empty()
    m = v_map_put(m, 'target', v_bytes(th))
    m = v_map_put(m, 'signer', v_bytes(id%id_hash))
    m = v_map_put(m, 'algorithm', v_text('ed25519'))
    m = v_map_put(m, 'signature', v_bytes(sig))
    sig_ent = ent_make('system/signature', m)
  end function id_sign

  ! verify a system/signature against the signer's system/peer entity. The §5.2
  ! signer-hash binding is the caller's responsibility.
  logical function id_verify_signature(signature, signer_peer)
    type(entity_t), intent(in) :: signature, signer_peer
    integer(int8), allocatable :: target(:), sig(:), pub(:)
    logical :: ok
    integer :: stat
    id_verify_signature = .false.
    target = ent_bytes(signature, 'target')
    sig    = ent_bytes(signature, 'signature')
    pub    = ent_bytes(signer_peer, 'public_key')
    if (size(target) == 0 .or. size(sig) /= 64 .or. size(pub) /= 32) return
    call ffi_ed25519_verify(pub, target, sig, ok, stat)
    id_verify_signature = ok
  end function id_verify_signature

end module entity_core_identity
