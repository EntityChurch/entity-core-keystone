! entity-core-protocol-fortran — src/status.f90
!
! The error model is STATUS-CODE (profile [error_model] style = "status-code"):
! Fortran has no exception / Result machinery, so every fallible subroutine takes an
! intent(out) integer `stat` the caller tests before using the result (the iostat=/
! stat= convention; the COBOL/errno family). The codes below are aligned with the
! C-ABI int32_t EC_* codes AND double as the codec's own leaf-reject kinds. A hard
! reject (non-canonical / truncated / tag) sets a distinguished NEGATIVE code; EC_OK
! (0) is success. `error stop` is reserved for genuinely unrecoverable faults.
module entity_core_status
  use, intrinsic :: iso_fortran_env, only : int32
  implicit none
  public

  ! --- C-ABI-aligned codes (entitycore_codec.h §6; numeric values ARE the ABI) ---
  integer, parameter :: EC_OK                 =   0
  integer, parameter :: EC_INVALID_ARGUMENT   =  -1
  integer, parameter :: EC_OUT_OF_SPACE       =  -2
  integer, parameter :: EC_DECODE_ERROR       =  -3
  integer, parameter :: EC_ENCODE_ERROR       =  -4
  integer, parameter :: EC_HASH_MISMATCH      =  -5
  integer, parameter :: EC_SIGNATURE_INVALID  =  -6
  integer, parameter :: EC_KEY_INVALID        =  -7
  integer, parameter :: EC_PEERID_INVALID     =  -8
  integer, parameter :: EC_ARENA_EXHAUSTED    =  -9
  integer, parameter :: EC_INTERNAL_ERROR     = -99

  ! --- Codec-side leaf reject kinds (EC_*-aligned distinguished negatives). These map
  !     onto the protocol's 400 non_canonical_ecf surface at the peer layer (S3). ---
  integer, parameter :: EC_NON_CANONICAL_ECF            = -101   ! tag / indefinite / non-minimal
  integer, parameter :: EC_TRUNCATED_INPUT              = -102
  integer, parameter :: EC_TAG_REJECTED                 = -103   ! N2: major-type-6 anywhere in data
  integer, parameter :: EC_BAD_SEED                     = -104
  integer, parameter :: EC_UNSUPPORTED_CONTENT_HASH_FMT = -105
  integer, parameter :: EC_UNSUPPORTED_KEY_TYPE         = -106

end module entity_core_status
