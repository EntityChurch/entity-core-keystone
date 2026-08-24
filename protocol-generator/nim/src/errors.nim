## Codec + crypto exception hierarchy (profile [error_model]: exceptions +
## {.raises.} effect tracking). Root `EcError`; the codec throws HARD on any
## canonicality violation (a fail-closed reject, never a silent sentinel).
## In-band "absent" is `Option[T]` at the call sites, NOT an exception.
##
## Leaves mirror profile [error_model].exception_base:
##   EcCodecError  -> NonCanonicalEcf / TruncatedInput / TagRejected /
##                    TrailingBytes / DuplicateKey
##   EcCryptoError -> BadSeed / UnsupportedHashFormat / SignFailed
##
## SPDX-License-Identifier: Apache-2.0

type
  EcError* = object of CatchableError

  EcCodecError* = object of EcError
  NonCanonicalEcf* = object of EcCodecError  ## indefinite / reserved length arg
  TruncatedInput* = object of EcCodecError   ## ran off the end of the buffer
  TagRejected* = object of EcCodecError      ## any CBOR tag (major type 6) — N2
  TrailingBytes* = object of EcCodecError     ## bytes left after one top-level item
  DuplicateKey* = object of EcCodecError      ## duplicate map key (RFC 8949 rule 5)
  UnsupportedSimple* = object of EcCodecError  ## simple/float value ECF does not use

  EcCryptoError* = object of EcError
  BadSeed* = object of EcCryptoError
  UnsupportedHashFormat* = object of EcCryptoError  ## e.g. SHA-384 (agility, deferred)
  SignFailed* = object of EcCryptoError
