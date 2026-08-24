## content_hash construction (ENTITY-CBOR-ENCODING.md §4.2 / §9.3):
##
##   content_hash = varint(format_code) || HASH(ECF({type, data}))
##
## format_code 0x00 = ecfv1-sha256 (the required floor). 0x01 = ecfv1-sha384
## (agility, DEFERRED — libsodium has no high-level SHA-384). The varint prefix
## is LEB128 (N1) — a synthetic code >= 0x80 exercises the multi-byte path
## (corpus content_hash.4, format_code 128 -> still SHA-256).
##
## SPDX-License-Identifier: Apache-2.0

import ./ecf
import ./varint
import ./crypto
import ./errors

proc contentHash*(formatCode: uint64; typ: string; data: EcValue): seq[byte]
    {.raises: [EcCryptoError, DuplicateKey, UnsupportedHashFormat].} =
  ## content_hash bytes. format_code 1 -> SHA-384 (deferred, raises); any other
  ## code emits varint(code) || SHA-256 (receive-side dispatch of unsupported
  ## codes is the S3 peer surface, not the codec's).
  let ecf = ecfOfEntity(typ, data)
  result = @[]
  varintEncode(result, formatCode)
  if formatCode == 1'u64:
    raise newException(UnsupportedHashFormat,
      "SHA-384 (format_code 0x01) is agility-deferred (A-NIM-004)")
  result.add sha256(ecf)
