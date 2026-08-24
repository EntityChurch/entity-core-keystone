## Ed25519 + SHA-256 crypto floor (§9.1) via libsodium, bound with native Nim
## `{.importc.}` C interop (profile [codec].ed25519_library, A-NIM-003).
##
## Nim COMPILES TO C, so binding libsodium via `{.importc, header: "sodium.h".}`
## is idiomatic, in-process, zero-marshalling interop — the C peer's exact crypto
## choice (crypto.c), NOT a foreign-language bridge. Deterministic detached
## signing (RFC-8032): a fixed 32-byte seed + fixed message yields a fixed 64-byte
## signature, reproducible across impls with no RNG.
##
## Ed448 / SHA-384 agility is DEFERRED (A-NIM-004): libsodium has no Ed448, and
## `crypto_hash_sha384` is not in libsodium's high-level API. The core corpus is
## Ed25519 + SHA-256 only (content_hash.4's format_code 128 still hashes SHA-256).
##
## SPDX-License-Identifier: Apache-2.0

import ./ecf
import ./errors

{.passL: "-lsodium".}

const
  Ed25519SeedLen* = 32
  Ed25519PubLen* = 32
  Ed25519SecLen* = 64
  Ed25519SigLen* = 64
  Sha256Len* = 32

proc sodium_init(): cint {.importc, header: "sodium.h", cdecl.}

proc crypto_hash_sha256(output: ptr byte; input: ptr byte;
                        inlen: culonglong): cint
  {.importc, header: "sodium.h", cdecl.}

proc crypto_sign_seed_keypair(pk: ptr byte; sk: ptr byte;
                              seed: ptr byte): cint
  {.importc, header: "sodium.h", cdecl.}

proc crypto_sign_detached(sig: ptr byte; siglen: ptr culonglong;
                          m: ptr byte; mlen: culonglong;
                          sk: ptr byte): cint
  {.importc, header: "sodium.h", cdecl.}

proc crypto_sign_verify_detached(sig: ptr byte; m: ptr byte;
                                 mlen: culonglong; pk: ptr byte): cint
  {.importc, header: "sodium.h", cdecl.}

var initialised = false

proc ensureInit() {.raises: [EcCryptoError].} =
  if not initialised:
    if sodium_init() < 0:
      raise newException(EcCryptoError, "libsodium initialisation failed")
    initialised = true

template uptr(a: openArray[byte]): ptr byte =
  ## Pointer to the first byte, or nil for an empty buffer (a nil+0-len call to
  ## libsodium is well-defined for the hash/sign message argument).
  (if a.len == 0: nil else: cast[ptr byte](unsafeAddr a[0]))

proc sha256*(input: openArray[byte]): array[Sha256Len, byte]
    {.raises: [EcCryptoError].} =
  ensureInit()
  if crypto_hash_sha256(addr result[0], uptr(input), culonglong(input.len)) != 0:
    raise newException(EcCryptoError, "crypto_hash_sha256 failed")

proc ed25519Pubkey*(seed: openArray[byte]): array[Ed25519PubLen, byte]
    {.raises: [EcCryptoError].} =
  ensureInit()
  if seed.len != Ed25519SeedLen:
    raise newException(BadSeed, "Ed25519 seed must be 32 bytes")
  var sk: array[Ed25519SecLen, byte]
  if crypto_sign_seed_keypair(addr result[0], addr sk[0],
                              cast[ptr byte](unsafeAddr seed[0])) != 0:
    raise newException(EcCryptoError, "crypto_sign_seed_keypair failed")

proc ed25519Sign*(seed, msg: openArray[byte]): array[Ed25519SigLen, byte]
    {.raises: [EcCryptoError].} =
  ## Deterministic Ed25519 signature (64 bytes) over `msg` for the 32-byte `seed`.
  ensureInit()
  if seed.len != Ed25519SeedLen:
    raise newException(BadSeed, "Ed25519 seed must be 32 bytes")
  var
    pk: array[Ed25519PubLen, byte]
    sk: array[Ed25519SecLen, byte]
  if crypto_sign_seed_keypair(addr pk[0], addr sk[0],
                              cast[ptr byte](unsafeAddr seed[0])) != 0:
    raise newException(EcCryptoError, "crypto_sign_seed_keypair failed")
  var siglen: culonglong = 0
  let rc = crypto_sign_detached(addr result[0], addr siglen,
                                uptr(msg), culonglong(msg.len), addr sk[0])
  if rc != 0 or siglen != culonglong(Ed25519SigLen):
    raise newException(SignFailed, "crypto_sign_detached failed")

proc ed25519Verify*(pubkey, sig, msg: openArray[byte]): bool
    {.raises: [EcCryptoError].} =
  ensureInit()
  if pubkey.len != Ed25519PubLen or sig.len != Ed25519SigLen:
    return false
  crypto_sign_verify_detached(cast[ptr byte](unsafeAddr sig[0]),
                              uptr(msg), culonglong(msg.len),
                              cast[ptr byte](unsafeAddr pubkey[0])) == 0

proc signEntity*(seed: openArray[byte]; typ: string; data: EcValue):
    array[Ed25519SigLen, byte] {.raises: [EcCryptoError, DuplicateKey].} =
  ## Sign the canonical-ECF encoding of {type, data} (the signature corpus surface).
  ed25519Sign(seed, ecfOfEntity(typ, data))
