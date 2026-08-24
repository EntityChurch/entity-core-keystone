require "./cbor"
require "./error"

module EntityCore
  # Ed25519 sign/verify over canonical-ECF-encoded entities, via a DIRECT
  # in-process libsodium C binding (`lib LibSodium` + `fun crypto_sign_*` under
  # `@[Link("sodium")]`). Crystal's stdlib OpenSSL exposes NO PKey/EVP Ed25519
  # surface (crystal-lang#3941), so the audited route is libsodium's
  # `crypto_sign_*` (Ed25519, RFC 8032 deterministic — a fixed seed + fixed
  # message yields fixed signature bytes, so the corpus can byte-pin them).
  #
  # Ed25519: 32-byte seed, 32-byte pubkey, 64-byte signature.
  # Ed448 is DEFERRED (libsodium has no Ed448; profile A-CRY-002 hybrid-FFI path).
  @[Link("sodium")]
  lib LibSodium
    fun sodium_init : LibC::Int
    fun crypto_sign_seed_keypair(pk : UInt8*, sk : UInt8*, seed : UInt8*) : LibC::Int
    fun crypto_sign_detached(sig : UInt8*, siglen : UInt64*, m : UInt8*, mlen : UInt64, sk : UInt8*) : LibC::Int
    fun crypto_sign_verify_detached(sig : UInt8*, m : UInt8*, mlen : UInt64, pk : UInt8*) : LibC::Int
  end

  module Signature
    SEED_BYTES   = 32
    PUBKEY_BYTES = 32
    SECKEY_BYTES = 64 # libsodium sk = seed(32) || pubkey(32)
    SIG_BYTES    = 64

    @@initialized = false

    extend self

    private def ensure_init
      return if @@initialized
      raise Error.new("sodium_init failed") if LibSodium.sodium_init < 0
      @@initialized = true
    end

    # Derive (pubkey, secretkey) from a raw 32-byte seed.
    def keypair(seed : Bytes) : {Bytes, Bytes}
      ensure_init
      raise UnsupportedValueError.new("Ed25519 seed must be #{SEED_BYTES} bytes") unless seed.size == SEED_BYTES
      pk = Bytes.new(PUBKEY_BYTES)
      sk = Bytes.new(SECKEY_BYTES)
      rc = LibSodium.crypto_sign_seed_keypair(pk.to_unsafe, sk.to_unsafe, seed.to_unsafe)
      raise Error.new("crypto_sign_seed_keypair failed (#{rc})") unless rc == 0
      {pk, sk}
    end

    # Derive the raw public key from a raw seed (seed -> pubkey, §1.5).
    def public_key(seed : Bytes) : Bytes
      keypair(seed)[0]
    end

    # Sign an already-serialized message with a raw seed.
    def sign_raw(seed : Bytes, message : Bytes) : Bytes
      ensure_init
      _, sk = keypair(seed)
      sig = Bytes.new(SIG_BYTES)
      siglen = 0_u64
      rc = LibSodium.crypto_sign_detached(sig.to_unsafe, pointerof(siglen),
        message.to_unsafe, message.size.to_u64, sk.to_unsafe)
      raise Error.new("crypto_sign_detached failed (#{rc})") unless rc == 0
      raise Error.new("unexpected signature length #{siglen}") unless siglen == SIG_BYTES.to_u64
      sig
    end

    # Sign the canonical ECF encoding of `entity` with a raw seed.
    def sign(seed : Bytes, entity : Cbor::EcValue) : Bytes
      sign_raw(seed, Cbor.encode(entity))
    end

    # Verify a signature over an already-serialized message, given a raw pubkey.
    def verify_raw(public_key : Bytes, message : Bytes, signature : Bytes) : Bool
      ensure_init
      return false unless signature.size == SIG_BYTES
      return false unless public_key.size == PUBKEY_BYTES
      rc = LibSodium.crypto_sign_verify_detached(signature.to_unsafe,
        message.to_unsafe, message.size.to_u64, public_key.to_unsafe)
      rc == 0
    end

    # Verify a signature over the canonical ECF encoding of `entity`.
    def verify(public_key : Bytes, entity : Cbor::EcValue, signature : Bytes) : Bool
      verify_raw(public_key, Cbor.encode(entity), signature)
    end
  end
end
