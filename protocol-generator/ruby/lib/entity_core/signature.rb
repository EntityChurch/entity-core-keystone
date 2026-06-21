# frozen_string_literal: true

require "openssl"

require_relative "cbor"
require_relative "error"

module EntityCore
  # Ed25519 (and Ed448) sign/verify over canonical-ECF-encoded entities, via
  # stdlib +openssl+ (OpenSSL 3.x backend). RFC 8032 PureEdDSA is deterministic
  # — a fixed seed + fixed message yields fixed signature bytes (so the corpus
  # can byte-pin them).
  #
  # Ed25519: 32-byte seed, 32-byte pubkey, 64-byte signature.
  # Ed448:   57-byte seed, 57-byte pubkey, 114-byte signature. Reachable
  #          natively here (no FFI, no libsodium) — the bundled OpenSSL ships
  #          Ed448 (asserted at container-build time; A-RUBY-002).
  #
  # API (A-RUBY-003, confirmed in-container against Ruby 3.4.4 / OpenSSL 3.x):
  #   * +OpenSSL::PKey.new_raw_private_key(alg, seed)+ — key from a raw seed
  #   * +OpenSSL::PKey.new_raw_public_key(alg, pub)+   — verify-only key
  #   * +pkey.sign(nil, msg)+ / +pkey.verify(nil, sig, msg)+ — digest=nil (Pure)
  #   * +pkey.raw_private_key+ / +pkey.raw_public_key+ — raw 32/57-byte material
  module Signature
    ALG = { ed25519: "ED25519", ed448: "ED448" }.freeze

    module_function

    # Sign an already-serialized message with a raw seed. +curve+ is :ed25519
    # (default) or :ed448.
    def sign_raw(seed, message, curve = :ed25519)
      key = OpenSSL::PKey.new_raw_private_key(alg(curve), seed.b)
      key.sign(nil, message.b).b
    end

    # Sign the canonical ECF encoding of +entity+ with a raw seed.
    def sign(seed, entity, curve = :ed25519)
      sign_raw(seed, Cbor.encode(entity), curve)
    end

    # Verify a signature over an already-serialized message, given a raw public
    # key.
    def verify_raw(public_key, message, signature, curve = :ed25519)
      key = OpenSSL::PKey.new_raw_public_key(alg(curve), public_key.b)
      key.verify(nil, signature.b, message.b)
    end

    # Verify a signature over the canonical ECF encoding of +entity+.
    def verify(public_key, entity, signature, curve = :ed25519)
      verify_raw(public_key, Cbor.encode(entity), signature, curve)
    end

    # Derive the raw public key from a raw seed (seed -> pubkey, V7 §1.5).
    def public_key(seed, curve = :ed25519)
      OpenSSL::PKey.new_raw_private_key(alg(curve), seed.b).raw_public_key.b
    end

    def alg(curve)
      ALG.fetch(curve) { raise UnsupportedValueError, "unknown curve: #{curve.inspect}" }
    end
    private_class_method :alg
  end
end
