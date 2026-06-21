# frozen_string_literal: true

require "openssl"

require_relative "base58"
require_relative "varint"
require_relative "error"

module EntityCore
  # Peer-id formatting/parsing (V7 §1.5):
  #
  #   peer_id = Base58(varint(key_type) <> varint(hash_type) <> digest)
  #
  # +key_type+ and +hash_type+ are multicodec-style LEB128 varints (invariant
  # N1). The §1.5 canonical-form derivation uses a size cutoff: a key <= 32
  # bytes is an identity-multihash (hash_type 0x00, digest = the key itself); a
  # larger key is SHA-256-form (hash_type 0x01, digest = SHA-256(key)). So
  # Ed25519 (32 B) maps to (0x01, 0x00, pubkey) and Ed448 (57 B) to
  # (0x02, 0x01, sha256(pubkey)). (A-SW-008 erratum: §1.5 supersedes the stale
  # §7.4 SHA256(pubkey) skeleton.)
  module PeerId
    KEY_TYPE_CODES = { ed25519: 1, ed448: 2 }.freeze

    module_function

    # Map a curve symbol to its key_type code.
    def key_type_code(curve)
      KEY_TYPE_CODES.fetch(curve) do
        raise UnsupportedValueError, "unknown curve: #{curve.inspect}"
      end
    end

    # Resolve an integer key_type code to its curve symbol (key registry,
    # V7 §1.5). Returns :ed25519 / :ed448, or nil for an unallocated/reserved
    # code (e.g. 255 — the agility VARINT-RESERVED-FF mint guard).
    def resolve_key_type(code)
      case code
      when 1 then :ed25519
      when 2 then :ed448
      end
    end

    # Derive a peer-id (Base58 String) from a raw public key (V7 §1.5).
    def from_public_key(public_key, curve)
      pk = public_key.b
      if pk.bytesize <= 32
        hash_type = 0
        digest = pk
      else
        hash_type = 1
        digest = OpenSSL::Digest.digest("SHA256", pk)
      end
      format(key_type_code(curve), hash_type, digest)
    end

    # Format a peer-id String from its components.
    def format(key_type, hash_type, digest)
      Base58.encode(Varint.encode(key_type) << Varint.encode(hash_type) << digest.b)
    end

    # Parse a peer-id String back to +[key_type, hash_type, digest]+.
    def parse(str)
      raw = Base58.decode(str)
      key_type, rest1 = Varint.decode(raw)
      hash_type, digest = Varint.decode(rest1)
      [key_type, hash_type, digest]
    end
  end
end
