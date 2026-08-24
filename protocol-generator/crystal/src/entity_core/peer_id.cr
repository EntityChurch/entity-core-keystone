require "digest/sha256"
require "./base58"
require "./varint"
require "./error"

module EntityCore
  # Peer-id formatting/parsing (§1.5):
  #
  #   peer_id = Base58(varint(key_type) <> varint(hash_type) <> digest)
  #
  # `key_type` and `hash_type` are multicodec-style LEB128 varints (invariant
  # N1). §1.5 canonical form: a key <= 32 bytes is an identity-multihash
  # (hash_type 0x00, digest = the key itself); a larger key is SHA-256-form
  # (hash_type 0x01, digest = SHA-256(key)). So Ed25519 (32 B) maps to
  # (0x01, 0x00, pubkey) and Ed448 (57 B) to (0x02, 0x01, sha256(pubkey)).
  #
  # The corpus pins the Base58 peer-id STRING (ECF-encoded as CBOR text by the
  # harness), so `format` returns the String.
  module PeerId
    extend self

    # Format a peer-id String from its components. `key_type` / `hash_type` route
    # through real LEB128 so a synthetic code >= 0x80 extends correctly (N1;
    # peer_id.3 exercises key_type 128).
    def format(key_type : UInt64, hash_type : UInt64, digest : Bytes) : String
      io = IO::Memory.new
      Varint.encode(key_type, io)
      Varint.encode(hash_type, io)
      io.write(digest)
      Base58.encode(io.to_slice)
    end

    # Parse a peer-id String back to `{key_type, hash_type, digest}`.
    def parse(str : String) : {UInt64, UInt64, Bytes}
      raw = Base58.decode(str)
      key_type, off1 = Varint.decode(raw)
      rest1 = raw[off1, raw.size - off1]
      hash_type, off2 = Varint.decode(rest1)
      digest = rest1[off2, rest1.size - off2].dup
      {key_type, hash_type, digest}
    end

    # Derive a peer-id (Base58 String) from a raw public key (§1.5 size cutoff).
    def from_public_key(public_key : Bytes, curve : Symbol) : String
      if public_key.size <= 32
        hash_type = 0_u64
        digest = public_key
      else
        hash_type = 1_u64
        d = Digest::SHA256.new
        d.update(public_key)
        digest = d.final
      end
      key_type =
        case curve
        when :ed25519 then 1_u64
        when :ed448   then 2_u64
        else
          raise UnsupportedValueError.new("unknown curve: #{curve}")
        end
      format(key_type, hash_type, digest)
    end
  end
end
