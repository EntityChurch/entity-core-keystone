require "digest/sha256"
require "digest/sha512"
require "openssl/digest"
require "./cbor"
require "./varint"
require "./error"

module EntityCore
  # Content-hash construction (ENTITY-CBOR-ENCODING.md §4.2):
  #
  #   content_hash = varint(format_code) <> hash_alg(ECF({type, data}))
  #
  # The default format code 0x00 is ecfv1-sha256; 0x01 is ecfv1-sha384
  # (reserved/agility). The `format_code` is NOT part of the hashed entity — only
  # `{"type" => ..., "data" => ...}` is hashed. The varint prefix is
  # multicodec-style LEB128, so a code >= 0x80 extends to multiple bytes
  # (invariant N1).
  #
  # Construction-vs-verification asymmetry (§4.7, v7.73): the construction path
  # serialises whatever `format_code` the caller supplies (does not gate on the
  # registry — forward-compat). content_hash.4 exercises caller-supplied code 128.
  module Hash
    # Allocated content-hash format codes (§4.3 registry — active/reserved set).
    # SHA-256 is the required floor (0x00). Codes outside the SHA-384 branch hash
    # with SHA-256 on the construct side; the peer layer (S3) gates the receive
    # side.
    extend self

    # Compute the wire content hash (varint format-code prefix + digest) over an
    # entity map carrying at least "type" and "data". `data` is an arbitrary ECF
    # value (not necessarily a map) — A-JAVA-010 / duck_typing.
    def content_hash(entity : Cbor::EcValue, format_code : UInt64 = 0_u64) : Bytes
      map = entity.as?(::Hash(Cbor::EcValue, Cbor::EcValue))
      raise UnsupportedValueError.new("content_hash entity must be a map") if map.nil?

      type_v = map["type"]? || raise(UnsupportedValueError.new("entity missing 'type'"))
      # 'data' may be legitimately absent-but-required; the corpus always carries it.
      raise UnsupportedValueError.new("entity missing 'data'") unless map.has_key?("data")
      data_v = map["data"]

      hashed = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      hashed["type"] = type_v
      hashed["data"] = data_v

      preimage = Cbor.encode(hashed)
      digest = digest_bytes(format_code, preimage)

      io = IO::Memory.new
      Varint.encode(format_code, io)
      io.write(digest)
      io.to_slice
    end

    # Construct-side digest. Code 0x01 = SHA-384 (agility); everything else =
    # SHA-256 (the required floor + the synthetic-high-code corpus case).
    private def digest_bytes(format_code : UInt64, preimage : Bytes) : Bytes
      if format_code == 1_u64
        d = OpenSSL::Digest.new("SHA384")
        d.update(preimage)
        d.final
      else
        d = Digest::SHA256.new
        d.update(preimage)
        d.final
      end
    end
  end
end
