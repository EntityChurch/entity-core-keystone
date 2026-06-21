# frozen_string_literal: true

require "openssl"

require_relative "cbor"
require_relative "varint"
require_relative "error"

module EntityCore
  # Content-hash construction (ENTITY-CBOR-ENCODING.md §4.2):
  #
  #   content_hash = varint(format_code) <> hash_alg(ECF({type, data}))
  #
  # The default format code 0x00 is ecfv1-sha256; 0x01 is ecfv1-sha384
  # (agility). The +format_code+ is NOT part of the hashed entity — only
  # +{"type" => ..., "data" => ...}+ is hashed. The varint prefix is
  # multicodec-style LEB128, so a code >= 0x80 extends to multiple bytes
  # (invariant N1).
  module Hash
    # Allocated content-hash format codes (V7 §1.2 / §4.3 registry — active
    # set). Codes outside this set still hash with SHA-256 on the construct side
    # (the codec corpus pins only the varint *prefix* for synthetic high codes,
    # e.g. content_hash.4); the peer layer (S3) rejects unallocated codes on the
    # receive side as unsupported_content_hash_format.
    ALLOCATED_FORMATS = { 0 => "SHA256", 1 => "SHA384" }.freeze

    module_function

    # Compute the wire content hash (varint format-code prefix + digest) over an
    # entity Hash carrying at least "type" and "data". +data+ is an arbitrary
    # ECF value (not necessarily a Hash) — A-JAVA-010 / duck_typing.
    def content_hash(entity, format_code = 0)
      hashed = { "type" => entity.fetch("type"), "data" => entity.fetch("data") }
      digest = OpenSSL::Digest.digest(digest_name(format_code), Cbor.encode(hashed))
      Varint.encode(format_code) << digest
    end

    # Resolve an integer format code to its OpenSSL digest name (receive side).
    # Returns the name for an allocated code, or nil for an unsupported one.
    def resolve_format(code)
      ALLOCATED_FORMATS[code]
    end

    # Decode a multicodec-style LEB128 format-code prefix and resolve it
    # (invariant N1 — the multi-byte varint decoder fires before the registry
    # check, so a code >= 0x80 is decoded, not short-circuited). Returns the
    # OpenSSL digest name or nil.
    def resolve_wire_format(prefix)
      code, = Varint.decode(prefix)
      resolve_format(code)
    end

    # Construct-side digest name. Code 0x01 = SHA-384 (agility); everything else
    # = SHA-256 (the required floor + the synthetic-high-code corpus case).
    def digest_name(format_code)
      format_code == 1 ? "SHA384" : "SHA256"
    end
    private_class_method :digest_name
  end
end
