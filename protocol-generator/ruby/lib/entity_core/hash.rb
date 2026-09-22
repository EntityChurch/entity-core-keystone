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

    # ECFv1-SHA-256 — the §9.1 conformance floor, and the format the system/peer
    # identity entity is pinned to unconditionally (§4.5a item 1a).
    PEER_IDENTITY_FLOOR_FORMAT = 0x00
    PEER_IDENTITY_TYPE = "system/peer"

    # Raised when an author asks for a system/peer under a non-floor format.
    class PeerEntityNotAtFloor < StandardError; end

    # The §4.5a AUTHORING entry point — use this wherever the peer *creates* an
    # entity under a chosen content_hash_format, as opposed to merely computing a
    # digest. +content_hash+ is the raw primitive; this adds the one normative
    # constraint on *which* format an author may choose.
    #
    # §4.5a item 1a — a system/peer identity entity is authored under
    # ECFv1-SHA-256 (0x00) UNCONDITIONALLY: on every connection, whatever the
    # active format, and whatever the peer's home format. Its data is wholly
    # recoverable from the public peer-id, so every consumer *derives* its hash
    # rather than fetching it. A system/peer under any other format is not a form
    # to be preserved but a construction that cannot exist.
    #
    # This is the constructor the `hash-format-sha-384.2` agility vector requires
    # the refusal to be observed through. That vector used to assert the opposite
    # and stayed green only because verifiers hand-built the entity instead of
    # routing through the code that forbids it — a fixture that exercises a
    # forbidden construction and passes by bypassing the guard certifies the
    # opposite of the rule (GUIDE-CONFORMANCE §2.4a).
    def author_content_hash(entity, format_code)
      if entity["type"] == PEER_IDENTITY_TYPE && format_code != PEER_IDENTITY_FLOOR_FORMAT
        raise PeerEntityNotAtFloor,
              "#{PEER_IDENTITY_TYPE} is pinned to the ECFv1-SHA-256 floor " \
              "(V7 §4.5a item 1a); refusing to author it under " \
              "content_hash_format #{format_code}"
      end

      content_hash(entity, format_code)
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
