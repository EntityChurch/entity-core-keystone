# frozen_string_literal: true

require_relative "cbor"
require_relative "hash"
require_relative "peer_id"
require_relative "signature"

module EntityCore
  # ECF conformance runner. Pure (no file IO): it takes the corpus bytes,
  # decodes them with THIS peer's own decoder (a decoder bug here is itself a
  # conformance failure, per ENTITY-CBOR-ENCODING.md §E.3), and runs every
  # vector.
  #
  # Vectors dispatch by category (the id prefix before the dot):
  #
  #   * content_hash — varint(format_code) <> SHA-2(ECF({type, data}))
  #   * peer_id      — ECF-of(Base58(varint(kt) <> varint(ht) <> digest)) ... no:
  #                    the corpus pins the Base58 peer-id String ENCODED as ECF
  #                    text, so the produced bytes are Cbor.encode(peer_id_str)
  #   * signature    — Ed25519_sign(seed, ECF({type, data}))
  #   * everything else (float/int/map_keys/length/primitive/nested/envelope)
  #     — plain Cbor.encode(input)
  #   * decode_reject — the decoder MUST reject the +canonical+ wire bytes
  module Conformance
    # A single vector result.
    Result = Struct.new(:id, :status, :detail)

    CONFORMANCE_KINDS = %w[encode_equal decode_reject].freeze

    module_function

    # Run every encode_equal / decode_reject vector in a decoded corpus.
    # +corpus_bytes+ is the raw +.cbor+ file content. Returns an Array of
    # +Result+. Non-conformance entries (meta rows) are skipped.
    def run(corpus_bytes)
      vectors = Cbor.decode(corpus_bytes)
      vectors
        .select { |v| v.is_a?(::Hash) && CONFORMANCE_KINDS.include?(v["kind"]) }
        .map { |v| run_vector(v) }
    end

    def run_vector(vector)
      id = vector["id"]
      case vector["kind"]
      when "decode_reject" then run_reject(id, vector["canonical"])
      when "encode_equal"  then run_encode(id, vector["input"], vector["canonical"])
      end
    end
    private_class_method :run_vector

    def run_reject(id, wire)
      Cbor.decode(wire)
      Result.new(id, :fail, "expected reject but decoded successfully")
    rescue CodecError
      Result.new(id, :pass, nil)
    end
    private_class_method :run_reject

    def run_encode(id, input, want)
      got = produce(id, input)
      if got == want
        Result.new(id, :pass, nil)
      else
        Result.new(id, :fail, { got: hexify(got), want: hexify(want) })
      end
    rescue StandardError => e
      Result.new(id, :fail, "raised #{e.class}: #{e.message}")
    end
    private_class_method :run_encode

    def produce(id, input)
      case category(id)
      when "content_hash"
        Hash.content_hash(input, input.fetch("format_code", 0))
      when "peer_id"
        peer = PeerId.format(input["key_type"], input["hash_type"], input["digest"])
        Cbor.encode(peer)
      when "signature"
        Signature.sign(input["seed"], input["entity"])
      else
        Cbor.encode(input)
      end
    end
    private_class_method :produce

    def category(id)
      id.split(".").first
    end
    private_class_method :category

    def hexify(bytes)
      bytes.b.unpack1("H*")
    end
    private_class_method :hexify
  end
end
