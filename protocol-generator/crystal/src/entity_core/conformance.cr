require "./cbor"
require "./hash"
require "./peer_id"
require "./signature"
require "./error"

module EntityCore
  # ECF conformance runner. Pure (no file IO): it takes the corpus bytes, decodes
  # them with THIS peer's own decoder (a decoder bug here is itself a conformance
  # failure, per ENTITY-CBOR-ENCODING.md §E.3), and runs every vector.
  #
  # Vectors dispatch by category (the id prefix before the dot):
  #   * content_hash — varint(format_code) <> SHA-256(ECF({type, data}))
  #   * peer_id      — Cbor.encode(PeerId.format(key_type, hash_type, digest))
  #   * signature    — Signature.sign(seed, entity)
  #   * everything else (float/int/map_keys/length/primitive/nested/envelope)
  #     — plain Cbor.encode(input)
  #   * decode_reject — the decoder MUST reject the `canonical` wire bytes
  module Conformance
    record Result, id : String, status : Symbol, detail : String?

    CONFORMANCE_KINDS = ["encode_equal", "decode_reject"]

    extend self

    # Run every encode_equal / decode_reject vector in a decoded corpus.
    # `corpus_bytes` is the raw `.cbor` file content. Non-conformance (meta) rows
    # are skipped.
    def run(corpus_bytes : Bytes) : Array(Result)
      vectors = Cbor.decode(corpus_bytes)
      arr = vectors.as?(Array(Cbor::EcValue))
      raise CodecError.new("corpus is not a CBOR array") if arr.nil?

      results = [] of Result
      arr.each do |v|
        map = v.as?(::Hash(Cbor::EcValue, Cbor::EcValue))
        next if map.nil?
        kind = map["kind"]?
        next unless kind.is_a?(String) && CONFORMANCE_KINDS.includes?(kind)
        results << run_vector(map)
      end
      results
    end

    private def run_vector(vector : ::Hash(Cbor::EcValue, Cbor::EcValue)) : Result
      id = vector["id"].as(String)
      case vector["kind"]
      when "decode_reject"
        run_reject(id, vector["canonical"].as(Bytes))
      when "encode_equal"
        run_encode(id, vector["input"], vector["canonical"].as(Bytes))
      else
        Result.new(id, :fail, "unknown kind")
      end
    end

    private def run_reject(id : String, wire : Bytes) : Result
      begin
        Cbor.decode(wire)
        Result.new(id, :fail, "expected reject but decoded successfully")
      rescue CodecError
        Result.new(id, :pass, nil)
      end
    end

    private def run_encode(id : String, input : Cbor::EcValue, want : Bytes) : Result
      got = produce(id, input)
      if got == want
        Result.new(id, :pass, nil)
      else
        Result.new(id, :fail, "got=#{hexify(got)} want=#{hexify(want)}")
      end
    rescue e : Exception
      Result.new(id, :fail, "raised #{e.class}: #{e.message}")
    end

    private def produce(id : String, input : Cbor::EcValue) : Bytes
      case category(id)
      when "content_hash"
        map = input.as(::Hash(Cbor::EcValue, Cbor::EcValue))
        fc = 0_u64
        if (raw = map["format_code"]?)
          ec = raw.as(Cbor::EcInt)
          fc = ec.arg # major 0 unsigned
        end
        Hash.content_hash(input, fc)
      when "peer_id"
        map = input.as(::Hash(Cbor::EcValue, Cbor::EcValue))
        kt = map["key_type"].as(Cbor::EcInt).arg
        ht = map["hash_type"].as(Cbor::EcInt).arg
        digest = map["digest"].as(Bytes)
        peer = PeerId.format(kt, ht, digest)
        Cbor.encode(peer)
      when "signature"
        map = input.as(::Hash(Cbor::EcValue, Cbor::EcValue))
        seed = map["seed"].as(Bytes)
        entity = map["entity"]
        Signature.sign(seed, entity)
      else
        Cbor.encode(input)
      end
    end

    private def category(id : String) : String
      id.split(".").first
    end

    private def hexify(bytes : Bytes) : String
      bytes.hexstring
    end
  end
end
