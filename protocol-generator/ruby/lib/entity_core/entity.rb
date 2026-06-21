# frozen_string_literal: true

require_relative "cbor"
require_relative "hash"
require_relative "error"

module EntityCore
  # A materialized entity +{type, data, content_hash}+ (V7 §1.1 / §3.4) on top of
  # the S2 codec.
  #
  # The content_hash covers ONLY +{type, data}+ (§1.1); the wire form
  # (+to_cbor+) carries content_hash as a third field so entities are
  # self-describing across serialization (§3.1). The two forms stay distinct:
  # the hash is never computed over a map that already carries content_hash.
  #
  # +data+ is an ARBITRARY ECF value (NOT necessarily a Hash) — A-JAVA-010 /
  # +duck_typing+. Core protocol entities happen to be maps, but a scalar-data
  # entity (e.g. +primitive/string+) is equally valid. +data_map+ returns the
  # map when +data+ is one, else the empty map, so a field read on a scalar
  # entity returns nil instead of raising.
  class Entity
    attr_reader :type, :data, :content_hash

    def initialize(type, data, content_hash)
      @type = type
      @data = data
      @content_hash = content_hash
      freeze
    end

    # Construct a materialized entity (arbitrary ECF +data+), computing
    # content_hash under the ecfv1-sha256 floor (format_code 0x00).
    def self.make(type, data)
      ch = EntityCore::Hash.content_hash({ "type" => type, "data" => data }, 0)
      new(type, data, ch)
    end

    # The +data+ as a map view: the Hash itself when data IS a Hash (every core
    # protocol entity), else the empty map (scalar-data entities read as empty).
    def data_map
      @data.is_a?(::Hash) ? @data : {}
    end

    # ── field reads off data (null-safe) ──────────────────────────────────────

    def field(key)
      data_map[key]
    end

    def text(key)
      v = data_map[key]
      v if v.is_a?(::String) && v.encoding != Encoding::BINARY
    end

    def bytes(key)
      v = data_map[key]
      v if v.is_a?(::String) && v.encoding == Encoding::BINARY
    end

    def uint(key)
      v = data_map[key]
      v if v.is_a?(::Integer)
    end

    def map_field(key)
      v = data_map[key]
      v if v.is_a?(::Hash)
    end

    # Decode a nested entity carried at +key+ (a wire cbor-map).
    def entity_field(key)
      m = map_field(key)
      m && Entity.from_cbor(m)
    end

    # ── wire form ──────────────────────────────────────────────────────────────

    # The wire cbor-map +{type, data, content_hash}+.
    def to_cbor
      { "type" => @type, "data" => @data, "content_hash" => @content_hash }
    end

    def wire_bytes
      Cbor.encode(to_cbor)
    end

    # Parse a wire entity cbor-map, recompute the hash from +{type, data}+, and
    # validate against the carried content_hash (§1.8 fidelity). We trust our
    # recomputed hash, not the wire bytes (§5.2 validate-before-trust).
    def self.from_cbor(map)
      type = map["type"]
      data = map["data"]
      raise ProtocolError, "entity: missing/invalid type" unless type.is_a?(::String) && type.encoding != Encoding::BINARY
      raise ProtocolError, "entity: missing data" if data.nil?

      e = make(type, data)
      carried = map["content_hash"]
      if carried.is_a?(::String) && carried.b != e.content_hash
        raise ProtocolError, "content_hash mismatch (§1.8 fidelity)"
      end

      e
    end

    def ==(other)
      other.is_a?(Entity) && other.content_hash == @content_hash
    end
    alias eql? ==

    def hash
      @content_hash.hash
    end

    def to_s
      "Entity(#{@type}, #{@content_hash.unpack1('H*')})"
    end
    alias inspect to_s
  end
end
