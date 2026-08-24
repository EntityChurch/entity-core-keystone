require "./cbor"
require "./hash"
require "./error"

module EntityCore
  # A materialized entity `{type, data, content_hash}` (V8 §1.1 / §3.4) on top of
  # the S2 codec.
  #
  # The content_hash covers ONLY `{type, data}` (§1.1); the wire form (`to_cbor`)
  # carries content_hash as a third field so entities are self-describing across
  # serialization (§3.1). The two forms stay distinct: the hash is never computed
  # over a map that already carries content_hash.
  #
  # `data` is an ARBITRARY ECF value (NOT necessarily a Hash) — A-JAVA-010 /
  # `data_is_arbitrary_ecf`. Core protocol entities happen to be maps, but a
  # scalar-data entity (`primitive/string`) is equally valid. `data_map` returns
  # the map view when `data` is one, else an empty map, so a field read on a
  # scalar entity returns nil instead of raising.
  #
  # A `class` (not `struct`) because entities are shared by reference across the
  # store + dispatch chain and used as Hash keys by content_hash (identity by
  # value; a struct copy per lookup would be wasteful for a 33-byte-keyed type).
  class Entity
    getter type : String
    getter data : Cbor::EcValue
    getter content_hash : Bytes

    def initialize(@type : String, @data : Cbor::EcValue, @content_hash : Bytes)
    end

    # Construct a materialized entity (arbitrary ECF `data`), computing
    # content_hash under the ecfv1-sha256 floor (format_code 0x00).
    def self.make(type : String, data : Cbor::EcValue) : Entity
      basis = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      basis["type"] = type
      basis["data"] = data
      ch = EntityCore::Hash.content_hash(basis, 0_u64)
      new(type, data, ch)
    end

    # Convenience: build from a plain (coercible) map literal — the caller writes
    # `Entity.build("system/hash", {"hash" => h})` without hand-coercing.
    def self.build(type : String, data) : Entity
      make(type, Cbor.coerce(data))
    end

    # The `data` as a map view: the Hash itself when data IS a Hash (every core
    # protocol entity), else an empty map (scalar-data entities read as empty).
    def data_map : ::Hash(Cbor::EcValue, Cbor::EcValue)
      d = @data
      d.is_a?(::Hash(Cbor::EcValue, Cbor::EcValue)) ? d : ::Hash(Cbor::EcValue, Cbor::EcValue).new
    end

    # ── field reads off data (nil-safe) ────────────────────────────────────────

    def field(key : String) : Cbor::EcValue
      data_map[key]?
    end

    # A CBOR text string (major 3 → Crystal String).
    def text(key : String) : String?
      v = data_map[key]?
      v.as?(String)
    end

    # A CBOR byte string (major 2 → Crystal Bytes).
    def bytes(key : String) : Bytes?
      v = data_map[key]?
      v.as?(Bytes)
    end

    # An unsigned/small integer as UInt64 (major 0 EcInt only).
    def uint(key : String) : UInt64?
      v = data_map[key]?
      return nil unless v.is_a?(Cbor::EcInt)
      v.major == 0_u8 ? v.arg : nil
    end

    def bool(key : String) : Bool?
      v = data_map[key]?
      v.as?(Bool)
    end

    def map_field(key : String) : ::Hash(Cbor::EcValue, Cbor::EcValue)?
      v = data_map[key]?
      v.as?(::Hash(Cbor::EcValue, Cbor::EcValue))
    end

    def array_field(key : String) : Array(Cbor::EcValue)?
      v = data_map[key]?
      v.as?(Array(Cbor::EcValue))
    end

    # Decode a nested entity carried at `key` (a wire cbor-map).
    def entity_field(key : String) : Entity?
      m = map_field(key)
      m ? Entity.from_cbor(m) : nil
    end

    # ── wire form ──────────────────────────────────────────────────────────────

    # The wire cbor-map `{type, data, content_hash}`.
    def to_cbor : ::Hash(Cbor::EcValue, Cbor::EcValue)
      m = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      m["type"] = @type
      m["data"] = @data
      m["content_hash"] = @content_hash
      m
    end

    def wire_bytes : Bytes
      Cbor.encode(to_cbor)
    end

    # Parse a wire entity cbor-map, recompute the hash from `{type, data}`, and
    # validate against the carried content_hash (§1.8 fidelity). We trust our
    # recomputed hash, not the wire bytes (§5.2 validate-before-trust).
    def self.from_cbor(map : ::Hash(Cbor::EcValue, Cbor::EcValue)) : Entity
      type = map["type"]?
      raise ProtocolError.new("entity: missing/invalid type") unless type.is_a?(String)
      raise ProtocolError.new("entity: missing data") unless map.has_key?("data")
      data = map["data"]

      e = make(type, data)
      carried = map["content_hash"]?
      if carried.is_a?(Bytes) && carried != e.content_hash
        raise ProtocolError.new("content_hash mismatch (§1.8 fidelity)")
      end
      e
    end

    def ==(other : Entity) : Bool
      other.content_hash == @content_hash
    end

    def_hash @content_hash

    def to_s(io : IO) : Nil
      io << "Entity(" << @type << ", " << @content_hash.hexstring << ")"
    end
  end
end
