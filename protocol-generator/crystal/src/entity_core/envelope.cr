require "./cbor"
require "./entity"
require "./error"

module EntityCore
  # The protocol envelope (§3.1): a `root` entity plus an `included` list of
  # protocol entities keyed by content_hash. `included` is the §5.8 authority
  # carrier (caps, peer identities, signatures travel here).
  #
  # Held as an insertion-ordered Array of `Included` (hash, entity) pairs so a
  # wire round-trip is deterministic; lookup is by content_hash octets. (The
  # codec re-sorts map keys length-then-lex on encode, so wire order is canonical
  # regardless of insertion order — N5 preservation.)
  class Envelope
    # One (content_hash, entity) inclusion. A struct — a small immutable pair.
    struct Included
      getter hash : Bytes
      getter entity : Entity

      def initialize(@hash : Bytes, @entity : Entity)
      end
    end

    getter root : Entity
    getter included : Array(Included)

    def initialize(@root : Entity, @included : Array(Included) = [] of Included)
    end

    # Convenience: wrap a root entity + a list of entities (keyed by their hash).
    def self.of(root : Entity, entities : Array(Entity) = [] of Entity) : Envelope
      inc = entities.map { |e| Included.new(e.content_hash, e) }
      new(root, inc)
    end

    # Find an included entity by its content_hash, or nil.
    def included_get(hash : Bytes) : Entity?
      @included.each do |i|
        return i.entity if i.hash == hash
      end
      nil
    end

    # ── wire form ──────────────────────────────────────────────────────────────

    def to_cbor : ::Hash(Cbor::EcValue, Cbor::EcValue)
      inc = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      @included.each { |i| inc[i.hash] = i.entity.to_cbor }
      m = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      m["root"] = @root.to_cbor
      m["included"] = inc
      m
    end

    def self.from_cbor(map : ::Hash(Cbor::EcValue, Cbor::EcValue)) : Envelope
      root_v = map["root"]?
      raise ProtocolError.new("envelope: missing root") unless root_v.is_a?(::Hash(Cbor::EcValue, Cbor::EcValue))
      root = Entity.from_cbor(root_v)

      included = [] of Included
      seen = Set(String).new
      inc = map["included"]?
      if inc.is_a?(::Hash(Cbor::EcValue, Cbor::EcValue))
        inc.each do |k, v|
          raise ProtocolError.new("envelope: included key not bytes") unless k.is_a?(Bytes)
          raise ProtocolError.new("envelope: included value not a map") unless v.is_a?(::Hash(Cbor::EcValue, Cbor::EcValue))
          ent = Entity.from_cbor(v)
          # §3.1: the included content_hash MUST equal the map key.
          raise ProtocolError.new("included key != content_hash") unless k == ent.content_hash
          key_str = k.hexstring
          unless seen.includes?(key_str)
            seen << key_str
            included << Included.new(k, ent)
          end
        end
      end
      new(root, included)
    end
  end
end
