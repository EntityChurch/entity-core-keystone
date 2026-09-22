# frozen_string_literal: true

require_relative "entity"
require_relative "error"

module EntityCore
  # The protocol envelope (§3.1): a +root+ entity plus an +included+ list of
  # protocol entities keyed by content_hash. +included+ is the §5.8 authority
  # carrier (caps, peer identities, signatures travel here).
  #
  # Held as an insertion-ordered Array of +Included+ (hash, entity) pairs so a
  # wire round-trip is deterministic; lookup is by content_hash octets. (The
  # codec re-sorts map keys length-then-lex on encode, so wire order is
  # canonical regardless of insertion order — N5 preservation.)
  class Envelope
    Included = Data.define(:hash, :entity)

    attr_reader :root, :included

    def initialize(root, included = [])
      @root = root
      @included = included.freeze
      freeze
    end

    # Find an included entity by its content_hash, or nil.
    def included_get(hash)
      h = hash.b
      pair = @included.find { |i| i.hash == h }
      pair&.entity
    end

    # ── wire form ──────────────────────────────────────────────────────────────

    def to_cbor
      inc = {}
      @included.each { |i| inc[i.hash] = i.entity.to_cbor }
      { "root" => @root.to_cbor, "included" => inc }
    end

    def self.from_cbor(map)
      root_v = map["root"]
      raise ProtocolError, "envelope: missing root" unless root_v.is_a?(::Hash)

      root = Entity.from_cbor(root_v)
      included = []
      seen = {}
      inc = map["included"]
      if inc.is_a?(::Hash)
        inc.each do |k, v|
          raise ProtocolError, "envelope: included key not bytes" unless k.is_a?(::String) && k.encoding == Encoding::BINARY
          raise ProtocolError, "envelope: included value not a map" unless v.is_a?(::Hash)

          ent = Entity.from_cbor(v)
          # §3.1 key != content_hash — §1.8's resolution-integrity obligation,
          # mechanism (a) "bind the key": reject the entry whose key is not
          # content_hash({type, data}) of the entity under it, which fails the
          # envelope closed at ONE site. §5.2a's code for this arm is
          # `hash_mismatch`, not the structural `invalid_request` beside it
          # (0.8.2.24 N4/N5) — the entry's encoding is canonical; what is false is
          # the claim the KEY makes.
          raise HashMismatchError, "included key != content_hash" unless k == ent.content_hash

          unless seen[k]
            seen[k] = true
            included << Included.new(hash: k.b, entity: ent)
          end
        end
      end
      new(root, included)
    end
  end
end
