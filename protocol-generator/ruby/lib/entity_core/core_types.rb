# frozen_string_literal: true

require_relative "entity"
require_relative "cbor"
require_relative "data/core_type_floor"

module EntityCore
  # Core type floor (V7 v7.72 §9.5) — the full 53-type registry (A-RUBY-008).
  #
  # Render-from-shapes, NOT ingest-the-served-bytes. Each floor type's
  # `TypeDefinition` *shape* (its ECF `data` payload) is vendored in
  # +CoreTypeFloor::DATA_HEX+ (dumped byte-exact from the keystone Go reference
  # registry @75c532e — see that file). THIS peer decodes each payload with its
  # OWN S2-green ECF decoder and re-materializes a +system/type+ entity via
  # +Entity.make+, so the content_hash is recomputed by this peer's codec. A
  # codec divergence would therefore surface immediately as a content_hash
  # mismatch against the oracle's pinned hash (+CoreTypeFloor::CONTENT_HASH+),
  # which +floor_entities+ asserts at build time — the single-source-of-truth-
  # in-code, diff-against-Go-golden pattern (type-registry-render-design), not
  # "emit these bytes to hit the check."
  #
  # Types OUTSIDE this 53-floor (compute/*, content/*, the type EXTENSION, …) are
  # extension-owned and intentionally absent under --profile core (the oracle
  # matches them if-present, never FAILs on absence).
  module CoreTypes
    TypeFloorError = Class.new(EntityCore::Error)

    module_function

    # Build the 53 floor `system/type` entities (decode shape → re-materialize),
    # asserting each recomputed content_hash equals the Go reference's pinned
    # hash. Returns +{ "type-name" => Entity }+.
    def floor_entities
      CoreTypeFloor::DATA_HEX.each_with_object({}) do |(name, hex), acc|
        data = Cbor.decode([hex].pack("H*").b)
        entity = Entity.make("system/type", data)
        want = [CoreTypeFloor::CONTENT_HASH.fetch(name)].pack("H*").b
        unless entity.content_hash == want
          raise TypeFloorError,
                "core-type floor #{name}: content_hash drift " \
                "(got #{entity.content_hash.unpack1('H*')}, want #{want.unpack1('H*')})"
        end
        acc[name] = entity
      end
    end

    # Publish every floor type at /{peer}/system/type/{name}.
    def publish(store, local_peer)
      floor_entities.each do |name, entity|
        store.bind("/#{local_peer}/system/type/#{name}", entity)
      end
    end
  end
end
