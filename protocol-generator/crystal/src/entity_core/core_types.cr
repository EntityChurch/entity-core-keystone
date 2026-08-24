require "./cbor"
require "./entity"
require "./store"
require "./error"
require "./data/core_type_floor"

module EntityCore
  # Core type floor (V8 §9.5) — the 53-type registry (A-CRY-008).
  #
  # Render-from-shapes, NOT ingest-the-served-bytes. Each floor type's
  # TypeDefinition *shape* (its ECF `data` payload) is vendored in
  # `CoreTypeFloor::DATA_HEX` (dumped byte-exact from the keystone Go reference
  # registry). THIS peer decodes each payload with its OWN S2-green ECF decoder and
  # re-materializes a `system/type` entity via `Entity.make`, so the content_hash
  # is recomputed by this peer's codec. A codec divergence surfaces immediately as
  # a content_hash mismatch against the oracle's pinned hash
  # (`CoreTypeFloor::CONTENT_HASH`), which `floor_entities` asserts at build time —
  # the single-source-of-truth-in-code, diff-against-Go-golden pattern, not "emit
  # these bytes to hit the check."
  #
  # Types OUTSIDE this 53-floor (compute/*, content/*, the type EXTENSION, …) are
  # extension-owned and intentionally absent under --profile core (the oracle
  # matches them if-present, never FAILs on absence).
  module CoreTypes
    class TypeFloorError < EntityCore::Error
    end

    extend self

    # Build the 53 floor `system/type` entities (decode shape → re-materialize),
    # asserting each recomputed content_hash equals the Go reference's pinned hash.
    def floor_entities : ::Hash(String, Entity)
      out = ::Hash(String, Entity).new
      CoreTypeFloor::DATA_HEX.each do |name, hex|
        data = Cbor.decode(hex.hexbytes)
        entity = Entity.make("system/type", data)
        want = CoreTypeFloor::CONTENT_HASH[name].hexbytes
        unless entity.content_hash == want
          raise TypeFloorError.new(
            "core-type floor #{name}: content_hash drift " \
            "(got #{entity.content_hash.hexstring}, want #{want.hexstring})")
        end
        out[name] = entity
      end
      out
    end

    # Publish every floor type at /{peer}/system/type/{name}.
    def publish(store : Store, local_peer : String) : Nil
      floor_entities.each do |name, entity|
        store.bind("/#{local_peer}/system/type/#{name}", entity)
      end
      nil
    end
  end
end
