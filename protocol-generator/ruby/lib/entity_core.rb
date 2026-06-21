# frozen_string_literal: true

# entity-core-protocol-ruby — core protocol peer (V7 Layers 0-4).
#
# `require "entity_core"` brings in the whole EntityCore namespace: the codec
# layer (S2: cbor/varint/base58/hash/peer_id/signature) and the peer machinery
# (S3: entity/envelope/identity/store/capability/wire/handler/peer/transport).

require_relative "entity_core/version"
require_relative "entity_core/error"
require_relative "entity_core/cbor"
require_relative "entity_core/varint"
require_relative "entity_core/base58"
require_relative "entity_core/hash"
require_relative "entity_core/peer_id"
require_relative "entity_core/signature"
require_relative "entity_core/conformance"
require_relative "entity_core/agility"

# Peer machinery (S3) — V7 Layers 1-4 + foundation.
require_relative "entity_core/entity"
require_relative "entity_core/envelope"
require_relative "entity_core/identity"
require_relative "entity_core/store"
require_relative "entity_core/capability"
require_relative "entity_core/wire"
require_relative "entity_core/handler"
require_relative "entity_core/core_types"
require_relative "entity_core/peer"
require_relative "entity_core/transport"

# Top-level namespace for the Ruby core protocol peer.
module EntityCore
end
