# entity-core-protocol-crystal — core codec entrypoint.
#
# Requiring `entity_core` pulls in the full S2 CODEC surface: the hand-rolled
# canonical-CBOR codec (EntityCore::Cbor), LEB128 varints, Base58, content-hash,
# peer-id, the libsodium-backed Ed25519 signature module, and the conformance
# runner. Core codec only — NO standard extension (TREE/CONTENT/…) is imported.
require "./entity_core/error"
require "./entity_core/varint"
require "./entity_core/base58"
require "./entity_core/cbor"
require "./entity_core/hash"
require "./entity_core/peer_id"
require "./entity_core/signature"
require "./entity_core/conformance"
# ── S3 peer machinery (Core Layers 1–4 + foundation) ──────────────────────────
require "./entity_core/entity"
require "./entity_core/envelope"
require "./entity_core/identity"
require "./entity_core/store"
require "./entity_core/wire"
require "./entity_core/handler"
require "./entity_core/capability"
require "./entity_core/core_types"
require "./entity_core/peer"
require "./entity_core/handlers"
require "./entity_core/transport"

module EntityCore
  VERSION = "0.1.0"
end
