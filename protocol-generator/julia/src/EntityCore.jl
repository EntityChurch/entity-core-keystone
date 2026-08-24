# entity-core-protocol-julia — codec umbrella module (S2).
#
# Scope: core Layers 0–4 codec surface only — ECF canonical CBOR, content_hash, peer_id
# parse/format, Ed25519 sign/verify. NO standard-extension encoding (TREE/CONTENT/… stop at
# the dispatcher; S3+). Self-contained floor: Julia stdlib (SHA/Sockets/Test) + system
# libsodium via ccall — zero registered packages (profile [codec], A-JULIA-002/003).
module EntityCore

# ── codec (S2) ────────────────────────────────────────────────────────────────────────────────
include("cbor.jl")
include("varint.jl")
include("base58.jl")
include("contenthash.jl")
include("peerid.jl")
include("sign.jl")

# ── peer machinery (S3): model → identity/store/handler → peer (dispatch) → transport ──────────
include("model.jl")
include("wire.jl")
include("identity.jl")
include("store.jl")
include("typedefs.jl")
include("capability.jl")
include("handler.jl")
include("peer.jl")
include("transport.jl")

using .Cbor
using .Varint
using .Base58
using .ContentHash
using .PeerId
using .Sign
using .Model
using .Wire
using .Identity
using .Store
using .TypeDefs
using .Capability
using .Handlers
using .Peer
using .Transport

# Public codec surface (re-exports)
export Cbor, Varint, Base58, ContentHash, PeerId, Sign
export CborMap, encode, decode
export encode_varint!, decode_varint
export base58encode, base58decode
export ecf_of_entity, content_hash
export peerid_format, peerid_parse
export ed25519_sign, ed25519_pubkey, ed25519_verify

# Public peer surface (re-exports)
export Model, Wire, Identity, Store, TypeDefs, Capability, Handlers, Peer, Transport
export Entity, Envelope, make_entity
export PeerIdentity, peer_identity
export Peer_t, Conn, create_peer, dispatch, register_handler!
export Io, Session, serve_connection, dial, initiate, session_execute, execute_raw, read_loop, close_io

end # module EntityCore
