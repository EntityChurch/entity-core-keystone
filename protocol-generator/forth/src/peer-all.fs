\ entity-core-protocol-forth — the PEER umbrella. require's the S2 codec umbrella + every
\ S3 peer-machinery module in dependency order. A peer boots from THIS file (with
\ libentitycore_codec on LIBRARY_PATH + LD_LIBRARY_PATH).
\
\ Codec (S2):  entity-core.fs -> buf, varint, base58, cbor, tv, peer-id, ffi/crypto, hash
\ Peer  (S3):  entity, store, identity, envelope, wire, capability, handlers, dispatch, peer

require entity-core.fs      \ the S2 codec umbrella (arena, cbor, crypto, peer-id, hash)
require b64.fs              \ base64 decode (keypair PEM seed)
require entity.fs           \ materialized entity {type,data,content_hash}
require store.fs            \ content store + entity tree (durable heap)
require identity.fs         \ L1 identity: seed -> pub/peer_id, sign/verify
require envelope.fs         \ §3.1 envelope {root, included} (byte-keyed, N5)
require wire.fs             \ §3.2/§3.3 EXECUTE / EXECUTE_RESPONSE builders
require capability.fs       \ §5 capability: token, chain-walk, §4.10(b) depth pre-check
require net.fs              \ native sockets + select loop + framing + §4.10(a) 16-MiB cap
require handlers.fs         \ connect handshake + handler registry + seed grant
require capauthz.fs         \ §5.2/§5.5 chain verification (single + multisig) + scope matching
require coretypes.fs        \ §9.5 53-type core floor publisher (render-from-model)
require dispatch.fs         \ §6.5 dispatch chain + §6.11 request_id demux + reentry pump
require validate.fs         \ §7a conformance handlers (system/validate/{echo,dispatch-outbound})
require peer.fs             \ peer assembly: bootstrap + listen + serve

arena-reset scratch-reset store-heap-reset
