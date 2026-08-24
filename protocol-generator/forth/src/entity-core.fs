\ entity-core-protocol-forth — umbrella loader.
\
\ require's every codec module in dependency order + the libcc crypto binding. A consumer
\ loads THIS file: `gforth -e 'include src/entity-core.fs'` (with libentitycore_codec on
\ LIBRARY_PATH + LD_LIBRARY_PATH). The peer machinery (S3) require's this same umbrella.
\
\ Layout (profile [layout]):
\   src/buf.fs        arena + tagged-value heap + error codes (foundation)
\   src/varint.fs     LEB128 varint (N1)
\   src/base58.fs     Base58 (byte-array long division)
\   src/cbor.fs       canonical CBOR (ECF) encode/decode — the stack-machine probe
\   src/tv.fs         tagged-value navigation (map-get, array-elem, unwrap)
\   src/peer-id.fs    peer_id canonical form (§1.5)
\   src/ffi/crypto.fs libentitycore_codec via gforth libcc (SHA + Ed25519 floor)
\   src/hash.fs       content_hash construction (§4.2)

\ requires are resolved relative to THIS file's directory (src/), so they name siblings.
require buf.fs
require varint.fs
require base58.fs
require cbor.fs
require tv.fs
require peer-id.fs
require ffi/crypto.fs
require hash.fs

arena-reset  scratch-reset
