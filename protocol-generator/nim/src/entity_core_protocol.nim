## entity-core-protocol-nim — public codec module surface (S2).
##
## The core protocol peer's codec layer: Entity Canonical Form (ECF) CBOR,
## content_hash, peer-id format/parse, Ed25519 sign/verify + SHA-256, LEB128
## varints, base58. Hand-rolled canonical layer (native, A-005), crypto floor via
## native libsodium `{.importc.}` interop. Re-exported here per profile [layout].
##
## S3 peer machinery (model / store / identity / wire / peer dispatch / transport)
## is layered on top and re-exported here.
##
## SPDX-License-Identifier: Apache-2.0

import ./errors
import ./ecf
import ./varint
import ./base58
import ./crypto
import ./content_hash
import ./peer_id
import ./model
import ./store
import ./identity
import ./wire
import ./peer
import ./transport

export errors, ecf, varint, base58, crypto, content_hash, peer_id
export model, store, identity, wire, peer, transport
