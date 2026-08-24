## Peer identifier (V8 §1.2 / §1.5 / §7.3):
##
##   peer_id = Base58(varint(key_type) || varint(hash_type) || digest)
##
## key_type / hash_type are LEB128 varints (N1). For the canonical Ed25519
## identity-multihash form the §1.5 v7.65 canonical-form table pins key_type
## 0x01 = ed25519, hash_type 0x00, digest = the RAW 32-byte public key (NOT the
## stale §7.4 SHA256(pubkey) skeleton — pre-resolved cohort trap, profile [spec]).
## `format` is construction-agnostic over the component values, so it also
## reproduces the corpus vectors' opaque digests faithfully. A synthetic
## key_type >= 0x80 exercises the multi-byte varint prefix (corpus peer_id.3).
##
## SPDX-License-Identifier: Apache-2.0

import ./base58
import ./varint
import ./errors

proc peerIdFormat*(keyType, hashType: uint64; digest: openArray[byte]): string =
  ## Format the peer-id string (Base58) from the abstract components.
  var raw: seq[byte]
  varintEncode(raw, keyType)
  varintEncode(raw, hashType)
  for b in digest: raw.add b
  base58Encode(raw)

type PeerId* = object
  keyType*: uint64
  hashType*: uint64
  digest*: seq[byte]

proc peerIdParse*(s: string): PeerId {.raises: [TruncatedInput, ValueError].} =
  ## Parse a peer-id string back into its components.
  let raw = base58Decode(s)
  let k = varintDecode(raw, 0)
  let h = varintDecode(raw, k.len)
  let off = k.len + h.len
  PeerId(keyType: k.value, hashType: h.value, digest: raw[off ..< raw.len])
