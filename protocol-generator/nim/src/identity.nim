## Peer identity (L1) — the Ed25519 seed and the entities derived from it
## (§1.5, §3.5, §4.6, §7.3):
##
##   public_key    = Ed25519 pub of seed                          (32 bytes)
##   peer_id       = Base58(varint(1) ‖ varint(0) ‖ public_key)   (§1.5 canonical
##                   identity-multihash — raw pubkey digest, NOT §7.4 SHA256 form;
##                   cohort-settled, profile [spec])
##   peer entity   = system/peer { public_key, key_type }         (§3.5; v7.65 —
##                   NO peer_id in the hashable basis)
##   identity_hash = content_hash(peer entity)                    (33 bytes)
##
## A system/signature over an entity signs the entity's full 33-byte content_hash
## (§4.6: "Sign full hash bytes (format code + digest)").
##
## SPDX-License-Identifier: Apache-2.0

import std/options
import ./ecf
import ./model
import ./crypto
import ./peer_id

type
  Identity* = object
    seed*: seq[byte]           ## 32-byte Ed25519 seed
    publicKey*: seq[byte]      ## 32-byte Ed25519 public key
    peerId*: string            ## Base58 canonical identity-multihash
    peerEntity*: Entity        ## system/peer entity
    identityHash*: seq[byte]   ## = peerEntity.hash (33 bytes)

proc peerEntityOfPubkey*(publicKey: openArray[byte]): Entity =
  ## system/peer entity (§3.5; v7.65 — public_key + key_type only, no peer_id).
  makeEntity("system/peer", mapV(@[
    EcPair(key: textV("public_key"), val: bytesV(@publicKey)),
    EcPair(key: textV("key_type"), val: textV("ed25519")),
  ]))

proc peerIdOfPubkey*(publicKey: openArray[byte]): string =
  ## Canonical Ed25519 peer_id (§1.5): key_type 0x01, hash_type 0x00, raw pubkey.
  peerIdFormat(0x01'u64, 0x00'u64, publicKey)

proc identityOfSeed*(seed: openArray[byte]): Identity =
  let pub = ed25519Pubkey(seed)
  let pe = peerEntityOfPubkey(pub)
  Identity(
    seed: @seed,
    publicKey: @pub,
    peerId: peerIdOfPubkey(pub),
    peerEntity: pe,
    identityHash: pe.hash,
  )

proc signEntityHash*(id: Identity; target: Entity): Entity =
  ## Produce a system/signature entity over `target`'s content_hash (§3.5 / §4.6).
  let sig = ed25519Sign(id.seed, target.hash)
  makeEntity("system/signature", mapV(@[
    EcPair(key: textV("target"), val: bytesV(target.hash)),
    EcPair(key: textV("signer"), val: bytesV(id.identityHash)),
    EcPair(key: textV("algorithm"), val: textV("ed25519")),
    EcPair(key: textV("signature"), val: bytesV(@sig)),
  ]))

proc verifySignatureEntity*(signature, signerPeer: Entity): bool =
  ## Verify a system/signature against the signer's system/peer public_key. The
  ## §5.2 signer-hash binding (signer == expected identity) is the caller's check.
  let target = signature.bytesField("target")
  let sigB = signature.bytesField("signature")
  let pub = signerPeer.bytesField("public_key")
  if target.isNone or sigB.isNone or pub.isNone: return false
  if sigB.get.len != 64 or pub.get.len != 32: return false
  ed25519Verify(pub.get, sigB.get, target.get)
