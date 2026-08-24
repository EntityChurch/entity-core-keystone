## §3.6 K-of-N multisig ACCEPT-PATH unit (the keystone "conformance-green can be
## vacuous" lesson). The oracle's `multisig` category is rejection-heavy — a
## fail-closed peer can pass it WITHOUT implementing the primitive — so this unit
## drives the direction the oracle can't: a genuinely valid 2-of-3 peer-signed root
## capability MUST be ACCEPTED by verifyCapabilityChain, and a below-threshold
## (1-of-3) presentation MUST be rejected. Complements the live
## `valid_2of3_peer_signed_accepted` probe with an in-repo, oracle-free assertion.
##
## Run (in-container, sealed offline):
##   nim c -r --mm:orc --overflowChecks:on -d:release --hints:off \
##     -o:/tmp/tmultisig tests/tmultisig.nim
##
## SPDX-License-Identifier: Apache-2.0

import std/unittest
import ../src/ecf
import ../src/model
import ../src/identity
import ../src/capability

proc mkSeed(b: byte): seq[byte] =
  result = newSeq[byte](32)
  for i in 0 ..< 32: result[i] = b

proc multiGranterVal(signers: seq[seq[byte]]; threshold: uint64): EcValue =
  var arr: seq[EcValue]
  for s in signers: arr.add bytesV(s)
  mapV(@[
    EcPair(key: textV("signers"), val: arrV(arr)),
    EcPair(key: textV("threshold"), val: uintV(threshold)),
  ])

proc rootMultiSigToken(signers: seq[seq[byte]]; threshold: uint64; grantee: seq[byte]): Entity =
  ## A §3.6 M3 root token whose granter is a {signers, threshold} quorum (parent: null).
  makeEntity("system/capability/token", mapV(@[
    EcPair(key: textV("grants"), val: arrV(@[])),
    EcPair(key: textV("granter"), val: multiGranterVal(signers, threshold)),
    EcPair(key: textV("grantee"), val: bytesV(grantee)),
    EcPair(key: textV("created_at"), val: uintV(1000'u64)),
  ]))

suite "§3.6 K-of-N multisig":
  # Three distinct peer identities; A is the LOCAL peer (§5.5 M6 root-at-local).
  let a = identityOfSeed(mkSeed(0x11))
  let b = identityOfSeed(mkSeed(0x22))
  let c = identityOfSeed(mkSeed(0x33))
  let signers = @[a.identityHash, b.identityHash, c.identityHash]
  let now = 2000'u64

  test "valid 2-of-3 peer-signed root is ACCEPTED (M4/M6 accept path)":
    let token = rootMultiSigToken(signers, 2, a.identityHash)
    # Two of the three quorum members sign the token's content hash.
    let sigA = a.signEntityHash(token)
    let sigB = b.signEntityHash(token)
    let env = Envelope(root: token, included: @[
      (key: a.identityHash, entity: a.peerEntity),
      (key: b.identityHash, entity: b.peerEntity),
      (key: c.identityHash, entity: c.peerEntity),
      (key: token.hash, entity: token),
      (key: sigA.hash, entity: sigA),
      (key: sigB.hash, entity: sigB),
    ])
    check verifyCapabilityChain(parseToken(token), env, a.peerId, now)

  test "1-of-3 (below threshold) is REJECTED":
    let token = rootMultiSigToken(signers, 2, a.identityHash)
    let sigA = a.signEntityHash(token)          # only ONE valid signature
    let env = Envelope(root: token, included: @[
      (key: a.identityHash, entity: a.peerEntity),
      (key: b.identityHash, entity: b.peerEntity),
      (key: c.identityHash, entity: c.peerEntity),
      (key: token.hash, entity: token),
      (key: sigA.hash, entity: sigA),
    ])
    check not verifyCapabilityChain(parseToken(token), env, a.peerId, now)

  test "threshold below 2 is REJECTED (M3 structural: threshold ∈ [2, N])":
    let token = rootMultiSigToken(signers, 1, a.identityHash)
    let sigA = a.signEntityHash(token)
    let sigB = b.signEntityHash(token)
    let env = Envelope(root: token, included: @[
      (key: a.identityHash, entity: a.peerEntity),
      (key: b.identityHash, entity: b.peerEntity),
      (key: c.identityHash, entity: c.peerEntity),
      (key: token.hash, entity: token),
      (key: sigA.hash, entity: sigA),
      (key: sigB.hash, entity: sigB),
    ])
    check not verifyCapabilityChain(parseToken(token), env, a.peerId, now)

  test "local peer NOT in the quorum is REJECTED (M6 root-at-local)":
    # A quorum of B and C only; the LOCAL peer A is not a signer.
    let bc = @[b.identityHash, c.identityHash]
    let token = rootMultiSigToken(bc, 2, a.identityHash)
    let sigB = b.signEntityHash(token)
    let sigC = c.signEntityHash(token)
    let env = Envelope(root: token, included: @[
      (key: a.identityHash, entity: a.peerEntity),
      (key: b.identityHash, entity: b.peerEntity),
      (key: c.identityHash, entity: c.peerEntity),
      (key: token.hash, entity: token),
      (key: sigB.hash, entity: sigB),
      (key: sigC.hash, entity: sigC),
    ])
    check not verifyCapabilityChain(parseToken(token), env, a.peerId, now)
