# entity-core-protocol-unison — §3.6 multi-signature ACCEPT-path unit test

The `multisig` oracle category is largely rejection-only (malformed → 403), so a
fail-closed peer can pass it WITHOUT implementing the K-of-N accept primitive (the
vacuous-green trap). This unit exercises the direction the oracle can't cover: a
genuine **2-of-3 multi-granter capability** whose root is local (the local peer is
one of the three signers) and which carries two valid co-signatures MUST verify to
`VAllow`; the same capability with only ONE signature (below threshold) MUST
`VDeny`. Proves the accept path is real K-of-N, not a fail-open.

```ucm
scratch/main> builtins.mergeio
scratch/main> load src/Codec.u
scratch/main> add
scratch/main> load src/Protocol.u
scratch/main> add
scratch/main> load src/Ed25519.u
scratch/main> add
scratch/main> load src/Model.u
scratch/main> add
scratch/main> load src/Wire.u
scratch/main> add
scratch/main> load src/Identity.u
scratch/main> add
scratch/main> load src/SeedPolicy.u
scratch/main> add
scratch/main> load src/Store.u
scratch/main> add
scratch/main> load src/TypeDefs.u
scratch/main> add
scratch/main> load src/Capability.u
scratch/main> add
```
```unison
seedOf : Nat -> Bytes
seedOf b = Bytes.fromList (List.map (_ -> b) (rangeTo 0 32))

-- three distinct identities; id1 is the LOCAL peer (one of the signers).
msId1 : Identity
msId1 = identityOfSeed (seedOf 17)
msId2 : Identity
msId2 = identityOfSeed (seedOf 34)
msId3 : Identity
msId3 = identityOfSeed (seedOf 51)

msLocal : Text
msLocal = Identity.idPeerId msId1

msMultiGranter : Value
msMultiGranter =
  VMap [ (VText "signers", VArray
           [ VBytes (Identity.idHash msId1)
           , VBytes (Identity.idHash msId2)
           , VBytes (Identity.idHash msId3) ])
       , (VText "threshold", VUInt 2) ]

-- a 2-of-3 capability: granter is the multi-granter, grantee is the local peer.
msCapData : Value
msCapData =
  VMap [ (VText "granter", msMultiGranter)
       , (VText "grantee", VBytes (Identity.idHash msId1))
       , (VText "grants", VArray [])
       , (VText "created_at", VUInt 1000) ]

msCap : Entity
msCap = makeEntity "system/capability/token" msCapData

msSig1 : Entity
msSig1 = signEntity msId1 msCap
msSig2 : Entity
msSig2 = signEntity msId2 msCap

msPeers : [(Bytes, Entity)]
msPeers =
  [ (Identity.idHash msId1, Identity.idPeerEntity msId1)
  , (Identity.idHash msId2, Identity.idPeerEntity msId2)
  , (Identity.idHash msId3, Identity.idPeerEntity msId3)
  , (Entity.ehash msCap, msCap) ]

-- ACCEPT: two valid co-signatures (2 of 3) → VAllow.
msIncludedAccept : [(Bytes, Entity)]
msIncludedAccept =
  msPeers List.++ [ (Entity.ehash msSig1, msSig1), (Entity.ehash msSig2, msSig2) ]

msResolveAccept : Bytes -> Optional Entity
msResolveAccept h = alLookupB h msIncludedAccept

-- REJECT control: only ONE signature (below threshold 2) → VDeny.
msIncludedReject : [(Bytes, Entity)]
msIncludedReject = msPeers List.++ [ (Entity.ehash msSig1, msSig1) ]

msResolveReject : Bytes -> Optional Entity
msResolveReject h = alLookupB h msIncludedReject

verdictText : (Verdict, Boolean) -> Text
verdictText r = match r with
  (VAllow, _) -> "VAllow"
  (VDeny, _) -> "VDeny"

-- expected: "VAllow"
multisig2of3Accept : Text
multisig2of3Accept =
  verdictText (verifyCapabilityChain msLocal 1000 msResolveAccept msIncludedAccept msCap)

-- expected: "VDeny"
multisig1of3Reject : Text
multisig1of3Reject =
  verdictText (verifyCapabilityChain msLocal 1000 msResolveReject msIncludedReject msCap)

-- the PASS/FAIL line the golden asserts on
multisigUnitResult : Text
multisigUnitResult =
  ok = (multisig2of3Accept == "VAllow") && (multisig1of3Reject == "VDeny")
  detail = "(2of3=" Text.++ multisig2of3Accept Text.++ ", 1of3=" Text.++ multisig1of3Reject Text.++ ")"
  if ok then "MULTISIG-ACCEPT-UNIT PASS " Text.++ detail
  else "MULTISIG-ACCEPT-UNIT FAIL " Text.++ detail

-- compiled to bytecode + run.compiled (the pure-Unison Ed25519 keygen ×3 is far
-- too slow INTERPRETED; the compiled runtime evaluates it in a fraction of a second).
multisigUnitMain : '{IO} ()
multisigUnitMain _ =
  h = io2.IO.stdHandle io2.StdHandle.StdOut
  _ = io2.IO.setBuffering.impl h io2.BufferMode.LineBuffering
  _ = io2.IO.putBytes.impl h (Text.toUtf8 (multisigUnitResult Text.++ "\n"))
  ()
```
```ucm
scratch/main> add
scratch/main> compile multisigUnitMain output/multisig-test
```
