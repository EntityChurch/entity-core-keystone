# entity-core-protocol-unison — S3 smoke runner

Boots two peers in-process over real loopback TCP and drives the lifecycle
scenario (handshake both ways, 401/404 auth-ordering, authority-gated get, cap
request, request\_id demux, register, dispatch-outbound reentry). Green = the peer
talks the wire correctly. Runs `--network=none` (builtins-only + loopback).

``` ucm
scratch/main> builtins.mergeio

  Done.

scratch/main> load src/Codec.u

  Loading changes detected in src/Codec.u.

  + type CodecError
  + type Value

  + atOr0               : [Nat] -> Nat -> Nat
  + bappend             : Bytes -> Bytes -> Bytes
  + buildHead           : Nat -> Nat -> Bytes
  + buildMap            : [(Value, Value)] -> Bytes
  + byteAt              : Bytes -> Nat -> Nat
  + bytesToText         : Bytes -> Text
  + concatBytes         : [Bytes] -> Bytes
  + decode              : Bytes -> Either CodecError Value
  + decodeArray         : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + decodeItem          : Bytes
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + decodeMap           : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + decodeSimpleOrFloat : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + doubleToF32Cand     : Nat -> Nat
  + doubleToHalfCand    : Nat -> Nat
  + encode              : Value -> Bytes
  + encodeFloatBits     : Nat -> Bytes
  + f32ToF64bits        : Nat -> Nat
  + foldl               : (b ->{g} a ->{g} b)
                          -> b
                          -> [a]
                          ->{g} b
  + fst2                : (a, b) -> a
  + halfToF64bits       : Nat -> Nat
  + highBit             : Nat -> Nat -> Nat
  + insertBy            : (a ->{g1} a ->{g} Boolean)
                          -> a
                          -> [a]
                          ->{g, g1} [a]
  + keyLt               : Bytes -> Bytes -> Boolean
  + lexLt               : Bytes
                          -> Bytes
                          -> Nat
                          -> Nat
                          -> Boolean
  + mapRight            : Either e a
                          -> (a ->{g} b)
                          ->{g} Either e b
  + maxN                : Nat -> Nat -> Nat
  + orderCheck          : Optional Bytes
                          -> Bytes
                          -> Either CodecError ()
  + rangeTo             : Nat -> Nat -> [Nat]
  + readArg             : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Nat, Nat)
  + readBE              : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Nat, Nat)
  + snd2                : (a, b) -> b
  + sortBy              : (a ->{g1} a ->{g} Boolean)
                          -> [a]
                          ->{g, g1} [a]
  + takeBytes           : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + varintDecode        : Bytes
                          -> Nat
                          -> Either CodecError (Nat, Nat)
  + varintEncode        : Nat -> Bytes

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Protocol.u

  Loading changes detected in src/Protocol.u.

  + b58AddByte        : [Nat] -> Nat -> [Nat]
  + base58Alphabet    : [Nat]
  + base58Encode      : Bytes -> Text
  + canonicalHashType : Nat -> Nat
  + contentHash       : Nat -> Text -> Value -> Bytes
  + countLeadingZeros : [Nat] -> Nat
  + derivePeerId      : Nat -> Bytes -> Text
  + ecfOfEntity       : Text -> Value -> Bytes
  + entityContentHash : Text -> Value -> Bytes
  + formatPeerId      : Nat -> Nat -> Bytes -> Text
  + reverseL          : [a] -> [a]

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Ed25519.u

  Loading changes detected in src/Ed25519.u.

  + type Pt

  + addLimbs      : [Nat] -> [Nat] -> [Nat]
  + addPt         : Pt -> Pt -> Pt
  + base16limb    : Nat
  + basePt        : Pt
  + bitAtLimbs    : [Nat] -> Nat -> Nat
  + bitOfBytes    : Bytes -> Nat -> Nat
  + bxConst       : [Nat]
  + byConst       : [Nat]
  + clearLow3     : Nat -> Nat
  + compress      : Pt -> Bytes
  + csubP         : [Nat] -> [Nat]
  + d2Const       : [Nat]
  + dConst        : [Nat]
  + ed25519Pub    : Bytes -> Bytes
  + ed25519Sign   : Bytes -> Bytes -> Bytes
  + ed25519Verify : Bytes -> Bytes -> Bytes -> Boolean
  + fadd          : [Nat] -> [Nat] -> [Nat]
  + feByteAt      : [Nat] -> Nat -> Nat
  + feOne         : [Nat]
  + feToBytesLE   : [Nat] -> Bytes
  + feZero        : [Nat]
  + finv          : [Nat] -> [Nat]
  + fmul          : [Nat] -> [Nat] -> [Nat]
  + fold38        : [Nat] -> [Nat]
  + fsqr          : [Nat] -> [Nat]
  + fsub          : [Nat] -> [Nat] -> [Nat]
  + geLimb        : [Nat] -> [Nat] -> Boolean
  + idPt          : Pt
  + mulCols       : [Nat] -> [Nat] -> [Nat]
  + normalize     : [Nat] -> [Nat]
  + pad16         : [Nat] -> [Nat]
  + pConst        : [Nat]
  + pExp          : [Nat]
  + Pt.pt         : Pt -> [Nat]
  + Pt.pt.modify  : ([Nat] ->{g} [Nat]) -> Pt ->{g} Pt
  + Pt.pt.set     : [Nat] -> Pt -> Pt
  + Pt.px         : Pt -> [Nat]
  + Pt.px.modify  : ([Nat] ->{g} [Nat]) -> Pt ->{g} Pt
  + Pt.px.set     : [Nat] -> Pt -> Pt
  + Pt.py         : Pt -> [Nat]
  + Pt.py.modify  : ([Nat] ->{g} [Nat]) -> Pt ->{g} Pt
  + Pt.py.set     : [Nat] -> Pt -> Pt
  + Pt.pz         : Pt -> [Nat]
  + Pt.pz.modify  : ([Nat] ->{g} [Nat]) -> Pt ->{g} Pt
  + Pt.pz.set     : [Nat] -> Pt -> Pt
  + reduceP       : [Nat] -> [Nat]
  + scaleLimbs    : Nat -> [Nat] -> [Nat]
  + setHigh       : Nat -> Nat
  + smul          : Bytes -> Pt
  + subLimbs      : [Nat] -> [Nat] -> [Nat]

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Model.u

  Loading changes detected in src/Model.u.

  + type Entity
  + type Envelope

  + alLookupB                 : Bytes
                                -> [(Bytes, a)]
                                -> Optional a
  + anyByte                   : Bytes -> Nat -> Boolean
  + base58CharsText           : Text
  + bytesField                : Entity -> Text -> Optional Bytes
  + Entity.edata              : Entity -> Value
  + Entity.edata.modify       : (Value ->{g} Value)
                                -> Entity
                                ->{g} Entity
  + Entity.edata.set          : Value -> Entity -> Entity
  + Entity.ehash              : Entity -> Bytes
  + Entity.ehash.modify       : (Bytes ->{g} Bytes)
                                -> Entity
                                ->{g} Entity
  + Entity.ehash.set          : Bytes -> Entity -> Entity
  + Entity.etype              : Entity -> Text
  + Entity.etype.modify       : (Text ->{g} Text)
                                -> Entity
                                ->{g} Entity
  + Entity.etype.set          : Text -> Entity -> Entity
  + entityField               : Entity
                                -> Text
                                -> Optional Entity
  + entityOfCbor              : Value
                                -> Either CodecError Entity
  + entityToCbor              : Entity -> Value
  + Envelope.eincluded        : Envelope -> [(Bytes, Entity)]
  + Envelope.eincluded.modify : ([(Bytes, Entity)]
                                 ->{g} [(Bytes, Entity)])
                                -> Envelope
                                ->{g} Envelope
  + Envelope.eincluded.set    : [(Bytes, Entity)]
                                -> Envelope
                                -> Envelope
  + Envelope.eroot            : Envelope -> Entity
  + Envelope.eroot.modify     : (Entity ->{g} Entity)
                                -> Envelope
                                ->{g} Envelope
  + Envelope.eroot.set        : Entity -> Envelope -> Envelope
  + envelopeOfCbor            : Value
                                -> Either CodecError Envelope
  + envelopeToCbor            : Envelope -> Value
  + field                     : Entity -> Text -> Optional Value
  + firstSegment              : Text -> Text
  + hexOf                     : Bytes -> Text
  + includedGet               : Envelope
                                -> Bytes
                                -> Optional Entity
  + isBase58Byte              : Nat -> Boolean
  + isPeerId                  : Text -> Boolean
  + joinSlash                 : [Text] -> Text
  + lookupKV                  : Text
                                -> [(Value, Value)]
                                -> Optional Value
  + makeEntity                : Text -> Value -> Entity
  + mapField                  : Value -> Text -> Optional Value
  + natField                  : Entity -> Text -> Optional Nat
  + optOr                     : Optional a -> a -> a
  + parseIncluded             : [(Value, Value)]
                                -> Either
                                  CodecError [(Bytes, Entity)]
  + splitSlash                : Text -> [Text]
  + textEndsWith              : Text -> Text -> Boolean
  + textField                 : Entity -> Text -> Optional Text
  + textStartsWith            : Text -> Text -> Boolean

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Wire.u

  Loading changes detected in src/Wire.u.

  + emptyParams      : Entity
  + envelopeOfFrame  : Bytes -> Either CodecError Envelope
  + errorResult      : Optional Text -> Text -> Entity
  + frameHeader      : Nat -> Bytes
  + frameOfEnvelope  : Envelope -> Bytes
  + makeExecute      : Text
                       -> Text
                       -> Text
                       -> Entity
                       -> Optional Value
                       -> Bytes
                       -> Bytes
                       -> Entity
  + makeResponse     : Text -> Nat -> Entity -> Entity
  + maxFrame         : Nat
  + parseFrameLength : Bytes -> Nat

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Identity.u

  Loading changes detected in src/Identity.u.

  + type Identity

  + ed25519VerifyRaw             : Bytes
                                   -> Bytes
                                   -> Bytes
                                   -> Boolean
  + Identity.idHash              : Identity -> Bytes
  + Identity.idHash.modify       : (Bytes ->{g} Bytes)
                                   -> Identity
                                   ->{g} Identity
  + Identity.idHash.set          : Bytes -> Identity -> Identity
  + Identity.idPeerEntity        : Identity -> Entity
  + Identity.idPeerEntity.modify : (Entity ->{g} Entity)
                                   -> Identity
                                   ->{g} Identity
  + Identity.idPeerEntity.set    : Entity
                                   -> Identity
                                   -> Identity
  + Identity.idPeerId            : Identity -> Text
  + Identity.idPeerId.modify     : (Text ->{g} Text)
                                   -> Identity
                                   ->{g} Identity
  + Identity.idPeerId.set        : Text -> Identity -> Identity
  + Identity.idPublicKey         : Identity -> Bytes
  + Identity.idPublicKey.modify  : (Bytes ->{g} Bytes)
                                   -> Identity
                                   ->{g} Identity
  + Identity.idPublicKey.set     : Bytes -> Identity -> Identity
  + Identity.idSeed              : Identity -> Bytes
  + Identity.idSeed.modify       : (Bytes ->{g} Bytes)
                                   -> Identity
                                   ->{g} Identity
  + Identity.idSeed.set          : Bytes -> Identity -> Identity
  + identityOfSeed               : Bytes -> Identity
  + peerEntityOfPubkey           : Bytes -> Entity
  + peerIdOfPubkey               : Bytes -> Text
  + signEntity                   : Identity -> Entity -> Entity
  + verifySignature              : Entity -> Entity -> Boolean

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/SeedPolicy.u

  Loading changes detected in src/SeedPolicy.u.

  + type SeedPolicy

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Store.u

  Loading changes detected in src/Store.u.

  + type Store
  + type StoreState

  + alDelete                    : k -> [(k, v)] -> [(k, v)]
  + alGet                       : k -> [(k, v)] -> Optional v
  + alInsert                    : k -> v -> [(k, v)] -> [(k, v)]
  + alMember                    : k -> [(k, v)] -> Boolean
  + bind                        : Store
                                  -> Text
                                  -> Entity
                                  ->{IO} ()
  + bindF                       : Text
                                  -> Entity
                                  -> StoreState
                                  -> (StoreState, ())
  + getAt                       : Store
                                  -> Text
                                  ->{IO} Optional Entity
  + getByHash                   : Store
                                  -> Bytes
                                  ->{IO} Optional Entity
  + hashAt                      : Store
                                  -> Text
                                  ->{IO} Optional Bytes
  + listing                     : Store
                                  -> Text
                                  ->{IO} [( Text,
                                    Optional Bytes,
                                    Boolean)]
  + mergeSeg                    : [( Text,
                                    (Optional Bytes, Boolean))]
                                  -> Text
                                  -> Optional Bytes
                                  -> Boolean
                                  -> [( Text,
                                    (Optional Bytes, Boolean))]
  + newStore                    : '{IO} Store
  + peekStore                   : Store ->{IO} StoreState
  + putEntity                   : Store -> Entity ->{IO} ()
  + putEntityF                  : Entity
                                  -> StoreState
                                  -> (StoreState, ())
  + putMVar                     : MVar a -> a ->{IO} ()
  + readMVar                    : MVar a ->{IO} a
  + snapshotContent             : Store
                                  ->{IO} Bytes
                                  -> Optional Entity
  + snapshotTreeMember          : Store ->{IO} Text -> Boolean
  + Store.stCell                : Store -> MVar StoreState
  + Store.stCell.modify         : (MVar StoreState
                                   ->{g} MVar StoreState)
                                  -> Store
                                  ->{g} Store
  + Store.stCell.set            : MVar StoreState
                                  -> Store
                                  -> Store
  + StoreState.ssContent        : StoreState
                                  -> [(Bytes, Entity)]
  + StoreState.ssContent.modify : ([(Bytes, Entity)]
                                   ->{g} [(Bytes, Entity)])
                                  -> StoreState
                                  ->{g} StoreState
  + StoreState.ssContent.set    : [(Bytes, Entity)]
                                  -> StoreState
                                  -> StoreState
  + StoreState.ssTree           : StoreState -> [(Text, Bytes)]
  + StoreState.ssTree.modify    : ([(Text, Bytes)]
                                   ->{g} [(Text, Bytes)])
                                  -> StoreState
                                  ->{g} StoreState
  + StoreState.ssTree.set       : [(Text, Bytes)]
                                  -> StoreState
                                  -> StoreState
  + takeMVar                    : MVar a ->{IO} a
  + unbind                      : Store -> Text ->{IO} ()
  + unbindF                     : Text
                                  -> StoreState
                                  -> (StoreState, ())
  + withStore                   : Store
                                  -> (StoreState
                                   -> (StoreState, a))
                                  ->{IO} a

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/TypeDefs.u

  Loading changes detected in src/TypeDefs.u.

  + coreTypeNames : [Text]
  + publish       : Store -> Text ->{IO} ()
  + publishAll    : Store -> Text -> [Text] ->{IO} ()
  + typeEntity    : Text -> Entity

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Capability.u

  Loading changes detected in src/Capability.u.

  + type Grant
  + type ReqVerdict
  + type Scope
  + type Verdict

  + allL                      : (a ->{g} Boolean)
                                -> [a]
                                ->{g} Boolean
  + anyL                      : (a ->{g} Boolean)
                                -> [a]
                                ->{g} Boolean
  + canonicalize              : Text -> Text -> Text
  + chainExceedsDepth         : (Bytes ->{g} Optional Entity)
                                -> Entity
                                ->{g} Boolean
  + checkPermission           : Text
                                -> Text
                                -> Entity
                                -> Entity
                                -> Text
                                -> Verdict
  + checkResourceScope        : Text
                                -> Text
                                -> Value
                                -> Scope
                                -> Boolean
  + childParentOk             : Text
                                -> (Bytes ->{g} Optional Entity)
                                -> Entity
                                -> Entity
                                ->{g} Boolean
  + collectChain              : (Bytes ->{g} Optional Entity)
                                -> Entity
                                ->{g} Optional [Entity]
  + collectText               : [Text] -> Value -> [Text]
  + coveredByFrame            : Text
                                -> [Text]
                                -> Text
                                -> Boolean
  + coveredByLocal            : Text
                                -> Text
                                -> [Text]
                                -> Boolean
  + dropRight                 : Nat -> Text -> Text
  + emptyScope                : Scope
  + exclCovered               : Text
                                -> Text
                                -> Scope
                                -> Text
                                -> Boolean
  + extractPeer               : Text -> Text -> Text
  + findSignature             : Bytes
                                -> [(Bytes, Entity)]
                                -> Optional Entity
  + Grant.grHandlers          : Grant -> Scope
  + Grant.grHandlers.modify   : (Scope ->{g} Scope)
                                -> Grant
                                ->{g} Grant
  + Grant.grHandlers.set      : Scope -> Grant -> Grant
  + Grant.grOperations        : Grant -> Scope
  + Grant.grOperations.modify : (Scope ->{g} Scope)
                                -> Grant
                                ->{g} Grant
  + Grant.grOperations.set    : Scope -> Grant -> Grant
  + Grant.grPeers             : Grant -> Optional Scope
  + Grant.grPeers.modify      : (Optional Scope
                                 ->{g} Optional Scope)
                                -> Grant
                                ->{g} Grant
  + Grant.grPeers.set         : Optional Scope -> Grant -> Grant
  + Grant.grResources         : Grant -> Scope
  + Grant.grResources.modify  : (Scope ->{g} Scope)
                                -> Grant
                                ->{g} Grant
  + Grant.grResources.set     : Scope -> Grant -> Grant
  + grantAllows               : Text
                                -> Text
                                -> Text
                                -> Text
                                -> Text
                                -> Optional Value
                                -> Grant
                                -> Boolean
  + granteeGranterMatch       : Entity -> Entity -> Boolean
  + granteeUnresolvable       : (Bytes ->{g} Optional Entity)
                                -> Entity
                                ->{g} Boolean
  + grantsOfToken             : Entity -> [Grant]
  + grantSubset               : Text
                                -> Text
                                -> Text
                                -> Grant
                                -> Grant
                                -> Boolean
  + headOpt                   : [a] -> Optional a
  + inclCovered               : Text
                                -> Text
                                -> Scope
                                -> Text
                                -> Boolean
  + indexOfSlash              : Text -> Optional Nat
  + isAttenuated              : Text
                                -> Text
                                -> Text
                                -> Entity
                                -> Entity
                                -> Boolean
  + isRevoked                 : (Bytes ->{g1} Boolean)
                                -> (Bytes ->{g} Optional Entity)
                                -> Entity
                                ->{g, g1} Boolean
  + lastL                     : [a] -> a -> a
  + linkGranterPeer           : (Bytes ->{g} Optional Entity)
                                -> Text
                                -> Entity
                                ->{g} Optional Text
  + linkSigOk                 : (Bytes ->{g} Optional Entity)
                                -> [(Bytes, Entity)]
                                -> Entity
                                ->{g} Boolean
  + matchesPattern            : Text -> Text -> Boolean
  + matchesScope              : Text -> Text -> Scope -> Boolean
  + normalizeUri              : Text -> Text
  + notBeforeOk               : Nat -> Entity -> Boolean
  + notExpiredOk              : Nat -> Entity -> Boolean
  + optIncludedResolve        : Envelope
                                -> Optional Bytes
                                -> Optional Entity
  + optScopeAt                : Value -> Text -> Optional Scope
  + parseGrant                : Value -> Grant
  + parseScope                : Value -> Scope
  + resolveGranterPeerId      : (Bytes ->{g} Optional Entity)
                                -> Entity
                                ->{g} Optional Text
  + resTargetOk               : Text
                                -> Text
                                -> Scope
                                -> [Text]
                                -> Text
                                -> Boolean
  + rootAtLocal               : Text
                                -> (Bytes ->{g} Optional Entity)
                                -> Entity
                                ->{g} Boolean
  + Scope.scExcl              : Scope -> [Text]
  + Scope.scExcl.modify       : ([Text] ->{g} [Text])
                                -> Scope
                                ->{g} Scope
  + Scope.scExcl.set          : [Text] -> Scope -> Scope
  + Scope.scIncl              : Scope -> [Text]
  + Scope.scIncl.modify       : ([Text] ->{g} [Text])
                                -> Scope
                                ->{g} Scope
  + Scope.scIncl.set          : [Text] -> Scope -> Scope
  + scopeAt                   : Value -> Text -> Scope
  + scopeSubset               : Text
                                -> Text
                                -> Scope
                                -> Scope
                                -> Boolean
  + sigSignerOk               : Entity -> Bytes -> Boolean
  + sigTargets                : Entity -> Bytes -> Boolean
  + stepChain                 : Text
                                -> Nat
                                -> (Bytes ->{g} Optional Entity)
                                -> [(Bytes, Entity)]
                                -> [Entity]
                                ->{g} [(Boolean, Boolean)]
  + stepLink                  : Text
                                -> Nat
                                -> (Bytes ->{g} Optional Entity)
                                -> [(Bytes, Entity)]
                                -> Entity
                                -> Optional Entity
                                ->{g} (Boolean, Boolean)
  + temporalOk                : Nat -> Entity -> Boolean
  + textList                  : Value -> [Text]
  + textListAt                : Value -> Text -> [Text]
  + unresolved                : (Bytes ->{g} Optional Entity)
                                -> Bytes
                                ->{g} Boolean
  + verifyCapabilityChain     : Text
                                -> Nat
                                -> (Bytes ->{g} Optional Entity)
                                -> [(Bytes, Entity)]
                                -> Entity
                                ->{g} (Verdict, Boolean)
  + verifyRequest             : Text
                                -> Nat
                                -> (Bytes ->{g1} Boolean)
                                -> (Bytes ->{g} Optional Entity)
                                -> Envelope
                                ->{g, g1} ReqVerdict

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Peer.u

  Loading changes detected in src/Peer.u.

  + type Conn
  + type Outcome
  + type Peer

  + absPath                   : Peer -> Text -> Text
  + authOp                    : Peer
                                -> Conn
                                -> Entity
                                -> [(Bytes, Entity)]
                                -> Boolean
                                ->{IO} Outcome
  + authSucceed               : Peer
                                -> Conn
                                -> Entity
                                -> Bytes
                                -> Optional Text
                                ->{IO} Outcome
  + authVerify                : Peer
                                -> Conn
                                -> [(Bytes, Entity)]
                                -> Entity
                                -> Bytes
                                -> Optional Text
                                ->{IO} Outcome
  + authWithParams            : Peer
                                -> Conn
                                -> [(Bytes, Entity)]
                                -> Bytes
                                -> Entity
                                ->{IO} Outcome
  + badKeyType                : Entity -> Boolean
  + bindSigPointer            : Peer
                                -> Entity
                                -> Entity
                                ->{IO} ()
  + buildListing              : Peer -> Text ->{IO} Outcome
  + bumpCounter               : Conn ->{IO} Nat
  + capabilityHandler         : Peer
                                -> Entity
                                -> Optional Entity
                                ->{IO} Outcome
  + capConfigure              : Peer
                                -> Optional Entity
                                ->{IO} Outcome
  + capRevoke                 : Peer
                                -> Optional Entity
                                ->{IO} Outcome
  + checkBounded              : Peer
                                -> Optional Entity
                                -> [Value]
                                -> Boolean
  + Conn.cEstablished         : Conn -> Ref {IO} Boolean
  + Conn.cEstablished.modify  : (Ref {IO} Boolean
                                 ->{g} Ref {IO} Boolean)
                                -> Conn
                                ->{g} Conn
  + Conn.cEstablished.set     : Ref {IO} Boolean -> Conn -> Conn
  + Conn.cHelloPeer           : Conn -> Ref {IO} (Optional Text)
  + Conn.cHelloPeer.modify    : (Ref {IO} (Optional Text)
                                 ->{g} Ref {IO} (Optional Text))
                                -> Conn
                                ->{g} Conn
  + Conn.cHelloPeer.set       : Ref {IO} (Optional Text)
                                -> Conn
                                -> Conn
  + Conn.cNonce               : Conn
                                -> Ref {IO} (Optional Bytes)
  + Conn.cNonce.modify        : (Ref {IO} (Optional Bytes)
                                 ->{g} Ref {IO} (Optional Bytes))
                                -> Conn
                                ->{g} Conn
  + Conn.cNonce.set           : Ref {IO} (Optional Bytes)
                                -> Conn
                                -> Conn
  + Conn.cOutbound            : Conn
                                -> Ref
                                  {IO}
                                  (Optional
                                    (Envelope
                                     ->{IO} Optional Envelope))
  + Conn.cOutbound.modify     : (Ref
                                   {IO}
                                   (Optional
                                     (Envelope
                                      ->{IO} Optional Envelope))
                                 ->{g} Ref
                                   {IO}
                                   (Optional
                                     (Envelope
                                      ->{IO} Optional Envelope)))
                                -> Conn
                                ->{g} Conn
  + Conn.cOutbound.set        : Ref
                                  {IO}
                                  (Optional
                                    (Envelope
                                     ->{IO} Optional Envelope))
                                -> Conn
                                -> Conn
  + Conn.cOutCounter          : Conn -> MVar Nat
  + Conn.cOutCounter.modify   : (MVar Nat ->{g} MVar Nat)
                                -> Conn
                                ->{g} Conn
  + Conn.cOutCounter.set      : MVar Nat -> Conn -> Conn
  + connectHandler            : Peer
                                -> Conn
                                -> Entity
                                -> [(Bytes, Entity)]
                                ->{IO} Outcome
  + createPeer                : Bytes
                                -> SeedPolicy
                                -> Boolean
                                ->{IO} Peer
  + deriveSeedGrants          : Peer
                                -> Entity
                                -> Text
                                ->{IO} [Value]
  + discoveryFloor            : [Value]
  + dispatch                  : Peer
                                -> Conn
                                -> Envelope
                                ->{IO} Optional Envelope
  + dispatchAllowed           : Peer
                                -> Conn
                                -> Envelope
                                -> Entity
                                -> Text
                                -> (Bytes -> Optional Entity)
                                ->{IO} Outcome
  + dispatchOutboundHandler   : Peer
                                -> Conn
                                -> Entity
                                ->{IO} Outcome
  + dispatchOutcome           : Peer
                                -> Conn
                                -> Envelope
                                -> Entity
                                -> Text
                                ->{IO} Outcome
  + dispatchWithCap           : Peer
                                -> Conn
                                -> Envelope
                                -> Entity
                                -> (Bytes -> Optional Entity)
                                -> Text
                                -> Entity
                                ->{IO} Outcome
  + doDispatchOutbound        : Peer
                                -> Conn
                                -> Entity
                                ->{IO} Outcome
  + doRegister                : Peer
                                -> Text
                                -> Entity
                                ->{IO} Outcome
  + echoHandler               : Peer -> Entity ->{IO} Outcome
  + errMsg                    : Nat -> Text -> Text -> Outcome
  + errOc                     : Nat -> Text -> Outcome
  + firstStored               : Store
                                -> [Text]
                                ->{IO} Optional Entity
  + firstTarget               : Value -> Optional Text
  + grantBoundedBy            : Peer
                                -> [Grant]
                                -> Grant
                                -> Boolean
  + grantsArrayOf             : Entity -> [Value]
  + grantV                    : [Text]
                                -> [Text]
                                -> [Text]
                                -> Optional [Text]
                                -> Value
  + handlersHandler           : Peer -> Entity ->{IO} Outcome
  + helloOp                   : Peer
                                -> Conn
                                -> Entity
                                -> Boolean
                                ->{IO} Outcome
  + helloReply                : Peer
                                -> Conn
                                -> Optional Entity
                                ->{IO} Outcome
  + ingestList                : Peer
                                -> Envelope
                                -> Bytes
                                -> [(Bytes, Entity)]
                                ->{IO} ()
  + ingestOne                 : Peer
                                -> Envelope
                                -> Bytes
                                -> Entity
                                ->{IO} ()
  + ingestSig                 : Peer
                                -> Envelope
                                -> Entity
                                ->{IO} ()
  + ingestSignatures          : Peer -> Envelope ->{IO} ()
  + installBootstrapHandler   : Peer -> Text -> Text ->{IO} ()
  + installCoreHandlers       : Peer ->{IO} ()
  + installSeedPolicy         : Peer ->{IO} ()
  + installValidateHandlers   : Peer -> Boolean ->{IO} ()
  + internalErrorResponse     : Envelope -> Optional Envelope
  + listingEntryKV            : (Text, Optional Bytes, Boolean)
                                -> (Value, Value)
  + manifestName              : Value -> Text -> Text
  + mintBounded               : Peer
                                -> Optional Entity
                                -> [Value]
                                -> Bytes
                                -> Optional Bytes
                                ->{IO} Outcome
  + mintInitial               : Peer
                                -> Conn
                                -> Bytes
                                -> Optional Text
                                ->{IO} Outcome
  + mintToken                 : Peer
                                -> Bytes
                                -> Optional Bytes
                                -> [Value]
                                ->{IO} (Entity, Entity)
  + mkResolve                 : (Bytes ->{g} Optional Entity)
                                -> [(Bytes, Entity)]
                                -> Bytes
                                ->{g} Optional Entity
  + mkRevoked                 : (Text ->{g} Boolean)
                                -> Text
                                -> Bytes
                                ->{g} Boolean
  + newConn                   : '{IO} Conn
  + nowMicros                 : '{IO} Nat
  + nowMs                     : '{IO} Nat
  + okI                       : [(Bytes, Entity)]
                                -> Entity
                                -> Outcome
  + okOc                      : Entity -> Outcome
  + openGrantsScope           : [Value]
  + outboundDispatch          : Peer
                                -> Conn
                                -> Text
                                -> Text
                                -> Entity
                                -> Optional Value
                                -> Entity
                                -> Entity
                                -> Entity
                                ->{IO} Optional Envelope
  + Outcome.ocIncluded        : Outcome -> [(Bytes, Entity)]
  + Outcome.ocIncluded.modify : ([(Bytes, Entity)]
                                 ->{g} [(Bytes, Entity)])
                                -> Outcome
                                ->{g} Outcome
  + Outcome.ocIncluded.set    : [(Bytes, Entity)]
                                -> Outcome
                                -> Outcome
  + Outcome.ocResult          : Outcome -> Entity
  + Outcome.ocResult.modify   : (Entity ->{g} Entity)
                                -> Outcome
                                ->{g} Outcome
  + Outcome.ocResult.set      : Entity -> Outcome -> Outcome
  + Outcome.ocStatus          : Outcome -> Nat
  + Outcome.ocStatus.modify   : (Nat ->{g} Nat)
                                -> Outcome
                                ->{g} Outcome
  + Outcome.ocStatus.set      : Nat -> Outcome -> Outcome
  + ownerGrants               : Peer -> [Value]
  + paramEntityField          : Optional Entity
                                -> Text
                                -> Optional Entity
  + paramTextField            : Optional Entity
                                -> Text
                                -> Optional Text
  + Peer.pConformance         : Peer -> Boolean
  + Peer.pConformance.modify  : (Boolean ->{g} Boolean)
                                -> Peer
                                ->{g} Peer
  + Peer.pConformance.set     : Boolean -> Peer -> Peer
  + Peer.pIdentity            : Peer -> Identity
  + Peer.pIdentity.modify     : (Identity ->{g} Identity)
                                -> Peer
                                ->{g} Peer
  + Peer.pIdentity.set        : Identity -> Peer -> Peer
  + Peer.pLocal               : Peer -> Text
  + Peer.pLocal.modify        : (Text ->{g} Text)
                                -> Peer
                                ->{g} Peer
  + Peer.pLocal.set           : Text -> Peer -> Peer
  + Peer.pSeedPolicy          : Peer -> SeedPolicy
  + Peer.pSeedPolicy.modify   : (SeedPolicy ->{g} SeedPolicy)
                                -> Peer
                                ->{g} Peer
  + Peer.pSeedPolicy.set      : SeedPolicy -> Peer -> Peer
  + Peer.pStore               : Peer -> Store
  + Peer.pStore.modify        : (Store ->{g} Store)
                                -> Peer
                                ->{g} Peer
  + Peer.pStore.set           : Store -> Peer -> Peer
  + popOk                     : [(Bytes, Entity)]
                                -> Entity
                                -> Bytes
                                -> Boolean
  + randomBytes               : Nat ->{IO} Bytes
  + registerHandler           : Peer -> Entity ->{IO} Outcome
  + registerPatternOf         : Entity -> Optional Text
  + registerScope             : Entity -> Value -> [Value]
  + reqGrantsOf               : Optional Entity -> [Value]
  + resolveHandler            : Peer
                                -> Text
                                ->{IO} Optional Text
  + resourceTarget            : Entity -> Optional Text
  + routeHandler              : Peer
                                -> Conn
                                -> Entity
                                -> Entity
                                -> Text
                                ->{IO} Outcome
  + scopeV                    : [Text] -> [Text] -> Value
  + seedEntryGrants           : Entity -> [Value]
  + strArrayHas               : Optional Entity
                                -> Text
                                -> Text
                                -> Boolean
  + stripLocal                : Peer -> Text -> Text
  + textArr                   : [Text] -> Value
  + treeGet                   : Peer
                                -> Optional Text
                                ->{IO} Outcome
  + treeGetOne                : Peer -> Text ->{IO} Outcome
  + treeHandler               : Peer -> Entity ->{IO} Outcome
  + treePut                   : Peer
                                -> Entity
                                -> Optional Text
                                ->{IO} Outcome
  + typesHandler              : Peer -> Entity ->{IO} Outcome
  + unregisterHandler         : Peer -> Entity ->{IO} Outcome
  + wrapRelay                 : Envelope -> Outcome

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Transport.u

  Loading changes detected in src/Transport.u.

  + type ConnIO

  + acceptLoop                : Peer -> Socket ->{IO} ()
  + clientConnect             : Text -> Nat ->{IO} Socket
  + closeConnIO               : ConnIO ->{IO} ()
  + ConnIO.ioClosed           : ConnIO -> Ref {IO} Boolean
  + ConnIO.ioClosed.modify    : (Ref {IO} Boolean
                                 ->{g} Ref {IO} Boolean)
                                -> ConnIO
                                ->{g} ConnIO
  + ConnIO.ioClosed.set       : Ref {IO} Boolean
                                -> ConnIO
                                -> ConnIO
  + ConnIO.ioPending          : ConnIO
                                -> MVar
                                  [( Text,
                                    Promise (Optional Envelope))]
  + ConnIO.ioPending.modify   : (MVar
                                   [( Text,
                                     Promise (Optional Envelope))]
                                 ->{g} MVar
                                   [( Text,
                                     Promise (Optional Envelope))])
                                -> ConnIO
                                ->{g} ConnIO
  + ConnIO.ioPending.set      : MVar
                                  [( Text,
                                    Promise (Optional Envelope))]
                                -> ConnIO
                                -> ConnIO
  + ConnIO.ioSock             : ConnIO -> Socket
  + ConnIO.ioSock.modify      : (Socket ->{g} Socket)
                                -> ConnIO
                                ->{g} ConnIO
  + ConnIO.ioSock.set         : Socket -> ConnIO -> ConnIO
  + ConnIO.ioWriteLock        : ConnIO -> MVar ()
  + ConnIO.ioWriteLock.modify : (MVar () ->{g} MVar ())
                                -> ConnIO
                                ->{g} ConnIO
  + ConnIO.ioWriteLock.set    : MVar () -> ConnIO -> ConnIO
  + fillNone                  : [( Text,
                                  Promise (Optional Envelope))]
                                ->{IO} ()
  + listenOn                  : Nat ->{IO} (Socket, Nat)
  + makeConnIO                : Socket ->{IO} ConnIO
  + onExecute                 : Peer
                                -> Conn
                                -> ConnIO
                                -> Envelope
                                ->{IO} ()
  + outbound                  : ConnIO
                                -> Envelope
                                ->{IO} Optional Envelope
  + promiseWrite              : Promise a -> a ->{IO} ()
  + readFrame                 : Socket ->{IO} Optional Bytes
  + readLoop                  : Peer -> Conn -> ConnIO ->{IO} ()
  + recvExact                 : Socket
                                -> Nat
                                ->{IO} Optional Bytes
  + registerPending           : ConnIO
                                -> Text
                                -> Promise (Optional Envelope)
                                ->{IO} ()
  + removePending             : ConnIO -> Text ->{IO} ()
  + routeOrDispatch           : Peer
                                -> Conn
                                -> ConnIO
                                -> Envelope
                                ->{IO} ()
  + routeResponse             : ConnIO -> Envelope ->{IO} ()
  + runReader                 : Peer -> Conn -> ConnIO ->{IO} ()
  + runWithConn               : Peer
                                -> Socket
                                ->{IO} (Conn, ConnIO)
  + sendOver                  : ConnIO
                                -> Envelope
                                ->{IO} Optional Envelope
  + serveConnection           : Peer -> Socket ->{IO} ()
  + tryCatch                  : '{IO} a ->{IO} Either Failure a
  + unwrapF                   : Either Failure a -> a
  + writeFramed               : ConnIO -> Envelope ->{IO} ()

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Smoke.u

  Loading changes detected in src/Smoke.u.

  + type Client

  + allEq200                : [Nat] -> Boolean
  + capHashOf               : Optional Entity -> Bytes
  + capReqGrants            : Value
  + captureCap              : Client
                              -> Optional Envelope
                              ->{IO} ()
  + Client.clCap            : Client
                              -> Ref {IO} (Optional Entity)
  + Client.clCap.modify     : (Ref {IO} (Optional Entity)
                               ->{g} Ref {IO} (Optional Entity))
                              -> Client
                              ->{g} Client
  + Client.clCap.set        : Ref {IO} (Optional Entity)
                              -> Client
                              -> Client
  + Client.clCapSig         : Client
                              -> Ref {IO} (Optional Entity)
  + Client.clCapSig.modify  : (Ref {IO} (Optional Entity)
                               ->{g} Ref {IO} (Optional Entity))
                              -> Client
                              ->{g} Client
  + Client.clCapSig.set     : Ref {IO} (Optional Entity)
                              -> Client
                              -> Client
  + Client.clCio            : Client -> ConnIO
  + Client.clCio.modify     : (ConnIO ->{g} ConnIO)
                              -> Client
                              ->{g} Client
  + Client.clCio.set        : ConnIO -> Client -> Client
  + Client.clCtr            : Client -> MVar Nat
  + Client.clCtr.modify     : (MVar Nat ->{g} MVar Nat)
                              -> Client
                              ->{g} Client
  + Client.clCtr.set        : MVar Nat -> Client -> Client
  + Client.clGranter        : Client
                              -> Ref {IO} (Optional Entity)
  + Client.clGranter.modify : (Ref {IO} (Optional Entity)
                               ->{g} Ref {IO} (Optional Entity))
                              -> Client
                              ->{g} Client
  + Client.clGranter.set    : Ref {IO} (Optional Entity)
                              -> Client
                              -> Client
  + Client.clIdent          : Client -> Identity
  + Client.clIdent.modify   : (Identity ->{g} Identity)
                              -> Client
                              ->{g} Client
  + Client.clIdent.set      : Identity -> Client -> Client
  + concurrentDemux         : Client
                              -> Nat
                              -> Entity
                              -> Value
                              ->{IO} Boolean
  + countTrue               : [(Text, Boolean)] -> Nat
  + echoPassthrough         : Optional Envelope
                              -> Optional Value
  + fails                   : [(Text, Boolean)] -> Text
  + firstOfType             : Text
                              -> [(Bytes, Entity)]
                              -> Optional Entity
  + fmtResults              : [(Text, Boolean)] -> Text
  + forkSenders             : Client
                              -> [Promise Nat]
                              -> Entity
                              -> Value
                              ->{IO} ()
  + handshake               : Client ->{IO} Boolean
  + makePromises            : Nat ->{IO} [Promise Nat]
  + nextReqId               : Client ->{IO} Text
  + nonceOf                 : Optional Envelope -> Bytes
  + optEntityOfValue        : Value -> Optional Entity
  + optIncl                 : Optional Entity
                              -> [(Bytes, Entity)]
  + readPromises            : [Promise Nat] ->{IO} [Nat]
  + reentryTest             : Client -> Identity ->{IO} Boolean
  + resultEntityOf          : Optional Envelope
                              -> Optional Entity
  + seed32                  : Nat -> Bytes
  + sendAndWrite            : Client
                              -> Promise Nat
                              -> Entity
                              -> Value
                              ->{IO} ()
  + sendAuthed              : Client
                              -> Text
                              -> Text
                              -> Entity
                              -> Optional Value
                              ->{IO} Optional Envelope
  + sendUnauthed            : Client
                              -> Text
                              -> Text
                              -> Entity
                              -> Optional Value
                              ->{IO} Optional Envelope
  + sigForToken             : Optional Entity
                              -> [(Bytes, Entity)]
                              -> Optional Entity
  + smokeMain               : '{IO} Text
  + statusOf                : Optional Envelope -> Nat
  + tokenFromResp           : Optional Envelope
                              -> [(Bytes, Entity)]
                              -> Optional Entity

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> run smokeMain

  "SMOKE 8/8"
```
