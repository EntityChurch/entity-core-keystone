⍝ entity-core-protocol-apl — src/peer.apl (peer assembly: L2 interaction + bootstrap + the
⍝ MUST system handlers + the §6.5 dispatch chain + §6.9/§6.9a seed policy + the ⎕FIO pump).
⍝
⍝ The pure protocol brain: dispatch is a function from an inbound envelope to an outbound
⍝ response envelope. A peer is a SINGLETON in this image's workspace globals — the profile
⍝ [async] "one image, one thread" model: one process is one peer, driven by a single ⎕FIO
⍝ select-pump (PeerServe). §4.8 store-safety is STRUCTURAL: one frame is dispatched to
⍝ completion before the next event is polled, so the store is never raced (N6 by
⍝ construction). Only EXECUTE / EXECUTE_RESPONSE are wire message types (§3.3); hello/
⍝ authenticate are OPERATIONS on system/protocol/connect (§4.1). request_id demux (§6.11,
⍝ N7) is in transport; the §6.13(b) handler-outbound reentry is a MANUAL pump on the same
⍝ loop (the correlation-map tax non-actor peers pay). The v7.75 floor is baked in: 413
⍝ before buffering (transport TrRxExtract + Send413), the 400 chain_depth_exceeded
⍝ structural pre-check (capability CapChainExceedsDepth) run BEFORE the per-link authz walk.
⍝ →-branch tradfns throughout (A-APL-012).

R_CONNECT←1 ⋄ R_TREE←2 ⋄ R_HANDLERS←3 ⋄ R_TYPE←4 ⋄ R_CAPABILITY←5 ⋄ R_ECHO←6 ⋄ R_DISPATCH←7

⍝ ═══════════ construction + bootstrap ═══════════
∇seed PeerCreate flags;openg;conf
 openg←1⊃flags ⋄ conf←2⊃flags
 gIdent←IdOfSeed seed
 StoreReset ⋄ TrReset
 gLocal←IdPeerId gIdent
 gOpenGrants←openg ⋄ gConformance←conf ⋄ gOutCtr←0
 gReentryDepth←0 ⋄ gDefer←⍬                       ⍝ §6.11 reentry serialization (A-APL-017)
 gHPattern←⍬ ⋄ gHRoutine←⍬
 gConnFd←⍬ ⋄ gConnEstab←⍬ ⋄ gConnHasNonce←⍬ ⋄ gConnNonce←⍬ ⋄ gConnHello←⍬
 gListen←¯1
 Bootstrap
∇

∇Z←PeerLocal                                     ⍝ tradfn — niladic dfns eval at load (A-APL-016)
 Z←gLocal
∇
PeerAbs←{'/',gLocal,'/',⍵}
NullHash←⍬

∇Z←OpSpec io;m
 m←VMapEmpty
 →(0=≢1⊃io)/no
 m←m VmPut('input_type')(VText 1⊃io)
 no:→(0=≢2⊃io)/fin
 m←m VmPut('output_type')(VText 2⊃io)
 fin:Z←m
∇

⍝ mint a capability token at a CALLER-PINNED created_at, with an optional §5.6
⍝ temporal ceiling -> (token sig). ⍵=(createdAt granteeHash grants parent expiry),
⍝ where `expiry` is a (value present) pair.
⍝
⍝ created_at is supplied by the caller and deliberately NOT re-sampled here: the
⍝ emitted birth instant and the expiry derived from it must be the SAME instant,
⍝ or the token carries a ceiling computed against a moment it does not claim to
⍝ have been born at.
∇Z←MintTokenAt a;createdAt;gh;grants;parent;expiry;tm;tok;sig
 createdAt←1⊃a ⋄ gh←2⊃a ⋄ grants←3⊃a ⋄ parent←4⊃a ⋄ expiry←5⊃a
 tm←VMapEmpty
 tm←tm VmPut('granter')(VBytes IdHash gIdent)
 tm←tm VmPut('grantee')(VBytes gh)
 tm←tm VmPut('grants')grants
 tm←tm VmPut('created_at')(VUint createdAt)
 →(0=≢parent)/np
 tm←tm VmPut('parent')(VBytes parent)
 np:→(~2⊃expiry)/ne
 tm←tm VmPut('expires_at')(VUint 1⊃expiry)
 ne:tok←'system/capability/token'EntMake tm
 sig←gIdent IdSign tok
 Z←tok sig
∇

⍝ mint with no §5.6 ceiling and a locally-sampled created_at -> (token sig).
⍝ ⍵=(granteeHash grants parent). The bootstrap/owner/handler-grant mints are
⍝ self-issued by this peer to itself and carry no caller capability to be bounded
⍝ by; the §5.6 ceiling applies to the request/delegate path (CapMintBounded).
∇Z←MintToken a
 Z←MintTokenAt(CapNowMs)(1⊃a)(2⊃a)(3⊃a)(0 0)
∇

⍝ the included bundle for a minted grant: (token localPeer capSig).
CapIncluded←{(1⊃⍵)(IdPeerEntity gIdent)(2⊃⍵)}

∇pattern RegHandler a;routine;name;ops;hp;im;m
 routine←1⊃a ⋄ name←2⊃a ⋄ ops←3⊃a
 gHPattern←gHPattern,⊂pattern ⋄ gHRoutine←gHRoutine,routine
 hp←VMapEmpty VmPut('interface')(VText'system/handler/',pattern)
 (PeerAbs pattern)StoreBind('system/handler'EntMake hp)
 im←VMapEmpty VmPut('pattern')(VText pattern)
 im←im VmPut('name')(VText name)
 im←im VmPut('operations')ops
 (PeerAbs'system/handler/',pattern)StoreBind('system/handler/interface'EntMake im)
 m←MintToken(IdHash gIdent)(VArrEmpty)(NullHash)
 (PeerAbs'system/capability/grants/',pattern)StoreBind 1⊃m
∇

∇Z←DiscoveryFloor
 Z←VArrEmpty
 Z←Z VArrAdd CapGrant('system/tree')('system/type/* system/handler/*')('get')('')
 Z←Z VArrAdd CapGrant('system/capability')('')('request')('')
∇
∇Z←OpenGrantsScope
 Z←VArrEmpty VArrAdd CapGrant('*')('* /*/*')('*')('*')
∇
∇Z←OwnerGrants
 Z←VArrEmpty VArrAdd CapGrant('*')('*')('*')(gLocal)
∇

∇Bootstrap;ops;owner;policyBase;dg;pe
 StorePutEntity IdPeerEntity gIdent
 CtPublish gLocal
 ops←(VMapEmpty VmPut('get')(OpSpec'' ''))VmPut('put')(OpSpec'' '')
 'system/tree'RegHandler(R_TREE)('Tree')ops
 ops←VMapEmpty VmPut('register')(OpSpec'system/handler/register-request' 'system/handler/register-result')
 ops←ops VmPut('unregister')(OpSpec'system/handler/unregister-request' '')
 'system/handler'RegHandler(R_HANDLERS)('Handlers')ops
 ops←VMapEmpty VmPut('validate')(OpSpec'system/type/validate-request' 'system/type/validate-result')
 'system/type'RegHandler(R_TYPE)('Types')ops
 ops←VMapEmpty VmPut('request')(OpSpec'system/capability/request' 'system/capability/grant')
 ops←ops VmPut('revoke')(OpSpec'system/capability/revoke-request' '')
 ops←ops VmPut('configure')(OpSpec'system/capability/policy-entry' '')
 ops←ops VmPut('delegate')(OpSpec'system/capability/delegate-request' 'system/capability/grant')
 'system/capability'RegHandler(R_CAPABILITY)('Capability')ops
 ops←(VMapEmpty VmPut('hello')(OpSpec'' ''))VmPut('authenticate')(OpSpec'' '')
 'system/protocol/connect'RegHandler(R_CONNECT)('Connect')ops
 ⍝ §6.9a Peer Authority Bootstrap: self-owner cap + default scope-template entry.
 policyBase←'/',gLocal,'/system/capability/policy/'
 owner←MintToken(IdHash gIdent)(OwnerGrants)(NullHash)
 (policyBase,HexLc IdHash gIdent)StoreBind 1⊃owner
 ('/',gLocal,'/system/signature/',HexLc EntHash 1⊃owner)StoreBind 2⊃owner
 dg←(1+gOpenGrants)⊃(DiscoveryFloor)(OpenGrantsScope)
 pe←VMapEmpty VmPut('peer_pattern')(VText'default')
 pe←pe VmPut('grants')dg
 (policyBase,'default')StoreBind('system/capability/policy-entry'EntMake pe)
 →(~gConformance)/0
 ops←VMapEmpty VmPut('echo')(OpSpec'' '')
 'system/validate/echo'RegHandler(R_ECHO)('validate-echo')ops
 ops←VMapEmpty VmPut('dispatch')(OpSpec'' '')
 'system/validate/dispatch-outbound'RegHandler(R_DISPATCH)('validate-dispatch-outbound')ops
∇

⍝ ═══════════ §6.9a seed policy ═══════════
∇Z←SeedEntryGrants e;sigPath;sgn
 Z←VArrEmpty
 →(~'system/capability/token'≡EntType e)/notok
 sigPath←'/',gLocal,'/system/signature/',HexLc EntHash e
 sgn←StoreGetAt sigPath
 →(~EntPresent sgn)/0
 →(~sgn IdVerifySignature IdPeerEntity gIdent)/0
 Z←(EntDataMap e)MArray'grants' ⋄ →0
 notok:→(~'system/capability/policy-entry'≡EntType e)/0
 Z←(EntDataMap e)MArray'grants'
∇

∇Z←DeriveSeedGrants a;remotePeer;remotePeerId;base;entry;floor;policy;i
 remotePeer←1⊃a ⋄ remotePeerId←2⊃a
 base←'/',gLocal,'/system/capability/policy/'
 entry←StoreGetAt base,HexLc EntHash remotePeer
 →(EntPresent entry)/have
 entry←StoreGetAt base,remotePeerId
 →(EntPresent entry)/have
 entry←StoreGetAt base,'default'
 have:floor←DiscoveryFloor
 →(~EntPresent entry)/onlyfloor
 policy←SeedEntryGrants entry
 →(0=ArrCount policy)/onlyfloor
 Z←floor ⋄ i←0
 lp:→(i≥ArrCount policy)/0
 i←i+1 ⋄ Z←Z VArrAdd policy ArrItem i
 →lp
 onlyfloor:Z←floor
∇

⍝ ═══════════ handler resolution (§6.6) ═══════════
∇Z←ResolveHandler path;segs;rest;slash;i;j;prefix;e
 Z←'' ⋄ segs←⍬ ⋄ rest←path
 sl:→(0=≢rest)/split
 slash←rest⍳'/'
 →(slash>≢rest)/last
 segs←segs,⊂(slash-1)↑rest ⋄ rest←slash↓rest ⋄ →sl
 last:segs←segs,⊂rest ⋄ rest←''
 split:i←≢segs
 ol:→(i<1)/0
 prefix←i JoinSegs segs               ⍝ segs[1..i] joined by '/'
 e←StoreGetAt prefix
 →(~EntPresent e)/dec
 →(~'system/handler'≡EntType e)/dec
 Z←prefix ⋄ →0
 dec:i←i-1 ⋄ →ol
∇

∇Z←n JoinSegs segs;i
 Z←1⊃segs ⋄ i←1
 lp:→(i≥n)/0
 i←i+1 ⋄ Z←Z,'/',(i⊃segs)
 →lp
∇

∇Z←StripLocal pattern;pfx
 pfx←'/',gLocal,'/'
 Z←pattern
 →(~pattern StartsWith pfx)/0
 Z←(≢pfx)↓pattern
∇

∇Z←HandlerRoutine stripped;i
 Z←0 ⋄ i←0
 lp:→(i≥≢gHPattern)/0
 i←i+1 ⋄ →(~(i⊃gHPattern)≡stripped)/lp
 Z←i⊃gHRoutine ⋄ →0
∇

⍝ ═══════════ dispatch chain (§6.5) ═══════════
⍝ ⍵=(fd env) -> (respEnv hasResp). hasResp=0 for a non-EXECUTE root (§3.3).
∇Z←fd PeerDispatch env;rid;oc;resp;inc
 Z←(EntAbsent(⍬))0
 →(~'system/protocol/execute'≡EntType EnvRoot env)/0
 rid←(EnvRoot env)EntText'request_id'
 oc←fd DispatchInner env
 resp←WireMakeResponse rid(1⊃oc)(2⊃oc)
 inc←3⊃oc
 Z←(resp EnvMake inc)1
∇

⍝ an outcome is (status resultEnt inc).
OutErr←{(1⊃⍵)(WireErrorResult(2⊃⍵)(3⊃⍵))(⍬)}
OutOk0←{(200)(⍵)(⍬)}
OutOk←{(200)(1⊃⍵)(2⊃⍵)}

∇Z←fd DispatchInner env;exec;uri;op;vr;verdict;unres;cn;pathr;path;invalid;pattern;capH;callerCap;granterPeer;stripped;routine
 exec←EnvRoot env
 uri←exec EntText'uri'
 op←exec EntText'operation'
 →(~uri≡'system/protocol/connect')/authz
 Z←fd CallHandler(R_CONNECT)(op)(env)(EntAbsent)('')('')
 →0
⍝ section 4.7 (0.8.2.6) - THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate
⍝ used to sit below the verdict branches, so a pre-establishment EXECUTE naming a
⍝ FOREIGN namespace took the 401 an unauthenticated request takes. The spec's own
⍝ reason: a 401 directs the caller to authenticate and retry, and for a foreign
⍝ namespace that retry cannot succeed at any authentication state, so the 401 names a
⍝ remedy that does not exist. section 6.5 step 3 calls it a gate, not an ordering
⍝ preference. An INVALID path keeps its 400 invalid_path disposition, below.
 authz:cn←gLocal CapCanonicalize CapNormalizeUri uri ⋄ path←1⊃cn ⋄ invalid←2⊃cn
 →(invalid)/av
 →(~(gLocal CapExtractPeer path)≡gLocal)/eNotLocal
 av:vr←CapVerifyRequest gLocal env ⋄ verdict←1⊃vr ⋄ unres←2⊃vr
 →(unres)/eUnres
 →(verdict=CV_AUTHN_FAIL)/eAuthn
 →(verdict=CV_AUTHZ_DENY)/eDeny
 →(verdict=CV_CHAIN_TOO_DEEP)/eDeep
 →(invalid)/eInvalid
 pattern←ResolveHandler path
 →(0=≢pattern)/eNoHandler
⍝ the BARE handler id, assigned here rather than after the granter branch below:
⍝ `gp:` is a jump target, so an assignment placed between the branch and the
⍝ label runs only on the fallback path. §5.2's handlers dimension is id-scope and
⍝ takes this relative form, never the absolute resolved `pattern`.
 stripped←StripLocal pattern
 capH←exec EntBytes'capability'
 callerCap←EntAbsent
 →(0=≢capH)/eDeny
 callerCap←env EnvIncludedGet capH
 →(~EntPresent callerCap)/eDeny
 granterPeer←(EnvInc env)CapResolveGranterPeerId callerCap
 →(0<≢granterPeer)/gp
 granterPeer←gLocal
 gp:→(~CapCheckPermission gLocal granterPeer exec callerCap stripped)/eDeny
 routine←HandlerRoutine stripped
 →(routine=0)/eNoHandler
 Z←fd CallHandler(routine)(op)(env)(callerCap)(granterPeer)(pattern) ⋄ →0
 eUnres:Z←OutErr(401)('unresolvable_grantee')('') ⋄ →0
 eAuthn:Z←OutErr(401)('authentication_failed')('') ⋄ →0
 eDeny:Z←OutErr(403)('capability_denied')('') ⋄ →0
 eDeep:Z←OutErr(400)('chain_depth_exceeded')('') ⋄ →0
 eInvalid:Z←OutErr(400)('invalid_path')('') ⋄ →0
 eNotLocal:Z←OutErr(400)('invalid_request')('not local peer') ⋄ →0
 eNoHandler:Z←OutErr(404)('handler_not_found')(path)
∇

⍝ ⍵=(routine op env callerCap granterPeer pattern); ⍺=fd.
∇Z←fd CallHandler a;routine;op;env;callerCap;granterPeer;pattern
 routine←1⊃a ⋄ op←2⊃a ⋄ env←3⊃a ⋄ callerCap←4⊃a ⋄ granterPeer←5⊃a ⋄ pattern←6⊃a
 →(routine=R_CONNECT)/c
 →(routine=R_TREE)/t
 →(routine=R_HANDLERS)/h
 →(routine=R_TYPE)/ty
 →(routine=R_CAPABILITY)/cap
 →(routine=R_ECHO)/e
 →(routine=R_DISPATCH)/d
 Z←OutErr(501)('unsupported_operation')('') ⋄ →0
 c:Z←fd HndConnect(op)(env) ⋄ →0
 t:Z←HndTree(op)(env) ⋄ →0
 h:Z←HndHandlers(op)(env) ⋄ →0
 ty:Z←HndType(op)(env) ⋄ →0
 cap:Z←HndCapability(op)(env)(callerCap) ⋄ →0
 e:Z←HndEcho(op)(env) ⋄ →0
 d:Z←fd HndDispatchOutbound(op)(env)(callerCap)(granterPeer)
∇

⍝ ═══════════ MUST handlers ═══════════
⍝ ── §4.1/§4.6 connect ── ⍺=fd ; ⍵=(op env).
∇Z←fd HndConnect a;op;env
 op←1⊃a ⋄ env←2⊃a
 →(op≡'hello')/h
 →(op≡'authenticate')/au
⍝ §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
⍝ 400 invalid_request, not the 501 every other handler answers. The table separates
⍝ a STATE conflict from an UNKNOWN operation because they select different remedies —
⍝ "an unknown connect operation is not out of order at all; it exists in no state",
⍝ so connection_sequence_error would point the caller at its ORDERING when the defect
⍝ is its OPERATION NAME. Row 10 is scoped "in any state", so this covers pre-handshake
⍝ AND established; the genuine sequence cases are refused below, with 409.
⍝
⍝ SCOPED TO THIS FUNCTION DELIBERATELY. The generic registered-handler rule (§3.3's
⍝ 501 row, §6.2) is a different contract and is separately gated; moving the other
⍝ handlers' 501 would trade one green check for another.
 Z←OutErr(400)('invalid_request')('connect: unknown operation') ⋄ →0
 h:Z←fd ConnectHello env ⋄ →0
 au:Z←fd ConnectAuthenticate env
∇

⍝ §4.5: does `protocols` carry at least one text? Separates the MALFORMED case (absent
⍝ params, absent field, empty array) from the we-compared-and-disagreed case, which take
⍝ different §4.7 codes. NegotiationDisjoint deliberately conflates the two — absent means
⍝ "no constraint" there — so `protocols`, Required with NO default, needs this first.
∇Z←ProtocolsPresent params;d;arr
 Z←0
 →(~EntPresent params)/0
 d←EntDataMap params
 →(~d MHas'protocols')/0
 arr←d MArray'protocols'
 Z←0<ArrCount arr
∇

⍝ §4.5: is a declared negotiation list PRESENT and DISJOINT from our single supported
⍝ value? A present-but-EMPTY array rejects; an ABSENT field defaults to include (skip).
∇Z←params NegotiationDisjoint ks;key;supported;d;arr;i
 key←1⊃ks ⋄ supported←2⊃ks
 Z←0
 →(~EntPresent params)/0
 d←EntDataMap params
 →(~d MHas key)/0
 arr←d MArray key ⋄ i←0
 lp:→(i≥ArrCount arr)/disj
 i←i+1 ⋄ →(~supported≡VStr arr ArrItem i)/lp
 →0
 disj:Z←1
∇

∇Z←HelloMap nonce;hm
 hm←VMapEmpty
 hm←hm VmPut('peer_id')(VText gLocal)
 hm←hm VmPut('nonce')(VBytes nonce)
 hm←hm VmPut('protocols')(VTextArray'entity-core/1.0')
 hm←hm VmPut('timestamp')(VUint CapNowMs)
 hm←hm VmPut('hash_formats')(VTextArray'ecfv1-sha256')
 hm←hm VmPut('key_types')(VTextArray'ed25519')
 Z←hm
∇

∇Z←fd ConnectHello env;exec;params;idx;nonce;hm;hpid;hkt
 exec←EnvRoot env
 idx←ConnSlot fd
 →(~idx⊃gConnEstab)/ok
 Z←OutErr(409)('connection_already_established')('') ⋄ →0
⍝ §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a HALF-OPEN
⍝ connection (hello done, authenticate not yet) is an operation we implement arriving
⍝ in a state that forbids it — the same class as connection_already_established above,
⍝ taking the same 409. A half-open connection is NOT established, so the guard above
⍝ cannot reach it; §4.7 names this gap explicitly because two adjacent rules each look
⍝ like they cover it and neither does.
 ok:→(~idx⊃gConnHasNonce)/fresh
 Z←OutErr(409)('connection_sequence_error')('') ⋄ →0
 fresh:params←exec EntEntityField'params'
 →(~params NegotiationDisjoint'hash_formats' 'ecfv1-sha256')/k1
 Z←OutErr(400)('incompatible_hash_format')('') ⋄ →0
 k1:→(~params NegotiationDisjoint'key_types' 'ed25519')/k2
 Z←OutErr(400)('unsupported_key_type')('') ⋄ →0
⍝ §4.5 mutual verifiability, the direction that is NOT the array. `key_types` is an
⍝ ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in its `peer_id` —
⍝ so a hello may advertise a perfectly good accept-set and still name an identity we
⍝ cannot verify. An UNPARSEABLE peer_id is left alone (PeerIdKeyType answers <0): a
⍝ malformed field, not a key_type we lack, and authenticate already refuses it.
 k2:hpid←(1+EntPresent params)⊃('')(params EntText'peer_id')
 →(0=≢hpid)/k3
 hkt←PeerIdKeyType hpid
 →((hkt<0)∨hkt=1)/k3
 Z←OutErr(400)('unsupported_key_type')('') ⋄ →0
⍝ §4.5 `protocols` — the one negotiated field Required with NO default, so there is no
⍝ floor to fall back to, and its two failure modes carry different codes on purpose
⍝ (§4.5 table row / §4.7 row 1):
⍝
⍝   absent or empty     -> 400 invalid_request       (a malformed hello)
⍝   non-empty, disjoint -> 400 incompatible_protocol (we compared)
⍝
⍝ The remedies differ (send the field vs change the version) and §4.7 exists so the
⍝ code selects the remedy. The vocabulary is §8.4's protocol version identifiers,
⍝ today the single entity-core/1.0.
⍝
⍝ ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no precedence
⍝ between the three, so a hello disjoint in more than one dimension may be refused on
⍝ any of them — but the choice is OBSERVABLE, and the reference peer refuses key_types
⍝ first. Checking protocols first makes AGILITY-UNKNOWN-1 answer incompatible_protocol,
⍝ because that probe's hello carries ["entity-core/v7"] — a spec-line name, not a §8.4
⍝ identifier (F56).
 k3:→(ProtocolsPresent params)/k4
 Z←OutErr(400)('invalid_request')('hello: protocols absent or empty') ⋄ →0
 k4:→(~params NegotiationDisjoint'protocols' 'entity-core/1.0')/k5
 Z←OutErr(400)('incompatible_protocol')('') ⋄ →0
 k5:gConnHello[idx]←⊂(1+EntPresent params)⊃('')(params EntText'peer_id')
 nonce←RandomBytes 32
 gConnNonce[idx]←⊂nonce ⋄ gConnHasNonce[idx]←1
 hm←HelloMap nonce
 Z←OutOk0('system/protocol/connect/hello'EntMake hm)
∇

∇Z←fd ConnectAuthenticate env;exec;idx;auth;kt;pub;claimed;ckt;echoed;issued;sgn;sb;sp;sigOk;helloPid;remotePeer;grants;m;gm
 exec←EnvRoot env
 idx←ConnSlot fd
 auth←exec EntEntityField'params'
⍝ §4.6 RT-6: the handshake nonce is SINGLE USE, and that check outranks the
⍝ already-established gate.
⍝
⍝ A second authenticate REPLAYING the consumed nonce is a NONCE failure, and
⍝ RT-6 pins it to 401 invalid_nonce. Answering 409 connection_already_established
⍝ first is wrong-but-safe — the replay is still refused — but the oracle scores
⍝ it rt6_class=wrong-status, which is a FAIL, because a state-conflict code does
⍝ not say the nonce was rejected. The established gate below still answers every
⍝ OTHER second authenticate; only the replay is reclassified.
⍝
⍝ The issued nonce is deliberately RETAINED past establishment rather than
⍝ zeroed: keeping it is what lets the replay be recognised as a replay instead of
⍝ collapsing into "no nonce outstanding".
 →(~idx⊃gConnEstab)/fresh
 →(~EntPresent auth)/estab
 echoed←auth EntBytes'nonce'
 issued←idx⊃gConnNonce
 →(~(32=≢echoed)∧(32=≢issued))/estab
 →(~∧/echoed=issued)/estab
 Z←OutErr(401)('invalid_nonce')('') ⋄ →0
 estab:Z←OutErr(409)('connection_already_established')('') ⋄ →0
 fresh:→(idx⊃gConnHasNonce)/nn
 Z←OutErr(401)('invalid_nonce')('') ⋄ →0
 nn:→(EntPresent auth)/ha
 Z←OutErr(401)('authentication_failed')('') ⋄ →0
 ha:kt←auth EntText'key_type'
 →((0=≢kt)∨kt≡'ed25519')/k2
 Z←OutErr(400)('unsupported_key_type')('') ⋄ →0
 k2:pub←auth EntBytes'public_key'
 →((0=≢pub)∨32=≢pub)/k3
 Z←OutErr(400)('unsupported_key_type')('') ⋄ →0
 k3:claimed←auth EntText'peer_id'
 →(0=≢claimed)/k4
 ckt←PeerIdKeyType claimed
 →((ckt<0)∨ckt=1)/k4
 Z←OutErr(400)('unsupported_key_type')('') ⋄ →0
 k4:echoed←auth EntBytes'nonce'
 issued←idx⊃gConnNonce
 →((32=≢echoed)∧(∧/echoed=issued))/k5
 Z←OutErr(401)('invalid_nonce')('') ⋄ →0
 k5:→(0<≢pub)/k6
 Z←OutErr(401)('authentication_failed')('') ⋄ →0
 k6:sgn←CapFindSignature(EntHash auth)(EnvInc env)
 sigOk←0
 →(~EntPresent sgn)/sc
 sb←sgn EntBytes'signature'
 →(64≠≢sb)/sc
 sp←PeerEntityOfPubkey pub
 sigOk←sgn IdVerifySignature sp
 sc:→(sigOk)/k7
 Z←OutErr(401)('authentication_failed')('') ⋄ →0
 k7:→(0=≢claimed)/k8
 →(claimed≡PeerIdOfPubkey pub)/k8
 Z←OutErr(401)('identity_mismatch')('') ⋄ →0
 k8:helloPid←idx⊃gConnHello
 →((0=≢helloPid)∨(0=≢claimed)∨(helloPid≡claimed))/k9
 Z←OutErr(401)('identity_mismatch')('') ⋄ →0
 k9:remotePeer←PeerEntityOfPubkey pub
 grants←DeriveSeedGrants remotePeer(PeerIdOfPubkey pub)
 m←MintToken(EntHash remotePeer)(grants)(NullHash)
 gConnEstab[idx]←1
 gm←VMapEmpty VmPut('token')(VBytes EntHash 1⊃m)
 Z←OutOk('system/capability/grant'EntMake gm)(CapIncluded m)
∇

⍝ ── §6.3 tree ──
∇Z←HndTree a;op;env
 op←1⊃a ⋄ env←2⊃a
 →(op≡'get')/g
 →(op≡'put')/p
 Z←OutErr(501)('unsupported_operation')(op) ⋄ →0
 g:Z←TreeGet env ⋄ →0
 p:Z←TreePut env
∇

∇Z←ExecResourceTarget exec;r;targets
 Z←''
 r←exec EntSubmap'resource'
 →(EV_MAP≠1⊃r)/0
 targets←TextList r MArray'targets'
 →(0=≢targets)/0
 Z←1⊃targets
∇

∇Z←TreeGet env;exec;target;path;cn;e;params;mode;hm
 exec←EnvRoot env
 target←ExecResourceTarget exec
 →(0=≢target)/rootlist
 cn←gLocal CapCanonicalize target ⋄ path←1⊃cn
 →(2⊃cn)/einval           ⍝ §1.4: null byte / empty segment / reserved-relative → 400
 →(target EndsWith'/')/dirlist   ⍝ trailing-slash ⇒ listing (monadic ⊃ is DISCLOSE in GNU APL, not first)
 e←StoreGetAt path
 →(EntPresent e)/found
 Z←OutErr(404)('not_found')(path) ⋄ →0
 einval:Z←OutErr(400)('invalid_path')(target) ⋄ →0
 found:params←exec EntEntityField'params'
 mode←(1+EntPresent params)⊃('')(params EntText'mode')
 →(~mode≡'hash')/plain
 hm←VMapEmpty VmPut('hash')(VBytes EntHash e)
 Z←OutOk0('system/hash'EntMake hm) ⋄ →0
 plain:Z←OutOk0 e ⋄ →0
 rootlist:Z←TreeListing'/',gLocal,'/' ⋄ →0
 dirlist:cn←gLocal CapCanonicalize target ⋄ Z←TreeListing 1⊃cn
∇

⍝ Digest byte length for a content_hash_format code per the §1.2 seed table, or ¯1
⍝ when this peer cannot VERIFY that code. The total wire length is this plus the
⍝ varint prefix, which is not a constant of the code (§7.3): codes ≥ 0x80 occupy
⍝ more than one byte. ContentHash here is the SHA-256 floor unconditionally, so
⍝ 0x00 is the whole verifiable set.
∇Z←HashDigestLen fmt
 Z←¯1
 →(fmt≠0)/0
 Z←32
∇

⍝ §6.3's `put` admission ladder (normative, 0.8.2.11) → (admitted value):
⍝ (1 entity) when admitted, (0 outcome) when refused.
⍝
⍝ `put` is a RECEIPT path: the submitter authors the entity, the peer validates
⍝ what it received (§1.8 item 1) and MUST NOT author a submitted entity's
⍝ content_hash on the submitter's behalf. Two ORDERED steps:
⍝   1. STRUCTURE — a map with a non-empty text `type`, a PRESENT `data` (any CBOR
⍝      value; null is legal), and a `content_hash` that is a well-formed
⍝      system/hash whose total byte length matches its format code (§1.2). Any
⍝      failure → 400 invalid_request; a well-formed hash naming a format code
⍝      this peer cannot verify is the separate §1.2 row → 400
⍝      unsupported_content_hash_format.
⍝   2. HASH — carried vs content_hash({type, data}) → 400 hash_mismatch.
⍝ Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
⍝ inputs are exactly what step 1 establishes, so a submission that is both
⍝ malformed and mis-hashed is step 1's and answers invalid_request.
⍝ Structural admission is not semantic validation: `data` is never checked
⍝ against the type named by `type`.
∇Z←AdmitPut v;type;data;carried;dec;fmt;consumed;dl
 →(EV_MAP=1⊃v)/ismap
 Z←0(OutErr(400)('invalid_request')('put: entity is not a map')) ⋄ →0
 ismap:type←v MText'type'
 →(0<≢type)/hastype
 Z←0(OutErr(400)('invalid_request')('put: entity.type absent, empty or not a text string')) ⋄ →0
 ⍝ Presence, not truthiness: a CBOR null is a legal `data` payload, so MHas is the
 ⍝ presence predicate rather than an emptiness test on the value.
 hastype:→(v MHas'data')/hasdata
 Z←0(OutErr(400)('invalid_request')('put: entity.data absent')) ⋄ →0
 hasdata:data←v MGet'data'
 carried←v MBytes'content_hash'
 →(0<≢carried)/hasch
 Z←0(OutErr(400)('invalid_request')('put: entity.content_hash absent or not a byte string')) ⋄ →0
 hasch:dec←1 VarintDecode carried
 →(EC_OK=3⊃dec)/decoded
 Z←0(OutErr(400)('invalid_request')('put: entity.content_hash is not a well-formed system/hash')) ⋄ →0
 decoded:fmt←1⊃dec ⋄ consumed←(2⊃dec)-1 ⋄ dl←HashDigestLen fmt
 →(dl≥0)/known
 ⍝ §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
 ⍝ invalid_request: the shape is fine, the algorithm is what we lack.
 Z←0(OutErr(400)('unsupported_content_hash_format')('put: unsupported content_hash_format')) ⋄ →0
 known:→((≢carried)=consumed+dl)/lenok
 Z←0(OutErr(400)('invalid_request')('put: content_hash length does not match its format code')) ⋄ →0
 lenok:→(carried≡fmt ContentHash(VText type)(data))/match
 Z←0(OutErr(400)('hash_mismatch')('put: content_hash does not match content_hash({type, data})')) ⋄ →0
 ⍝ The carried hash IS the entity's address; recomputing it into the store would
 ⍝ be the authoring arm §6.3 forbids.
 match:Z←1(1(,type)(data)(carried))
∇

∇Z←TreePut env;exec;target;cn;path;params;entity;rawEnt;hasEnt;adm;expected;current;casOk;hm
 exec←EnvRoot env
 target←ExecResourceTarget exec
 →(0<≢target)/ht
 Z←OutErr(400)('ambiguous_resource')('tree: missing resource target') ⋄ →0
 ht:cn←gLocal CapCanonicalize target ⋄ path←1⊃cn
 →(2⊃cn)/einval           ⍝ §1.4: null byte / empty segment / reserved-relative → 400
 params←exec EntEntityField'params'
 hasEnt←0 ⋄ rawEnt←⍬ ⋄ expected←⍬
 →(~EntPresent params)/nocas
 hasEnt←(EntDataMap params)MHas'entity'
 rawEnt←params EntFieldV'entity'
 expected←params EntBytes'expected_hash'
 nocas:current←StoreHashAt path
 →(0=≢expected)/okcas
 →(HashZero expected)/expempty
 casOk←(0<≢current)∧current≡HexLc expected ⋄ →caschk
 expempty:casOk←0=≢current ⋄ →caschk
 okcas:casOk←1
 caschk:→(casOk)/hasent
 Z←OutErr(409)('hash_mismatch')(path) ⋄ →0
 hasent:→(hasEnt)/admit
 Z←OutErr(400)('unexpected_params')('put: missing entity') ⋄ →0
 admit:adm←AdmitPut rawEnt
 →(1⊃adm)/bind
 Z←2⊃adm ⋄ →0
 bind:entity←2⊃adm ⋄ path StoreBind entity
 hm←VMapEmpty VmPut('hash')(VBytes EntHash entity)
 Z←OutOk0('system/hash'EntMake hm) ⋄ →0
 einval:Z←OutErr(400)('invalid_path')(target)
∇

∇Z←TreeListing path;lst;segs;hexes;kids;em;i;led;lm;count;me;hb
 lst←StoreListing path ⋄ segs←1⊃lst ⋄ hexes←2⊃lst ⋄ kids←3⊃lst
 em←VMapEmpty ⋄ count←0 ⋄ i←0
 lp:→(i≥≢segs)/done
 i←i+1
 →((0=≢i⊃hexes)∨(i⊃kids))/emit
 hb←HexToBytes i⊃hexes
 me←StoreGetByHash hb
 →(~EntPresent me)/emit
 →('system/deletion-marker'≡EntType me)/lp
 emit:led←VMapEmpty VmPut('has_children')(VBool i⊃kids)
 →(0=≢i⊃hexes)/nohash
 led←led VmPut('hash')(VBytes HexToBytes i⊃hexes)
 nohash:em←em VmPut(i⊃segs)(EntToCbor('system/tree/listing-entry'EntMake led))
 count←count+1
 →lp
 done:lm←VMapEmpty VmPut('path')(VText path)
 lm←lm VmPut('entries')em
 lm←lm VmPut('count')(VUint count)
 lm←lm VmPut('offset')(VUint 0)
 Z←OutOk0('system/tree/listing'EntMake lm)
∇

⍝ ── §6.2 handlers (register/unregister — minimal) ──
∇Z←HndHandlers a;op;env
 op←1⊃a ⋄ env←2⊃a
 →(op≡'register')/r
 →(op≡'unregister')/u
 Z←OutErr(501)('unsupported_operation')(op) ⋄ →0
 r:Z←HandlersRegister env ⋄ →0
 u:Z←HandlersUnregister env
∇

∇Z←RegisterPattern exec;target;pfx
 Z←'' ⋄ pfx←'system/handler/'
 target←ExecResourceTarget exec
 →((≢target)≤≢pfx)/0
 →(~target StartsWith pfx)/0
 Z←(≢pfx)↓target
∇

∇Z←RegisterPatternError exec
 →(0=≢ExecResourceTarget exec)/amb
 Z←OutErr(400)('invalid_resource')('resource target MUST be system/handler/{pattern}') ⋄ →0
 amb:Z←OutErr(400)('ambiguous_resource')('register/unregister require exactly one resource target')
∇

⍝ §6.2: 1 iff `pattern` is exactly 'system' or begins 'system/'. User-installed
⍝ handlers MUST NOT register at a reserved system path — a register there is
⍝ refused with 403 forbidden_pattern, and (the negative half the oracle also
⍝ checks) MUST publish nothing: the refusal returns before any StoreBind runs.
∇Z←ReservedPattern pattern
 Z←1
 →(pattern≡'system')/0
 →(pattern StartsWith'system/')/0
 Z←0
∇

∇Z←HandlersRegister env;exec;pattern;req;manifest;name;ops;hp;im;m;rm;gscope
 exec←EnvRoot env
 pattern←RegisterPattern exec
 →(0<≢pattern)/ok
 Z←RegisterPatternError exec ⋄ →0
 ok:→(~ReservedPattern pattern)/np
 Z←OutErr(403)('forbidden_pattern')('section 6.2: user-installed handlers MUST NOT register at system/* paths: ',pattern) ⋄ →0
 np:req←exec EntEntityField'params'
 →(EntPresent req)/hp0
 Z←OutErr(400)('unexpected_params')('register: missing params') ⋄ →0
 hp0:→('system/handler/register-request'≡EntType req)/hp1
 Z←OutErr(400)('unexpected_params')('register expects register-request') ⋄ →0
 hp1:manifest←req EntSubmap'manifest'
 →(EV_MAP=1⊃manifest)/hm
 manifest←VMapEmpty
 hm:name←manifest MText'name'
 →(0<≢name)/hn
 name←pattern
 hn:ops←manifest MSubmap'operations'
 →(EV_MAP=1⊃ops)/ho
 ops←VMapEmpty
 ho:gscope←(EntDataMap req)MArray'requested_scope'
 hp←VMapEmpty VmPut('interface')(VText'system/handler/',pattern)
 (PeerAbs pattern)StoreBind('system/handler'EntMake hp)
 m←MintToken(IdHash gIdent)(gscope)(NullHash)
 (PeerAbs'system/capability/grants/',pattern)StoreBind 1⊃m
 (PeerAbs'system/signature/',HexLc EntHash 1⊃m)StoreBind 2⊃m
 im←VMapEmpty VmPut('pattern')(VText pattern)
 im←im VmPut('name')(VText name)
 im←im VmPut('operations')ops
 (PeerAbs'system/handler/',pattern)StoreBind('system/handler/interface'EntMake im)
 gHPattern←gHPattern,⊂pattern ⋄ gHRoutine←gHRoutine,R_ECHO   ⍝ community handler stub routing
 rm←VMapEmpty VmPut('pattern')(VText pattern)
 rm←rm VmPut('grant')(EntDataV 1⊃m)
 Z←OutOk0('system/handler/register-result'EntMake rm)
∇

∇Z←HandlersUnregister env;exec;pattern;g
 exec←EnvRoot env
 pattern←RegisterPattern exec
 →(0<≢pattern)/ok
 Z←RegisterPatternError exec ⋄ →0
 ok:g←StoreGetAt PeerAbs'system/capability/grants/',pattern
 →(~EntPresent g)/nu
 StoreUnbind PeerAbs'system/signature/',HexLc EntHash g
 StoreUnbind PeerAbs'system/capability/grants/',pattern
 nu:StoreUnbind PeerAbs pattern
 StoreUnbind PeerAbs'system/handler/',pattern
 Z←OutOk0 WireEmptyParams
∇

⍝ ── system/type:validate (minimal presence check) ──
∇Z←HndType a;op;env;exec;req;subject;typeName;typeDef;fields;subjData;valid;i;fk;fv;fname;optional;present;pay;np;vm
 op←1⊃a ⋄ env←2⊃a
 →(op≡'validate')/ok
 Z←OutErr(501)('unsupported_operation')(op) ⋄ →0
 ok:exec←EnvRoot env
 req←exec EntEntityField'params'
 →(EntPresent req)/hr
 Z←OutErr(400)('invalid_params')('validate requires a params entity') ⋄ →0
 hr:subject←req EntEntityField'entity'
 →(EntPresent subject)/hs
 Z←OutErr(400)('unexpected_params')('validate-request missing entity') ⋄ →0
 hs:typeName←req EntText'type_path'
 →(0<≢typeName)/ht
 typeName←EntType subject
 ht:typeDef←StoreGetAt PeerAbs'system/type/',typeName
 →(EntPresent typeDef)/hd
 vm←VMapEmpty VmPut('valid')(VBool 0)
 Z←OutOk0('system/type/validate-result'EntMake vm) ⋄ →0
 hd:fields←typeDef EntSubmap'fields'
 subjData←EntDataMap subject
 valid←1
 →(EV_MAP≠1⊃fields)/fin
 pay←2⊃fields ⋄ np←⌊(≢pay)÷2 ⋄ i←0
 fl:→(i≥np)/fin
 i←i+1 ⋄ fk←(¯1+2×i)⊃pay ⋄ fv←(2×i)⊃pay
 →(EV_TEXT≠1⊃fk)/fl
 fname←⎕UCS ,2⊃fk
 optional←(EV_MAP=1⊃fv)∧fv MBool'optional'
 present←subjData MHas fname
 →(optional∨present)/fl
 valid←0 ⋄ →fl
 fin:vm←VMapEmpty VmPut('valid')(VBool valid)
 Z←OutOk0('system/type/validate-result'EntMake vm)
∇

⍝ ── §6.2 capability ──
∇Z←HndCapability a;op;env;callerCap
 op←1⊃a ⋄ env←2⊃a ⋄ callerCap←3⊃a
 →(op≡'request')/rq
 →(op≡'delegate')/dg
 →(op≡'revoke')/rv
 →(op≡'configure')/cf
 Z←OutErr(501)('unsupported_operation')(op) ⋄ →0
 rq:Z←env CapRequest callerCap ⋄ →0
 dg:Z←env CapDelegate callerCap ⋄ →0
 rv:Z←CapRevoke env ⋄ →0
 cf:Z←CapConfigure env
∇

∇Z←ReqGrants params
 Z←VArrEmpty
 →(~EntPresent params)/0
 Z←(EntDataMap params)MArray'grants'
∇

∇Z←env CapRequest callerCap;params;author
 params←(EnvRoot env)EntEntityField'params'
 author←(EnvRoot env)EntBytes'author'
 →(0<≢author)/ok
 Z←OutErr(403)('capability_denied')('') ⋄ →0
 ok:Z←CapMintBounded callerCap(ReqGrants params)(author)(NullHash)(params)(EnvInc env)
∇

∇Z←env CapDelegate callerCap;params;author;ph
 params←(EnvRoot env)EntEntityField'params'
 author←(EnvRoot env)EntBytes'author'
 ph←(1+EntPresent params)⊃(⍬)(params EntBytes'parent')
 →(0<≢ph)/hasp
 Z←OutErr(400)('unexpected_params')('delegate: parent required') ⋄ →0
 hasp:→(~HashZero ph)/nz
 Z←OutErr(400)('unexpected_params')('delegate: zero parent') ⋄ →0
 nz:→((0<≢author)∧(IdHash gIdent)HashEq author)/same
 Z←OutErr(501)('unsupported_operation')('delegate: same-peer-only in v1') ⋄ →0
 same:Z←CapMintBounded callerCap(ReqGrants params)(author)(ph)(params)(EnvInc env)
∇

∇Z←CapMintBounded a;callerCap;rg;grantee;parent;params;inc;bounded;pg;i;j;c;covered;m;gm;createdAt;expiry
 callerCap←1⊃a ⋄ rg←2⊃a ⋄ grantee←3⊃a ⋄ parent←4⊃a ⋄ params←5⊃a ⋄ inc←6⊃a
 bounded←0
 →(~EntPresent callerCap)/chk
 pg←CapGrantsOfToken callerCap ⋄ bounded←1 ⋄ i←0
 il:→(i≥ArrCount rg)/chk
 i←i+1 ⋄ c←rg ArrItem i ⋄ covered←0 ⋄ j←0
 jl:→(j≥ArrCount pg)/jchk
 j←j+1 ⋄ →(~gLocal CapGrantSubsetLocal c(pg ArrItem j))/jl
 covered←1
 jchk:→(covered)/il
 bounded←0
 chk:→(bounded)/mint
 Z←OutErr(403)('scope_exceeds_authority')('') ⋄ →0
⍝ §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). created_at is sampled ONCE
⍝ here and the duration terms are converted against that same instant.
⍝
⍝ Note what this is NOT: an authorization decision. An over-long ttl_ms from a
⍝ bounded caller MINTS a clamped token and returns 200 — "rejecting it is
⍝ non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
⍝ (parent: null), so §5.6's parent-child attenuation never reaches it; without
⍝ this clamp, temporal attenuation is the one dimension a requester could escape
⍝ and policy withdrawal would have no bounded latency.
 mint:createdAt←CapNowMs
 expiry←MinDefinedExpiry(inc ParentExpiryTerm parent)(CallerCapExpiryTerm callerCap)(createdAt DurationTerm params 'ttl_ms')
 m←MintTokenAt(createdAt)(grantee)(rg)(parent)(expiry)
 gm←VMapEmpty VmPut('token')(VBytes EntHash 1⊃m)
 Z←OutOk('system/capability/grant'EntMake gm)(CapIncluded m)
∇

∇Z←CapRevoke env;params;th;rm;marker
 params←(EnvRoot env)EntEntityField'params'
 th←(1+EntPresent params)⊃(⍬)(params EntBytes'token')
 →(0<≢th)/ht
 Z←OutErr(400)('unexpected_params')('revoke: missing token') ⋄ →0
 ht:→(~HashZero th)/nz
 Z←OutErr(400)('unexpected_params')('revoke: zero token') ⋄ →0
 nz:rm←VMapEmpty VmPut('token')(VBytes th)
 rm←rm VmPut('revoked_at')(VUint CapNowMs)
 marker←'system/capability/revocation'EntMake rm
 ('/',gLocal,'/system/capability/revocations/',HexLc th)StoreBind marker
 Z←OutOk0 WireEmptyParams
∇

∇Z←CapConfigure env;params;pp;isHex
 params←(EnvRoot env)EntEntityField'params'
 pp←(1+EntPresent params)⊃('')(params EntText'peer_pattern')
 →(0<≢pp)/hp
 Z←OutErr(400)('unexpected_params')('configure: missing peer_pattern') ⋄ →0
 hp:isHex←(66=≢pp)∧IsHexStr pp
 →((pp≡'default')∨isHex∨CapIsPeerId pp)/ok
 Z←OutErr(400)('invalid_peer_pattern')(pp) ⋄ →0
 ok:('/',gLocal,'/system/capability/policy/',pp)StoreBind params
 Z←OutOk0 WireEmptyParams
∇

⍝ ── §7a conformance handlers ──
∇Z←HndEcho a;op;env;p
 op←1⊃a ⋄ env←2⊃a
 →(op≡'echo')/ok
 Z←OutErr(501)('unsupported_operation')(op) ⋄ →0
 ok:p←(EnvRoot env)EntEntityField'params'
 →(EntPresent p)/hp
 Z←OutErr(400)('invalid_params')('echo requires params') ⋄ →0
 hp:Z←OutOk0 p
∇

⍝ §6.13(b) handler-initiated outbound dispatch, exercised by the §7a.2a validate probe.
⍝ Originates an outbound EXECUTE on the SAME inbound connection (the reentry seam) and
⍝ pumps the serve loop reentrantly until the reply correlates by request_id (§6.11).
∇Z←fd HndDispatchOutbound a;op;env;params;target;dop;value;rcap;rgranter;rcapsig;hasVal;innerData;inner;resource;rid;exec;execsig;inc;outenv;frame;pumped;taken;payload;resp;status;resv;om
 op←1⊃a ⋄ env←2⊃a ⋄ params←3⊃a   ⍝ params slot carries callerCap (unused); read from env
 →(op≡'dispatch')/ok
 Z←OutErr(501)('unsupported_operation')(op) ⋄ →0
 ok:params←(EnvRoot env)EntEntityField'params'
 →(EntPresent params)/hp
 Z←OutErr(400)('invalid_params')('dispatch-outbound requires a params entity') ⋄ →0
 hp:target←params EntText'target'
 dop←params EntText'operation'
 hasVal←(EntDataMap params)MHas'value'
 value←params EntFieldV'value'
 rcap←params EntEntityField'reentry_capability'
 rgranter←params EntEntityField'reentry_granter'
 rcapsig←params EntEntityField'reentry_cap_signature'
 →((0<≢target)∧hasVal∧(EntPresent rcap)∧(EntPresent rgranter)∧(EntPresent rcapsig))/args
 Z←OutErr(400)('invalid_params')('dispatch-outbound requires value + reentry authority') ⋄ →0
 args:innerData←(1+VIsMap value)⊃(VMapEmpty VmPut('value')value)(value)
 inner←'primitive/any'EntMake innerData
 →(fd≠0)/seam
 Z←OutErr(503)('no_outbound_seam')('no live section 6.11 reentry connection') ⋄ →0
 seam:resource←WireResourceTarget'system/handler/',target
 rid←'out-',⍕NextRidCtr
 exec←WireMakeExecute(rid)(target)(dop)(inner)(IdHash gIdent)(EntHash rcap)(resource)
 execsig←gIdent IdSign exec
 inc←(rcap)(rgranter)(IdPeerEntity gIdent)(rcapsig)(execsig)
 outenv←exec EnvMake inc
 TrPendRegister rid
 frame←FrameOf WireFrameOfEnvelope outenv
 zz←fd NetSend frame
 gReentryDepth←gReentryDepth+1               ⍝ defer nested inbound EXECUTEs (A-APL-017)
 pumped←fd PumpUntil rid
 gReentryDepth←gReentryDepth-1
 →(pumped)/took
 Z←OutErr(503)('connection_broken')('reentry connection lost') ⋄ →0
 took:taken←TrPendTake rid
 →(2⊃taken)/have
 Z←OutErr(503)('connection_broken')('reentry response missing') ⋄ →0
 have:payload←1⊃taken
 resp←1⊃WireEnvelopeOfFrame payload
 status←WireResponseStatus resp
 resv←(EnvRoot resp)EntFieldV'result'
 →(EV_MAP=1⊃resv)/hr
 resv←VMapEmpty
 hr:om←VMapEmpty VmPut('status')(VUint status)
 om←om VmPut('result')resv
 Z←OutOk0('primitive/any'EntMake om)
∇

⍝ ═══════════ transport pump (serve + client) ═══════════
∇Z←NextRidCtr
 gOutCtr←gOutCtr+1 ⋄ Z←gOutCtr
∇

∇Z←ConnSlot fd;i
 Z←0 ⋄ i←0
 lp:→(i≥≢gConnFd)/0
 i←i+1 ⋄ →((i⊃gConnFd)≠fd)/lp
 Z←i ⋄ →0
∇

∇ConnOpen fd;s
 s←ConnSlot fd
 →(s>0)/0
 gConnFd←gConnFd,fd ⋄ gConnEstab←gConnEstab,0 ⋄ gConnHasNonce←gConnHasNonce,0
 gConnNonce←gConnNonce,⊂32⍴0 ⋄ gConnHello←gConnHello,⊂''
∇

∇ConnClose fd;s
 s←ConnSlot fd
 →(s=0)/0
 gConnFd←gConnFd/⍨(⍳≢gConnFd)≠s
 gConnEstab←gConnEstab/⍨(⍳≢gConnEstab)≠s
 gConnHasNonce←gConnHasNonce/⍨(⍳≢gConnHasNonce)≠s
 gConnNonce←gConnNonce/⍨(⍳≢gConnNonce)≠s
 gConnHello←gConnHello/⍨(⍳≢gConnHello)≠s
 TrRxDrop fd
 zz←NetClose fd
∇

∇fd OnFrame payload;pk;rt;rid;isResp;ok;dr;env;resp;frame;rframe
 pk←WirePeek payload ⋄ rt←1⊃pk ⋄ rid←2⊃pk ⋄ isResp←3⊃pk ⋄ ok←4⊃pk
 →(~ok)/0
 →(~isResp)/inbound
 rid TrPendDeliver payload ⋄ →0
 inbound:→(rt≡'system/protocol/execute')/exec
 →0                                    ⍝ §3.3: ignore other root types
 ⍝ §6.11: while a handler reentry (HndDispatchOutbound) is pendent awaiting its outbound
 ⍝ reply, a SECOND inbound EXECUTE must NOT be dispatched here — that would recursively
 ⍝ re-enter the pendent HndDispatchOutbound and corrupt GNU APL's interpreter (A-APL-017).
 ⍝ Defer it to the queue PeerServe drains at depth 0 (serialized single-thread dispatch).
 exec:→(gReentryDepth>0)/defer
 ConnOpen fd
 dr←WireEnvelopeOfFrame payload
 →(2⊃dr)/good
 →(0=≢rid)/0
 rframe←FrameOf WireFrameOfEnvelope((WireMakeResponse rid(400)(WireErrorResult('non_canonical_ecf')('')))EnvMake ⍬)
 zz←fd NetSend rframe ⋄ →0
 good:env←1⊃dr
 resp←fd PeerDispatch env
 →(~2⊃resp)/0
 frame←FrameOf WireFrameOfEnvelope 1⊃resp
 zz←fd NetSend frame
 →0
 defer:gDefer←gDefer,⊂(fd)(payload)   ⍝ processed by DrainDeferred at reentry depth 0
∇

∇Send413 fd;rframe
 ⍝ §4.10(a): oversize length prefix caught BEFORE buffering the body; answer 413, keep
 ⍝ serving. request_id is unknown (body never read) -> empty.
 rframe←FrameOf WireFrameOfEnvelope((WireMakeResponse('')(413)(WireErrorResult('payload_too_large')('')))EnvMake ⍬)
 zz←fd NetSend rframe
∇

⍝ process one readable fd (accept / recv+frames / EOF). Returns nothing.
∇ServeReadable fd;conn;chunk;ex;frames;i
 →(fd≠gListen)/data
 conn←NetAccept fd
 →(conn<0)/0
 ConnOpen conn ⋄ →0
 data:chunk←NetRecv fd
 →(0<≢chunk)/have
 ConnClose fd ⋄ →0
 have:fd TrRxAppend chunk
 ex←TrRxExtract fd ⋄ frames←1⊃ex
 →(2⊃ex)/oversize
 i←0
 fl:→(i≥≢frames)/0
 i←i+1 ⋄ fd OnFrame(i⊃frames)
 →fl
 oversize:Send413 fd ⋄ ConnClose fd
∇

∇Z←PeerListen port
 gListen←NetListen port
 →(gListen<0)/fail
 Z←NetBoundPort gListen ⋄ →0
 fail:Z←¯1
∇

⍝ the persistent §4.9 serve loop: block on the read set, service every readable fd.
∇PeerServe;rdy;i;fd
 loop:rdy←NetSelectRead ReadSet
 i←0
 il:→(i≥≢rdy)/drain
 i←i+1 ⋄ fd←i⊃rdy
 →(~fd∊ReadSet)/skip     ⍝ fd may have been closed by a prior iteration
 ServeReadable fd
 skip:→il
 drain:DrainDeferred     ⍝ dispatch inbound EXECUTEs deferred during a reentry (A-APL-017)
 →loop
∇

⍝ dispatch the inbound EXECUTEs that arrived while a handler reentry was pendent. Runs at
⍝ reentry depth 0 (from PeerServe), so each dispatch — including its own reentry pump —
⍝ completes fully before the next, and HndDispatchOutbound is never pendent more than once.
∇DrainDeferred;item;fd;payload
 dl:→(0=≢gDefer)/0
 item←1⊃gDefer ⋄ gDefer←1↓gDefer
 fd←1⊃item ⋄ payload←2⊃item
 →(~fd∊gConnFd)/dl       ⍝ connection closed meanwhile → drop
 fd OnFrame payload
 →dl
∇

⍝ pump events on the reentry connection `fd` until `rid` is delivered -> ok (0 on
⍝ connection loss). The reentrant pump shared by the initiator session send (fd=gSessFd)
⍝ and the §6.13 handler reentry (fd=the inbound seam). It services ONLY `fd` — NOT the
⍝ whole read set — so a §6.11 concurrent-reentry flood is SERIALIZED: each dispatch-outbound
⍝ completes (send outbound, await its correlated reply on the SAME connection, send the
⍝ final response) before PeerServe advances to the next ready fd. This is the single-thread
⍝ event-loop discipline the §6.11(a) no-serialization MUST permits (t1_1 is informational
⍝ for non-parallel runtimes). Critically, it means HndDispatchOutbound is NEVER pendent more
⍝ than once at a time: pumping the whole read set here would recursively re-enter a pendent
⍝ HndDispatchOutbound for a second connection's inbound dispatch-outbound, which corrupts
⍝ GNU APL 1.9's interpreter state (SYNTAX ERROR on the re-entered call — A-APL-017).
∇Z←fd PumpUntil rid;rdy
 loop:→(TrPendDone rid)/ok
 →(~fd∊gConnFd)/lost         ⍝ the reentry connection was closed (EOF) → lost
 rdy←NetSelectRead(,fd)
 →(0=≢rdy)/lost
 ServeReadable fd
 →loop
 lost:Z←0 ⋄ →0
 ok:Z←1
∇


⍝ read set for the select loop: the listener (only if bound) + all live connections.
∇Z←ReadSet
 Z←((gListen≥0)/gListen),gConnFd
∇

⍝ ═══════════ initiator session (§4.4) ═══════════
⍝ a session lives in globals (the peer dials ONE responder): ok fd reqCtr remote cap
⍝ granter capSig.
∇Z←PeerDial port;fd
 gSessOk←0 ⋄ gSessRemote←'' ⋄ gSessReqCtr←0
 fd←NetConnect port
 →(fd≥0)/ok
 Z←0 ⋄ →0
 ok:gSessFd←fd ⋄ ConnOpen fd
 Handshake
 Z←gSessOk
∇

⍝ send an envelope, pump the loop until its reply correlates by request_id (§6.11) ->
⍝ (respEnv ok). ok=0 on connection loss.
∇Z←SessSend env;rid;frame;ok;taken
 rid←(EnvRoot env)EntText'request_id'
 TrPendRegister rid
 frame←FrameOf WireFrameOfEnvelope env
 zz←gSessFd NetSend frame
 ok←gSessFd PumpUntil rid
 →(ok)/took
 Z←(EntAbsent(⍬))0 ⋄ →0
 took:taken←TrPendTake rid
 →(2⊃taken)/have
 Z←(EntAbsent(⍬))0 ⋄ →0
 have:Z←WireEnvelopeOfFrame 1⊃taken
∇

⍝ §4.1 forward handshake: hello then authenticate.
∇Handshake;hm;hello;ex1;r1;ok;remoteHello;remoteNonce;am;auth;sig;ex2;r2;grant;tokenH;token;granterH;granter;capSig
 gSessOk←0
 hm←HelloMap RandomBytes 32
 hello←'system/protocol/connect/hello'EntMake hm
 gSessReqCtr←gSessReqCtr+1
 ex1←WireMakeExecute('req-',⍕gSessReqCtr)('system/protocol/connect')('hello')(hello)(⍬)(⍬)(EV_ABSENT ⍬)
 r1←SessSend ex1 EnvMake ⍬
 →(2⊃r1)/h1
 →0
 h1:→(200=WireResponseStatus 1⊃r1)/h2
 →0
 h2:remoteHello←WireResponseResult 1⊃r1
 gSessRemote←remoteHello EntText'peer_id'
 remoteNonce←remoteHello EntBytes'nonce'
 →(0<≢remoteNonce)/h3
 →0
 h3:am←VMapEmpty VmPut('peer_id')(VText IdPeerId gIdent)
 am←am VmPut('public_key')(VBytes IdPub gIdent)
 am←am VmPut('key_type')(VText'ed25519')
 am←am VmPut('nonce')(VBytes remoteNonce)
 auth←'system/protocol/connect/authenticate'EntMake am
 sig←gIdent IdSign auth
 gSessReqCtr←gSessReqCtr+1
 ex2←WireMakeExecute('req-',⍕gSessReqCtr)('system/protocol/connect')('authenticate')(auth)(⍬)(⍬)(EV_ABSENT ⍬)
 r2←SessSend ex2 EnvMake((IdPeerEntity gIdent)(sig))
 →(2⊃r2)/h4
 →0
 h4:→(200=WireResponseStatus 1⊃r2)/h5
 →0
 h5:grant←WireResponseResult 1⊃r2
 tokenH←grant EntBytes'token'
 →(0<≢tokenH)/h6
 →0
 h6:token←(1⊃r2)EnvIncludedGet tokenH
 →(EntPresent token)/h7
 →0
 h7:granterH←token EntBytes'granter'
 granter←(1⊃r2)EnvIncludedGet granterH
 →(EntPresent granter)/h8
 →0
 h8:capSig←CapFindSignature(EntHash token)(EnvInc 1⊃r2)
 →(EntPresent capSig)/h9
 →0
 h9:gSessCap←token ⋄ gSessGranter←granter ⋄ gSessCapSig←capSig ⋄ gSessOk←1
∇

⍝ the included bundle for an authenticated request: (cap granter localPeer capSig execSig).
AuthIncluded←{(gSessCap)(gSessGranter)(IdPeerEntity gIdent)(gSessCapSig)(⍵)}

⍝ build a signed authenticated EXECUTE envelope. ⍵=(uri op params resource).
∇Z←BuildExec a;uri;op;params;resource;exec;execsig
 uri←1⊃a ⋄ op←2⊃a ⋄ params←3⊃a ⋄ resource←4⊃a
 gSessReqCtr←gSessReqCtr+1
 exec←WireMakeExecute('req-',⍕gSessReqCtr)(uri)(op)(params)(IdHash gIdent)(EntHash gSessCap)(resource)
 execsig←gIdent IdSign exec
 Z←exec EnvMake AuthIncluded execsig
∇

⍝ build+sign+send an authenticated EXECUTE; await the response -> (respEnv ok).
∇Z←SessExecute a
 Z←SessSend BuildExec a
∇

⍝ fire WITHOUT awaiting (multiple in-flight -> §6.11 out-of-order demux) -> the rid.
∇Z←SessExecuteAsync a;env;rid;frame
 env←BuildExec a
 rid←(EnvRoot env)EntText'request_id'
 TrPendRegister rid
 frame←FrameOf WireFrameOfEnvelope env
 zz←gSessFd NetSend frame
 Z←rid
∇

SessAwait←{gSessFd PumpUntil ⍵}
∇Z←SessResponse rid;taken
 Z←(EntAbsent(⍬))0
 taken←TrPendTake rid
 →(~2⊃taken)/0
 Z←WireEnvelopeOfFrame 1⊃taken
∇

∇PeerShutdown
 zz←NetClose¨gConnFd
 →(gListen<0)/0
 zz←NetClose gListen
∇
