⍝ entity-core-protocol-apl — test/s3_selftest.apl (offline foundation self-test).
⍝
⍝ Exercises the S3 peer-layer foundation with NO network: the content store + entity tree,
⍝ materialized-entity content_hash + wire round-trip (§1.8 fidelity), L1 identity
⍝ sign/verify, base64 keystore round-trip, the full §5.2 capability verify-request chain
⍝ (A grants to B; B's request ALLOWs; a tampered signature DENIES), the §4.10(b) chain-
⍝ depth pre-check, and the §4.10(a) 413 length-prefix pre-check. This is the accept-path
⍝ coverage the rejection-only oracle categories cannot reach ("conformance-green can be
⍝ vacuous"). Output is file-redirected (A-APL-013). Prints SELFTEST: PASS/FAIL.

nPass←0 ⋄ nFail←0
∇name Check cond
 →(cond)/ok
 nFail←nFail+1 ⋄ ⎕←'  [FAIL] ',name ⋄ →0
 ok:nPass←nPass+1 ⋄ ⎕←'  [PASS] ',name
∇

∇TestKeystore;seed;b64;dec;known
 seed←(32⍴7)×⍳32                       ⍝ 7 14 21 ... mod 256 pattern
 seed←256|seed
 b64←B64Encode seed
 dec←B64Decode b64
 'base64 round-trip (32-byte seed)'Check(32=≢dec)∧seed≡dec
 known←B64Encode KeystoreSeedOfHexbyte'11'
 'seed 0x11 x32 == known base64 ERER...'Check'ERERERER'≡8↑known
∇

∇TestStore;a;b;got
 StoreReset
 a←'primitive/string'EntMake VText'alpha'
 b←'primitive/string'EntMake VText'beta'
 '/x/a'StoreBind a ⋄ '/x/b'StoreBind b
 got←StoreGetAt'/x/a'
 'store bind/get round-trip'Check(EntPresent got)∧'primitive/string'≡EntType got
 'store get by hash'Check EntPresent StoreGetByHash EntHash b
 'store miss -> absent'Check~EntPresent StoreGetAt'/x/missing'
 StoreUnbind'/x/a'
 'store unbind'Check~EntPresent StoreGetAt'/x/a'
∇

∇TestEntityRoundtrip;e;m;wire;bytes;dr;dec;rc
 m←VMapEmpty VmPut('k')(VUint 42)
 m←m VmPut('name')(VText'z')
 e←'system/peer'EntMake m
 wire←EntToCbor e
 bytes←CborEncode wire
 dr←CborDecode bytes
 'entity wire decode ok'Check(EC_OK=3⊃dr)∧(2⊃dr)=≢bytes
 dec←EntOfCbor 1⊃dr
 'entity of_cbor recomputes hash'Check(EC_OK=2⊃dec)∧EntPresent 1⊃dec
 'content_hash stable across round-trip'Check(EntHash e)≡EntHash 1⊃dec
∇

∇TestSignVerify;id;target;sig;other
 id←IdOfSeed KeystoreSeedOfHexbyte'11'
 'peer_id is base58'Check CapIsPeerId IdPeerId id
 target←'primitive/string'EntMake VText'sign me'
 sig←id IdSign target
 'signature verifies against signer peer'Check sig IdVerifySignature IdPeerEntity id
 other←IdOfSeed KeystoreSeedOfHexbyte'22'
 'signature FAILS against wrong peer'Check~sig IdVerifySignature IdPeerEntity other
∇

∇TestFraming;ex;exn
 ⍝ §4.10(a): an oversize length prefix is flagged BEFORE the body is buffered.
 TrReset
 99 TrRxAppend((4⍴256)⊤MAX_FRAME+1),10⍴0
 ex←TrRxExtract 99
 '413 pre-check: oversize length prefix flagged before buffering'Check 2⊃ex
 ⍝ a normal frame is delimited out of the receive buffer.
 TrReset
 88 TrRxAppend FrameOf(5⍴65)
 exn←TrRxExtract 88
 'framing: a normal length-prefixed frame is delimited'Check(1=≢1⊃exn)∧0=2⊃exn
∇

∇TestCapabilityChain;a;b;ap;grants;tm;token;capsig;exec;execsig;inc;env;vr;bexec;bsig;inc2;env2;vr2
 StoreReset
 a←IdOfSeed KeystoreSeedOfHexbyte'aa'         ⍝ responder / granter (local)
 b←IdOfSeed KeystoreSeedOfHexbyte'bb'         ⍝ requester / grantee (author)
 StorePutEntity IdPeerEntity a ⋄ StorePutEntity IdPeerEntity b
 ap←IdPeerId a
 grants←VArrEmpty VArrAdd CapGrant('system/tree')('system/type/*')('get')('')
 tm←VMapEmpty VmPut('granter')(VBytes IdHash a)
 tm←tm VmPut('grantee')(VBytes IdHash b)
 tm←tm VmPut('grants')grants
 tm←tm VmPut('created_at')(VUint CapNowMs)
 token←'system/capability/token'EntMake tm
 capsig←a IdSign token
 exec←WireMakeExecute('r1')('/',ap,'/system/tree')('get')(WireEmptyParams)(IdHash b)(EntHash token)(EV_ABSENT ⍬)
 execsig←b IdSign exec
 inc←(token)(IdPeerEntity a)(IdPeerEntity b)(capsig)(execsig)
 env←exec EnvMake inc
 vr←CapVerifyRequest ap env
 'verify_request ALLOWs a valid delegated request'Check(CV_ALLOW=1⊃vr)∧0=2⊃vr
 'permission check ALLOWs system/tree:get'Check CapCheckPermission ap ap exec token('/',ap,'/system/tree')
 'chain-depth pre-check: single token within bound'Check~token CapChainExceedsDepth inc
 ⍝ tamper: A signs but author claims B -> signer!=author -> AUTHN_FAIL
 bexec←WireMakeExecute('r2')('/',ap,'/system/tree')('get')(WireEmptyParams)(IdHash b)(EntHash token)(EV_ABSENT ⍬)
 bsig←a IdSign bexec
 inc2←(token)(IdPeerEntity a)(IdPeerEntity b)(capsig)(bsig)
 env2←bexec EnvMake inc2
 vr2←CapVerifyRequest ap env2
 'verify_request DENIES a mis-signed request (401 authn)'Check CV_AUTHN_FAIL=1⊃vr2
∇

∇SelfMain
 TestKeystore ⋄ TestStore ⋄ TestEntityRoundtrip ⋄ TestSignVerify ⋄ TestCapabilityChain ⋄ TestFraming
 ⎕←''
 →(nFail>0)/bad
 ⎕←'SELFTEST: PASS (',(⍕nPass),'/',(⍕nPass+nFail),')'
 →0
 bad:⎕←'SELFTEST: FAIL (',(⍕nPass),'/',(⍕nPass+nFail),')'
∇

SelfMain
)OFF
