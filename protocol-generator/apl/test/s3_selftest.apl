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
 ⍝ CapCheckPermission takes the STRIPPED handler pattern, not the absolute URI:
 ⍝ DispatchInner calls it as `CapCheckPermission gLocal granterPeer exec callerCap stripped`
 ⍝ where stripped is `StripLocal pattern`. This assertion passed the absolute
 ⍝ `/{peer}/system/tree` and was therefore comparing an absolute path against a
 ⍝ grant that names the handler RELATIVELY (`CapGrant('system/tree')...` above), so
 ⍝ it could only ever deny. Same shape as the cobol id-scope defect: an id is
 ⍝ compared literally, and the value handed to the matcher decides everything.
 ⍝ The peer was right (756 · 0F); this unit had gone stale under it, and the S3
 ⍝ axis had no cohort sweep to say so.
 'permission check ALLOWs system/tree:get'Check CapCheckPermission ap ap exec token'system/tree'
 'chain-depth pre-check: single token within bound'Check~token CapChainExceedsDepth inc
 ⍝ tamper: A signs but author claims B -> signer!=author -> AUTHN_FAIL
 bexec←WireMakeExecute('r2')('/',ap,'/system/tree')('get')(WireEmptyParams)(IdHash b)(EntHash token)(EV_ABSENT ⍬)
 bsig←a IdSign bexec
 inc2←(token)(IdPeerEntity a)(IdPeerEntity b)(capsig)(bsig)
 env2←bexec EnvMake inc2
 vr2←CapVerifyRequest ap env2
 'verify_request DENIES a mis-signed request (401 authn)'Check CV_AUTHN_FAIL=1⊃vr2
∇

⍝ ═══════════════════════════════════════════════════════════════════════════════════
⍝ 0.8.2.25 — the section 5.4 sentinel's SCOPE-TYPE scoping (RULE B), the TYPED subset
⍝ check (RULE E / F50), the section 5.2 EFFECTIVE TARGET LIST, and section 6.3's
⍝ check_path_permission. Driven through the peer's own functions, never a restatement.
⍝ ═══════════════════════════════════════════════════════════════════════════════════

⍝ The local peer_id for these tests. gLocal is set by PeerInit and does NOT exist in the
⍝ selftest workspace, which loads the modules without starting a peer -- reaching for it
⍝ is a VALUE ERROR, not a wrong answer, which is the good direction for a missing global.
∇Z←SelfLocal
 Z←IdPeerId IdOfSeed KeystoreSeedOfHexbyte'aa'
∇

⍝ a scope map carrying BOTH include and exclude (VScope builds include only).
⍝ ⍵=(includeWords excludeWords), each a blank-separated string.
∇Z←ScopeIE a;m
 m←VMapEmpty VmPut('include')(VTextArray 1⊃a)
 →(0=≢(2⊃a)~' ')/fin
 m←m VmPut('exclude')(VTextArray 2⊃a)
 fin:Z←m
∇
⍝ a one-grant capability token. ⍵=(handlers operations resourcesIncl resourcesExcl).
∇Z←CapTok a;g;m
 g←VMapEmpty
 g←g VmPut('handlers')(VScope 1⊃a)
 g←g VmPut('operations')(VScope 2⊃a)
 g←g VmPut('resources')(ScopeIE(3⊃a)(4⊃a))
 m←VMapEmpty VmPut('grants')(VArrEmpty VArrAdd g)
 Z←'system/capability/token'EntMake m
∇
⍝ The first survivor, or '' when there is none. TOTAL ON PURPOSE.
⍝
⍝ APL's conjunction is NOT short-circuiting, so an assertion of the form
⍝ "the flag is 1 AND the first survivor is a" evaluates BOTH conjuncts, and an EMPTY
⍝ survivor list makes the second an INDEX ERROR -- which ABORTS THE WHOLE SUITE instead
⍝ of reporting the FAIL the assertion exists for. Measured: the fail-CLOSED plant on the
⍝ caller-exclude arm killed the run rather than reddening its named case, so the control
⍝ could not observe the defect it was written for. A test must be able to REPORT the
⍝ failure it is about.
∇Z←Head1 v
 Z←''
 →(0=≢v)/0
 Z←,1⊃v
∇

⍝ an EXECUTE carrying only a `resource` map. ⍵=(targetWords excludeWords).
∇Z←ExecRes a;m;r
 r←VMapEmpty VmPut('targets')(VTextArray 1⊃a)
 →(0=≢(2⊃a)~' ')/mk
 r←r VmPut('exclude')(VTextArray 2⊃a)
 mk:m←VMapEmpty VmPut('resource')r
 Z←'system/protocol/execute'EntMake m
∇

⍝ RULE B — the section 5.4 sentinel is scoped to PATH-SCOPE (0.8.2.24, N2/N3).
⍝
⍝ An `operations` exclude of star-slash-apply is an ordinary NAMESPACED OPERATION NAME;
⍝ under section 3.6's id grammar it is a literal that matches nothing. Running it through
⍝ the section 5.4 PATH transforms purely to classify it answers the sentinel and DENIES
⍝ THE WHOLE DIMENSION -- over-denial, invisible on any well-formed grant. section 5.4:
⍝ "It does NOT reach `operations` or `peers` [MUST]".
⍝
⍝ ON THIS PEER THE ARM IS SATISFIED BY CONSTRUCTION, and that is the evidence rather than
⍝ an assumption: the sentinel test lives in CapMatchesScope, the PATH-scope matcher, and
⍝ the id dimensions go through CapMatchesIdScope, a separate function with no such test
⍝ that never canonicalizes. There is no type dispatch to get wrong. The BEHAVIOUR is
⍝ pinned anyway, because "separate functions" is a claim about today's source.
∇TestSentinelScopeType;idsc;pathsc;tLocal
 tLocal←SelfLocal
 idsc←ScopeIE('*')('*/apply')
 '0.8.2.24: an operations exclude of star-slash-apply does not deny get'Check CapMatchesIdScope('get')(idsc)
 '0.8.2.24: ... and it still excludes ITSELF, as a literal'Check~CapMatchesIdScope('*/apply')(idsc)
 pathsc←ScopeIE('*')('../nope')
 '0.8.2.21: an unmatchable PATH-scope exclude still denies'Check~tLocal CapMatchesScope('q/a')(pathsc)
∇

⍝ RULE F — the sentinel guard sits on EVERY path reaching the decision it protects
⍝ (0.8.2.22: "a sentinel arm is a control-flow obligation, not a line").
⍝
⍝ On this peer the guard is the FIRST ARM OF CapMatchesPattern ITSELF, over BOTH operands,
⍝ and there is no unguarded variant to call -- the four call sites (the /*/-recursion,
⍝ Covered, CoveredLiteral, ScopeSubset) all go through it. That is the opposite of lean,
⍝ where the guard lives in a WRAPPER and the raw matcher stays callable, which is exactly
⍝ how scopeSubset bypassed it, permissively. The ATTENUATION path is the one that was
⍝ bypassed there, so it is asserted directly rather than left to the construction argument.
⍝
⍝ EACH ARM'S FIXTURE IS CHOSEN SO THE ARM DECIDES IT: `/*` is already absolute, survives
⍝ canonicalization unchanged, and its trailing-star prefix test is StartsWith '/', which
⍝ the sentinel satisfies. A bare star canonicalizes to /{local}/* and refuses the sentinel
⍝ on the prefix test anyway -- it would measure the ordinary matcher, not the guard.
∇TestSentinelReachesAttenuation;tLocal
 tLocal←SelfLocal
 'RULE F: an unmatchable CHILD include is not a subset of /*'Check~ScopeSubset tLocal tLocal(ScopeIE('../nope')(''))(ScopeIE('/*')(''))SK_PATH
 'RULE F: two different unmatchable patterns do not certify each other'Check~ScopeSubset tLocal tLocal(ScopeIE('../other')(''))(ScopeIE('../nope')(''))SK_PATH
 'RULE F control: an ordinary child IS a subset of /*'Check ScopeSubset tLocal tLocal(ScopeIE('q/a')(''))(ScopeIE('/*')(''))SK_PATH
 'RULE F control: ... and of a bare star'Check ScopeSubset tLocal tLocal(ScopeIE('q/a')(''))(ScopeIE('*')(''))SK_PATH
∇

⍝ RULE E — ScopeSubset is TYPED by scope kind (F50, ruled YES at 0.8.2.16;
⍝ entity-core-formalization K-7). The differential: 2 of 64 include pairs disagree
⍝ between the two readings, fail-closed, and a 16-pair control alphabet reports 0 --
⍝ which is why every hand-tried example missed it.
∇TestScopeSubsetTyped;tLocal
 tLocal←SelfLocal
 'F50: under ID, a bare star covers any literal'Check ScopeSubset tLocal tLocal(ScopeIE('*/apply')(''))(ScopeIE('*')(''))SK_ID
 'F50: under PATH, the same pair is NOT a subset'Check~ScopeSubset tLocal tLocal(ScopeIE('*/apply')(''))(ScopeIE('*')(''))SK_PATH
 'F50 control: a concrete-under-star pair agrees on ID'Check ScopeSubset tLocal tLocal(ScopeIE('tree/get')(''))(ScopeIE('*')(''))SK_ID
 'F50 control: ... and on PATH, which is why a coarse survey sees nothing'Check ScopeSubset tLocal tLocal(ScopeIE('tree/get')(''))(ScopeIE('*')(''))SK_PATH
∇

⍝ section 5.2's EFFECTIVE TARGET LIST (0.8.2.20) and its NON-LOSSY pair (0.8.2.25 N11).
∇TestEffectiveTargets;r;tLocal
 tLocal←SelfLocal
 ⍝ THE TWO EMPTIES ARE DISTINCT and the second result is what says so. A function
 ⍝ returning only a list collapses them and deletes the discriminator before any handler
 ⍝ can read it -- which is exactly what N11 forbids [MUST].
 r←tLocal CapEffectiveTargets('system/protocol/execute'EntMake VMapEmpty)
 'N11: an ABSENT resource answers (empty, hadResource=0)'Check(0=≢1⊃r)∧(0=2⊃r)
 r←tLocal CapEffectiveTargets ExecRes('a')('a')
 'N11: PRESENT-but-self-excluded answers (empty, hadResource=1)'Check(0=≢1⊃r)∧(1=2⊃r)
 r←tLocal CapEffectiveTargets ExecRes('a b')('b')
 '0.8.2.20: the caller exclude removes b, a survives'Check(1=≢1⊃r)∧(,'a')≡Head1 1⊃r
 ⍝ RAW survivors, not canonical forms (0.8.2.21): the value flows on to the store lookup,
 ⍝ which canonicalizes for itself, and to the trailing-slash test, which is about what
 ⍝ the caller WROTE.
 r←tLocal CapEffectiveTargets ExecRes('x/y')('')
 '0.8.2.21: effective_targets yields RAW survivors'Check(,'x/y')≡Head1 1⊃r
 ⍝ The caller-exclude arm is fail-OPEN on an unmatchable pattern -- section 5.4 rules it
 ⍝ separately from the GRANT arm, and conflating them silently narrows every request
 ⍝ carrying a malformed exclude.
 r←tLocal CapEffectiveTargets ExecRes('a')('../nope')
 'section 5.4: an unmatchable CALLER exclude carves out nothing'Check(1=2⊃r)∧(,'a')≡Head1 1⊃r
∇

⍝ section 6.3's check_path_permission. THE ACCEPT CASE IS WHAT VALIDATES THE FIXTURE:
⍝ without it a capability that parsed as empty would make every deny below pass for free.
⍝ ONE DENY PER DIMENSION, because a single deny cannot distinguish "the predicate checks
⍝ the dimension I care about" from "the predicate denies".
∇TestCheckPathPermission;p;q;tLocal
 tLocal←SelfLocal
 p←'/',tLocal,'/q/a' ⋄ q←'/',tLocal,'/q/b'
 'section 6.3: a covering grant ALLOWS'Check CapCheckPathPermission tLocal('get')(p)(CapTok('*')('*')('*')(''))('system/tree')
 'section 6.3: denies on RESOURCES'Check~CapCheckPathPermission tLocal('get')(q)(CapTok('*')('*')('q/a')(''))('system/tree')
 'section 6.3: denies on OPERATIONS'Check~CapCheckPathPermission tLocal('put')(p)(CapTok('*')('get')('*')(''))('system/tree')
 'section 6.3: denies on HANDLERS'Check~CapCheckPathPermission tLocal('get')(p)(CapTok('system/capability')('*')('*')(''))('system/tree')
 ⍝ An empty resources.include is a LEGAL grant shape (section 5.2: handlers that touch no
 ⍝ tree paths) and DENIES every path here -- Covered over an empty include list is 0.
 'section 5.2: an EMPTY resources.include denies every path'Check~CapCheckPathPermission tLocal('get')(p)(CapTok('*')('*')('')(''))('system/tree')
 ⍝ A malformed subject Canons to NeverMatch, which matches no grant (section 5.4), so it
 ⍝ falls through to DENY rather than being matched against anything. The grant is `/*`
 ⍝ and NOT a bare star deliberately -- see the RULE F note above.
 'section 5.4 control: a /* grant DOES cover an ordinary path'Check CapCheckPathPermission tLocal('get')(p)(CapTok('*')('*')('/*')(''))('system/tree')
 'section 5.4: a reserved-form subject falls through to DENY under /*'Check~CapCheckPathPermission tLocal('get')('../escape')(CapTok('*')('*')('/*')(''))('system/tree')
∇

⍝ RULE G — OPERATION RESOLUTION PRECEDES RESOURCE VALIDATION, AS A DIFFERENTIAL.
⍝
⍝ HndTree's op branch selects before either arm reads `resource`, so an unknown operation
⍝ answers an OPERATION fault (501 unsupported_operation) WHETHER OR NOT a resource is
⍝ present. `ocaml` put the any-operation-no-resource arm ABOVE the unknown-operation arm,
⍝ so the same call answered a RESOURCE fault with no resource and 501 with one -- which is
⍝ why only the PAIR can see it (entity-system-conformance X9/F52).
⍝
⍝ THE THIRD ROW IS WHAT STOPS "501 TO EVERYTHING" SATISFYING THE FIRST TWO VACUOUSLY: a
⍝ KNOWN operation must still REACH the section 3.3 ladder, and here it reaches the
⍝ malformed_resource arm rather than 501.
⍝
⍝ Driven with NO caller capability, which is the bootstrap context section 6.3 does not
⍝ narrow -- so the rows measure the HANDLER's ladder and not the dispatch check.
∇TestOperationBeforeResource;env;r;code
 gLocal←SelfLocal
 code←{2⊃(EntDataMap 2⊃⍵)MText'code'}
 env←('system/protocol/execute'EntMake(VMapEmpty VmPut('operation')(VText'bogusop')))EnvMake ⍬
 r←HndTree('bogusop')(env)(EntAbsent)('system/tree')
 'RULE G: unknown op with NO resource is an OPERATION fault'Check(501=1⊃r)∧'unsupported_operation'≡(2⊃r)EntText'code'
 env←(ExecRes('q/a')(''))EnvMake ⍬
 r←HndTree('bogusop')(env)(EntAbsent)('system/tree')
 'RULE G: unknown op WITH a resource is the same fault'Check(501=1⊃r)∧'unsupported_operation'≡(2⊃r)EntText'code'
 env←(ExecRes('q/*')(''))EnvMake ⍬
 r←HndTree('get')(env)(EntAbsent)('system/tree')
 'RULE G: a KNOWN op still reaches the section 3.3 ladder'Check(400=1⊃r)∧'malformed_resource'≡(2⊃r)EntText'code'
∇

∇SelfMain
 TestKeystore ⋄ TestStore ⋄ TestEntityRoundtrip ⋄ TestSignVerify ⋄ TestCapabilityChain ⋄ TestFraming
 TestSentinelScopeType ⋄ TestSentinelReachesAttenuation ⋄ TestScopeSubsetTyped
 TestEffectiveTargets ⋄ TestCheckPathPermission ⋄ TestOperationBeforeResource
 ⎕←''
 →(nFail>0)/bad
 ⎕←'SELFTEST: PASS (',(⍕nPass),'/',(⍕nPass+nFail),')'
 →0
 bad:⎕←'SELFTEST: FAIL (',(⍕nPass),'/',(⍕nPass+nFail),')'
∇

SelfMain
)OFF
