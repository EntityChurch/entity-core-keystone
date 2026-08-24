"entity-core-protocol-smalltalk — L3 capability CHAIN verification (§5.2 / §5.5 / §PR-8): the
AUTHZ interior beyond the S3 depth/grantee primitives (EcCapability). Ported NATIVELY (message-
sends over EcEntity / EcValue objects — NOT transpiled) from the already-converged cohort §5.5
logic (forth src/capauthz.fs / the Rexx Cap_VerifyChain). EcCapability supplies the trichotomy
scaffold + the §4.10(b) depth pre-check; THIS class adds the full chain walk (root single-sig +
multisig M3/M4/M6), per-link signature + attenuation + grantee/expiry, §5.7 caveats, §5.1
revocation, and the §5.2 permission-scope gate the dispatcher maps to a status — ALL FOUR grant
dimensions (handlers, operations, peers, resources; 2026-08-13 fix, see
research/stewardship/HANDOFF-TO-ARCH-2026-08-13-peers-grant-dimension-oracle-gap.md — `peers`
was previously never read at dispatch).

THE PURE-OBJECT REP (A-ST-000): a capability token is an EcEntity; grants/scopes are EcMap /
EcArray value objects; a peer_id / hash is a String / ByteArray. Path patterns are Strings;
scope matching (§5.4 /*/ recursion + /* suffix) is String message-sends. Verdicts are Symbols
(#allow/#authz/#unresolvable/#depth) — no integer enum.

The class is STATELESS: every method takes the resolution context (the local peer_id String,
the inbound EcEnvelope for included-set resolution, and the EcStore for §5.1 revocation-marker
lookups). No shared mutable state → §N8 verdict determinism structural.

LIVE-IMAGE NOTE: EcCapability / EcIdentity / EcEntity / EcMap / EcArray / EcTextString /
EcByteString / EcBase58 resolve at send-time inside method bodies."

| pkg cls |
pkg := 'EntityCore-Capability'.
cls := (Object << #EcCapAuthz package: pkg) install.

"── wall clock (ms) for §5.6 validity windows ──"
cls class compile: 'nowMillis  ^ (DateAndTime now asUnixTime) * 1000'.

"── §5.4 canonicalization: a bare (non-absolute) path is peer-rooted /<local>/<path>. Answers
    the canonical String, or signals a coded error Symbol via a return sentinel: a reserved-
    relative (./ ../) or bare-peer-wildcard (*/) path is a 400 at the boundary — we answer nil
    and let the caller treat an uncanonicalizable pattern as non-matching (§5.4). ──"
cls class compile: 'canon: aPath local: aLocalPeerId
	((aPath beginsWith: ''./'') or: [ aPath beginsWith: ''../'' ]) ifTrue: [ ^ nil ].
	(aPath beginsWith: ''*/'') ifTrue: [ ^ nil ].
	(aPath beginsWith: ''/'') ifTrue: [ ^ aPath ].
	^ ''/'', aLocalPeerId, ''/'', aPath'.

"── §5.4 pattern matching (recursive /*/ + /* suffix). Both path + pattern are already
    canonicalized (absolute /<peer>/...). ──"
cls class compile: 'path: aPath matchesPattern: aPat
	aPat = ''*'' ifTrue: [ ^ true ].                    "bare * matches all"
	(aPat beginsWith: ''/*/'') ifTrue: [
		"strip a /<seg> from the path, recurse on the remainder."
		aPath isEmpty ifTrue: [ ^ false ].
		^ self patMatchStar: aPath rest: (aPat copyFrom: 4 to: aPat size) ].
	(aPat size >= 2 and: [ aPat endsWith: ''/*'' ]) ifTrue: [
		^ aPath beginsWith: (aPat copyFrom: 1 to: aPat size - 1) ].
	^ aPath = aPat'.

"patMatchStar:rest: — /*/<restpat> : find the next / at/after index 2 of aPath (past a leading
 /), strip that segment, recurse the remainder against /<restpat>. (aPath is absolute.)"
cls class compile: 'patMatchStar: aPath rest: restPat
	| idx |
	idx := aPath indexOf: $/ startingAt: 2.
	idx = 0 ifTrue: [ ^ false ].
	^ self path: (aPath copyFrom: idx to: aPath size) matchesPattern: ''/'', restPat'.

"── scope reads (a system/capability/*-scope map {include:[...], exclude:[...]}) ──"
"scopeArray:key: — the include/exclude EcArray of a scope EcMap, or nil."
cls class compile: 'scopeArray: aScopeMap key: aKey
	| v |
	(aScopeMap isKindOf: EcMap) ifFalse: [ ^ nil ].
	v := aScopeMap entryAt: aKey.
	(v isKindOf: EcArray) ifTrue: [ ^ v ].
	^ nil'.

"coveredByArray:frame:value:local: — is canonicalized `val` matched by any pattern in the
 array (each pattern canonicalized against `frame`)? nil array -> false."
cls class compile: 'coveredByArray: anArray frame: aFrame value: aCanonVal local: aLocal
	anArray isNil ifTrue: [ ^ false ].
	^ anArray items anySatisfy: [ :e |
		(e isKindOf: EcTextString)
			and: [ | cp | cp := self canon: e string local: aFrame.
				cp notNil and: [ self path: aCanonVal matchesPattern: cp ] ] ]'.

"── §5.2 id-scope literal match (0.8.1, F40) — `operations` and `peers`. Compared as the RAW
    value, a literal string, with exactly two wildcard forms: bare `*` matches any value, and a
    trailing `/*` matches by literal segment-prefix (the slash is KEPT, only the star is
    dropped, so `compute/*` matches `compute/apply` but not bare `compute`). None of the §5.4
    path transforms apply here — no leading-/ universal-scope reading, no `/*/` interior peer-
    wildcard, no peer-relative -> /{local}/... qualification — so a pattern carrying path syntax
    is matched AS A LITERAL STRING: a non-match, never a fault. ──"
cls class compile: 'value: aVal matchesIdPattern: aPat
	aPat = ''*'' ifTrue: [ ^ true ].
	(aPat size >= 2 and: [ aPat endsWith: ''/*'' ]) ifTrue: [
		^ aVal beginsWith: (aPat copyFrom: 1 to: aPat size - 1) ].
	^ aVal = aPat'.

"coveredByIdArray:value: — is `val` matched, as a LITERAL id-scope pattern (no
 canonicalization, no frame), by any pattern in the array? nil array -> false."
cls class compile: 'coveredByIdArray: anArray value: aVal
	anArray isNil ifTrue: [ ^ false ].
	^ anArray items anySatisfy: [ :e |
		(e isKindOf: EcTextString) and: [ self value: aVal matchesIdPattern: e string ] ]'.

"matchesScope:frame:value:local:kind: — §5.2, typed (0.8.1, F40): covered by include AND NOT
 covered by exclude, but the cover test itself depends on the grant dimension's SCOPE TYPE.
 `aKind` is a REQUIRED argument — #idScope or #pathScope, deliberately no default — so a new
 call site cannot silently inherit the wrong matcher, which is exactly the F40 defect
 re-introduced. #idScope (operations, peers): literal match, no canonicalization. #pathScope
 (handlers, resources): unchanged §5.4 behaviour — `frame` is the peer-id that frames both the
 value and the patterns; a value that fails canonicalization is not covered."
cls class compile: 'matchesScope: aScopeMap frame: aFrame value: aVal local: aLocal kind: aKind
	| inc exc |
	aKind = #idScope
		ifTrue: [
			inc := self scopeArray: aScopeMap key: ''include''.
			(self coveredByIdArray: inc value: aVal) ifFalse: [ ^ false ].
			exc := self scopeArray: aScopeMap key: ''exclude''.
			^ (self coveredByIdArray: exc value: aVal) not ]
		ifFalse: [
			| cv |
			cv := self canon: aVal local: aFrame.
			cv isNil ifTrue: [ ^ false ].
			inc := self scopeArray: aScopeMap key: ''include''.
			(self coveredByArray: inc frame: aFrame value: cv local: aLocal) ifFalse: [ ^ false ].
			exc := self scopeArray: aScopeMap key: ''exclude''.
			^ (self coveredByArray: exc frame: aFrame value: cv local: aLocal) not ]'.

"── token field reads ──"
"grantsOf: — the {grants:[...]} EcArray of a token, or nil."
cls class compile: 'grantsOf: aToken
	| v |
	v := aToken field: ''grants''.
	(v isKindOf: EcArray) ifTrue: [ ^ v ].
	^ nil'.
"granterValueOf: — the raw `granter` EcValue (an EcByteString single-sig hash or an EcMap
 multi-granter map), or nil."
cls class compile: 'granterValueOf: aToken
	| v |
	v := aToken field: ''granter''.
	v isAbsent ifTrue: [ ^ nil ].
	^ v'.
"isMultisig: — granter present AND a map."
cls class compile: 'isMultisig: aToken
	^ (self granterValueOf: aToken) isKindOf: EcMap'.

"── §PR-8 granter-peer resolution (frames a cap''s resource patterns) ──"
"resolvePeerOfHash:in: — the peer_id String of the peer entity at content-hash h (from the
 envelope included set), via its public_key. nil if absent / not a 32-byte-keyed peer."
cls class compile: 'resolvePeerOfHash: aHashBytes in: anEnvelope
	| pe pk |
	aHashBytes isNil ifTrue: [ ^ nil ].
	pe := anEnvelope includedForHash: aHashBytes.
	pe isNil ifTrue: [ ^ nil ].
	pk := pe bytesAt: ''public_key''.
	(pk isNil or: [ pk size ~= 32 ]) ifTrue: [ ^ nil ].
	^ EcIdentity peerIdForPubkey: pk'.

"granterPeerOfCap:local:in: — the frame peer for a link: a single-sig granter''s peer_id; a
 rootless (no-granter) cap frames as `local`; a multisig granter frames as `local`
 (root-at-local); an unresolvable granter frames as nil."
cls class compile: 'granterPeerOfCap: aCap local: aLocal in: anEnvelope
	| g |
	g := self granterValueOf: aCap.
	g isNil ifTrue: [ ^ aLocal ].                       "no granter -> local frame"
	(g isKindOf: EcByteString) ifFalse: [ ^ aLocal ].    "multisig granter (map) -> local"
	^ self resolvePeerOfHash: g bytes in: anEnvelope'.

"── the chain: collect parent pointers into an OrderedCollection of caps (root last). Answers
    the chain, or nil if a parent is unreachable or depth exceeds MAX (structural). No sig work. ──"
cls class compile: 'collectChain: aCap in: anEnvelope
	| chain cur depth parentHash parent |
	chain := OrderedCollection new.
	cur := aCap. depth := 0.
	[ true ] whileTrue: [
		depth > EcCapability maxChainDepth ifTrue: [ ^ nil ].
		chain add: cur.
		parentHash := EcCapability parentOf: cur.
		parentHash isNil ifTrue: [ ^ chain ].            "no parent -> root reached"
		parent := anEnvelope includedForHash: parentHash.
		parent isNil ifTrue: [ ^ nil ].                  "unreachable parent -> structural fail"
		cur := parent. depth := depth + 1 ]'.

"── §5.5 M4 quorum for a multisig root ──"
"multiSignersOf: — the {signers:[b..]} EcArray of a multi-granter map, or nil."
cls class compile: 'multiSignersOf: aGmap
	| v |
	v := aGmap entryAt: ''signers''.
	(v isKindOf: EcArray) ifTrue: [ ^ v ].
	^ nil'.
"multiThresholdOf: — the {threshold:i} of a multi-granter map, or 0."
cls class compile: 'multiThresholdOf: aGmap
	| v |
	v := aGmap entryAt: ''threshold''.
	(v isKindOf: EcInt) ifTrue: [ ^ v value ].
	^ 0'.
"signerHashAt:index: — the idx-th signer hash ByteArray from {signers:[b..]}, or nil."
cls class compile: 'signerHashesOf: aGmap
	| arr out |
	arr := self multiSignersOf: aGmap.
	arr isNil ifTrue: [ ^ #() ].
	out := OrderedCollection new.
	arr items do: [ :e | (e isKindOf: EcByteString) ifTrue: [ out add: e bytes ] ifFalse: [ out add: nil ] ].
	^ out'.

"sigForSigner:target:signer:pubkey:in: — is there a system/signature in `included` on target
 (ByteArray), by signer (ByteArray), valid under pubkey?"
cls class compile: 'anyValidSigOnTarget: aTargetBytes signer: aSignerBytes pubkey: aPubkey in: anEnvelope
	^ anEnvelope included anySatisfy: [ :e |
		e type = ''system/signature''
			and: [ (e bytesAt: ''target'') = aTargetBytes
			and: [ (e bytesAt: ''signer'') = aSignerBytes
			and: [ EcIdentity verifySignatureEntity: e withPubkey: aPubkey ] ] ] ]'.

"countValidSigs:for:in: — count DISTINCT signers (each once) with a valid signature over the
 root''s content_hash (§5.5 M4)."
cls class compile: 'countValidSigsFor: aRoot signers: aGmap in: anEnvelope
	| rootHash seen count |
	rootHash := aRoot contentHash.
	seen := OrderedCollection new. count := 0.
	(self signerHashesOf: aGmap) do: [ :sh |
		(sh notNil and: [ (seen includes: sh) not ]) ifTrue: [
			| speer pk |
			speer := anEnvelope includedForHash: sh.
			speer ifNotNil: [
				pk := speer bytesAt: ''public_key''.
				(pk notNil and: [ self anyValidSigOnTarget: rootHash signer: sh pubkey: pk in: anEnvelope ])
					ifTrue: [ seen add: sh. count := count + 1 ] ] ] ].
	^ count'.

"noDuplicateSigners: — M3: no two signer hashes equal."
cls class compile: 'noDuplicateSigners: aGmap
	| hashes |
	hashes := (self signerHashesOf: aGmap) reject: [ :h | h isNil ].
	^ hashes asSet size = hashes size'.

"signerIsLocal:local:in: — M6: some signer''s resolved peer_id == local."
cls class compile: 'signerIsLocal: aGmap local: aLocal in: anEnvelope
	^ (self signerHashesOf: aGmap) anySatisfy: [ :sh |
		sh notNil and: [ (self resolvePeerOfHash: sh in: anEnvelope) = aLocal ] ]'.

"validityWindowOk: — §5.6: reject if now < not_before or now > expires_at."
cls class compile: 'validityWindowOk: aCap
	| now nb ex |
	now := self nowMillis.
	nb := aCap uintAt: ''not_before''.
	(nb notNil and: [ now < nb ]) ifTrue: [ ^ false ].
	ex := aCap uintAt: ''expires_at''.
	(ex notNil and: [ now > ex ]) ifTrue: [ ^ false ].
	^ true'.

"verifyMultisigRoot:local:in: — §3.6 M3 + §5.5 M4/M6."
cls class compile: 'verifyMultisigRoot: aRoot local: aLocal in: anEnvelope
	| gmap n k grantee |
	gmap := self granterValueOf: aRoot.
	(gmap isKindOf: EcMap) ifFalse: [ ^ false ].
	(EcCapability parentOf: aRoot) notNil ifTrue: [ ^ false ].   "M3: multisig cap MUST be root"
	n := (self signerHashesOf: gmap) size.
	n < 2 ifTrue: [ ^ false ].                                    "M3: N >= 2"
	k := self multiThresholdOf: gmap.
	(k < 2 or: [ k > n ]) ifTrue: [ ^ false ].                    "M3: K in [2, N]"
	(self noDuplicateSigners: gmap) ifFalse: [ ^ false ].         "M3: distinct signers"
	(self signerIsLocal: gmap local: aLocal in: anEnvelope) ifFalse: [ ^ false ].  "M6"
	(self validityWindowOk: aRoot) ifFalse: [ ^ false ].          "§5.6"
	grantee := EcCapability granteeOf: aRoot.
	(grantee isNil or: [ (anEnvelope includedForHash: grantee) isNil ]) ifTrue: [ ^ false ].
	^ (self countValidSigsFor: aRoot signers: gmap in: anEnvelope) >= k'.   "M4"

"verifySingleRoot:local:in: — §5.5 root-at-local: the single-sig granter''s peer_id == local."
cls class compile: 'verifySingleRoot: aRoot local: aLocal in: anEnvelope
	| p |
	p := self granterPeerOfCap: aRoot local: aLocal in: anEnvelope.
	^ p notNil and: [ p = aLocal ]'.

"── per-link signature (§5.5): cur''s single-sig granter signed cur''s hash. ──"
cls class compile: 'linkSigOk: aCap in: anEnvelope
	| g granterHash sig granter pk |
	g := self granterValueOf: aCap.
	(g isKindOf: EcByteString) ifFalse: [ ^ false ].
	granterHash := g bytes.
	sig := EcCapability findSignatureFor: aCap contentHash in: anEnvelope.
	sig isNil ifTrue: [ ^ false ].
	(sig bytesAt: ''signer'') = granterHash ifFalse: [ ^ false ].
	granter := anEnvelope includedForHash: granterHash.
	granter isNil ifTrue: [ ^ false ].
	pk := granter bytesAt: ''public_key''.
	pk isNil ifTrue: [ ^ false ].
	^ EcIdentity verifySignatureEntity: sig withPubkey: pk'.

"── §5.2/PR-3 grantee resolvable (MUST resolve to a system/peer). ──"
cls class compile: 'linkGranteeResolvable: aCap in: anEnvelope
	| grantee ent |
	grantee := EcCapability granteeOf: aCap.
	grantee isNil ifTrue: [ ^ false ].
	ent := anEnvelope includedForHash: grantee.
	ent isNil ifTrue: [ ^ false ].
	^ ent type = ''system/peer'''.

"── §5.5 per-link attenuation: a child''s grants MUST be a subset of the parent''s. ──"
"grantScope:key: — a grant''s handlers/resources/operations EcMap, or nil."
cls class compile: 'grantScope: aGrant key: aKey
	| v |
	(aGrant isKindOf: EcMap) ifFalse: [ ^ nil ].
	v := aGrant entryAt: aKey.
	(v isKindOf: EcMap) ifTrue: [ ^ v ].
	^ nil'.
"scopeSubsetChildFrame:parentFrame:child:parent:local: — every child include pattern is covered
 by the parent include set."
cls class compile: 'scopeSubsetChildFrame: cf parentFrame: pf child: cs parent: ps local: aLocal
	| cinc pinc |
	cinc := self scopeArray: cs key: ''include''.
	cinc isNil ifTrue: [ ^ true ].                      "no child includes -> vacuously subset"
	pinc := self scopeArray: ps key: ''include''.
	^ cinc items allSatisfy: [ :e |
		(e isKindOf: EcTextString) not
			or: [ | cp | cp := self canon: e string local: cf.
				cp notNil and: [ self coveredByArray: pinc frame: pf value: cp local: aLocal ] ] ]'.
"grantSubsetChildFrame:parentFrame:child:parent:local:"
cls class compile: 'grantSubsetChildFrame: cf parentFrame: pf child: cg parent: pg local: aLocal
	(self scopeSubsetChildFrame: cf parentFrame: cf
		child: (self grantScope: cg key: ''handlers'') parent: (self grantScope: pg key: ''handlers'') local: aLocal) ifFalse: [ ^ false ].
	(self scopeSubsetChildFrame: cf parentFrame: cf
		child: (self grantScope: cg key: ''operations'') parent: (self grantScope: pg key: ''operations'') local: aLocal) ifFalse: [ ^ false ].
	^ self scopeSubsetChildFrame: cf parentFrame: pf
		child: (self grantScope: cg key: ''resources'') parent: (self grantScope: pg key: ''resources'') local: aLocal'.
"isAttenuated:parent:local:in: — every child grant is a subset of some parent grant; child
 expiry <= parent expiry (if parent bounded)."
cls class compile: 'isAttenuated: aChild parent: aParent local: aLocal in: anEnvelope
	| cf pf cga pga pe cex |
	cf := self granterPeerOfCap: aChild local: aLocal in: anEnvelope.
	pf := self granterPeerOfCap: aParent local: aLocal in: anEnvelope.
	(cf isNil or: [ pf isNil ]) ifTrue: [ ^ false ].
	cga := self grantsOf: aChild.
	cga isNil ifTrue: [ ^ true ].
	pga := self grantsOf: aParent.
	pga isNil ifTrue: [ ^ false ].
	(cga items allSatisfy: [ :cg |
		pga items anySatisfy: [ :pg |
			self grantSubsetChildFrame: cf parentFrame: pf child: cg parent: pg local: aLocal ] ])
		ifFalse: [ ^ false ].
	pe := aParent uintAt: ''expires_at''.
	pe ifNotNil: [
		cex := aChild uintAt: ''expires_at''.
		cex isNil ifTrue: [ ^ false ].
		cex > pe ifTrue: [ ^ false ] ].
	^ true'.

"── §5.7 delegation caveats (a parent grant may bound its children) ──"
cls class compile: 'caveatsOk: aParent child: aChild depth: aDepth
	| cav mdd ttl cex ccr |
	cav := aParent field: ''delegation_caveats''.
	(cav isKindOf: EcMap) ifFalse: [ ^ true ].
	((cav entryAt: ''no_delegation'') isKindOf: EcBool)
		ifTrue: [ (cav entryAt: ''no_delegation'') value ifTrue: [ ^ false ] ].
	((cav entryAt: ''max_delegation_depth'') isKindOf: EcInt) ifTrue: [
		mdd := (cav entryAt: ''max_delegation_depth'') value.
		aDepth >= mdd ifTrue: [ ^ false ] ].
	((cav entryAt: ''max_delegation_ttl'') isKindOf: EcInt) ifTrue: [
		ttl := (cav entryAt: ''max_delegation_ttl'') value.
		cex := aChild uintAt: ''expires_at''.
		cex isNil ifTrue: [ ^ false ].
		ccr := (aChild uintAt: ''created_at'') ifNil: [ 0 ].
		(cex - ccr) > ttl ifTrue: [ ^ false ] ].
	^ true'.

"linkParentOk:parent:depth:local:in: — parent.grantee==child.granter AND child attenuates
 parent AND the parent''s §5.7 caveats permit the link."
cls class compile: 'linkParentOk: aChild parent: aParent depth: aDepth local: aLocal in: anEnvelope
	| pg cg |
	pg := EcCapability granteeOf: aParent.
	cg := self granterValueOf: aChild.
	(cg isKindOf: EcByteString) ifFalse: [ ^ false ].
	(pg isNil or: [ pg ~= cg bytes ]) ifTrue: [ ^ false ].
	(self isAttenuated: aChild parent: aParent local: aLocal in: anEnvelope) ifFalse: [ ^ false ].
	^ self caveatsOk: aParent child: aChild depth: aDepth'.

"verifyLink:index:chain:local:in: — one chain link''s verdict (#allow to continue)."
cls class compile: 'verifyLink: aCap index: idx chain: aChain local: aLocal in: anEnvelope
	| isLast |
	isLast := idx = (aChain size - 1).
	(self isMultisig: aCap)
		ifTrue: [ isLast ifFalse: [ ^ #authz ] ]         "multisig only at the root"
		ifFalse: [ (self linkSigOk: aCap in: anEnvelope) ifFalse: [ ^ #authz ] ].
	(self linkGranteeResolvable: aCap in: anEnvelope) ifFalse: [ ^ #unresolvable ].
	(self validityWindowOk: aCap) ifFalse: [ ^ #authz ].
	isLast ifFalse: [
		(self linkParentOk: aCap parent: (aChain at: idx + 2) depth: idx local: aLocal in: anEnvelope)
			ifFalse: [ ^ #authz ] ].
	^ #allow'.

"── §5.5 full chain verification -> #allow / #authz / #unresolvable ──"
cls class compile: 'verifyChain: aCap local: aLocal in: anEnvelope
	| chain root rootOk |
	chain := self collectChain: aCap in: anEnvelope.
	chain isNil ifTrue: [ ^ #authz ].
	root := chain last.
	rootOk := (self isMultisig: root)
		ifTrue: [ self verifyMultisigRoot: root local: aLocal in: anEnvelope ]
		ifFalse: [ self verifySingleRoot: root local: aLocal in: anEnvelope ].
	rootOk ifFalse: [ ^ #authz ].
	chain doWithIndex: [ :cap :i |
		| v |
		v := self verifyLink: cap index: i - 1 chain: chain local: aLocal in: anEnvelope.
		v = #allow ifFalse: [ ^ v ] ].
	^ #allow'.

"── §5.2 permission scope check (the resolved cap covers op + handler + resource targets) ──"
"execHandlerPath: — the exec.uri stripped to the bare §6.6 handler path."
cls class compile: 'execHandlerPath: anExec
	| u idx |
	u := (anExec textAt: ''uri'') ifNil: [ ^ '''' ].
	(u beginsWith: ''entity://'') ifTrue: [ u := u copyFrom: 10 to: u size ].
	(u beginsWith: ''/'') ifTrue: [ u := u copyFrom: 2 to: u size ].
	idx := u indexOf: $/.
	idx = 0 ifTrue: [ ^ u ].
	^ u copyFrom: idx + 1 to: u size'.

"execResourceTargets: — the exec.resource.targets Strings (an OrderedCollection), or nil if the
 exec carries no resource with targets (handler-only §4.4 request shape → vacuously covered)."
cls class compile: 'execResourceTargets: anExec
	| r targets out |
	r := anExec field: ''resource''.
	(r isKindOf: EcMap) ifFalse: [ ^ nil ].
	targets := r entryAt: ''targets''.
	(targets isKindOf: EcArray) ifFalse: [ ^ nil ].
	out := OrderedCollection new.
	targets items do: [ :t | (t isKindOf: EcTextString) ifTrue: [ out add: t string ] ].
	^ out'.

"resourceTargetCovered:local:granter:grant: — is one canonicalized target covered by the
 grant''s resources INCLUDE (framed by the granter peer) AND not by its EXCLUDE?"
cls class compile: 'resourceTargetCovered: aTarget local: aLocal granter: aGranter grant: aGrant
	| rs cv inc exc |
	rs := self grantScope: aGrant key: ''resources''.
	rs isNil ifTrue: [ ^ false ].
	cv := self canon: aTarget local: aLocal.
	cv isNil ifTrue: [ ^ false ].
	inc := self scopeArray: rs key: ''include''.
	(self coveredByArray: inc frame: aGranter value: cv local: aLocal) ifFalse: [ ^ false ].
	exc := self scopeArray: rs key: ''exclude''.
	^ (self coveredByArray: exc frame: aGranter value: cv local: aLocal) not'.

"grantCoversResource:exec:local:granter: — §5.2 resource dimension: EVERY target covered."
cls class compile: 'grant: aGrant coversResourceExec: anExec local: aLocal granter: aGranter
	| targets |
	targets := self execResourceTargets: anExec.
	targets isNil ifTrue: [ ^ true ].                   "no targets -> handler-only, vacuous"
	targets isEmpty ifTrue: [ ^ true ].
	^ targets allSatisfy: [ :t | self resourceTargetCovered: t local: aLocal granter: aGranter grant: aGrant ]'.

"── §5.2 peers dimension (target_peer): the EXECUTE''s own dispatch URI, NOT the resource-
    target field — §3.6 line 3228''s worked example (a peer serving /{remote_peer_id}/data/*
    locally) is exactly the case peers vs. resources must distinguish. ──"
"isPeerIdSeg: — §1.5: is aSeg a syntactically valid peer_id (Base58, >= 46 chars)? Mirrors
 EcPeerHandlers2.st>>isPeerIdSeg: (§1.4 R1 path validity) — duplicated here, not shared,
 because EcCapAuthz is deliberately EcPeer-free (see the class comment); sourced off
 EcBase58''s alphabet accessor rather than a third hardcoded literal."
cls class compile: 'isPeerIdSeg: aSeg
	| alpha |
	aSeg size < 46 ifTrue: [ ^ false ].
	alpha := EcBase58 alphabet.
	^ aSeg allSatisfy: [ :c | alpha includes: c ]'.
"firstSegment: — the leading path segment of a (possibly leading-/) URI body."
cls class compile: 'firstSegment: aUriBody
	| u idx |
	u := (aUriBody beginsWith: ''/'') ifTrue: [ aUriBody copyFrom: 2 to: aUriBody size ] ifFalse: [ aUriBody ].
	idx := u indexOf: $/.
	idx = 0 ifTrue: [ ^ u ].
	^ u copyFrom: 1 to: idx - 1'.
"execTargetPeer:local: — §5.2 target_peer = extract_peer(execute.data.uri, local_peer_id)
 (line 2196): the exec.uri''s first path segment if it is a syntactically valid peer_id,
 else local."
cls class compile: 'execTargetPeer: anExec local: aLocal
	| u first |
	u := (anExec textAt: ''uri'') ifNil: [ ^ aLocal ].
	(u beginsWith: ''entity://'') ifTrue: [ u := u copyFrom: 10 to: u size ].
	first := self firstSegment: u.
	^ (self isPeerIdSeg: first) ifTrue: [ first ] ifFalse: [ aLocal ]'.
"grant:peersOk:target: — grant.peers or the spec default {include: [local_peer_id]} (line
 2378) must cover target_peer; an id-scope dimension (literal match like `operations`, F40,
 kind: #idScope). Peer IDs are explicit, no `self` alias — so the omitted-scope default
 (no exclude, include = [local]) reduces to plain equality against local."
cls class compile: 'grant: aGrant peersOk: aLocal target: aTargetPeer
	| ps |
	ps := self grantScope: aGrant key: ''peers''.
	ps isNil ifTrue: [ ^ aTargetPeer = aLocal ].
	^ self matchesScope: ps frame: aLocal value: aTargetPeer local: aLocal kind: #idScope'.

"grantCoversOpHandler:exec:local:granter:targetPeer: — one grant covers operation + handler +
 peers + resources (§5.2, all four dimensions unconditionally, line 2059-2083/2390). §F40:
 `operations`/`peers` are id-scope dimensions (literal match, kind: #idScope); `handlers` is a
 path-scope dimension (canonicalize + §5.4 match, kind: #pathScope) — the dimensions MUST NOT
 be interchanged."
cls class compile: 'grant: aGrant coversOpHandlerExec: anExec local: aLocal granter: aGranter targetPeer: aTargetPeer
	(self matchesScope: (self grantScope: aGrant key: ''operations'')
		frame: aLocal value: (anExec textAt: ''operation'') local: aLocal kind: #idScope) ifFalse: [ ^ false ].
	(self matchesScope: (self grantScope: aGrant key: ''handlers'')
		frame: aLocal value: (self execHandlerPath: anExec) local: aLocal kind: #pathScope) ifFalse: [ ^ false ].
	(self grant: aGrant peersOk: aLocal target: aTargetPeer) ifFalse: [ ^ false ].
	^ self grant: aGrant coversResourceExec: anExec local: aLocal granter: aGranter'.

"checkPermission:cap:local:in: — ALLOW iff some grant of the resolved LEAF cap covers
 operation + handler + peer + resource targets (resources granter-framed, §PR-8)."
cls class compile: 'checkPermission: anExec cap: aCap local: aLocal in: anEnvelope
	| grants granter targetPeer |
	grants := self grantsOf: aCap.
	grants isNil ifTrue: [ ^ false ].
	granter := self granterPeerOfCap: aCap local: aLocal in: anEnvelope.
	targetPeer := self execTargetPeer: anExec local: aLocal.
	^ grants items anySatisfy: [ :g |
		self grant: g coversOpHandlerExec: anExec local: aLocal granter: granter targetPeer: targetPeer ]'.

"── §5.1 revocation: deny iff a revocation marker is bound at
    /<local>/system/capability/revocations/<hex(H)> for H in {leaf cap hash, chain-root hash}. ──"
"hexOf: — LOWERCASE hex (§3.4/§3.5 tree-path convention, A-CL-009). printPaddedWith: yields
 UPPERCASE, which would never match a lowercase revocation-marker path — force lowercase so the
 §5.1 marker lookup finds what handleCapRevoke bound."
cls class compile: 'hexOf: aByteArray
	| s |
	s := WriteStream on: String new.
	aByteArray do: [ :b | s nextPutAll: (b printPaddedWith: $0 to: 2 base: 16) asLowercase ].
	^ s contents'.
cls class compile: 'markerAt: aHashBytes local: aLocal store: aStore
	| path |
	aHashBytes isNil ifTrue: [ ^ false ].
	path := ''/'', aLocal, ''/system/capability/revocations/'', (self hexOf: aHashBytes).
	^ (aStore getAt: path) notNil'.
cls class compile: 'capRevoked: aCap local: aLocal store: aStore in: anEnvelope
	| chain |
	(self markerAt: aCap contentHash local: aLocal store: aStore) ifTrue: [ ^ true ].
	chain := self collectChain: aCap in: anEnvelope.
	chain ifNil: [ ^ false ].
	^ self markerAt: chain last contentHash local: aLocal store: aStore'.

"── §6.2 request/delegate mint-bounded check (the keystone accept-path the reject-only oracle
    vectors cannot cover): every requested grant MUST be a subset of some grant on the presented
    cap. No presented cap -> allow (connection-seed bounded). ──"
cls class compile: 'requestedGrants: aGrantsArray boundedBy: anExec local: aLocal in: anEnvelope
	| capHash cap presented |
	capHash := anExec bytesAt: ''capability''.
	capHash isNil ifTrue: [ ^ true ].                   "no cap presented -> seed-bounded"
	cap := anEnvelope includedForHash: capHash.
	cap isNil ifTrue: [ ^ true ].                       "unresolved -> defer to authz"
	presented := self grantsOf: cap.
	presented isNil ifTrue: [ ^ false ].
	^ aGrantsArray items allSatisfy: [ :cg |
		presented items anySatisfy: [ :pg |
			self grantSubsetChildFrame: aLocal parentFrame: aLocal child: cg parent: pg local: aLocal ] ]'.

"── the §5.2 dispatch authorization gate (replaces the S3 EcCapability>>verifyAuthz: stub for
    the full-chain path). Answers a verdict Symbol; the dispatcher maps it to a status. ──"
"authorizeExec:local:store:in: — resolve the presented cap, run §5.1 revocation + §4.10(b)
 depth pre-check, verify the chain (root trust + per-link sig/grantee/expiry/attenuation), bind
 grantee==author, then check the grant scope covers operation+handler+resource. A resolved+
 verified cap that does not cover the request is the default DENY (#authz -> 403)."
cls class compile: 'authorizeExec: anExec local: aLocal store: aStore in: anEnvelope
	| capHash cap v author grantee |
	capHash := anExec bytesAt: ''capability''.
	capHash isNil ifTrue: [ ^ #authz ].
	cap := anEnvelope includedForHash: capHash.
	cap isNil ifTrue: [ ^ #authz ].
	(self capRevoked: cap local: aLocal store: aStore in: anEnvelope) ifTrue: [ ^ #authz ].
	(EcCapability exceedsDepth: cap in: anEnvelope) ifTrue: [ ^ #depth ].
	v := self verifyChain: cap local: aLocal in: anEnvelope.
	v = #allow ifFalse: [ ^ v ].
	"grantee binding: the leaf cap''s grantee == the request author (§5.2)."
	author := anExec bytesAt: ''author''.
	author isNil ifTrue: [ ^ #authz ].
	grantee := EcCapability granteeOf: cap.
	(grantee isNil or: [ grantee ~= author ]) ifTrue: [ ^ #authz ].
	(self checkPermission: anExec cap: cap local: aLocal in: anEnvelope) ifFalse: [ ^ #authz ].
	^ #allow'.

'EntityCore-Capability:EcCapAuthz installed'
