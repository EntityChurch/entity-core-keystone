"entity-core-protocol-smalltalk — L3 capability CHAIN verification (§5.2 / §5.5 / §PR-8): the
AUTHZ interior beyond the S3 depth/grantee primitives (EcCapability). Ported NATIVELY (message-
sends over EcEntity / EcValue objects — NOT transpiled) from the already-converged cohort §5.5
logic (forth src/capauthz.fs / the Rexx Cap_VerifyChain). EcCapability supplies the trichotomy
scaffold + the §4.10(b) depth pre-check; THIS class adds the full chain walk (root single-sig +
multisig M3/M4/M6), per-link signature + attenuation + grantee/expiry, §5.7 caveats, §5.1
revocation, and the §5.2 permission-scope gate the dispatcher maps to a status — ALL FOUR grant
dimensions (handlers, operations, peers, resources; 2026-08-13 fix, see
protocol-generator/shared/findings/peers-grant-dimension-oracle-gap.md — `peers`
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

"── §5.4 canonicalization, TOTAL (0.8.2.20). A bare (non-absolute) path is peer-rooted
    /<local>/<path>; the three reserved prefixes (./ ../ */) have no canonical form and answer
    the SENTINEL rather than nil.

    MATCHING NOTHING IS THE RIGHT ANSWER IN AN INCLUDE AND THE OPPOSITE OF IT IN AN EXCLUDE,
    which is why the nil return had to go: a grant whose resources exclude is `../nope` carved
    out NOTHING, so the grant was silently wider than its author wrote. The sentinel is what
    lets the exclude-reading call sites tell the two positions apart while the matcher stays
    uniform over its operands.

    neverMatch is unreachable as a real canonical path BY CONSTRUCTION: its first segment
    would have to be a peer_id, and isPeerIdSeg: wants >= 46 Base58 characters while $- is not
    in the Base58 alphabet at all. ──"
cls class compile: 'neverMatch  ^ ''/never-match'''.
cls class compile: 'canon: aPath local: aLocalPeerId
	((aPath beginsWith: ''./'') or: [ aPath beginsWith: ''../'' ]) ifTrue: [ ^ self neverMatch ].
	(aPath beginsWith: ''*/'') ifTrue: [ ^ self neverMatch ].
	(aPath beginsWith: ''/'') ifTrue: [ ^ aPath ].
	^ ''/'', aLocalPeerId, ''/'', aPath'.

"── §5.4 pattern matching (recursive /*/ + /* suffix). Both path + pattern are already
    canonicalized (absolute /<peer>/...). ──"
cls class compile: 'path: aPath matchesPattern: aPat
	"THE SENTINEL NEVER MATCHES, IN EITHER OPERAND (§5.4, 0.8.2.20) — and it is a MATCHER
	 RULE asked FIRST, not a property the value happens to have. The arm below answers true
	 for a bare *, so safety must not rest on /never-match merely looking unmatchable."
	(aPath = self neverMatch or: [ aPat = self neverMatch ]) ifTrue: [ ^ false ].
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
			exc := self scopeArray: aScopeMap key: ''exclude''.
			(self excludeUnmatchable: exc frame: aFrame) ifTrue: [ ^ false ].
			cv := self canon: aVal local: aFrame.
			inc := self scopeArray: aScopeMap key: ''include''.
			(self coveredByArray: inc frame: aFrame value: cv local: aLocal) ifFalse: [ ^ false ].
			^ (self coveredByArray: exc frame: aFrame value: cv local: aLocal) not ]'.

"excludeUnmatchable:frame: — does any pattern in the exclude array canonicalize to the §5.4
 sentinel? AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21): the sentinel is fail-CLOSED
 in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an exclude (carves
 out nothing), so the reading is chosen where the POSITION is known — here — and the matcher
 stays uniform over its operands.

 ASKED ONLY ON THE PATH-SCOPE ARM (0.8.2.24, N2/N3), which is why it sits inside the kind
 dispatch rather than above it. neverMatch is a §5.4 PATH-canonicalization artifact with no
 meaning on an id-scope dimension, whose patterns are literal identifiers §5.2's own id-scope
 arm forbids putting through the §5.4 transforms. Asked of `operations`, an exclude of
 star-slash-apply — an ordinary namespaced operation name, a literal matching nothing under the
 id-scope grammar — canonicalizes to the sentinel and would deny EVERY operation."
cls class compile: 'excludeUnmatchable: anArray frame: aFrame
	anArray isNil ifTrue: [ ^ false ].
	^ anArray items anySatisfy: [ :e |
		(e isKindOf: EcTextString) and: [ (self canon: e string local: aFrame) = self neverMatch ] ]'.

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

"temporalFieldsRepresentable: — §6.2 CAP-6a. True iff every temporal field on a RECEIVED
 token is either absent (legal) or representable as a uint64.

 This is the reader-side half of CAP-6 and it is where a peer fails OPEN. EcEntity>>uintAt:
 answers nil BOTH when a field is ABSENT and when it is PRESENT but not an EcInt; and
 Smalltalk Integers are arbitrary-precision, so an EcInt can itself carry a negative or a
 >2^64 magnitude that the range comparison then reads as an ordinary value. Either way the
 expiry check could not fire and a hostile expires_at:-1 was honored with 200. §6.2 CAP-6a
 is explicit: such a token `is malformed. A verifier MUST refuse it and MUST NOT treat the
 unrepresentable field as absent.` An absent field stays legal and is NOT rejected here.

 PRESENCE is asked of `hasField:` and REPRESENTABILITY of `uintAt:` -- deliberately, and it
 is the whole point: the two disagree exactly on the malformed case, and the guard IS that
 disagreement.

 PRESENCE MUST BE `hasField:`, NOT `field: ... ifNotNil:`. EcEntity>>field: answers
 `EcAbsent default` for a missing key, never nil -- the pure-object absent sentinel this
 peer uses everywhere (A-ST-000). Written the obvious way, `v ifNotNil:` is therefore
 ALWAYS true, every absent temporal field reads as present-but-unrepresentable, and the
 guard denies every capability the peer has ever been shown. Measured: 176 FAILs, with the
 handshake still green and every authenticated request 403.

 That is the SAME defect this guard exists to fix, one level up. CAP-6a is about an
 accessor whose `nothing` conflates absent with malformed; this is about an accessor whose
 `something` conflates absent with present. The absent spelling is a per-peer decision and
 has to be read from the peer, not assumed.

 Refusal must be the §5.2 capability_denied disposition (a status-bearing response), never
 a decode-layer silent drop or a transport close."
cls class compile: 'temporalFieldsRepresentable: aCap
	#(''expires_at'' ''not_before'' ''created_at'') do: [ :k |
		| n |
		(aCap hasField: k) ifTrue: [
			n := aCap uintAt: k.
			(n isNil or: [ n < 0 or: [ n >= 18446744073709551616 ] ]) ifTrue: [ ^ false ] ] ].
	^ true'.

"addTtl:to: — §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp
 relative to createdAt. Rule 3: a conversion that is not representable is treated as ABSENT
 (nil) exactly as a null term is -- it MUST NOT wrap and MUST NOT saturate to a
 representable maximum, since saturation manufactures expires_at == 2^64-1, a finite bound
 no reader can distinguish from a deliberate one. Smalltalk Integers do not wrap, so this
 is a deliberate range check.

 ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
 yielding createdAt (expire immediately). The absent field is the only `no bound` spelling,
 and falling out of the arithmetic is what keeps the two from collapsing."
cls class compile: 'addTtl: aTtl to: createdAt
	| sum |
	aTtl < 0 ifTrue: [ ^ nil ].
	sum := createdAt + aTtl.
	sum >= 18446744073709551616 ifTrue: [ ^ nil ].
	^ sum'.

"validityWindowOk: — §5.6: reject if now < not_before or now > expires_at."
cls class compile: 'validityWindowOk: aCap
	| now nb ex |
	"CAP-6a FIRST (§6.2): a present-but-unrepresentable expires_at / not_before /
	 created_at is MALFORMED and must be refused outright. This has to run BEFORE the two
	 range checks below, because those use uintAt:, which cannot tell `absent` from
	 `present but not a uint64` -- so on their own they skip the check and honor the token
	 (fail-open)."
	(self temporalFieldsRepresentable: aCap) ifFalse: [ ^ false ].
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
"execHandlerPath: — the exec.uri stripped to the bare §6.6 handler path.

 THE LEADING SEGMENT IS DROPPED ONLY IF IT IS A PEER ID. §1.4 admits three spellings of the
 same address — `system/tree`, `/{peer}/system/tree` and `entity://{peer}/system/tree` — and
 this used to drop the first segment unconditionally, so the PEER-RELATIVE spelling came back
 as `tree`. That is the spelling validate-peer and every wire probe use.

 What it cost, and why it survived: the handlers dimension then compared `/{local}/tree`
 against a grant naming `system/tree`, so ANY caller-supplied grant written the way §3.7 and
 §6.2 write them was denied 403 — a self-minted token presented straight back to this peer
 could not authorize anything. It stayed invisible because the shipped seed policy and the
 oracle's own caps grant handlers as `*`, which is vacuous over the value: the dimension
 passed for a reason unrelated to what it compares. Measured 2026-09-15 by tracing the deny
 site, after reading it had cleared the peer twice.

 isPeerIdSeg: is the same predicate execTargetPeer: below already uses — a predicate written
 for one caller's path form is not reusable by a second caller with a different one, so the
 two call sites now share it rather than each carrying an assumption."
cls class compile: 'execHandlerPath: anExec
	| u idx first |
	u := (anExec textAt: ''uri'') ifNil: [ ^ '''' ].
	(u beginsWith: ''entity://'') ifTrue: [ u := u copyFrom: 10 to: u size ].
	(u beginsWith: ''/'') ifTrue: [ u := u copyFrom: 2 to: u size ].
	idx := u indexOf: $/.
	idx = 0 ifTrue: [ ^ u ].
	first := u copyFrom: 1 to: idx - 1.
	(self isPeerIdSeg: first) ifFalse: [ ^ u ].
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
	exc := self scopeArray: rs key: ''exclude''.
	"An unmatchable GRANT exclude DENIES (0.8.2.21), and it is asked FIRST, before any target:
	 the coverage tests below are correct in isolation and are simply never reached on a
	 sentinel, because path:matchesPattern: answers false for it. UNGUARDED ON SCOPE TYPE on
	 purpose, unlike matchesScope''s: `rs` here is always the RESOURCES dimension, which §5.2
	 fixes as path-scope, so the type test would be a constant. Naming the dimension in the
	 selector is what makes that checkable."
	(self excludeUnmatchable: exc frame: aGranter) ifTrue: [ ^ false ].
	cv := self canon: aTarget local: aLocal.
	inc := self scopeArray: rs key: ''include''.
	(self coveredByArray: inc frame: aGranter value: cv local: aLocal) ifFalse: [ ^ false ].
	^ (self coveredByArray: exc frame: aGranter value: cv local: aLocal) not'.

"execResourceExcludes: — the exec.resource.exclude Strings (the CALLER's own carve-out), or an
 empty collection. Written in the REQUEST, about paths in THIS peer's namespace, so it frames
 against the LOCAL peer and never against the granter — framing a caller exclude against the
 granter is the same defect as framing a grant pattern against the verifier, one operand over."
cls class compile: 'execResourceExcludes: anExec
	| r ex out |
	out := OrderedCollection new.
	r := anExec field: ''resource''.
	(r isKindOf: EcMap) ifFalse: [ ^ out ].
	ex := r entryAt: ''exclude''.
	(ex isKindOf: EcArray) ifFalse: [ ^ out ].
	ex items do: [ :t | (t isKindOf: EcTextString) ifTrue: [ out add: t string ] ].
	^ out'.

"grantCoversResource:exec:local:granter: — §5.2 resource dimension: EVERY target the CALLER
 did not carve out is covered.

 A TARGET THE CALLER EXCLUDED IS ADMITTED RATHER THAN CHECKED: the caller narrowed it out of
 its own request, so there is nothing there to authorize. That is what lets
 `targets:[qA] exclude:[qA]` reach the handler and be answered 400 path_required instead of
 403 — and it is also what makes §6.3's handler-level check load-bearing rather than
 redundant, because the dispatch check no longer sees the excluded path at all."
cls class compile: 'grant: aGrant coversResourceExec: anExec local: aLocal granter: aGranter
	| targets callerExcl |
	targets := self execResourceTargets: anExec.
	targets isNil ifTrue: [ ^ true ].                   "no targets -> handler-only, vacuous"
	targets isEmpty ifTrue: [ ^ true ].
	callerExcl := self execResourceExcludes: anExec.
	^ targets allSatisfy: [ :t |
		(callerExcl notEmpty and: [ self coveredByArray: (self textArrayOf: callerExcl)
			frame: aLocal value: (self canon: t local: aLocal) local: aLocal ])
			or: [ self resourceTargetCovered: t local: aLocal granter: aGranter grant: aGrant ] ]'.

"textArrayOf: — wrap a collection of Strings as the EcArray shape coveredByArray: reads, so
 the caller-exclude arm goes through the SAME matcher as every grant pattern rather than a
 second copy of it."
cls class compile: 'textArrayOf: aStringCollection
	^ EcArray items: (aStringCollection collect: [ :s | EcTextString string: s ]) asArray'.

"checkPathPermission:operation:path:local:cap: — §6.3's handler-level path check, AND IT IS NOT
 A SECONDARY CHECK (0.8.2.20). It is the enforcement wherever the subject is derived after
 dispatch, because the dispatch-level check can be made VACUOUS by caller-controlled input: a
 caller who excludes the one target its capability does not cover removes that target from
 checkPermission's view entirely, and a handler that then acts on it has authorized nothing.

 THREE DIMENSIONS, NOT FOUR, and the LOCAL frame — both from §6.3's own signature,
 matches_scope(canonical_path, grant.resources, path-scope, local_peer_id), which has no
 granter parameter to pass. `peers` is not consulted: the path is local by construction here,
 since §1.4's inbound rule refused a foreign namespace before any handler ran.

 There is no caller-exclude set at this call site: the subject is a single concrete path and
 the caller's exclusions were applied in deriving it, so every grant exclude covering the
 subject denies — which matchesScope already implements, including 0.8.2.21's sentinel rule."
cls class compile: 'checkPathPermission: aCap operation: anOp path: aPath local: aLocal handler: aHandlerPattern
	| grants |
	aCap isNil ifTrue: [ ^ true ].                      "no presented authority to check against"
	grants := self grantsOf: aCap.
	grants isNil ifTrue: [ ^ false ].
	^ grants items anySatisfy: [ :g |
		(self matchesScope: (self grantScope: g key: ''handlers'')
			frame: aLocal value: aHandlerPattern local: aLocal kind: #pathScope)
		and: [ (self matchesScope: (self grantScope: g key: ''operations'')
			frame: aLocal value: anOp local: aLocal kind: #idScope)
		and: [ self matchesScope: (self grantScope: g key: ''resources'')
			frame: aLocal value: aPath local: aLocal kind: #pathScope ] ] ]'.

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
