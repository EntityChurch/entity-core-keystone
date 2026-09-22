"entity-core-protocol-smalltalk — the S4 handler surface, compiled onto EcPeer (EntityCore-Peer).
Cross-FILE class references by global name are fine (A-ST-010): EcPeer is globally registered by
the time this doit runs (loads after EcPeer.st + EcPeerHandlers.st).

Adds beyond the S3 minimal connect + tree-get:
  - §6.3 tree put (+ §3.9 CAS + §9.5a deletion-marker) and tree listing (immediate children).
  - §6.2 system/capability: request (the mint-bounded accept-path), configure, revoke, delegate(501).
  - §6.2 system/handler: register / unregister (the five-write protocol) — NORMATIVE under core.
  - system/type (validate op -> 501; the type floor is published as tree entities, not via a handler).
  - §6.2 handler-manifest interfaces + N2 dispatch entities publishing.
  - the §4.5 negotiation key_type reject (AGILITY-UNKNOWN-1) beyond the S3 disjointness check.

Handlers are message-sends receiving an EcHandlerContext, answering an EcHandlerResult.

LIVE-IMAGE NOTE: EcCapAuthz / EcCoreTypes / EcVal / EcEntity resolve at send-time."

| ecPeer |
ecPeer := Smalltalk at: #EcPeer.

"── validate / open-grants flags (set by bin/peer.st before bootstrap) ──"
ecPeer compile: 'validate: aBool  validateOn := aBool'.
ecPeer compile: 'openGrants: aBool  openGrantsOn := aBool'.
ecPeer compile: 'validateOn  ^ validateOn == true'.
ecPeer compile: 'openGrantsOn  ^ openGrantsOn == true'.

"── path helpers ──"
"peerAbs: — /<local>/<sub> (the peer-rooted absolute form a tree.get canonicalizes to)."
ecPeer compile: 'peerAbs: aSub  ^ ''/'', identity peerId, ''/'', aSub'.
"capAbs: — /<local>/system/capability/<sub>."
ecPeer compile: 'capAbs: aSub  ^ ''/'', identity peerId, ''/system/capability/'', aSub'.
"treeCanon: — a bare path is peer-rooted /<local>/<path>; an absolute path is returned as-is."
ecPeer compile: 'treeCanon: aPath
	(aPath notEmpty and: [ aPath first = $/ ]) ifTrue: [ ^ aPath ].
	^ ''/'', identity peerId, ''/'', aPath'.
"hexOf: — LOWERCASE-hex encode a ByteArray (§3.4/§3.5 tree-path convention, A-CL-009). NB:
 `printPaddedWith:to:base:` yields UPPERCASE hex, which mismatches the oracle''s lowercase
 revocation/signature path hex → a revoke marker bound uppercase is never found by a
 lowercase tree.get (the revoke_happy_path 404). Force lowercase."
ecPeer compile: 'hexOf: aByteArray
	| s |
	s := WriteStream on: String new.
	aByteArray do: [ :b | s nextPutAll: (b printPaddedWith: $0 to: 2 base: 16) asLowercase ].
	^ s contents'.

"── §1.4 R1 path validity: no NUL, no empty/./.. segments; a leading-/ path''s first segment
    MUST be a valid peer_id (Base58, >= 46 chars). ──"
ecPeer compile: 'segBad: aSeg
	aSeg isEmpty ifTrue: [ ^ true ].
	(aSeg = ''.'' or: [ aSeg = ''..'' ]) ifTrue: [ ^ true ].
	^ false'.
ecPeer compile: 'isPeerIdSeg: aSeg
	| b58 |
	aSeg size < 46 ifTrue: [ ^ false ].
	b58 := ''123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz''.
	^ aSeg allSatisfy: [ :c | b58 includes: c ]'.
ecPeer compile: 'pathFlexOk: aPath
	| body segs |
	aPath isEmpty ifTrue: [ ^ false ].
	(aPath includes: (Character value: 0)) ifTrue: [ ^ false ].
	aPath first = $/ ifTrue: [
		| rest firstSeg idx |
		rest := aPath copyFrom: 2 to: aPath size.
		idx := rest indexOf: $/.
		firstSeg := idx = 0 ifTrue: [ rest ] ifFalse: [ rest copyFrom: 1 to: idx - 1 ].
		(self isPeerIdSeg: firstSeg) ifFalse: [ ^ false ] ].
	"walk the segments (skip a single leading /, strip a single trailing /)."
	body := aPath first = $/ ifTrue: [ aPath copyFrom: 2 to: aPath size ] ifFalse: [ aPath ].
	(body notEmpty and: [ body last = $/ ]) ifTrue: [ body := body copyFrom: 1 to: body size - 1 ].
	"findTokens: collapses empty segments, so reject an explicit // (empty segment) by scanning."
	((body indexOfSubCollection: ''//'') > 0) ifTrue: [ ^ false ].
	segs := body findTokens: ''/''.
	^ segs allSatisfy: [ :seg | (self segBad: seg) not ]'.

"── raw params reads: the register-request/manifest fields are plain EcMaps, not nested
    {type,data,hash} entities. mapText:/mapField: read off an EcMap value directly. ──"
ecPeer compile: 'mapText: aMap key: aKey
	| v |
	(aMap isKindOf: EcMap) ifFalse: [ ^ nil ].
	v := aMap entryAt: aKey.
	(v isKindOf: EcTextString) ifTrue: [ ^ v string ].
	^ nil'.
ecPeer compile: 'mapField: aMap key: aKey
	(aMap isKindOf: EcMap) ifFalse: [ ^ nil ].
	^ aMap entryAt: aKey'.

"── the response included builder helpers ──"
ecPeer compile: 'includeAuthority: aResult token: aToken
	aResult includeInResponse: aToken.
	aResult includeInResponse: (identity signatureEntityFor: aToken contentHash).
	aResult includeInResponse: identity peerEntity.
	^ aResult'.

"── §4.5 negotiation: reject a hello whose peer_id multihash key_type prefix is NOT ed25519. ──"
ecPeer compile: 'helloKeyTypeBad: aParams
	| pid decoded |
	aParams isNil ifTrue: [ ^ false ].
	pid := aParams textAt: ''peer_id''.
	pid isNil ifTrue: [ ^ false ].
	decoded := [ EcPeerId parseKeyType: pid ] on: Error do: [ :e | ^ false ].
	decoded isNil ifTrue: [ ^ false ].
	^ decoded ~= EcIdentity keyTypeEd25519'.

"════════════════════════ tree put / listing (§6.3) ════════════════════════"
"treeEntityFromParams: — the params.entity value (a nested wire map or a bytes-CBOR blob) as
 an EcEntity, or nil."
ecPeer compile: 'treeEntityFromParams: aParamsEntity
	| etv |
	etv := aParamsEntity field: ''entity''.
	etv isAbsent ifTrue: [ ^ nil ].
	^ [ EcEntity fromWireValue: etv ] on: EntityCoreError do: [ :e | nil ]'.

"hashDigestLenFor: — digest byte length for a content_hash_format code per the §1.2 seed
 table, or nil when this peer cannot VERIFY that code. The total wire length is this plus the
 varint prefix, which is not a constant of the code (§7.3): codes >= 0x80 occupy more than one
 byte."
ecPeer compile: 'hashDigestLenFor: aCode
	aCode = 0 ifTrue: [ ^ 32 ].
	aCode = 1 ifTrue: [ ^ 48 ].
	^ nil'.

"admitPut: — §6.3''s put admission ladder (normative, 0.8.2.11).

 put is a RECEIPT path: the submitter authors the entity, the peer validates what it received
 (§1.8 item 1) and MUST NOT author a submitted entity''s content_hash on the submitter''s
 behalf. Two ordered steps:

   1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any CBOR value;
      null is a legal payload), and a `content_hash` that is a well-formed system/hash whose
      total byte length matches its format code (§1.2). Any failure -> 400 invalid_request. A
      well-formed hash naming a format code this peer cannot verify is the separate §1.2
      ingest-dispatch case -> 400 unsupported_content_hash_format.
   2. HASH — carried content_hash vs content_hash({type, data}) -> 400 hash_mismatch.

 Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2''s inputs are
 exactly what step 1 establishes, so a submission that is both malformed and mis-hashed is
 step 1''s and answers invalid_request.

 Structural admission is not semantic validation: `data` is never checked against the type
 named by `type`.

 Answers an EcEntity, or an EcHandlerResult when refused."
ecPeer compile: 'admitPut: aValue
	| typeV dataV chV carried decoded code consumed digestLen |
	(aValue isKindOf: EcMap) ifFalse: [
		^ EcHandlerResult error: 400 code: ''invalid_request'' message: ''put: entity is not a map'' ].
	typeV := aValue entryAt: ''type''.
	((typeV isKindOf: EcTextString) and: [ typeV string notEmpty ]) ifFalse: [
		^ EcHandlerResult error: 400 code: ''invalid_request''
			message: ''put: entity.type absent, empty or not a text string'' ].
	"Presence, not truthiness: a CBOR null is a legal `data` payload, and entryAt: answers the
	 null NODE for it rather than nil (A-ST-000 — the absent sentinel is the peer''s, not the
	 language''s)."
	dataV := aValue entryAt: ''data''.
	dataV isNil ifTrue: [
		^ EcHandlerResult error: 400 code: ''invalid_request'' message: ''put: entity.data absent'' ].
	chV := aValue entryAt: ''content_hash''.
	((chV isKindOf: EcByteString) and: [ chV bytes notEmpty ]) ifFalse: [
		^ EcHandlerResult error: 400 code: ''invalid_request''
			message: ''put: entity.content_hash absent or not a byte string'' ].
	carried := chV bytes.
	decoded := [ EcVarint decodeFrom: carried at: 1 ] on: Error do: [ :e | nil ].
	decoded isNil ifTrue: [
		^ EcHandlerResult error: 400 code: ''invalid_request''
			message: ''put: entity.content_hash is not a well-formed system/hash'' ].
	code := decoded key. consumed := decoded value.
	digestLen := self hashDigestLenFor: code.
	"§1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT invalid_request:
	 the shape is fine, the algorithm is what we lack."
	digestLen isNil ifTrue: [
		^ EcHandlerResult error: 400 code: ''unsupported_content_hash_format''
			message: ''put: unsupported content_hash_format'' ].
	carried size = (consumed + digestLen) ifFalse: [
		^ EcHandlerResult error: 400 code: ''invalid_request''
			message: ''put: content_hash length does not match its format code'' ].
	(EcContentHash of: typeV string data: dataV format: code) = carried ifFalse: [
		^ EcHandlerResult error: 400 code: ''hash_mismatch''
			message: ''put: content_hash does not match content_hash({type, data})'' ].
	"The carried hash IS the entity''s address; recomputing it into the store would be the
	 authoring arm §6.3 forbids."
	^ EcEntity admittedType: typeV string data: dataV hash: carried'.

"effectiveTargetsOf: — §5.2's effective target list (0.8.2.20): the caller's OWN
 `resource.exclude` removes entries from the request BEFORE anything else looks at it.

 Survivors keep the CALLER'S OWN SPELLING, not a canonical form — 0.8.2.21 is explicit that
 effective_targets yields RAW survivors, and it is load-bearing here because the value flows on
 to treeCanon: and to the store, which canonicalize for themselves.

 Answers #absent | #empty | #ambiguous | the single survivor String, AND THE FIRST TWO ARE
 DIFFERENT REQUESTS rather than two spellings of one (0.8.2.24 N7, 0.8.2.25 N10). §3.3's `an
 empty effective list IS the absent case` is scoped to an operation that REQUIRES a resource;
 `get` does not, and EXTENSION-TREE §2.2a declares it resource-OPTIONAL and BROAD-RESULT —
 absent answers the root listing, self-excluded answers path_required, because serving the root
 listing to a caller who excluded the one path it named answers something WIDER than the
 request. Collapsing the two here would delete the discriminator before any handler could read
 it, and the refusal arm would become dead code only a wire drive could detect.

 The caller-exclude arm is fail-OPEN on an unmatchable pattern: §5.4's table rules it separately
 from the grant arm, canon answers the sentinel and path:matchesPattern: then answers false, so
 the target simply survives. That asymmetry is 0.8.2.21's whole point and it is inherited from
 the matcher rather than restated here."
ecPeer compile: 'effectiveTargetsOf: anExec
	| resource targets excl surv local |
	resource := anExec field: ''resource''.
	(resource isKindOf: EcMap) ifFalse: [ ^ #absent ].
	targets := resource entryAt: ''targets''.
	(targets isKindOf: EcArray) ifFalse: [ ^ #absent ].
	local := identity peerId.
	excl := OrderedCollection new.
	(resource entryAt: ''exclude'') ifNotNil: [ :ex |
		(ex isKindOf: EcArray) ifTrue: [
			ex items do: [ :t | (t isKindOf: EcTextString) ifTrue: [ excl add: t string ] ] ] ].
	surv := OrderedCollection new.
	targets items do: [ :t |
		(t isKindOf: EcTextString) ifTrue: [
			| cv |
			cv := EcCapAuthz canon: t string local: local.
			(excl anySatisfy: [ :x | EcCapAuthz path: cv matchesPattern: (EcCapAuthz canon: x local: local) ])
				ifFalse: [ surv add: t string ] ] ].
	surv isEmpty ifTrue: [ ^ #empty ].
	surv size > 1 ifTrue: [ ^ #ambiguous ].
	^ surv first'.

"isPatternPath: — §3.3 (0.8.2.20): a resource-requiring operation takes a CONCRETE path, so a
 pattern surviving as the single effective target is 400 malformed_resource — not a 404 for a
 literal key spelled with a star, which is what this peer answered before."
ecPeer compile: 'isPatternPath: aPath  ^ aPath includes: $*'.

"callerCapOf: — the capability the dispatch stage authorized this request against, resolved
 the same way §5.2 resolved it. nil when none was presented."
ecPeer compile: 'callerCapOf: ctx
	| ch |
	ch := ctx exec bytesAt: ''capability''.
	ch isNil ifTrue: [ ^ nil ].
	^ ctx envelope includedForHash: ch'.

"handleTreePut: — §6.3 put + §3.9 CAS. params {entity, expected_hash}. CAS: expected absent ->
 unconditional; zero-hash -> create-only (409 if bound); else must equal the current binding."
ecPeer compile: 'handleTreePut: ctx
	| target params ent canon expected curHash result |
	"§3.3''s ladder, on the EFFECTIVE list — the same seam `get` uses, so one request cannot
	 receive two different answers according to which operation it named. BOTH EMPTIES ANSWER
	 path_required here, and that is the operation''s own specification rather than a shortcut:
	 `put` REQUIRES a resource, and 0.8.2.24 (N7) scopes `an empty effective list IS the absent
	 case` to exactly that kind of operation. §3.3 also pins path_required rather than
	 ambiguous_resource for a MISSING target — 0.8.2.20 names inverting those two as the defect,
	 because the remedies are opposites (name one against name fewer), and this peer answered
	 ambiguous_resource for the absent case."
	target := self effectiveTargetsOf: ctx exec.
	target == #ambiguous ifTrue: [ ^ EcHandlerResult error: 400 code: ''ambiguous_resource'' message: nil ].
	(target == #absent or: [ target == #empty ]) ifTrue: [
		^ EcHandlerResult error: 400 code: ''path_required'' message: nil ].
	(self pathFlexOk: target) ifFalse: [ ^ EcHandlerResult error: 400 code: ''invalid_path'' message: nil ].
	(self isPatternPath: target) ifTrue: [ ^ EcHandlerResult error: 400 code: ''malformed_resource'' message: nil ].
	canon := self treeCanon: target.
	params := ctx params.
	params isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''unexpected_params'' message: nil ].
	ent := params field: ''entity''.
	ent isAbsent ifTrue: [ ^ EcHandlerResult error: 400 code: ''unexpected_params'' message: nil ].
	ent := self admitPut: ent.
	(ent isKindOf: EcHandlerResult) ifTrue: [ ^ ent ].
	expected := params bytesAt: ''expected_hash''.
	curHash := store hashAt: canon.
	expected ifNotNil: [
		(expected allSatisfy: [ :b | b = 0 ])
			ifTrue: [ curHash ifNotNil: [ ^ EcHandlerResult error: 409 code: ''hash_mismatch'' message: nil ] ]
			ifFalse: [
				curHash isNil ifTrue: [ ^ EcHandlerResult error: 409 code: ''hash_mismatch'' message: nil ].
				curHash ~= expected ifTrue: [ ^ EcHandlerResult error: 409 code: ''hash_mismatch'' message: nil ] ] ].
	store bind: canon to: ent.
	"§9.5a: a system/deletion-marker tombstones the path (a subsequent get -> 404)."
	ent type = ''system/deletion-marker'' ifTrue: [ store unbind: canon ].
	result := EcEntity type: ''system/hash'' data: (EcVal map: { ''hash'' -> (EcVal bytes: ent contentHash) }).
	^ EcHandlerResult ok: result'.

"immediateChildrenOf: — the distinct immediate child segments of a canonical prefix (with a
 trailing /), each with {has_children, hash}. Answers an OrderedCollection of Associations
 (seg -> {hasChildren Boolean. hashOrNil})."
ecPeer compile: 'immediateChildrenOf: aPrefix
	| seen out |
	seen := Set new. out := OrderedCollection new.
	store boundPaths do: [ :p |
		(p size > aPrefix size and: [ (p beginsWith: aPrefix) ]) ifTrue: [
			| rem idx seg hasChildren |
			rem := p copyFrom: aPrefix size + 1 to: p size.
			idx := rem indexOf: $/.
			seg := idx = 0 ifTrue: [ rem ] ifFalse: [ rem copyFrom: 1 to: idx - 1 ].
			hasChildren := idx ~= 0.
			(seen includes: seg) ifFalse: [
				seen add: seg.
				out add: (seg -> { hasChildren. (hasChildren ifTrue: [ nil ] ifFalse: [ store hashAt: p ]) }) ] ] ].
	^ out'.

"handleTreeListing: — build a system/tree/listing {path, entries, count, offset} of the
 immediate children of a (canonical, trailing-/) prefix."
ecPeer compile: 'handleTreeListing: aCanonPrefix ctx: ctx
	| prefix children entryPairs listing cap hp local |
	prefix := (aCanonPrefix notEmpty and: [ aCanonPrefix last = $/ ]) ifTrue: [ aCanonPrefix ] ifFalse: [ aCanonPrefix, ''/'' ].
	children := self immediateChildrenOf: prefix.
	"§6.3''s LISTING FILTER (0.8.2.21/.22): every entry of a multi-entry result is checked
	 INDIVIDUALLY with check_path_permission, entries that DENY are omitted, and `count` MUST
	 reflect the filtered total rather than the source tree''s. Filtering BEFORE the count is
	 computed is what makes the two agree by construction rather than by a second pass.

	 This is the read path at its highest volume, which is the reason 0.8.2.21 refused to carve
	 reads out: a listing naming an entry the caller''s own capability excludes discloses a
	 binding that capability was written to hide."
	cap := self callerCapOf: ctx.
	local := identity peerId.
	hp := ctx isNil ifTrue: [ ''system/tree'' ] ifFalse: [ EcCapAuthz execHandlerPath: ctx exec ].
	cap ifNotNil: [
		children := children select: [ :assoc |
			EcCapAuthz checkPathPermission: cap operation: ''get'' path: prefix, assoc key
				local: local handler: hp ] ].
	entryPairs := children collect: [ :assoc |
		| hasChildren hashOrNil entryMap |
		hasChildren := (assoc value at: 1).
		hashOrNil := (assoc value at: 2).
		entryMap := EcVal map: {
			''has_children'' -> (EcVal bool: hasChildren).
			''hash'' -> (hashOrNil ifNil: [ EcVal bytes: (ByteArray new: 0) ] ifNotNil: [ EcVal bytes: hashOrNil ]) }.
		assoc key -> entryMap ].
	listing := EcEntity type: ''system/tree/listing'' data: (EcVal map: {
		''path'' -> (EcVal text: prefix).
		''entries'' -> (EcVal map: entryPairs asArray).
		''count'' -> (EcVal uint: children size).
		''offset'' -> (EcVal uint: 0) }).
	^ EcHandlerResult ok: listing'.

"handleTree: — replaces the S3 get-only body: get / put / listing."
ecPeer compile: 'handleTreeFull: ctx
	| op target canon cap |
	op := ctx operation.
	op = ''put'' ifTrue: [ ^ self handleTreePut: ctx ].
	op = ''get'' ifFalse: [ ^ EcHandlerResult error: 501 code: ''unsupported_operation'' message: nil ].
	"§3.3''s ladder runs on the EFFECTIVE list, never on resource.targets: a handler that counts
	 the effective list and then indexes targets[0] has implemented the arithmetic completely
	 and is still reading a path no authorization covered."
	target := self effectiveTargetsOf: ctx exec.
	target == #absent ifTrue: [ ^ self handleTreeListing: (self treeCanon: ''/'') ctx: ctx ].
	target == #empty ifTrue: [
		"`resource` PRESENT and every target carved out by the caller''s own exclude. Serving it
		 the absent case would answer a request for one excluded path with a listing of the
		 whole tree — wider than what was asked for, which is what BROAD-RESULT means."
		^ EcHandlerResult error: 400 code: ''path_required'' message: nil ].
	target == #ambiguous ifTrue: [ ^ EcHandlerResult error: 400 code: ''ambiguous_resource'' message: nil ].
	target isEmpty ifTrue: [ ^ self handleTreeListing: (self treeCanon: ''/'') ctx: ctx ].
	(self pathFlexOk: target) ifFalse: [ ^ EcHandlerResult error: 400 code: ''invalid_path'' message: nil ].
	canon := self treeCanon: target.
	(canon notEmpty and: [ canon last = $/ ]) ifTrue: [ ^ self handleTreeListing: canon ctx: ctx ].
	(self isPatternPath: target) ifTrue: [ ^ EcHandlerResult error: 400 code: ''malformed_resource'' message: nil ].
	"§6.3 — the handler verifies the CALLER''s capability covers the path it is about to read.
	 Not redundant with the dispatch stage: see EcCapAuthz>>checkPathPermission:..."
	cap := self callerCapOf: ctx.
	(EcCapAuthz checkPathPermission: cap operation: ''get'' path: canon local: identity peerId
		handler: (EcCapAuthz execHandlerPath: ctx exec))
		ifFalse: [ ^ EcHandlerResult error: 403 code: ''capability_denied'' message: nil ].
	(store getAt: canon)
		ifNil: [ ^ EcHandlerResult error: 404 code: ''not_found'' message: nil ]
		ifNotNil: [ :e | ^ EcHandlerResult ok: e ]'.

"════════════════════════ system/capability (§6.2) ════════════════════════"
"mintGrantToken:grants: — a single-sig token {grantee, granter=us, grants, created_at}."
ecPeer compile: 'mintGrantToken: aGranteeHash grants: aGrantsArray
	^ self mintGrantToken: aGranteeHash grants: aGrantsArray at: self nowMillis expiresAt: nil'.

"mintGrantToken:grants:at:expiresAt: — mint at a caller-supplied instant, carrying §5.6''s
 MIN_DEFINED ceiling.

 A nil expiresAt means no term was defined and the token genuinely has no expiry (the ONLY
 `no bound` spelling). A non-nil value is emitted verbatim -- including one equal to
 createdAt, which §5.6 rule 2 requires for ttl_ms == 0 and which means `already expired at
 every observable instant`, not `unbounded`.

 createdAt is supplied rather than sampled here so a computed expiry is guaranteed to be
 relative to the SAME instant that lands in the token; sampling the clock twice skews the
 two."
ecPeer compile: 'mintGrantToken: aGranteeHash grants: aGrantsArray at: createdAt expiresAt: expiresAt
	| pairs |
	pairs := OrderedCollection new.
	pairs add: ''grantee'' -> (EcVal bytes: aGranteeHash).
	pairs add: ''granter'' -> (EcVal bytes: identity idHash).
	pairs add: ''grants'' -> aGrantsArray.
	pairs add: ''created_at'' -> (EcVal uint: createdAt).
	expiresAt ifNotNil: [ :e | pairs add: ''expires_at'' -> (EcVal uint: e) ].
	^ EcEntity type: ''system/capability/token'' data: (EcVal map: pairs asArray)'.

"handleCapRequest: — mint a grant for the caller, attenuated against the presented capability.
 The requested grants ride in params.grants; grantee = the authenticated author. A requested
 grant that EXCEEDS the presented cap''s authority is refused 403 (§6.2 keystone accept-path)."
ecPeer compile: 'handleCapRequest: ctx
	| params grants author token result createdAt ceiling callerCap |
	params := ctx params.
	params isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	grants := params field: ''grants''.
	((grants isKindOf: EcArray) and: [ grants items notEmpty ]) ifFalse: [
		^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	(EcCapAuthz requestedGrants: grants boundedBy: ctx exec local: identity peerId in: ctx envelope)
		ifFalse: [ ^ EcHandlerResult error: 403 code: ''scope_exceeds_authority'' message: nil ].
	author := ctx exec bytesAt: ''author''.
	author isNil ifTrue: [ ^ EcHandlerResult error: 401 code: ''authentication_failed'' message: nil ].
	"§5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and convert
	 the duration term against that same instant.

	 Note what this is NOT: an authorization decision. An over-long ttl_ms from a bounded
	 caller MINTS a clamped token and returns 200 -- `rejecting it is non-conformant`
	 (§5.6). The bound exists because `request` mints a ROOT token (parent: null), so
	 §5.6''s parent-child attenuation never reaches it; without this clamp, temporal
	 attenuation is the one dimension a requester could escape."
	createdAt := self nowMillis.
	ceiling := nil.
	callerCap := (ctx exec bytesAt: ''capability'')
		ifNil: [ nil ]
		ifNotNil: [ :ch | ctx envelope includedForHash: ch ].
	callerCap ifNotNil: [
		(callerCap uintAt: ''expires_at'') ifNotNil: [ :ce |
			(ceiling isNil or: [ ce < ceiling ]) ifTrue: [ ceiling := ce ] ] ].
	(params uintAt: ''ttl_ms'') ifNotNil: [ :ttl |
		(EcCapAuthz addTtl: ttl to: createdAt) ifNotNil: [ :abs |
			(ceiling isNil or: [ abs < ceiling ]) ifTrue: [ ceiling := abs ] ] ].
	token := self mintGrantToken: author grants: grants at: createdAt expiresAt: ceiling.
	result := EcHandlerResult ok: (EcEntity type: ''system/capability/grant'' data: (EcVal map: {
		''token'' -> (EcVal bytes: token contentHash) })).
	^ self includeAuthority: result token: token'.

"validPeerPattern: — §4: default, OR a full-hex/Base58 peer, but reject a trailing-* prefix."
ecPeer compile: 'validPeerPattern: aPat
	aPat = ''default'' ifTrue: [ ^ true ].
	aPat isEmpty ifTrue: [ ^ false ].
	aPat last = $* ifTrue: [ ^ false ].
	^ true'.

"handleCapConfigure: — write a policy entry at policy/<peer_pattern>."
ecPeer compile: 'handleCapConfigure: ctx
	| params pat grants entity |
	params := ctx params.
	params isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	pat := params textAt: ''peer_pattern''.
	(pat isNil or: [ (self validPeerPattern: pat) not ]) ifTrue: [
		^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	grants := params field: ''grants''.
	"CAP-2 (§6.2): `grants: []` is the WITHDRAWAL form and MUST be accepted -- it writes a
	 present policy entry carrying an empty grants array, which is how an operator revokes
	 a seed policy without deleting the entry. `notEmpty` conflated `no grants` with
	 `malformed`, and the two are distinct states: the ABSENT field is malformed, the
	 EMPTY array is deliberate."
	(grants isKindOf: EcArray) ifFalse: [
		^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	store bind: (self capAbs: ''policy/'', pat) to: params.
	^ EcHandlerResult ok: params'.

"handleCapRevoke: — write a revocation marker at revocations/<hex(token)>."
ecPeer compile: 'handleCapRevoke: ctx
	| params token marker |
	params := ctx params.
	params isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	token := params bytesAt: ''token''.
	(token isNil or: [ token allSatisfy: [ :b | b = 0 ] ]) ifTrue: [
		^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	marker := EcEntity type: ''system/capability/revocation'' data: (EcVal map: {
		''token'' -> (EcVal bytes: token).
		''reason'' -> (EcVal text: ''revoked'').
		''revoked_at'' -> (EcVal uint: self nowMillis) }).
	store bind: (self capAbs: ''revocations/'', (self hexOf: token)) to: marker.
	^ EcHandlerResult ok: marker'.

"handleCapability: — request / configure / revoke / delegate(501)."
ecPeer compile: 'handleCapability: ctx
	| op |
	op := ctx operation.
	op = ''request'' ifTrue: [ ^ self handleCapRequest: ctx ].
	op = ''configure'' ifTrue: [ ^ self handleCapConfigure: ctx ].
	op = ''revoke'' ifTrue: [ ^ self handleCapRevoke: ctx ].
	^ EcHandlerResult error: 501 code: ''unsupported_operation'' message: nil'.

"handleType: — the type floor is published as tree entities; the handler only fields validate."
ecPeer compile: 'handleType: ctx
	^ EcHandlerResult error: 501 code: ''unsupported_operation'' message: nil'.

"════════════════════════ system/handler register/unregister (§6.2) ════════════════════════"
"regPattern: — the register/unregister pattern = resource.targets[0] with the leading
 system/handler/ stripped. nil if the target is missing or not under system/handler/."
ecPeer compile: 'regPattern: anExec
	| target pfx |
	target := self treeTargetOf: anExec.
	target isNil ifTrue: [ ^ nil ].
	pfx := ''system/handler/''.
	(target size > pfx size and: [ target beginsWith: pfx ]) ifFalse: [ ^ nil ].
	^ target copyFrom: pfx size + 1 to: target size'.

"isReservedSystemPattern: — §6.2: user-installed handlers MUST NOT register at
 system/* paths. pattern = ''system'' or begins with ''system/''."
ecPeer compile: 'isReservedSystemPattern: aPattern
	^ aPattern = ''system'' or: [ aPattern beginsWith: ''system/'' ]'.

"bindAssociatedTypes: — WRITE 2: walk a {name -> type-def} map, binding each at
 /<local>/system/type/<name> as a system/type entity."
ecPeer compile: 'bindAssociatedTypes: aTypesValue
	(aTypesValue isKindOf: EcMap) ifFalse: [ ^ self ].
	aTypesValue entries do: [ :entry |
		(entry key isKindOf: EcTextString) ifTrue: [
			| name val ent |
			name := entry key string. val := entry value.
			ent := (val isKindOf: EcMap)
				ifTrue: [ EcEntity type: ''system/type'' data: val ]
				ifFalse: [ EcEntity type: ''system/type'' data: (EcVal map: { ''def'' -> val }) ].
			store bind: (self peerAbs: ''system/type/'', name) to: ent ] ]'.

"regWriteHandler: — WRITE 1 + 5: the dispatch handler entity at <pattern> AND the interface
 entity at system/handler/<pattern>. `manifest` is the RAW manifest EcMap (inline CBOR)."
ecPeer compile: 'regWriteHandler: aPattern manifest: aManifest
	| iface handlerData handlerEnt name opsVal ifaceEnt |
	iface := ''system/handler/'', aPattern.
	handlerData := OrderedCollection new.
	handlerData add: (''interface'' -> (EcVal text: iface)).
	(self mapText: aManifest key: ''expression_path'') ifNotNil: [ :xp |
		handlerData add: (''expression_path'' -> (EcVal text: xp)) ].
	handlerEnt := EcEntity type: ''system/handler'' data: (EcVal map: handlerData asArray).
	store bind: (self peerAbs: aPattern) to: handlerEnt.
	name := (self mapText: aManifest key: ''name'') ifNil: [ aPattern ].
	opsVal := (self mapField: aManifest key: ''operations'').
	(opsVal isKindOf: EcMap) ifFalse: [ opsVal := EcVal emptyMap ].
	ifaceEnt := EcEntity type: ''system/handler/interface'' data: (EcVal map: {
		''name'' -> (EcVal text: name).
		''operations'' -> opsVal.
		''pattern'' -> (EcVal text: aPattern) }).
	store bind: (self peerAbs: iface) to: ifaceEnt'.

"regWriteGrant: — WRITE 3 + 4: mint the handler grant token (grantee=us,
 grants=requested_scope|internal_scope) at system/capability/grants/<pattern>, then bind its
 §3.5 signature at system/signature/<hex(grant_hash)>."
ecPeer compile: 'regWriteGrant: aPattern req: aReq manifest: aManifest
	| scope grantEnt sigEnt |
	scope := aReq field: ''requested_scope''.
	scope isAbsent ifTrue: [ scope := (self mapField: aManifest key: ''internal_scope'') ].
	(scope isKindOf: EcArray) ifFalse: [ scope := EcVal array: {} ].
	grantEnt := EcEntity type: ''system/capability/token'' data: (EcVal map: {
		''grantee'' -> (EcVal bytes: identity idHash).
		''granter'' -> (EcVal bytes: identity idHash).
		''grants'' -> scope.
		''created_at'' -> (EcVal uint: self nowMillis) }).
	store bind: (self peerAbs: ''system/capability/grants/'', aPattern) to: grantEnt.
	sigEnt := identity signatureEntityFor: grantEnt contentHash.
	store bind: (self peerAbs: ''system/signature/'', (self hexOf: grantEnt contentHash)) to: sigEnt.
	^ grantEnt'.

"handleHandlerRegister: — the five spec writes + a system/handler/register-result."
ecPeer compile: 'handleHandlerRegister: ctx
	| pattern req manifest grant result |
	pattern := self regPattern: ctx exec.
	pattern isNil ifTrue: [
		(self treeTargetOf: ctx exec) isNil
			ifTrue: [ ^ EcHandlerResult error: 400 code: ''ambiguous_resource'' message: nil ]
			ifFalse: [ ^ EcHandlerResult error: 400 code: ''invalid_resource'' message: nil ] ].
	req := ctx params.
	req isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''unexpected_params'' message: nil ].
	req type = ''system/handler/register-request'' ifFalse: [
		^ EcHandlerResult error: 400 code: ''unexpected_params'' message: nil ].
	(self isReservedSystemPattern: pattern) ifTrue: [
		^ EcHandlerResult error: 403 code: ''forbidden_pattern''
			message: ''§6.2: user-installed handlers MUST NOT register at system/* paths: '', pattern ].
	manifest := req field: ''manifest''.
	self regWriteHandler: pattern manifest: manifest.               "WRITEs 1 + 5"
	self bindAssociatedTypes: (req field: ''types'').               "WRITE 2"
	grant := self regWriteGrant: pattern req: req manifest: manifest. "WRITEs 3 + 4"
	result := EcEntity type: ''system/handler/register-result'' data: (EcVal map: {
		''grant'' -> grant data.
		''pattern'' -> (EcVal text: pattern) }).
	^ EcHandlerResult ok: result'.

"handleHandlerUnregister: — remove the grant signature + grant, then handler + interface."
ecPeer compile: 'handleHandlerUnregister: ctx
	| pattern grantPath grantEnt |
	pattern := self regPattern: ctx exec.
	pattern isNil ifTrue: [
		(self treeTargetOf: ctx exec) isNil
			ifTrue: [ ^ EcHandlerResult error: 400 code: ''ambiguous_resource'' message: nil ]
			ifFalse: [ ^ EcHandlerResult error: 400 code: ''invalid_resource'' message: nil ] ].
	grantPath := self peerAbs: ''system/capability/grants/'', pattern.
	grantEnt := store getAt: grantPath.
	grantEnt ifNotNil: [
		store unbind: (self peerAbs: ''system/signature/'', (self hexOf: grantEnt contentHash)).
		store unbind: grantPath ].
	store unbind: (self peerAbs: pattern).
	store unbind: (self peerAbs: ''system/handler/'', pattern).
	^ EcHandlerResult ok: (EcEntity type: ''primitive/any'' data: EcVal emptyMap)'.

"handleHandlers: — register / unregister."
ecPeer compile: 'handleHandlers: ctx
	| op |
	op := ctx operation.
	op = ''register'' ifTrue: [ ^ self handleHandlerRegister: ctx ].
	op = ''unregister'' ifTrue: [ ^ self handleHandlerUnregister: ctx ].
	^ EcHandlerResult error: 501 code: ''unsupported_operation'' message: nil'.

"════════════════════════ §6.2 manifest + N2 dispatch publishing ════════════════════════"
"publishHandlerInterface: — a system/handler/interface {pattern, name, operations:{op:{}}} at
 /<local>/system/handler/<pattern>."
ecPeer compile: 'publishHandlerInterface: aPattern name: aName operations: opNames
	| opsPairs iface |
	opsPairs := opNames collect: [ :op | op -> EcVal emptyMap ].
	iface := EcEntity type: ''system/handler/interface'' data: (EcVal map: {
		''pattern'' -> (EcVal text: aPattern).
		''name'' -> (EcVal text: aName).
		''operations'' -> (EcVal map: opsPairs asArray) }).
	store bind: (self peerAbs: ''system/handler/'', aPattern) to: iface'.

"publishHandlerDispatch: — a system/handler {interface: system/handler/<pattern>} at
 /<local>/<pattern> (the handler_<name>_dispatch_type / _interface_ref checks)."
ecPeer compile: 'publishHandlerDispatch: aPattern
	| ent |
	ent := EcEntity type: ''system/handler'' data: (EcVal map: {
		''interface'' -> (EcVal text: ''system/handler/'', aPattern) }).
	store bind: (self peerAbs: aPattern) to: ent'.

"════════════════════════ the §9.0 open-grants seed token (--debug-open-grants) ════════════════════════"
"openGrantsScope — {handlers:[*], operations:[*], peers:[*], resources:[*, /*/*]} as a grant."
ecPeer compile: 'openGrantScope
	| starScope |
	starScope := EcVal map: { ''include'' -> (EcVal array: { EcVal text: ''*'' }) }.
	^ EcVal map: {
		''handlers'' -> starScope.
		''operations'' -> (EcVal map: { ''include'' -> (EcVal array: { EcVal text: ''*'' }) }).
		''peers'' -> (EcVal map: { ''include'' -> (EcVal array: { EcVal text: ''*'' }) }).
		''resources'' -> (EcVal map: { ''include'' -> (EcVal array: { EcVal text: ''*''. EcVal text: ''/*/*'' }) }) }'.

'EntityCore-Peer:EcPeer S4 handlers installed'
