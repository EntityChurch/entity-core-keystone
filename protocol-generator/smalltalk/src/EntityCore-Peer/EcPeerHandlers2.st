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

"handleTreePut: — §6.3 put + §3.9 CAS. params {entity, expected_hash}. CAS: expected absent ->
 unconditional; zero-hash -> create-only (409 if bound); else must equal the current binding."
ecPeer compile: 'handleTreePut: ctx
	| target params ent canon expected curHash result |
	target := self treeTargetOf: ctx exec.
	target isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''ambiguous_resource'' message: nil ].
	(self pathFlexOk: target) ifFalse: [ ^ EcHandlerResult error: 400 code: ''invalid_path'' message: nil ].
	canon := self treeCanon: target.
	params := ctx params.
	params isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''unexpected_params'' message: nil ].
	ent := self treeEntityFromParams: params.
	ent isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''unexpected_params'' message: nil ].
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
ecPeer compile: 'handleTreeListing: aCanonPrefix
	| prefix children entryPairs listing |
	prefix := (aCanonPrefix notEmpty and: [ aCanonPrefix last = $/ ]) ifTrue: [ aCanonPrefix ] ifFalse: [ aCanonPrefix, ''/'' ].
	children := self immediateChildrenOf: prefix.
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
	| op target canon |
	op := ctx operation.
	op = ''put'' ifTrue: [ ^ self handleTreePut: ctx ].
	op = ''get'' ifFalse: [ ^ EcHandlerResult error: 501 code: ''unsupported_operation'' message: nil ].
	target := self treeTargetOf: ctx exec.
	(target isNil or: [ target isEmpty ]) ifTrue: [ ^ self handleTreeListing: (self treeCanon: ''/'') ].
	(self pathFlexOk: target) ifFalse: [ ^ EcHandlerResult error: 400 code: ''invalid_path'' message: nil ].
	canon := self treeCanon: target.
	(canon notEmpty and: [ canon last = $/ ]) ifTrue: [ ^ self handleTreeListing: canon ].
	(store getAt: canon)
		ifNil: [ ^ EcHandlerResult error: 404 code: ''not_found'' message: nil ]
		ifNotNil: [ :e | ^ EcHandlerResult ok: e ]'.

"════════════════════════ system/capability (§6.2) ════════════════════════"
"mintGrantToken:grants: — a single-sig token {grantee, granter=us, grants, created_at}."
ecPeer compile: 'mintGrantToken: aGranteeHash grants: aGrantsArray
	^ EcEntity type: ''system/capability/token'' data: (EcVal map: {
		''grantee'' -> (EcVal bytes: aGranteeHash).
		''granter'' -> (EcVal bytes: identity idHash).
		''grants'' -> aGrantsArray.
		''created_at'' -> (EcVal uint: self nowMillis) })'.

"handleCapRequest: — mint a grant for the caller, attenuated against the presented capability.
 The requested grants ride in params.grants; grantee = the authenticated author. A requested
 grant that EXCEEDS the presented cap''s authority is refused 403 (§6.2 keystone accept-path)."
ecPeer compile: 'handleCapRequest: ctx
	| params grants author token result |
	params := ctx params.
	params isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	grants := params field: ''grants''.
	((grants isKindOf: EcArray) and: [ grants items notEmpty ]) ifFalse: [
		^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	(EcCapAuthz requestedGrants: grants boundedBy: ctx exec local: identity peerId in: ctx envelope)
		ifFalse: [ ^ EcHandlerResult error: 403 code: ''scope_exceeds_authority'' message: nil ].
	author := ctx exec bytesAt: ''author''.
	author isNil ifTrue: [ ^ EcHandlerResult error: 401 code: ''authentication_failed'' message: nil ].
	token := self mintGrantToken: author grants: grants.
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
	((grants isKindOf: EcArray) and: [ grants items notEmpty ]) ifFalse: [
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
