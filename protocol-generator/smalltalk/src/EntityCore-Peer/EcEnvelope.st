"entity-core-protocol-smalltalk — the protocol envelope (§3.1): a `root` entity plus an
`included` map of protocol entities keyed by content_hash (the §5.8 authority carrier —
capabilities, peer identities, signatures travel here). (EntityCore-Peer.)

On the wire (§3.1) `included` is a content_hash -> entity MAP with BYTE-string keys (the
major-2 seam, N5 — NOT text keys). Duplicate hashes collapse, so we dedup preserving
first-seen order (an OrderedCollection of EcEntity, deduped on add by content_hash); on
decode we verify each map key == its entity''s content_hash (§3.1) — N5 BOTH sides.

An EcEnvelope is a mutable builder object: a root EcEntity + an ordered included set. The
peer keeps one inbound (the request being served) and — during a §6.11 reentry — one
outbound envelope; the single-event-loop model means no more than two are live at once.

LIVE-IMAGE NOTE: EcEntity / EcMap / EcVal / EcCborEncoder / EcCborDecoder resolve at send-time."

| pkg cls |
pkg := 'EntityCore-Peer'.
cls := ((Object << #EcEnvelope) slots: { #root. #included }; package: pkg; install).

cls class compile: 'root: aRootEntity
	^ self new setRoot: aRootEntity'.
cls class compile: 'new  ^ super new initEnvelope'.
cls compile: 'initEnvelope  root := nil. included := OrderedCollection new. ^ self'.
cls compile: 'setRoot: aRootEntity  root := aRootEntity. ^ self'.
cls compile: 'root  ^ root'.
cls compile: 'root: aRootEntity  root := aRootEntity'.
cls compile: 'included  ^ included'.
cls compile: 'includedCount  ^ included size'.

"include: — add an entity to the included set, deduped by content_hash (first-seen wins).
 Answers the entity (present or newly-added)."
cls compile: 'include: anEntity
	| h existing |
	h := anEntity contentHash.
	existing := included detect: [ :e | e contentHash = h ] ifNone: [ nil ].
	existing ifNotNil: [ ^ existing ].
	included add: anEntity.
	^ anEntity'.

"includedForHash: — find an included entity by its content_hash ByteArray, or nil."
cls compile: 'includedForHash: aHashByteArray
	^ included detect: [ :e | e contentHash = aHashByteArray ] ifNone: [ nil ]'.

"── envelope encode: {included, root} map, canonically CBOR-encoded to a frame payload. ──"
"asWireMap — the {included, root} EcMap. `included` is a byte-keyed map (content_hash ->
 entity wire map)."
cls compile: 'asWireMap
	| incMap env |
	incMap := EcMap new.
	included do: [ :e | incMap at: (EcByteString bytes: e contentHash) put: e asWireMap ].
	env := EcMap new.
	env at: (EcTextString string: ''included'') put: incMap.
	env at: (EcTextString string: ''root'') put: root asWireMap.
	^ env'.

"asWireBytes — the canonical wire payload for this envelope."
cls compile: 'asWireBytes  ^ EcCborEncoder encode: self asWireMap'.

"── envelope decode: parse a wire payload into an EcEnvelope (root + a filled included set),
    verifying each included key == its entity''s content_hash (N5). Signals EcWireError on a
    bad shape (caught at the dispatch boundary). ──"
cls class compile: 'fromWireBytes: aByteArray
	^ self fromWireMap: (EcCborDecoder decode: aByteArray)'.

cls class compile: 'fromWireMap: anEcMap
	| env rootV incV |
	(anEcMap isKindOf: EcMap) ifFalse: [ ^ EcWireError signal: ''envelope: not a map'' ].
	env := self new.
	rootV := anEcMap entryAt: ''root''.
	rootV isNil ifTrue: [ ^ EcWireError signal: ''envelope: missing root'' ].
	env root: (EcEntity fromWireValue: rootV).
	incV := anEcMap entryAt: ''included''.
	incV ifNotNil: [
		(incV isKindOf: EcMap) ifFalse: [ ^ EcWireError signal: ''envelope: included not a map'' ].
		incV entries do: [ :entry | | keyBytes ent |
			(entry key isKindOf: EcByteString) ifFalse: [
				^ EcWireError signal: ''envelope: included key not bytes (N5)'' ].
			keyBytes := entry key bytes.
			ent := EcEntity fromWireValue: entry value.
			ent contentHash = keyBytes ifFalse: [
				^ EcWireError signal: ''envelope: included key != content_hash (N5)'' ].
			env include: ent ] ].
	^ env'.

'EntityCore-Peer:EcEnvelope installed'
