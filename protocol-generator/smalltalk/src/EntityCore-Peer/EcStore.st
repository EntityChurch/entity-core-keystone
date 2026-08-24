"entity-core-protocol-smalltalk — the foundation store (EntityCore-Peer): a content-addressed
Content Store (§1.1 immutable, content_hash -> entity) + an Entity Tree (§6.3 mutable, path ->
content_hash).

§4.8 store-safety is STRUCTURAL here (A-ST single-event-loop): the Pharo VM runs all green
processes on ONE native OS thread, and the peer dispatches one inbound frame to completion
before the next accept/readiness wake — so there is never a truly-concurrent store access. No
lock, no data race by construction. This is the same store-safety outcome as the Forth/COBOL
single-thread family, obtained here from the VM''s single-native-thread green-process model.

The two indexes are Dictionaries keyed on the content_hash / path as a String; ByteArray
hashes are keyed by their hex string (a ByteArray is not a stable Dictionary key across
identity, so we key on a canonical String form).

LIVE-IMAGE NOTE: EcEntity resolves at send-time."

| pkg cls |
pkg := 'EntityCore-Peer'.
cls := ((Object << #EcStore) slots: { #content. #tree }; package: pkg; install).

cls class compile: 'new  ^ super new initStore'.
cls compile: 'initStore  content := Dictionary new. tree := Dictionary new. ^ self'.
cls compile: 'reset  content := Dictionary new. tree := Dictionary new'.

"hexKey: — a lowercase-hex String key for a ByteArray content_hash (a stable Dictionary key).
 `printPaddedWith:to:base:` yields UPPERCASE, so `asLowercase` is load-bearing (A-CL-009):
 the comment claimed lowercase while the code produced uppercase. Self-consistent as a key
 either way — put: and getByHash: both go through here — but the store's hex and the
 §3.4/§3.5 path hex built by EcCapAuthz>>hexOf: MUST agree in case, or a revocation-marker
 lookup silently misses. RT-14 (§3.5, 0.8.1) makes lowercase the cohort rule, so pin it here
 rather than rely on the two sites never meeting."
cls compile: 'hexKey: aByteArray
	| s |
	s := WriteStream on: String new.
	aByteArray do: [ :b |
		s nextPutAll: (b printPaddedWith: $0 to: 2 base: 16) asLowercase ].
	^ s contents'.

"── Content Store: content_hash -> entity (idempotent, §1.1 immutability). ──"
cls compile: 'put: anEntity
	content at: (self hexKey: anEntity contentHash) put: anEntity.
	^ anEntity'.
cls compile: 'getByHash: aHashByteArray
	^ content at: (self hexKey: aHashByteArray) ifAbsent: [ nil ]'.

"── Entity Tree: path -> content_hash (nil == unbound / deletion marker). ──"
"bind:to: — put the entity + bind path -> its content_hash."
cls compile: 'bind: aPathString to: anEntity
	self put: anEntity.
	tree at: aPathString put: anEntity contentHash.
	^ anEntity'.
"getAt: — the entity bound at a path (or nil if unbound / absent)."
cls compile: 'getAt: aPathString
	| h |
	h := tree at: aPathString ifAbsent: [ ^ nil ].
	h isNil ifTrue: [ ^ nil ].
	^ self getByHash: h'.
"hashAt: — the content_hash bound at a path (or nil)."
cls compile: 'hashAt: aPathString
	^ tree at: aPathString ifAbsent: [ nil ]'.
"unbind: — clear a path binding (a deletion marker leaves the path present but unbound)."
cls compile: 'unbind: aPathString
	tree at: aPathString put: nil'.

"paths — the bound tree paths (for §6.3 listing); count — the entity-tree size."
cls compile: 'paths  ^ tree keys'.
cls compile: 'boundPaths  ^ tree keys select: [ :p | (tree at: p) notNil ]'.
cls compile: 'entityCount  ^ content size'.

'EntityCore-Peer:EcStore installed'
