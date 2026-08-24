"entity-core-protocol-smalltalk — the conformance PRODUCTION dispatch (EntityCore-Codec).

Given a vector id + its decoded `input` EcValue, produce the wire ByteArray the corpus's
`canonical` field should equal. Class A (float/int/map_keys/length/primitive/nested/envelope)
re-encodes the input directly; Class B (content_hash / peer_id / signature) reconstructs
through the pure-Smalltalk hash/peer_id builders + the FFI crypto binding. Keeping the
category dispatch in a real method (rather than a nested block in the driver) reads as native
Smalltalk and lets the SUnit TestCase reuse it."

| pkg cls |
pkg := 'EntityCore-Codec'.
cls := (Object << #EcConformance package: pkg) install.

cls class compile: 'produceFor: vid input: input
	(vid beginsWith: ''peer_id.'') ifTrue: [ ^ self producePeerId: input ].
	(vid beginsWith: ''content_hash.'') ifTrue: [ ^ self produceContentHash: input ].
	(vid beginsWith: ''signature.'') ifTrue: [ ^ self produceSignature: input ].
	"default class A + envelope: re-encode the input EcValue directly."
	^ EcCborEncoder encode: input'.

cls class compile: 'producePeerId: input
	| kt ht digest pid |
	kt := (input entryAt: ''key_type'') value.
	ht := (input entryAt: ''hash_type'') value.
	digest := (input entryAt: ''digest'') bytes.
	pid := EcPeerId format: kt hash: ht digest: digest.
	^ EcCborEncoder encode: (EcTextString string: pid)'.

cls class compile: 'produceContentHash: input
	| typeStr dataV fmt |
	typeStr := (input entryAt: ''type'') string.
	dataV := input entryAt: ''data''.
	fmt := (input includesKey: ''format_code'')
		ifTrue: [ (input entryAt: ''format_code'') value ] ifFalse: [ 0 ].
	^ EcContentHash of: typeStr data: dataV format: fmt'.

cls class compile: 'produceSignature: input
	| seed entity |
	seed := (input entryAt: ''seed'') bytes.
	entity := input entryAt: ''entity''.
	^ EcContentHash signEntity: entity withSeed: seed'.

'EntityCore-Codec:EcConformance installed'
