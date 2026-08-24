"entity-core-protocol-smalltalk — SUnit conformance TestCase (EntityCore-Tests).

SUnit is bundled in the base Pharo image (the original xUnit — a first-class test framework
at zero dependency cost, unlike the rest of the FFI-hybrid cohort which hand-rolled a
harness). This TestCase loads the pinned v0.8.0 corpus and asserts byte-identity per vector
against the hand-rolled codec + the UFFI crypto binding, plus the reject vectors, the int
boundary, and the crypto accept-path. Run headless: `pharo <image> test EntityCore-Tests`.

The corpus path comes from the EC_CORPUS env var or the pinned default."

| pkg cls |
pkg := 'EntityCore-Tests'.
cls := ((TestCase << #EcCodecTest) package: pkg; install).

cls compile: 'corpusBytes
	| path |
	path := (Smalltalk os environment at: ''EC_CORPUS'' ifAbsent: [ nil ])
		ifNil: [ ''../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor'' ].
	^ path asFileReference binaryReadStream upToEnd'.

cls compile: 'corpusVectors
	^ (EcCborDecoder decode: self corpusBytes) items'.

cls compile: 'testEncodeEqualVectors
	"Every encode_equal vector: produce(input) = canonical, byte-identical."
	self corpusVectors do: [ :vec | | vid |
		vid := (vec entryAt: ''id'') string.
		(vec entryAt: ''kind'') string = ''encode_equal'' ifTrue: [
			self
				assert: (EcConformance produceFor: vid input: (vec entryAt: ''input''))
				equals: (vec entryAt: ''canonical'') bytes ] ]'.

cls compile: 'testDecodeRejectVectors
	"Every decode_reject vector: decode(canonical) signals an EntityCodecError."
	self corpusVectors do: [ :vec | | vid |
		vid := (vec entryAt: ''id'') string.
		(vec entryAt: ''kind'') string = ''decode_reject'' ifTrue: [
			self
				should: [ EcCborDecoder decode: (vec entryAt: ''canonical'') bytes ]
				raise: EntityCodecError ] ]'.

cls compile: 'testIntBoundaryUint64
	"BIGNUM class: the full uint64 range, canonical minimal head + round-trip."
	{ 2 raisedTo: 63. (2 raisedTo: 63) - 1. (2 raisedTo: 64) - 1. 2 raisedTo: 32 } do: [ :v |
		self assert: (EcCborDecoder decode: (EcCborEncoder encode: (EcInt value: v))) value equals: v ]'.

cls compile: 'testMt1NegativeFloor
	"mt1 -2^64 encodes as major 1, argument 2^64-1."
	self
		assert: (EcCborEncoder encode: (EcInt value: 0 - (2 raisedTo: 64)))
		equals: (ByteArray readHexFrom: ''3BFFFFFFFFFFFFFFFF'')'.

cls compile: 'testCryptoAcceptPath
	"Sign -> verify accepts; tamper -> rejects (the direction the rejection-heavy oracle
	 cannot cover). Crosses the UFFI binding."
	| lib seed msg sig pub tampered |
	lib := EcLibEntityCoreCodec default.
	seed := ByteArray new: 32 withAll: 0.
	msg := ''AAAA'' asByteArray.
	sig := lib ed25519Sign: msg withSeed: seed.
	pub := lib ed25519PubkeyFromSeed: seed.
	self assert: (lib ed25519Verify: msg sig: sig pubkey: pub).
	tampered := sig copy.
	tampered at: 1 put: ((tampered at: 1) bitXor: 1).
	self deny: (lib ed25519Verify: msg sig: tampered pubkey: pub)'.

cls compile: 'testSha256Kat
	self
		assert: (EcLibEntityCoreCodec default sha256: (ByteArray new: 0))
		equals: (ByteArray readHexFrom: ''e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'')'.

'EntityCore-Tests:EcCodecTest installed'
