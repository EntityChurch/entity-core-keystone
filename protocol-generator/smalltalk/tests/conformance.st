"entity-core-protocol-smalltalk — S2 FULL codec conformance (v0.8.0 corpus, 71 vectors).

Walks the pinned corpus (decoded with OUR OWN EcCborDecoder) and asserts, per vector:
  - encode_equal: encode(reconstructed input) == canonical bytes (byte-identical);
  - decode_reject: decode(canonical) REJECTS (signals an EntityCodecError).
Class B (content_hash / peer_id / signature / envelope) is reconstructed through the FFI
crypto binding + the pure-Smalltalk hash/peer_id builders. A codec reject is a signalled
exception caught here.

This is a plain doit driver (the run scripts eval it against the loaded peer image); it
prints a final N/69 line and the FAIL details. See tests/EntityCore-Tests for the SUnit
TestCase mirror. Path to the corpus .cbor is the FIRST command-line argument (or the pinned
default)."

| corpusPath bytes top npass nfail nskip out toHex judge processVec |
"Corpus path from the EC_CORPUS env var (the run scripts set it) or the pinned default."
corpusPath := (Smalltalk os environment at: 'EC_CORPUS' ifAbsent: [ nil ])
	ifNil: [ '../shared/test-vectors/ecf-conformance/conformance-vectors.cbor' ].
bytes := corpusPath asFileReference binaryReadStream upToEnd.
top := EcCborDecoder decode: bytes.

npass := 0. nfail := 0. nskip := 0.
out := WriteStream on: String new.
toHex := [ :ba | | s | s := WriteStream on: String new.
	ba do: [ :b | s nextPutAll: (b printPaddedWith: $0 to: 2 base: 16) ]. s contents ].

"judge: a produced wire ByteArray against the canonical ByteArray for a vector id."
judge := [ :produced :canonical :vid |
	produced = canonical
		ifTrue: [ npass := npass + 1 ]
		ifFalse: [ nfail := nfail + 1.
			out nextPutAll: 'FAIL '; nextPutAll: vid;
				nextPutAll: ' want='; nextPutAll: (toHex value: canonical);
				nextPutAll: ' got='; nextPutAll: (toHex value: produced);
				nextPut: Character lf ] ].

"encodeReject: feed canonical wire to the decoder; it MUST signal an EntityCodecError."
"encodeClassB helpers return the produced ByteArray per category; classA re-encodes input."
processVec := [ :vec | | vid kindV canonical input produced |
	vid := (vec entryAt: 'id') string.
	kindV := (vec entryAt: 'kind') string.
	canonical := (vec entryAt: 'canonical') bytes.
	input := vec entryAt: 'input'.

	kindV = 'decode_reject'
		ifTrue: [
			[ EcCborDecoder decode: canonical.
			  nfail := nfail + 1.
			  out nextPutAll: 'FAIL '; nextPutAll: vid; nextPutAll: ' decoded OK, expected reject'; nextPut: Character lf ]
				on: EntityCodecError do: [ :ex | npass := npass + 1 ] ]
		ifFalse: [
			produced := EcConformance produceFor: vid input: input.
			judge value: produced value: canonical value: vid ] ].

top items do: [ :vec | processVec value: vec ].

out nextPut: Character lf.
out nextPutAll: '=== conformance: '; print: top items size; nextPutAll: ' vectors — ';
	print: npass; nextPutAll: ' pass / '; print: nfail; nextPutAll: ' fail / ';
	print: nskip; nextPutAll: ' skip ==='; nextPut: Character lf.
out contents
