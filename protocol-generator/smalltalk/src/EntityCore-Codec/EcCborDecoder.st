"entity-core-protocol-smalltalk — the canonical-CBOR DECODER (EntityCore-Codec).

Reads a ByteArray, returns the EcValue graph, and REJECTS any non-canonical input by
signalling an EntityCodecError subclass:
  - minimal-argument head enforcement on decode (a non-shortest head → NonCanonicalEcfError)
  - N2: explicit recursive major-type-6 TAG rejection (TagRejectedError) — do not trust a
    library default; the scanner runs on every node
  - length-then-lex map-key ordering re-validated (§4.2.1)
  - shortest-float ladder re-validated (a wider float encoding that fits a narrower width
    is non-canonical)
  - full-consume: trailing bytes after the top value are rejected (TruncatedInputError)

The decoder is a WriteStream-free cursor walker; #cursor advances an index over the input."

| pkg cls |
pkg := 'EntityCore-Codec'.

cls := ((Object << #EcCborDecoder) slots: { #bytes. #pos }; package: pkg; install).

cls class compile: 'decode: aByteArray
	"Public entry: full-consume decode of one canonical value."
	| d value |
	d := self new setBytes: aByteArray.
	value := d decodeNode.
	d atEnd ifFalse: [ ^ TruncatedInputError signal: ''trailing bytes'' ].
	^ value'.

cls compile: 'setBytes: aByteArray  bytes := aByteArray. pos := 1. ^ self'.
cls compile: 'atEnd  ^ pos > bytes size'.
cls compile: 'remaining  ^ bytes size - pos + 1'.

cls compile: 'nextByte
	pos > bytes size ifTrue: [ ^ TruncatedInputError signal: ''truncated'' ].
	^ bytes at: pos.
	'.
"take: n — return n bytes at the cursor as a ByteArray and advance."
cls compile: 'take: n
	| slice |
	n > self remaining ifTrue: [ ^ TruncatedInputError signal: ''truncated'' ].
	slice := bytes copyFrom: pos to: pos + n - 1.
	pos := pos + n.
	^ slice'.
"consumeByte — read one byte and advance."
cls compile: 'consumeByte
	| b |
	pos > bytes size ifTrue: [ ^ TruncatedInputError signal: ''truncated'' ].
	b := bytes at: pos. pos := pos + 1. ^ b'.
"beUint: aByteArray — big-endian unsigned integer from a byte slice (bignum)."
cls compile: 'beUint: aByteArray
	| n |
	n := 0.
	aByteArray do: [ :b | n := (n bitShift: 8) bitOr: b ].
	^ n'.

"readHead — read a CBOR head with minimal-argument enforcement; answer major -> arg."
cls compile: 'readHead
	| ib major ai arg |
	ib := self consumeByte.
	major := ib bitShift: -5.
	ai := ib bitAnd: 16r1F.
	ai < 24 ifTrue: [ ^ major -> ai ].
	ai = 24 ifTrue: [
		arg := self consumeByte.
		arg < 24 ifTrue: [ ^ NonCanonicalEcfError signal: ''non-minimal 1-byte head'' ].
		^ major -> arg ].
	ai = 25 ifTrue: [
		arg := self beUint: (self take: 2).
		arg < 256 ifTrue: [ ^ NonCanonicalEcfError signal: ''non-minimal 2-byte head'' ].
		^ major -> arg ].
	ai = 26 ifTrue: [
		arg := self beUint: (self take: 4).
		arg < 65536 ifTrue: [ ^ NonCanonicalEcfError signal: ''non-minimal 4-byte head'' ].
		^ major -> arg ].
	ai = 27 ifTrue: [
		arg := self beUint: (self take: 8).
		arg < 4294967296 ifTrue: [ ^ NonCanonicalEcfError signal: ''non-minimal 8-byte head'' ].
		^ major -> arg ].
	^ NonCanonicalEcfError signal: ''reserved additional-info''.
	'.

"decodeNode — decode one item at the cursor; return the EcValue."
cls compile: 'decodeNode
	| m0 head major arg |
	m0 := self nextByte bitShift: -5.
	m0 = 6 ifTrue: [ ^ TagRejectedError signal: ''major-type-6 tag rejected (N2)'' ].
	m0 = 7 ifTrue: [ ^ self decodeSimple ].
	head := self readHead.
	major := head key. arg := head value.
	major = 0 ifTrue: [ ^ EcInt value: arg ].
	major = 1 ifTrue: [ ^ EcInt value: (-1 - arg) ].
	major = 2 ifTrue: [ ^ EcByteString bytes: (self take: arg) ].
	major = 3 ifTrue: [ ^ EcTextString string: (self take: arg) utf8Decoded ].
	major = 4 ifTrue: [ | arr |
		arr := EcArray new.
		arg timesRepeat: [ arr add: self decodeNode ].
		^ arr ].
	major = 5 ifTrue: [ ^ self decodeMap: arg ].
	^ NonCanonicalEcfError signal: ''unreachable major''.
	'.

"decodeMap: n — decode n key/value pairs; re-validate canonical key ordering (§4.2.1)."
cls compile: 'decodeMap: n
	| map prevKey |
	map := EcMap new.
	prevKey := nil.
	n timesRepeat: [ | keyStart keyBytes keyValue valueValue |
		keyStart := pos.
		keyValue := self decodeNode.
		keyBytes := bytes copyFrom: keyStart to: pos - 1.
		prevKey notNil ifTrue: [
			(EcKeyOrder compareKey: prevKey to: keyBytes) >= 0
				ifTrue: [ ^ NonCanonicalEcfError signal: ''map keys not canonically ordered'' ] ].
		prevKey := keyBytes.
		valueValue := self decodeNode.
		map at: keyValue put: valueValue ].
	^ map'.

"decodeSimple — major type 7 (already peeked)."
cls compile: 'decodeSimple
	| ib ai bits |
	ib := self consumeByte.
	ai := ib bitAnd: 16r1F.
	ai = 20 ifTrue: [ ^ EcBool value: false ].
	ai = 21 ifTrue: [ ^ EcBool value: true ].
	ai = 22 ifTrue: [ ^ EcNull new ].
	ai = 23 ifTrue: [ ^ EcSimple code: 23 ].
	ai < 20 ifTrue: [ ^ EcSimple code: ai ].
	ai = 24 ifTrue: [ | v |
		v := self consumeByte.
		v < 32 ifTrue: [ ^ NonCanonicalEcfError signal: ''non-minimal simple'' ].
		^ EcSimple code: v ].
	ai = 25 ifTrue: [
		bits := EcFloatBits f16ToF64: (self beUint: (self take: 2)).
		^ EcFloat value: (Float fromIEEE64Bit: bits) ].
	ai = 26 ifTrue: [
		bits := EcFloatBits f32ToF64: (self beUint: (self take: 4)).
		(EcFloatBits wouldBeF16: bits) ifTrue: [ ^ NonCanonicalEcfError signal: ''f32 should be f16'' ].
		^ EcFloat value: (Float fromIEEE64Bit: bits) ].
	ai = 27 ifTrue: [
		bits := self beUint: (self take: 8).
		((EcFloatBits wouldBeF16: bits) or: [ EcFloatBits wouldBeF32: bits ])
			ifTrue: [ ^ NonCanonicalEcfError signal: ''f64 should be narrower'' ].
		^ EcFloat value: (Float fromIEEE64Bit: bits) ].
	^ NonCanonicalEcfError signal: ''reserved simple''.
	'.

'EntityCore-Codec:EcCborDecoder installed'
