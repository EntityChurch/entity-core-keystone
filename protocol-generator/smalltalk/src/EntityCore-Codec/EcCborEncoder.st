"entity-core-protocol-smalltalk — the canonical-CBOR WRITER + ENCODER (EntityCore-Codec).

EcCborWriter is a growing byte sink; a value's #encodeOn: sends it #writeHead:argument: /
#writeByte: / #writeBytes: / #writeFloat:. All head arithmetic is bitShift:/bitAnd:/bitOr:
message-sends over an arbitrary-precision Integer, assembled big-endian into a WriteStream
on a ByteArray. EcCborEncoder is the public facade (`EcCborEncoder encode: anEcValue`).

LIVE-IMAGE NOTE: each class captured in a temp; cross-class name references inside method
BODIES (EcFloatBits) resolve at send-time and are fine."

| pkg keyOrder writer encoder |
pkg := 'EntityCore-Codec'.

"── EcKeyOrder — §4.2.1 length-then-lexicographic compare of two ENCODED key byte spans. ──"
keyOrder := (Object << #EcKeyOrder package: pkg) install.
keyOrder class compile: 'compareKey: aBytes to: bBytes
	| n |
	aBytes size ~= bBytes size ifTrue: [
		^ aBytes size < bBytes size ifTrue: [ -1 ] ifFalse: [ 1 ] ].
	n := aBytes size.
	1 to: n do: [ :i | | x y |
		x := aBytes at: i. y := bBytes at: i.
		x ~= y ifTrue: [ ^ x < y ifTrue: [ -1 ] ifFalse: [ 1 ] ] ].
	^ 0'.

"── EcCborWriter — the byte sink. ──"
writer := ((Object << #EcCborWriter) slots: { #stream }; package: pkg; install).
writer class compile: 'new  ^ super new initStream'.
writer compile: 'initStream  stream := WriteStream on: (ByteArray new: 64). ^ self'.
writer compile: 'contents  ^ stream contents'.
writer compile: 'writeByte: anInteger  stream nextPut: (anInteger bitAnd: 16rFF)'.
writer compile: 'writeBytes: aByteArray  stream nextPutAll: aByteArray'.
writer compile: 'writeUint: value bytes: n
	n to: 1 by: -1 do: [ :i |
		stream nextPut: ((value bitShift: 0 - (8 * (i - 1))) bitAnd: 16rFF) ]'.
writer compile: 'writeHead: major argument: arg
	| ib |
	ib := major bitShift: 5.
	arg < 24 ifTrue: [ ^ self writeByte: ib + arg ].
	arg < 256 ifTrue: [ self writeByte: ib + 24. ^ self writeUint: arg bytes: 1 ].
	arg < 65536 ifTrue: [ self writeByte: ib + 25. ^ self writeUint: arg bytes: 2 ].
	arg < 4294967296 ifTrue: [ self writeByte: ib + 26. ^ self writeUint: arg bytes: 4 ].
	self writeByte: ib + 27.
	^ self writeUint: arg bytes: 8'.
writer compile: 'writeFloat: aFloat
	| bits half single |
	bits := aFloat asIEEE64BitWord.
	(EcFloatBits isInfOrNanBits: bits) ifTrue: [
		self writeByte: 16rF9.
		(EcFloatBits isNanBits: bits)
			ifTrue: [ ^ self writeBytes: #[16r7E 16r00] ]
			ifFalse: [ ^ (EcFloatBits signBits: bits) = 0
				ifTrue: [ self writeBytes: #[16r7C 16r00] ]
				ifFalse: [ self writeBytes: #[16rFC 16r00] ] ] ].
	half := EcFloatBits f64ToF16: bits.
	half notNil ifTrue: [
		self writeByte: 16rF9. ^ self writeUint: half bytes: 2 ].
	single := EcFloatBits f64ToF32: bits.
	single notNil ifTrue: [
		self writeByte: 16rFA. ^ self writeUint: single bytes: 4 ].
	self writeByte: 16rFB.
	^ self writeUint: bits bytes: 8'.

"── EcCborEncoder — the public facade. ──"
encoder := (Object << #EcCborEncoder package: pkg) install.
encoder class compile: 'encode: anEcValue
	| w |
	w := EcCborWriter new.
	anEcValue encodeOn: w.
	^ w contents'.

'EntityCore-Codec:EcCborEncoder installed'
