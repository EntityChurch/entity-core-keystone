"entity-core-protocol-smalltalk — unsigned LEB128 varint (§7.3 multicodec, N1).

N1: all format-code / key-type / hash-type framing routes through a REAL varint primitive,
never a hard-coded single byte. Currently-allocated codes are < 0x80 (one byte) so this is
byte-identical to a fixed field today, but peer_id.3 and content_hash.4 carry synthetic
codes >= 0x80 that widen to 2 bytes, proving the primitive. Pure Smalltalk over
bitShift:/bitAnd: message-sends; values are arbitrary-precision Integers (bignum → the full
u64 range free)."

| pkg cls |
pkg := 'EntityCore-Codec'.

cls := (Object << #EcVarint package: pkg) install.

"encode: anInteger -> a ByteArray of the unsigned LEB128 form."
cls class compile: 'encode: anInteger
	| n stream |
	stream := WriteStream on: (ByteArray new: 4).
	n := anInteger.
	[ | hi |
		hi := n bitShift: -7.
		hi ~= 0
			ifTrue: [ stream nextPut: ((n bitAnd: 16r7F) bitOr: 16r80). n := hi. true ]
			ifFalse: [ stream nextPut: (n bitAnd: 16r7F). false ] ] whileTrue.
	^ stream contents'.

"decodeFrom: aByteArray at: index -> an Association value -> nConsumed. Rejects a truncated
 or non-minimal (trailing 0x00 continuation) form (BadVarintError)."
cls class compile: 'decodeFrom: aByteArray at: startIndex
	| result shift i byte |
	result := 0. shift := 0. i := startIndex.
	[ i > aByteArray size ifTrue: [ ^ BadVarintError signal: ''truncated varint'' ].
	  byte := aByteArray at: i.
	  result := result + ((byte bitAnd: 16r7F) bitShift: shift).
	  shift := shift + 7. i := i + 1.
	  (byte bitAnd: 16r80) ~= 0 ] whileTrue.
	"minimality: a >1-byte varint whose last byte is 0x00 is non-minimal."
	((i - startIndex) > 1 and: [ (aByteArray at: i - 1) = 0 ])
		ifTrue: [ ^ BadVarintError signal: ''non-minimal varint'' ].
	^ result -> (i - startIndex)'.

'EntityCore-Codec:EcVarint installed'
