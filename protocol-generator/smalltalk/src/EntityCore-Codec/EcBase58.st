"entity-core-protocol-smalltalk — Base58 (Bitcoin alphabet), pure Smalltalk (§1.5).

Unlike Forth's byte-array long-division (forced by 64-bit cells), Smalltalk integers are
ARBITRARY-PRECISION bignums, so base-256<->base-58 goes through a single big integer FREE
(the bignum class, A-ST-001): the byte span IS a big-endian integer; divide/mod by 58 to
encode, multiply-by-58-add-digit to decode. Leading zero bytes map to leading '1' chars
(and back), which the pure-integer path cannot recover, so they are counted explicitly."

| pkg alphabet cls |
pkg := 'EntityCore-Codec'.
alphabet := '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.

cls := (Object << #EcBase58 package: pkg) install.

cls class compile: ('alphabet  ^ ''', alphabet, '''').

"countLeading: aCollection equalTo: x — number of leading elements equal to x."
cls class compile: 'countLeading: aCollection equalTo: x
	| n |
	n := 0.
	aCollection do: [ :e | e = x ifTrue: [ n := n + 1 ] ifFalse: [ ^ n ] ].
	^ n'.

"encode: aByteArray -> a String."
cls class compile: 'encode: aByteArray
	| num digits leadingZeros alpha result |
	aByteArray isEmpty ifTrue: [ ^ '''' ].
	alpha := self alphabet.
	leadingZeros := self countLeading: aByteArray equalTo: 0.
	"big-endian bytes -> a big integer (bignum, arbitrary precision)."
	num := 0.
	aByteArray do: [ :b | num := (num * 256) + b ].
	digits := OrderedCollection new.
	[ num > 0 ] whileTrue: [
		digits addFirst: (alpha at: (num \\ 58) + 1).
		num := num // 58 ].
	result := WriteStream on: (String new: leadingZeros + digits size).
	leadingZeros timesRepeat: [ result nextPut: (alpha at: 1) ].
	digits do: [ :ch | result nextPut: ch ].
	^ result contents'.

"decode: aString -> a ByteArray. Rejects a non-alphabet char (BadBase58Error)."
cls class compile: 'decode: aString
	| num alpha leadingOnes sig stream |
	aString isEmpty ifTrue: [ ^ ByteArray new: 0 ].
	alpha := self alphabet.
	num := 0.
	aString do: [ :ch | | v |
		v := alpha indexOf: ch.
		v = 0 ifTrue: [ ^ BadBase58Error signal: ''bad base58 char'' ].
		num := (num * 58) + (v - 1) ].
	"num -> big-endian significant bytes."
	sig := OrderedCollection new.
	[ num > 0 ] whileTrue: [ sig addFirst: (num bitAnd: 16rFF). num := num bitShift: -8 ].
	"leading ''1''s -> leading zero bytes."
	leadingOnes := self countLeading: aString equalTo: (alpha at: 1).
	stream := WriteStream on: (ByteArray new: leadingOnes + sig size).
	leadingOnes timesRepeat: [ stream nextPut: 0 ].
	sig do: [ :b | stream nextPut: b ].
	^ stream contents'.

'EntityCore-Codec:EcBase58 installed'
