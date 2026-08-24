"entity-core-protocol-smalltalk — value-construction convenience (EntityCore-Peer).

A thin message-send facade over the EcValue constructors so the peer + handlers build wire
values IDIOMATICALLY (`EcVal text: 'hello'`, `EcVal map: { 'k' -> value. ... }`,
`EcVal array: { a. b }`) instead of spelling out EcTextString/EcByteString/EcMap everywhere.
The explicit-value-tagging discipline (A-ST-003) is PRESERVED: the caller still chooses the
class (text vs bytes, int vs float) — this facade never infers a CBOR major type from a raw
Smalltalk value. `map:` takes an Array of Associations whose keys are Strings (encoded as
text keys) and whose values are already EcValues.

LIVE-IMAGE NOTE: sibling EcValue classes resolve at send-time inside method bodies."

| pkg cls |
pkg := 'EntityCore-Peer'.
cls := (Object << #EcVal package: pkg) install.

cls class compile: 'text: aString  ^ EcTextString string: aString'.
cls class compile: 'bytes: aByteArray  ^ EcByteString bytes: aByteArray'.
cls class compile: 'uint: anInteger  ^ EcInt value: anInteger'.
cls class compile: 'bool: aBoolean  ^ EcBool value: aBoolean'.

"array: — an EcArray from a SequenceableCollection of EcValues."
cls class compile: 'array: aCollection
	| a |
	a := EcArray new.
	aCollection do: [ :each | a add: each ].
	^ a'.

"map: — an EcMap from an Array of Associations (stringKey -> ecValue), first-seen order.
 The canonical §4.2.1 key sort happens at encode time in EcMap>>encodeOn:, so insertion
 order here is irrelevant to the wire bytes."
cls class compile: 'map: anArrayOfAssociations
	| m |
	m := EcMap new.
	anArrayOfAssociations do: [ :assoc |
		m at: (EcTextString string: assoc key) put: assoc value ].
	^ m'.

"emptyMap — the canonical empty map value (single byte 0xa0 on the wire)."
cls class compile: 'emptyMap  ^ EcMap new'.

'EntityCore-Peer:EcVal installed'
