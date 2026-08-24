"entity-core-protocol-smalltalk — the tagged VALUE object hierarchy (EntityCore-Codec).

THE PURE-OBJECT / MESSAGE-PASSING PROBE (A-ST-000). A protocol value is a first-class
tagged object — an `EcValue` subclass — and the canonical-CBOR encoder is a POLYMORPHIC
`encodeOn:` double-dispatch over these classes (a value knows how to write itself onto an
`EcCborWriter`), NOT a procedural `case`-on-type. int-vs-float and bytes-vs-text intent
live in the value's CLASS (A-ST-003: EcInt vs EcFloat, EcByteString vs EcTextString), so
the peer NEVER infers a CBOR major type from a raw Smalltalk value.

Canonical rules (ENTITY-CBOR-ENCODING v1.5): minimal int/length heads; length-then-lex
map-key ordering on ENCODED key bytes (§4.2.1); shortest-float ladder f16->f32->f64 with
canonical NaN 0x7e00 / ±Inf / ±0; definite-length containers only.

LIVE-IMAGE NOTE: each class captured in a temp; a subclass is created from its parent temp
(EcInt := base << ...), never by referencing the parent's not-yet-registered global name in
this doit. Method bodies referencing sibling classes (EcCborEncoder, EcKeyOrder, EcMapEntry)
resolve at send-time — fine."

| pkg base int float bstr tstr arr map entry bool null simple |
pkg := 'EntityCore-Codec'.

"── abstract base ──"
base := (Object << #EcValue package: pkg) install.
base compile: 'encodeOn: aWriter  ^ self subclassResponsibility'.
base compile: 'isEcValue ^ true'.
"isAbsent — false for every real value; the EcAbsent sentinel (EntityCore-Peer) overrides it
 to true. Making this polymorphic on the value base lets a field read answer `v isAbsent`
 uniformly (A-ST-007) without an isKindOf: check at each call site."
base compile: 'isAbsent ^ false'.

"── EcInt — mt0 (uint) / mt1 (nint). BIGNUM value; canonical minimal head still explicit. ──"
int := ((base << #EcInt) slots: { #value }; package: pkg; install).
int class compile: 'value: anInteger  ^ self new setValue: anInteger'.
int compile: 'setValue: anInteger  value := anInteger. ^ self'.
int compile: 'value ^ value'.
int compile: 'encodeOn: aWriter
	value >= 0
		ifTrue: [ aWriter writeHead: 0 argument: value ]
		ifFalse: [ aWriter writeHead: 1 argument: (-1 - value) ]'.

"── EcFloat — mt7 float; shortest-float ladder over NATIVE IEEE bits (A-ST-002). ──"
float := ((base << #EcFloat) slots: { #value }; package: pkg; install).
float class compile: 'value: aFloat  ^ self new setValue: aFloat'.
float compile: 'setValue: aFloat  value := aFloat. ^ self'.
float compile: 'value ^ value'.
float compile: 'encodeOn: aWriter  aWriter writeFloat: value'.

"── EcByteString — mt2. Raw ByteArray. ──"
bstr := ((base << #EcByteString) slots: { #bytes }; package: pkg; install).
bstr class compile: 'bytes: aByteArray  ^ self new setBytes: aByteArray'.
bstr compile: 'setBytes: aByteArray  bytes := aByteArray. ^ self'.
bstr compile: 'bytes ^ bytes'.
bstr compile: 'encodeOn: aWriter
	aWriter writeHead: 2 argument: bytes size.
	aWriter writeBytes: bytes'.

"── EcTextString — mt3. WIRE length is the UTF-8 BYTE count (A-ST-004). ──"
tstr := ((base << #EcTextString) slots: { #string }; package: pkg; install).
tstr class compile: 'string: aString  ^ self new setString: aString'.
tstr compile: 'setString: aString  string := aString. ^ self'.
tstr compile: 'string ^ string'.
tstr compile: 'utf8Bytes  ^ string utf8Encoded'.
tstr compile: 'encodeOn: aWriter
	| u8 |
	u8 := self utf8Bytes.
	aWriter writeHead: 3 argument: u8 size.
	aWriter writeBytes: u8'.

"── EcArray — mt4, definite length. ──"
arr := ((base << #EcArray) slots: { #items }; package: pkg; install).
arr class compile: 'new  ^ super new setItems: OrderedCollection new'.
arr class compile: 'items: aCollection  ^ self new setItems: aCollection asOrderedCollection'.
arr compile: 'setItems: aCollection  items := aCollection. ^ self'.
arr compile: 'items ^ items'.
arr compile: 'add: anEcValue  items add: anEcValue. ^ anEcValue'.
arr compile: 'encodeOn: aWriter
	aWriter writeHead: 4 argument: items size.
	items do: [ :each | each encodeOn: aWriter ]'.

"── EcMap — mt5, definite length. Entries sorted by ENCODED key bytes (§4.2.1) at encode. ──"
map := ((base << #EcMap) slots: { #entries }; package: pkg; install).
map class compile: 'new  ^ super new setEntries: OrderedCollection new'.
map compile: 'setEntries: aCollection  entries := aCollection. ^ self'.
map compile: 'entries ^ entries'.
map compile: 'at: aKeyValue put: aValueValue
	entries add: (EcMapEntry key: aKeyValue value: aValueValue).
	^ aValueValue'.
map compile: 'entryAt: aStringKey
	^ (entries detect: [ :e |
		(e key isKindOf: EcTextString) and: [ e key string = aStringKey ] ]
		ifNone: [ ^ nil ]) value'.
map compile: 'includesKey: aStringKey
	^ entries anySatisfy: [ :e |
		(e key isKindOf: EcTextString) and: [ e key string = aStringKey ] ]'.
map compile: 'encodeOn: aWriter
	| sorted |
	sorted := entries asSortedCollection: [ :a :b |
		(EcKeyOrder compareKey: a encodedKey to: b encodedKey) <= 0 ].
	aWriter writeHead: 5 argument: sorted size.
	sorted do: [ :ea |
		aWriter writeBytes: ea encodedKey.
		ea value encodeOn: aWriter ]'.

"── EcMapEntry — one (key,value) pair; caches the canonical encoding of its key. ──"
entry := ((Object << #EcMapEntry) slots: { #key. #value. #encodedKey }; package: pkg; install).
entry class compile: 'key: aKeyValue value: aValueValue
	^ self new setKey: aKeyValue value: aValueValue'.
entry compile: 'setKey: aKeyValue value: aValueValue
	key := aKeyValue. value := aValueValue.
	encodedKey := EcCborEncoder encode: aKeyValue.
	^ self'.
entry compile: 'key ^ key'.
entry compile: 'value ^ value'.
entry compile: 'encodedKey ^ encodedKey'.

"── EcBool / EcNull / EcSimple — mt7 simple values. ──"
bool := ((base << #EcBool) slots: { #value }; package: pkg; install).
bool class compile: 'value: aBoolean  ^ self new setValue: aBoolean'.
bool compile: 'setValue: aBoolean  value := aBoolean. ^ self'.
bool compile: 'value ^ value'.
bool compile: 'encodeOn: aWriter
	aWriter writeByte: (value ifTrue: [ 16rF5 ] ifFalse: [ 16rF4 ])'.

null := (base << #EcNull package: pkg) install.
null compile: 'encodeOn: aWriter  aWriter writeByte: 16rF6'.

simple := ((base << #EcSimple) slots: { #code }; package: pkg; install).
simple class compile: 'code: anInteger  ^ self new setCode: anInteger'.
simple compile: 'setCode: anInteger  code := anInteger. ^ self'.
simple compile: 'code ^ code'.
simple compile: 'encodeOn: aWriter
	code < 24
		ifTrue: [ aWriter writeByte: 16rE0 + code ]
		ifFalse: [ aWriter writeByte: 16rF8. aWriter writeByte: code ]'.

'EntityCore-Codec:EcValue hierarchy installed'
