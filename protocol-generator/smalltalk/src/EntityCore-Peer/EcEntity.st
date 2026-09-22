"entity-core-protocol-smalltalk — a materialized entity {type, data, content_hash} (§1.1,
§3.4) on top of the S2 EcValue codec (EntityCore-Peer).

THE PURE-OBJECT REP (A-ST-000): unlike Forth's self-delimiting (addr,len) byte string, an
entity here is a first-class OBJECT — an `EcEntity` with a `type` String, a `data` EcValue
(an ARBITRARY value, NOT necessarily an EcMap — A-JAVA-010), and a lazily-computed
`content_hash` ByteArray. content_hash covers ONLY {type, data} (§1.1, format_code 0x00,
SHA-256 floor); the WIRE form (`#asWireMap`) carries it as a third field so entities are
self-describing across serialization (§3.1).

Field reads message-send into the data EcMap VIEW (an empty map for a scalar data value, so
a read never faults). Absent is the EcAbsent singleton (A-ST-007), NEVER nil / the empty
value — the empty byte/text string is a legitimate wire value.

LIVE-IMAGE NOTE (A-ST-010): each class captured in a temp; sibling class references inside
method BODIES (EcCborEncoder, EcContentHash, EcMap, EcTextString) resolve at send-time."

| pkg absent entity |
pkg := 'EntityCore-Peer'.

"── EcAbsent — the distinguished absent sentinel (A-ST-007): NOT nil, NOT an empty value.
    The singleton is held in a class-instance variable, declared BEFORE compiling the methods
    that reference it (else the compiler flags it Undeclared). ──"
absent := (Object << #EcAbsent package: pkg) install.
absent class instanceVariableNames: 'Ec_absentSingleton'.
absent class compile: 'default
	Ec_absentSingleton isNil ifTrue: [ Ec_absentSingleton := self new ].
	^ Ec_absentSingleton'.
absent class compile: 'reset  Ec_absentSingleton := nil'.
absent compile: 'isAbsent  ^ true'.
absent compile: 'printOn: aStream  aStream nextPutAll: ''<absent>'''.

"── EcEntity — {type, data} + a memoized content_hash. ──"
entity := ((Object << #EcEntity) slots: { #type. #data. #hash }; package: pkg; install).

entity class compile: 'type: aTypeString data: aDataValue
	^ self new setType: aTypeString data: aDataValue'.
entity compile: 'setType: aTypeString data: aDataValue
	type := aTypeString. data := aDataValue. hash := nil. ^ self'.
entity compile: 'isAbsent  ^ false'.
entity compile: 'type  ^ type'.
entity compile: 'data  ^ data'.

"content_hash — memoized §1.1 content_hash over {type, data} (format_code 0x00, SHA-256)."
entity compile: 'contentHash
	hash isNil ifTrue: [ hash := EcContentHash of: type data: data format: 0 ].
	^ hash'.

"dataMap — the data value AS an EcMap view (an empty EcMap if data is a scalar). Every
 field-read goes through this so a scalar-data entity never faults."
entity compile: 'dataMap
	^ (data isKindOf: EcMap) ifTrue: [ data ] ifFalse: [ EcMap new ]'.

"── data-map field reads (return EcAbsent default on a missing key). ──"
"field: — the raw EcValue at a data-map key, or the absent sentinel."
entity compile: 'field: aKeyString
	| v |
	v := self dataMap entryAt: aKeyString.
	^ v ifNil: [ EcAbsent default ]'.
"hasField: — is the key present in the data map?"
entity compile: 'hasField: aKeyString
	^ self dataMap includesKey: aKeyString'.
"textAt: — a text/bytes field as a Smalltalk String (utf8-decoded), or nil if absent/other."
entity compile: 'textAt: aKeyString
	| v |
	v := self field: aKeyString.
	(v isKindOf: EcTextString) ifTrue: [ ^ v string ].
	^ nil'.
"bytesAt: — a byte-string field as a ByteArray, or nil if absent/other."
entity compile: 'bytesAt: aKeyString
	| v |
	v := self field: aKeyString.
	(v isKindOf: EcByteString) ifTrue: [ ^ v bytes ].
	^ nil'.
"uintAt: — an int field value (an Integer), or nil if absent/other."
entity compile: 'uintAt: aKeyString
	| v |
	v := self field: aKeyString.
	(v isKindOf: EcInt) ifTrue: [ ^ v value ].
	^ nil'.

"── wire form: {type, data, content_hash} as an EcMap (§3.1). ──"
entity compile: 'asWireMap
	| m |
	m := EcMap new.
	m at: (EcTextString string: ''type'') put: (EcTextString string: type).
	m at: (EcTextString string: ''data'') put: data.
	m at: (EcTextString string: ''content_hash'') put: (EcByteString bytes: self contentHash).
	^ m'.

"asWireBytes — the entity''s wire map canonically CBOR-encoded (a nested-entity value)."
entity compile: 'asWireBytes  ^ EcCborEncoder encode: self asWireMap'.

"fromWireMap: — parse a wire {type,data,content_hash} map, RECOMPUTE the hash from
 {type,data}, validate against the carried content_hash (§1.8 fidelity). Signals
 EcProtocolError on a bad shape / mismatch (caught at the dispatch boundary)."
entity class compile: 'fromWireMap: anEcMap
	| typeV dataV ent carried |
	(anEcMap isKindOf: EcMap) ifFalse: [ ^ EcWireError signal: ''entity: not a map'' ].
	typeV := anEcMap entryAt: ''type''.
	(typeV isKindOf: EcTextString) ifFalse: [ ^ EcWireError signal: ''entity: missing type'' ].
	dataV := anEcMap entryAt: ''data''.
	dataV isNil ifTrue: [ ^ EcWireError signal: ''entity: missing data'' ].
	ent := self type: typeV string data: dataV.
	carried := anEcMap entryAt: ''content_hash''.
	(carried isKindOf: EcByteString) ifTrue: [
		ent contentHash = carried bytes ifFalse: [ ^ EcHashMismatchError signal: ''entity: content_hash mismatch'' ] ].
	^ ent'.

"admittedType:data:hash: — the §6.3 RECEIPT constructor: bind an entity to a content_hash
 the CALLER has already verified against content_hash({type, data}).

 Every other constructor AUTHORS a hash (contentHash memoizes a fresh EcContentHash). On the
 system/tree:put path that is exactly what §6.3 (0.8.2.11) forbids — the submitter authors,
 the peer verifies. This takes the carried bytes verbatim and is reachable only from the
 admission ladder, which has just proved they match."
entity class compile: 'admittedType: aTypeString data: aDataValue hash: verifiedHash
	| e |
	e := self type: aTypeString data: aDataValue.
	e setContentHash: verifiedHash.
	^ e'.
entity compile: 'setContentHash: aByteArray  hash := aByteArray'.

"fromWireValue: — accept either a nested wire map OR a bytes-wrapped CBOR of one."
entity class compile: 'fromWireValue: anEcValue
	(anEcValue isKindOf: EcMap) ifTrue: [ ^ self fromWireMap: anEcValue ].
	(anEcValue isKindOf: EcByteString)
		ifTrue: [ ^ self fromWireMap: (EcCborDecoder decode: anEcValue bytes) ].
	^ EcWireError signal: ''entity: unrecognized wire value'''.

'EntityCore-Peer:EcEntity + EcAbsent installed'
