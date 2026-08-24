"entity-core-protocol-smalltalk — content_hash construction (ENTITY-CBOR-ENCODING §4.2):

  content_hash = varint(format_code) || hash_alg(ECF({type, data}))

format_code 0x00 = ecfv1-sha256 (the §9.1 floor); 0x01 = ecfv1-sha384 (agility). The
format_code is NOT part of the hashed basis (only {type,data} is hashed) and its prefix is a
multicodec LEB128 varint (N1 — content_hash.4 uses a synthetic >=0x80 code). The ECF encoding
is the pure-Smalltalk codec; the SHA crosses the C-ABI (A-ST-009: one audited source).

The entity carrier is the EcMap {type: <text>, data: <value>}; data is an ARBITRARY EcValue,
NOT necessarily a map (A-JAVA-010)."

| pkg cls |
pkg := 'EntityCore-Codec'.

cls := (Object << #EcContentHash package: pkg) install.

"of: aTypeString data: aDataEcValue format: formatCode -> the content_hash ByteArray."
cls class compile: 'of: aTypeString data: aDataValue format: formatCode
	| entity ecf digest out |
	entity := EcMap new.
	entity at: (EcTextString string: ''type'') put: (EcTextString string: aTypeString).
	entity at: (EcTextString string: ''data'') put: aDataValue.
	ecf := EcCborEncoder encode: entity.
	digest := formatCode = 1
		ifTrue: [ EcLibEntityCoreCodec default sha384: ecf ]
		ifFalse: [ (formatCode = 0)
			ifTrue: [ EcLibEntityCoreCodec default sha256: ecf ]
			ifFalse: [ "forward-compat: a synthetic code >= 0x80 still uses SHA-256 for the
			           digest per content_hash.4 (the test exercises the varint prefix width,
			           not a new hash algorithm)."
				EcLibEntityCoreCodec default sha256: ecf ] ].
	out := WriteStream on: (ByteArray new: digest size + 2).
	out nextPutAll: (EcVarint encode: formatCode).
	out nextPutAll: digest.
	^ out contents'.

"signEntity: anEntityMapValue withSeed: seedBytes -> the 64-byte Ed25519 signature over the
 canonical-ECF-encoded entity (§9.1). The entity is {type, data}."
cls class compile: 'signEntity: anEntityValue withSeed: seedBytes
	| ecf |
	ecf := EcCborEncoder encode: anEntityValue.
	^ EcLibEntityCoreCodec default ed25519Sign: ecf withSeed: seedBytes'.

'EntityCore-Codec:EcContentHash installed'
