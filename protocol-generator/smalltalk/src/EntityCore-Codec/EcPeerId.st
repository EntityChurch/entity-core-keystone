"entity-core-protocol-smalltalk — peer_id canonical form (§1.5 canonical-form table).

peer_id wire form = Base58( varint(key_type) || varint(hash_type) || digest ). For Ed25519
the §1.5 table sets hash_type = 0x00 identity-multihash with digest = the raw 32-byte public
key; the conformance vectors also exercise SHA-256 peer-ids (hash_type 0x01) and a synthetic
multi-byte key_type (peer_id.3, the N1 varint test). The peer_id VALUE on the wire is a CBOR
text string wrapping the base58 string (the caller wraps with EcTextString)."

| pkg cls |
pkg := 'EntityCore-Codec'.

cls := (Object << #EcPeerId package: pkg) install.

"format: keyType hash: hashType digest: aByteArray -> the base58 peer_id String."
cls class compile: 'format: keyType hash: hashType digest: aByteArray
	| raw |
	raw := WriteStream on: (ByteArray new: 64).
	raw nextPutAll: (EcVarint encode: keyType).
	raw nextPutAll: (EcVarint encode: hashType).
	raw nextPutAll: aByteArray.
	^ EcBase58 encode: raw contents'.

"parse: aString -> an Array { keyType. hashType. digest }. THROWs on bad char / truncated."
cls class compile: 'parse: aString
	| raw kt htPair ht digestStart |
	raw := EcBase58 decode: aString.
	kt := EcVarint decodeFrom: raw at: 1.
	htPair := EcVarint decodeFrom: raw at: 1 + kt value.
	ht := htPair.
	digestStart := 1 + kt value + htPair value.
	^ { kt key. htPair key. (raw copyFrom: digestStart to: raw size) }'.

"parseKeyType: aString -> the multihash key_type Integer (element 1 of parse:). THROWs on a
 malformed peer_id — callers wrap in on: Error do: to defer to a later check (A-ST negotiation)."
cls class compile: 'parseKeyType: aString
	^ (self parse: aString) first'.

'EntityCore-Codec:EcPeerId installed'
