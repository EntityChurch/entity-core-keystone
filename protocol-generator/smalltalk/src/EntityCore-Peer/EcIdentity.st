"entity-core-protocol-smalltalk — L1 identity: keystore + peer identity + signatures
(EntityCore-Peer).

An identity is derived from a 32-byte Ed25519 SEED (the entity-core PEM = base64 of the raw
seed). From the seed we derive: the 32-byte public key (FFI), the `system/peer` entity
{public_key, key_type} (§3.5 — peer_id is NOT in the hashable basis), the id_hash =
content_hash(peer_entity), and the wire peer_id String (§1.5 canonical form:
Base58(varint(0x01) ‖ varint(0x00) ‖ raw-pubkey) — hash_type 0x00 identity-multihash).

Single-event-loop peer: ONE identity per process (an EcIdentity instance held by EcPeer).
Crypto crosses the C-ABI via `EcLibEntityCoreCodec default` (A-ST-005/009).

LIVE-IMAGE NOTE: EcContentHash / EcPeerId / EcEntity / EcVal resolve at send-time."

| pkg cls |
pkg := 'EntityCore-Peer'.

cls := ((Object << #EcIdentity) slots: { #seed. #pubkey. #peerEntity. #idHash. #peerId };
	package: pkg; install).

"§1.5 key_type 0x01 (ed25519), hash_type 0x00 (identity-multihash) — class-side constants."
cls class compile: 'keyTypeEd25519  ^ 1'.
cls class compile: 'hashTypeIdentity  ^ 0'.

"fromSeed: — install an identity from a 32-byte seed ByteArray. Signals BadSeedError on a
 wrong length. Derives pubkey, the system/peer entity, id_hash, and the peer_id String."
cls class compile: 'fromSeed: aSeedByteArray
	aSeedByteArray size = 32 ifFalse: [ ^ BadSeedError signal: ''seed must be 32 bytes'' ].
	^ self new setSeed: aSeedByteArray'.

cls compile: 'setSeed: aSeedByteArray
	seed := aSeedByteArray copy.
	pubkey := EcLibEntityCoreCodec default ed25519PubkeyFromSeed: seed.
	peerEntity := EcEntity type: ''system/peer'' data: (EcVal map: {
		''public_key'' -> (EcVal bytes: pubkey).
		''key_type'' -> (EcVal text: ''ed25519'') }).
	idHash := peerEntity contentHash.
	peerId := EcPeerId format: EcIdentity keyTypeEd25519
		hash: EcIdentity hashTypeIdentity digest: pubkey.
	^ self'.

cls compile: 'seed  ^ seed'.
cls compile: 'pubkey  ^ pubkey'.
cls compile: 'peerEntity  ^ peerEntity'.
cls compile: 'idHash  ^ idHash'.
cls compile: 'peerId  ^ peerId'.

"── signatures (§3.5 system/signature) ──"
"signatureEntityFor: targetHashBytes — build a system/signature {algorithm, signature,
 signer, target} entity signing the target content-hash bytes with our seed. signer = our
 id_hash. The full hash bytes (format-code ‖ digest) are the signed message (§4.6)."
cls compile: 'signatureEntityFor: targetHashBytes
	| sig |
	sig := EcLibEntityCoreCodec default ed25519Sign: targetHashBytes withSeed: seed.
	^ EcEntity type: ''system/signature'' data: (EcVal map: {
		''algorithm'' -> (EcVal text: ''ed25519'').
		''signature'' -> (EcVal bytes: sig).
		''signer'' -> (EcVal bytes: idHash).
		''target'' -> (EcVal bytes: targetHashBytes) })'.

"peerIdForPubkey: — derive the §1.5 peer_id String of an Ed25519 public key."
cls class compile: 'peerIdForPubkey: aPubkeyByteArray
	^ EcPeerId format: self keyTypeEd25519 hash: self hashTypeIdentity digest: aPubkeyByteArray'.

"verifySignatureEntity:withPubkey: — verify a system/signature entity''s signature over its
 `target` under the given 32-byte public key. Answers a Boolean."
cls class compile: 'verifySignatureEntity: aSigEntity withPubkey: aPubkey
	| target sig |
	aPubkey size = 32 ifFalse: [ ^ false ].
	target := aSigEntity bytesAt: ''target''.
	sig := aSigEntity bytesAt: ''signature''.
	(target isNil or: [ sig isNil ]) ifTrue: [ ^ false ].
	sig size = 64 ifFalse: [ ^ false ].
	^ EcLibEntityCoreCodec default ed25519Verify: target sig: sig pubkey: aPubkey'.

'EntityCore-Peer:EcIdentity installed'
