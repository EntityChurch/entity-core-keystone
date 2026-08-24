"entity-core-protocol-smalltalk — the built-in MUST handlers, compiled onto EcPeer
(EntityCore-Peer). Cross-FILE class references by global name are fine (A-ST-010): EcPeer is
globally registered by the time this doit runs (it loads after EcPeer.st).

The only handler with a full §4.1 body at S3 is system/protocol/connect (hello +
authenticate — the handshake the smoke exercises). system/tree is registered with a minimal
get body (so §6.6 resolves it for the authority-gated leg; full semantics are S4).

Handlers are message-sends receiving an EcHandlerContext, answering an EcHandlerResult."

| ecPeer |
ecPeer := Smalltalk at: #EcPeer.

"── keypair loading (§ peer --name): read ~/.entity/peers/NAME/keypair (entity-core PEM =
    base64 of a raw 32-byte seed; armor lines starting '-' are skipped). Class-side. ──"
ecPeer class compile: 'loadSeedForName: aName
	| home path lines b64 seed |
	home := Smalltalk os environment at: ''HOME'' ifAbsent: [ ''/root'' ].
	path := home, ''/.entity/peers/'', aName, ''/keypair''.
	lines := (FileLocator root / path) contents lines
		reject: [ :ln | ln isEmpty or: [ (ln beginsWith: ''-'') ] ].
	b64 := lines inject: '''' into: [ :acc :ln | acc, ln trimBoth ].
	seed := b64 base64Decoded.
	seed size = 32 ifFalse: [ ^ BadSeedError signal: ''keypair seed must be 32 bytes'' ].
	^ seed asByteArray'.

"── nonce mint (§4.6 SHOULD): SHA256(counter ‖ our id_hash). Uniqueness + reproducibility,
    not CSPRNG strength. ──"
ecPeer compile: 'mintNonceFor: aConn
	| ctr seed digest |
	ctr := self nextNonceCounter.   "PEER-GLOBAL counter (§4.6): unique per issuance across
	                                 connections, so a captured authenticate never replays (F12)."
	seed := WriteStream on: (ByteArray new: 8 + identity idHash size).
	8 to: 1 by: -1 do: [ :i | seed nextPut: ((ctr bitShift: 0 - (8 * (i - 1))) bitAnd: 16rFF) ].
	seed nextPutAll: identity idHash.
	digest := EcLibEntityCoreCodec default sha256: seed contents.
	aConn issuedNonce: digest.
	^ digest'.

"── §4.5 negotiation: is `key` a params array that does NOT include our `supported` value? ──"
ecPeer compile: 'params: aParamsEntity disjointOn: aKey supported: aValue
	| v |
	aParamsEntity isNil ifTrue: [ ^ false ].
	v := aParamsEntity field: aKey.
	(v isKindOf: EcArray) ifFalse: [ ^ false ].               "absent / non-array -> no constraint"
	^ (v items anySatisfy: [ :e | (e isKindOf: EcTextString) and: [ e string = aValue ] ]) not'.

"── the connect handler (§4.1): hello then authenticate. Ordering (§4.2): hello before
    authenticate; an unknown op is a sequence error. ──"
ecPeer compile: 'handleConnect: ctx
	ctx operation = ''hello'' ifTrue: [ ^ self handleHello: ctx ].
	ctx operation = ''authenticate'' ifTrue: [ ^ self handleAuthenticate: ctx ].
	^ EcHandlerResult error: 400 code: ''connection_sequence_error'' message: ''unknown connect op'''.

"handleHello: — §4.5 negotiation, issue a nonce, answer the responder hello."
ecPeer compile: 'handleHello: ctx
	| conn params nonce result |
	conn := ctx connection.
	conn isEstablished ifTrue: [
		^ EcHandlerResult error: 409 code: ''connection_already_established'' message: nil ].
	params := ctx params.
	(self params: params disjointOn: ''hash_formats'' supported: ''ecfv1-sha256'')
		ifTrue: [ ^ EcHandlerResult error: 400 code: ''incompatible_hash_format'' message: nil ].
	(self params: params disjointOn: ''key_types'' supported: ''ed25519'')
		ifTrue: [ ^ EcHandlerResult error: 400 code: ''unsupported_key_type'' message: nil ].
	(self helloKeyTypeBad: params)
		ifTrue: [ ^ EcHandlerResult error: 400 code: ''unsupported_key_type'' message: nil ].
	nonce := self mintNonceFor: conn.
	result := EcEntity type: ''system/protocol/connect/hello'' data: (EcVal map: {
		''peer_id'' -> (EcVal text: identity peerId).
		''nonce'' -> (EcVal bytes: nonce).
		''protocols'' -> (EcVal array: { EcVal text: ''entity-core/1.0'' }).
		''timestamp'' -> (EcVal uint: 0).
		''hash_formats'' -> (EcVal array: { EcVal text: ''ecfv1-sha256'' }).
		''key_types'' -> (EcVal array: { EcVal text: ''ed25519'' }) }).
	^ EcHandlerResult ok: result'.

"handleAuthenticate: — verify nonce echo + signature + identity binding, then issue a seed
 grant. On success: mint a root single-sig token granting the §4.4 floor, sign it, and carry
 the token + our peer entity + the signature + the grantee peer into the response included."
ecPeer compile: 'handleAuthenticate: ctx
	| conn params nonce pubkey sig claimedPeerId grantee token sigEnt granteePeer result res |
	conn := ctx connection.
	"RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed single-use
	 nonce. The STATUS is pinned to 401 invalid_nonce -- a 409 state-conflict under-
	 signals the replay."
	conn isEstablished ifTrue: [
		^ EcHandlerResult error: 401 code: ''invalid_nonce'' message: nil ].
	conn issuedNonce isNil ifTrue: [
		^ EcHandlerResult error: 401 code: ''invalid_nonce'' message: ''no nonce issued'' ].
	params := ctx params.
	params isNil ifTrue: [ ^ EcHandlerResult error: 401 code: ''authentication_failed'' message: nil ].
	"nonce echo check"
	nonce := params bytesAt: ''nonce''.
	(nonce isNil or: [ nonce ~= conn issuedNonce ]) ifTrue: [
		^ EcHandlerResult error: 401 code: ''invalid_nonce'' message: nil ].
	"public key (32 bytes)"
	pubkey := params bytesAt: ''public_key''.
	(pubkey isNil or: [ pubkey size ~= 32 ]) ifTrue: [
		^ EcHandlerResult error: 400 code: ''unsupported_key_type'' message: nil ].
	"verify the authenticate signature (target = params entity content_hash) from included"
	sig := EcCapability findSignatureFor: params contentHash in: ctx envelope.
	sig isNil ifTrue: [ ^ EcHandlerResult error: 401 code: ''authentication_failed'' message: nil ].
	(EcIdentity verifySignatureEntity: sig withPubkey: pubkey) ifFalse: [
		^ EcHandlerResult error: 401 code: ''authentication_failed'' message: nil ].
	"identity binding: claimed peer_id == peer_id derived from public_key"
	claimedPeerId := params textAt: ''peer_id''.
	(claimedPeerId isNil or: [ claimedPeerId ~= (EcIdentity peerIdForPubkey: pubkey) ]) ifTrue: [
		^ EcHandlerResult error: 401 code: ''identity_mismatch'' message: nil ].
	"SUCCESS: the grantee id_hash = content_hash(system/peer{public_key,key_type}) of the auth''d peer."
	granteePeer := EcEntity type: ''system/peer'' data: (EcVal map: {
		''public_key'' -> (EcVal bytes: pubkey).
		''key_type'' -> (EcVal text: ''ed25519'') }).
	grantee := granteePeer contentHash.
	token := self mintSeedTokenFor: grantee.
	sigEnt := identity signatureEntityFor: token contentHash.
	conn establish.
	result := EcEntity type: ''system/capability/grant'' data: (EcVal map: {
		''token'' -> (EcVal bytes: token contentHash) }).
	res := EcHandlerResult ok: result.
	res includeInResponse: token.
	res includeInResponse: identity peerEntity.
	res includeInResponse: sigEnt.
	res includeInResponse: granteePeer.
	^ res'.

"mintSeedTokenFor: — a root single-sig capability token (granter = us, grantee = the auth''d
 peer) granting the §4.4 open-grants floor (default -> * on handlers/operations/peers/
 resources). created_at is stamped so a delegated child never collides on content_hash with
 the seed (§5.1 revocation-cascade avoidance)."
ecPeer compile: 'mintSeedTokenFor: aGranteeHash
	| star grantEntry |
	star := [ :field | field -> (EcVal map: { ''include'' -> (EcVal array: { EcVal text: ''*'' }) }) ].
	grantEntry := EcVal map: {
		(star value: ''handlers'').
		(star value: ''operations'').
		(star value: ''peers'').
		''resources'' -> (EcVal map: { ''include'' -> (EcVal array: { EcVal text: ''*''. EcVal text: ''/*/*'' }) }) }.
	^ EcEntity type: ''system/capability/token'' data: (EcVal map: {
		''grantee'' -> (EcVal bytes: aGranteeHash).
		''granter'' -> (EcVal bytes: identity idHash).
		''grants'' -> (EcVal array: { grantEntry }).
		''created_at'' -> (EcVal uint: self nowMillis) })'.

"nowMillis — wall-clock ms since the epoch (§2a handler-set timestamps)."
ecPeer compile: 'nowMillis
	^ (DateAndTime now asUnixTime) * 1000'.

"── the tree handler (§6.3): get an entity bound in the tree by path. Minimal get body at S3;
    put / listing are S4. ──"
ecPeer compile: 'handleTree: ctx
	| target ent |
	ctx operation = ''get'' ifFalse: [
		^ EcHandlerResult error: 501 code: ''unsupported_operation'' message: nil ].
	target := self treeTargetOf: ctx exec.
	target isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''ambiguous_resource'' message: nil ].
	ent := store getAt: target.
	ent isNil ifTrue: [ ^ EcHandlerResult error: 404 code: ''not_found'' message: nil ].
	^ EcHandlerResult ok: ent'.

"treeTargetOf: — the resource.targets[0] text of an EXECUTE, or nil."
ecPeer compile: 'treeTargetOf: anExec
	| resource targets first |
	resource := anExec field: ''resource''.
	(resource isKindOf: EcMap) ifFalse: [ ^ nil ].
	targets := resource entryAt: ''targets''.
	(targets isKindOf: EcArray) ifFalse: [ ^ nil ].
	targets items isEmpty ifTrue: [ ^ nil ].
	first := targets items first.
	(first isKindOf: EcTextString) ifFalse: [ ^ nil ].
	^ first string'.

'EntityCore-Peer:EcPeer handlers installed'
