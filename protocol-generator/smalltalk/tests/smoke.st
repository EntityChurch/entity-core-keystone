"entity-core-protocol-smalltalk — S3 two-peer loopback smoke (the initiator side).

Runs as a headless doit against the peer image; the responder port is read from the
EC_SMOKE_PORT env var (a headless eval appends argv to the source, so options travel via ENV
— the S2 A-ST note). Dials the responder (a bin/peer.st process on 127.0.0.1:<port>) and
drives the §4.1 handshake + the post-handshake checks, asserting each leg. Prints
`SMOKE <pass>/<total>` and exits non-zero on any failure.

Scenario (the cohort shape — study forth test/smoke.fs 6/6):
  1. connect:hello        -> 200, responder hello carries a peer_id + nonce
  2. connect:authenticate -> 200, result is a system/capability/grant with a token
  3. connection established (the grant proves it)
  4. EXECUTE unregistered path -> EXECUTE_RESPONSE status 404 handler_not_found
  5. request_id demux: two EXECUTEs PIPELINED (both sent before either reply is read); replies
     correlate by request_id (out-of-order-safe)
  6. clean teardown

The initiator uses a DISTINCT identity (seed 0x22) so authenticate binds a real second peer.
Everything is offline (loopback 127.0.0.1 under --network=none)."

| port ident conn ridCtr pass total out check nextRid sendExec recvRoot doHello respNonce grantTokenHash
  helloRoot authRoot unregRoot ridA ridB r1 r2 g1 g2 hasA hasB buildExec signAndSend |

port := Integer readFrom: (Smalltalk os environment at: 'EC_SMOKE_PORT' ifAbsent: [ '0' ]) readStream.
ident := EcIdentity fromSeed: (ByteArray new: 32 withAll: 16r22).
pass := 0. total := 0. ridCtr := 0.
"A-ST-006: build a result STRING (the non-interactive transcript has no #show:)."
out := WriteStream on: String new.
check := [ :flag :name |
	total := total + 1.
	flag ifTrue: [ pass := pass + 1. out nextPutAll: 'ok   ' ] ifFalse: [ out nextPutAll: 'FAIL ' ].
	out nextPutAll: name; nextPut: Character lf ].

nextRid := [ ridCtr := ridCtr + 1. 'req-', ridCtr printString ].

"recvRoot — read one frame, decode the envelope, answer the root entity (or nil)."
recvRoot := [
	| frame env |
	frame := conn readFrame.
	((frame == #eof) or: [ frame == #oversize ])
		ifTrue: [ nil ]
		ifFalse: [ env := EcEnvelope fromWireBytes: frame. env root ] ].

"sendExec — frame + send an EXECUTE with its included set (an OrderedCollection of entities)."
sendExec := [ :exec :includedEntities |
	| env |
	env := EcEnvelope root: exec.
	includedEntities do: [ :e | env include: e ].
	conn sendFrame: env asWireBytes ].

"── open the connection ──"
Socket initializeNetwork.
conn := EcNet dial: port.

"── 1. hello ── params {peer_id, nonce, protocols, timestamp} on system/protocol/connect ──"
doHello := [
	| params exec |
	params := EcEntity type: 'system/protocol/connect/hello' data: (EcVal map: {
		'peer_id' -> (EcVal text: ident peerId).
		'nonce' -> (EcVal bytes: (ByteArray new: 32 withAll: 16r33)).
		'protocols' -> (EcVal array: { EcVal text: 'entity-core/0.8' }).
		'timestamp' -> (EcVal uint: 0) }).
	exec := EcWire execRequestId: nextRid value uri: 'system/protocol/connect'
		operation: 'hello' params: params author: nil capability: nil.
	sendExec value: exec value: OrderedCollection new.
	recvRoot value ].
helloRoot := doHello value.
check value: (helloRoot notNil and: [ (helloRoot uintAt: 'status') = 200 ]) value: 'hello -> 200'.

"capture the responder-issued nonce from the hello result entity."
respNonce := nil.
helloRoot ifNotNil: [
	| resultV hello |
	resultV := helloRoot field: 'result'.
	resultV isAbsent ifFalse: [
		hello := EcEntity fromWireValue: resultV.
		respNonce := hello bytesAt: 'nonce' ] ].
check value: (respNonce notNil) value: 'responder issued a nonce'.

"── 2. authenticate ── sign the params entity content_hash, carry sig + our peer entity ──"
authRoot := nil.
respNonce ifNotNil: [
	| params sigEnt exec inc |
	params := EcEntity type: 'system/protocol/connect/authenticate' data: (EcVal map: {
		'peer_id' -> (EcVal text: ident peerId).
		'public_key' -> (EcVal bytes: ident pubkey).
		'key_type' -> (EcVal text: 'ed25519').
		'nonce' -> (EcVal bytes: respNonce) }).
	sigEnt := ident signatureEntityFor: params contentHash.
	exec := EcWire execRequestId: nextRid value uri: 'system/protocol/connect'
		operation: 'authenticate' params: params author: nil capability: nil.
	inc := OrderedCollection new.
	inc add: sigEnt; add: ident peerEntity.
	sendExec value: exec value: inc.
	authRoot := recvRoot value ].
check value: (authRoot notNil and: [ (authRoot uintAt: 'status') = 200 ]) value: 'authenticate -> 200 (grant)'.

"── 3. established: the grant result carries a token hash ──"
grantTokenHash := nil.
authRoot ifNotNil: [
	| resultV grant |
	resultV := authRoot field: 'result'.
	resultV isAbsent ifFalse: [
		grant := EcEntity fromWireValue: resultV.
		grantTokenHash := grant bytesAt: 'token' ] ].
check value: (grantTokenHash notNil) value: 'grant carries a capability token'.

"── 4. unregistered path -> 404 (an authenticated, signed EXECUTE; §6.6 resolution-first) ──"
buildExec := [ :rid |
	EcWire execRequestId: rid uri: 'local/does-not-exist' operation: 'get'
		params: EcWire emptyParams author: ident idHash capability: grantTokenHash ].
signAndSend := [ :exec |
	| sigEnt inc |
	sigEnt := ident signatureEntityFor: exec contentHash.
	inc := OrderedCollection new.
	inc add: sigEnt; add: ident peerEntity.
	sendExec value: exec value: inc ].
unregRoot := nil.
grantTokenHash ifNotNil: [
	signAndSend value: (buildExec value: nextRid value).
	unregRoot := recvRoot value ].
check value: (unregRoot notNil and: [ (unregRoot uintAt: 'status') = 404 ]) value: 'unregistered path -> 404'.

"── 5. request_id demux (§6.11): PIPELINE two EXECUTEs (both sent before any reply is read),
    then read both replies and assert each returned request_id is one we sent. The demux is by
    request_id, not by wire order. ──"
ridA := nextRid value. ridB := nextRid value.
grantTokenHash ifNotNil: [
	signAndSend value: (buildExec value: ridA).
	signAndSend value: (buildExec value: ridB) ].
r1 := grantTokenHash ifNotNil: [ recvRoot value ] ifNil: [ nil ].
r2 := grantTokenHash ifNotNil: [ recvRoot value ] ifNil: [ nil ].
g1 := r1 ifNotNil: [ r1 textAt: 'request_id' ].
g2 := r2 ifNotNil: [ r2 textAt: 'request_id' ].
hasA := (g1 = ridA) or: [ g2 = ridA ].
hasB := (g1 = ridB) or: [ g2 = ridB ].
check value: (hasA and: [ hasB ]) value: 'pipelined replies correlate by request_id (§6.11 demux)'.

"── 6. clean teardown ──"
conn close.

out nextPut: Character lf; nextPutAll: 'SMOKE '; print: pass; nextPut: $/; print: total; nextPut: Character lf.
Stdio stdout nextPutAll: out contents; flush.
"exit non-zero on any failure: raise so the eval handler returns exit 1."
pass = total ifFalse: [ Error signal: 'smoke had failures' ].
'SMOKE ', pass printString, '/', total printString
