"entity-core-protocol-smalltalk — MULTISIG ACCEPT-path unit test (the keystone payoff).

The oracle's `multisig` category is REJECTION-ONLY (every vector is a malformed 2-of-3 that
MUST be 403), so a fail-closed peer passes it VACUOUSLY without ever implementing the K-of-N
accept path. Per the keystone lesson (conformance-green can be vacuous — always add an accept
test the oracle can't cover), this builds a GENUINE 2-of-3 multisig root cap in-image, co-signs
it as two of the three signers (one of them the local peer, M6), and asserts the §5.5 M3/M4/M6
verifier ACCEPTS it — then flips each M-rule and asserts it REJECTS. Exercises the direction
the oracle only exercises negatively.

Runs headless against the peer image. Prints MULTISIG-ACCEPT <pass>/<total>; raises on failure.
Crypto crosses the UFFI binding to libentitycore_codec."

| out pass total check localSeed s2Seed s3Seed
  localIdent peer2Ident peer3Ident local peer2 peer3
  mkPeer mkSig gmap tokenData token env buildEnv
  sig2 sig3 sigLocal okAccept |
out := WriteStream on: String new.
pass := 0. total := 0.
check := [ :flag :name |
	total := total + 1.
	flag ifTrue: [ pass := pass + 1. out nextPutAll: 'ok   ' ] ifFalse: [ out nextPutAll: 'FAIL ' ].
	out nextPutAll: name; nextPut: Character lf ].

"three distinct identities; `local` is the peer (M6 signer-is-local)."
localSeed := ByteArray new: 32 withAll: 16r11.
s2Seed := ByteArray new: 32 withAll: 16r22.
s3Seed := ByteArray new: 32 withAll: 16r33.
localIdent := EcIdentity fromSeed: localSeed.
peer2Ident := EcIdentity fromSeed: s2Seed.
peer3Ident := EcIdentity fromSeed: s3Seed.
local := localIdent peerId.

"── build a 2-of-3 multi-granter map {signers:[h1,h2,h3], threshold:2} where the signer HASHES
    are the id_hashes of the three peer entities. ──"
gmap := EcVal map: {
	'signers' -> (EcVal array: {
		EcVal bytes: localIdent idHash.
		EcVal bytes: peer2Ident idHash.
		EcVal bytes: peer3Ident idHash }).
	'threshold' -> (EcVal uint: 2) }.

"the root token: granter = the multi-granter map, grantee = local (resolvable), grants floor."
tokenData := EcVal map: {
	'granter' -> gmap.
	'grantee' -> (EcVal bytes: localIdent idHash).
	'grants' -> (EcVal array: { EcVal map: {
		'handlers' -> (EcVal map: { 'include' -> (EcVal array: { EcVal text: '*' }) }).
		'operations' -> (EcVal map: { 'include' -> (EcVal array: { EcVal text: '*' }) }).
		'resources' -> (EcVal map: { 'include' -> (EcVal array: { EcVal text: '*' }) }) } }).
	'created_at' -> (EcVal uint: 1) }.
token := EcEntity type: 'system/capability/token' data: tokenData.

"buildEnv — an envelope with the token as root + the given included entities (the 3 signer peer
 entities + the K signatures over the token hash)."
buildEnv := [ :includedEntities |
	| e |
	e := EcEnvelope root: token.
	includedEntities do: [ :ent | e include: ent ].
	e ].

"K=2 valid signatures over the token content_hash: local + peer2 (M4 threshold met; M6 local∈)."
sigLocal := localIdent signatureEntityFor: token contentHash.
sig2 := peer2Ident signatureEntityFor: token contentHash.
sig3 := peer3Ident signatureEntityFor: token contentHash.

"── ACCEPT: 2 distinct valid sigs (local + peer2), all 3 signer peers resolvable. ──"
env := buildEnv value: {
	localIdent peerEntity. peer2Ident peerEntity. peer3Ident peerEntity. sigLocal. sig2 }.
okAccept := EcCapAuthz verifyMultisigRoot: token local: local in: env.
check value: okAccept value: '2-of-3 multisig root ACCEPTED (M3 struct + M4 threshold=2 + M6 local-signer)'.

"── REJECT: only 1 valid signature (local) — below threshold 2 (M4 fails). ──"
env := buildEnv value: {
	localIdent peerEntity. peer2Ident peerEntity. peer3Ident peerEntity. sigLocal }.
check value: (EcCapAuthz verifyMultisigRoot: token local: local in: env) not
	value: '1 valid signature REJECTED (below threshold 2 — M4)'.

"── REJECT: 2 sigs but NEITHER is the local peer (peer2 + peer3) — M6 local-in-signers still ok
    (local IS a listed signer), BUT the sigs are valid so this should ACCEPT (M6 is about the
    signer SET, not who signed). Instead assert the negative case: local NOT in the signer set. ──"
"M6 negative: rebuild gmap WITHOUT the local id_hash (only peer2, peer3, and a bogus third)."
gmap := EcVal map: {
	'signers' -> (EcVal array: {
		EcVal bytes: peer2Ident idHash.
		EcVal bytes: peer3Ident idHash.
		EcVal bytes: (ByteArray new: 34 withAll: 16r44) }).
	'threshold' -> (EcVal uint: 2) }.
tokenData := EcVal map: {
	'granter' -> gmap. 'grantee' -> (EcVal bytes: localIdent idHash).
	'grants' -> (EcVal array: { EcVal map: { 'handlers' -> (EcVal map: { 'include' -> (EcVal array: { EcVal text: '*' }) }) } }).
	'created_at' -> (EcVal uint: 1) }.
token := EcEntity type: 'system/capability/token' data: tokenData.
sig2 := peer2Ident signatureEntityFor: token contentHash.
sig3 := peer3Ident signatureEntityFor: token contentHash.
env := (EcEnvelope root: token)
	include: peer2Ident peerEntity; include: peer3Ident peerEntity;
	include: sig2; include: sig3; yourself.
check value: (EcCapAuthz verifyMultisigRoot: token local: local in: env) not
	value: 'local NOT in signer set REJECTED (M6)'.

"── REJECT: threshold 1 (K < 2 violates M3). ──"
gmap := EcVal map: {
	'signers' -> (EcVal array: { EcVal bytes: localIdent idHash. EcVal bytes: peer2Ident idHash }).
	'threshold' -> (EcVal uint: 1) }.
tokenData := EcVal map: {
	'granter' -> gmap. 'grantee' -> (EcVal bytes: localIdent idHash).
	'grants' -> (EcVal array: { EcVal map: { 'handlers' -> (EcVal map: { 'include' -> (EcVal array: { EcVal text: '*' }) }) } }).
	'created_at' -> (EcVal uint: 1) }.
token := EcEntity type: 'system/capability/token' data: tokenData.
sigLocal := localIdent signatureEntityFor: token contentHash.
sig2 := peer2Ident signatureEntityFor: token contentHash.
env := (EcEnvelope root: token)
	include: localIdent peerEntity; include: peer2Ident peerEntity;
	include: sigLocal; include: sig2; yourself.
check value: (EcCapAuthz verifyMultisigRoot: token local: local in: env) not
	value: 'threshold 1 REJECTED (K<2 — M3)'.

out nextPut: Character lf; nextPutAll: 'MULTISIG-ACCEPT '; print: pass; nextPut: $/; print: total; nextPut: Character lf.
Stdio stdout nextPutAll: out contents; flush.
pass = total ifFalse: [ Error signal: 'multisig-accept had failures' ].
'MULTISIG-ACCEPT ', pass printString, '/', total printString
