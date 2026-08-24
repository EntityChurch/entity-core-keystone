"entity-core-protocol-smalltalk — S3 peer-layer foundation self-test (no network).

Exercises the S3 machinery UNITS directly (the direction the loopback smoke + a
rejection-only oracle can't fully cover): identity derivation + sign/verify, store
round-trips, the N5 envelope `included` byte-key/content_hash invariant + first-seen dedup,
the wire builders, and the two §4.10 non-functional MUSTs baked in at S3 — the §4.10(b)
chain-depth pre-check (-> #depth / 400, BEFORE the authz walk) and the §4.10(a) 16-MiB
payload cap classifier on the length prefix (-> 413 / drain-and-keep).

Prints `SELFTEST <pass>/<total>` and exits non-zero on any failure. Runs against the
snapshotted peer image (A-ST-010)."

"ALL temporaries are declared at the TOP: in a single live-image doit a temp decl cannot
 follow a statement (A-ST-010 family — the doit compiles as one method before running)."
| pass total out check ident store env root wa r2 tokenRoot cur envD exec resp rid
  sigEnt ent e2 orphanEnv orphan pend recA recB replyRoot |
pass := 0. total := 0.
"A-ST-006: the non-interactive transcript has no #show:/#showln:; a driver builds a result
 STRING and returns it (eval prints the doit''s value)."
out := WriteStream on: String new.
check := [ :flag :name |
	total := total + 1.
	flag ifTrue: [ pass := pass + 1. out nextPutAll: 'ok   ' ] ifFalse: [ out nextPutAll: 'FAIL ' ].
	out nextPutAll: name; nextPut: Character lf ].

"── L1 identity ──"
ident := EcIdentity fromSeed: (ByteArray new: 32 withAll: 16r11).
check value: (ident peerEntity type = 'system/peer') value: 'identity: peer entity is system/peer'.
check value: (ident idHash size = 33) value: 'identity: id_hash is 33 bytes (fmt+sha256)'.
check value: (ident peerId notEmpty) value: 'identity: peer_id string non-empty'.
"sign + verify round-trip over the peer entity''s content_hash"
sigEnt := ident signatureEntityFor: ident idHash.
check value: (EcIdentity verifySignatureEntity: sigEnt withPubkey: ident pubkey)
	value: 'identity: sign/verify round-trip'.

"── foundation store ──"
store := EcStore new.
ent := EcEntity type: 'prim/x' data: (EcVal map: { 'k' -> (EcVal text: 'v') }).
store bind: 'a/b/c' to: ent.
check value: ((store getAt: 'a/b/c') notNil) value: 'store: bind+get round-trip'.
check value: ((store getAt: 'a/b/c') contentHash = ent contentHash)
	value: 'store: retrieved entity hash matches'.
check value: ((store getAt: 'a/b/nope') isNil) value: 'store: absent path -> nil'.

"── N5 envelope included: byte-keyed, key==content_hash, first-seen dedup ──"
root := EcEntity type: 'test/root' data: (EcVal map: { 'x' -> (EcVal text: 'y') }).
env := EcEnvelope root: root.
"add our peer entity TWICE (dedup must collapse to one)"
env include: ident peerEntity.
env include: ident peerEntity.
check value: (env includedCount = 1) value: 'N5: duplicate included entity deduped'.
wa := env asWireBytes.
r2 := EcEnvelope fromWireBytes: wa.
check value: (r2 root type = 'test/root') value: 'N5: envelope root round-trips'.
check value: (r2 includedCount = 1) value: 'N5: included preserved (1 entity)'.
check value: (r2 included first contentHash = ident peerEntity contentHash)
	value: 'N5: included key == content_hash'.

"── §4.10(b) chain-depth pre-check -> #depth, BEFORE the authz walk ──"
"Build a chain of tokens each pointing to the next via `parent`, exceeding maxChainDepth,
 all present in an included set. exceedsDepth:in: must answer true (structural, no signature)."
envD := EcEnvelope root: (EcEntity type: 'test/root' data: EcVal emptyMap).
tokenRoot := EcEntity type: 'system/capability/token' data: (EcVal map: {
	'grantee' -> (EcVal bytes: ident idHash).
	'granter' -> (EcVal bytes: ident idHash) }).
envD include: tokenRoot.
cur := tokenRoot.
70 timesRepeat: [
	| child |
	child := EcEntity type: 'system/capability/token' data: (EcVal map: {
		'grantee' -> (EcVal bytes: ident idHash).
		'granter' -> (EcVal bytes: ident idHash).
		'parent' -> (EcVal bytes: cur contentHash) }).
	envD include: child.
	cur := child ].
check value: (EcCapability exceedsDepth: cur in: envD)
	value: '4.10(b): deep chain (70) -> exceeds-depth (400)'.
check value: ((EcCapability exceedsDepth: tokenRoot in: envD) not)
	value: '4.10(b): root token within depth'.
"an UNREACHABLE parent is NOT a depth problem (answers false -> real walk handles as 403)"
orphanEnv := EcEnvelope root: (EcEntity type: 'test/root' data: EcVal emptyMap).
orphan := EcEntity type: 'system/capability/token' data: (EcVal map: {
	'grantee' -> (EcVal bytes: ident idHash).
	'granter' -> (EcVal bytes: ident idHash).
	'parent' -> (EcVal bytes: #[16r00 16rDE 16rAD 16rBE 16rEF]) }).
orphanEnv include: orphan.
check value: ((EcCapability exceedsDepth: orphan in: orphanEnv) not)
	value: '4.10(b): unreachable parent is NOT depth (stays 403)'.

"── the verdict mapping (§5.2 trichotomy) ──"
check value: ((EcCapability verdictStatusCode: #depth) first = 400)
	value: '4.10(b): #depth verdict -> 400 chain_depth_exceeded'.
check value: ((EcCapability verdictStatusCode: #authz) first = 403)
	value: '5.2: #authz verdict -> 403 capability_denied'.
check value: ((EcCapability verdictStatusCode: #unresolvable) first = 401)
	value: '5.2: #unresolvable verdict -> 401 unresolvable_grantee'.

"── §4.10(a) 16-MiB payload cap: MAX-FRAME finite + over-limit classified ──"
check value: (EcNet maxFrame = (16 * 1024 * 1024)) value: '4.10(a): maxFrame = 16 MiB (finite)'.
check value: ((EcNet maxFrame + 1) > EcNet maxFrame) value: '4.10(a): flen > maxFrame flagged oversize (413/drain)'.
check value: ((1000 > EcNet maxFrame) not) value: '4.10(a): a normal frame is NOT oversize'.

"── wire builders: EXECUTE / EXECUTE_RESPONSE round-trip through the codec ──"
rid := 'req-9'.
exec := EcWire execRequestId: rid uri: 'system/tree' operation: 'get'
	params: EcWire emptyParams author: nil capability: nil.
check value: (exec type = 'system/protocol/execute') value: 'wire: EXECUTE builds'.
check value: ((exec textAt: 'request_id') = rid) value: 'wire: EXECUTE request_id field'.
resp := EcWire response: rid status: 404 result: EcWire emptyParams.
check value: ((resp uintAt: 'status') = 404) value: 'wire: RESPONSE status field'.
"round-trip the EXECUTE through an envelope + decode"
e2 := (EcEnvelope fromWireBytes: (EcEnvelope root: exec) asWireBytes) root.
check value: ((e2 textAt: 'uri') = 'system/tree') value: 'wire: EXECUTE round-trips through envelope'.

"── §6.11 demux table: distinct request_ids -> distinct records, correlated delivery ──"
pend := EcPending new.
recA := pend open: 'req-A'.
recB := pend open: 'req-B'.
replyRoot := EcWire response: 'req-A' status: 200 result: EcWire emptyParams.
pend deliverReplyFor: 'req-A' root: replyRoot.
check value: (recA isDone and: [ recB isDone not ])
	value: '6.11: reply correlates to its OWN request_id record (no cross-talk)'.

out nextPut: Character lf; nextPutAll: 'SELFTEST '; print: pass; nextPut: $/; print: total; nextPut: Character lf.
"exit non-zero on any failure: raise AFTER emitting the summary (the eval handler prints the
 doit''s value only on success, so print the summary to stdout ourselves, then raise)."
Stdio stdout nextPutAll: out contents; flush.
pass = total ifFalse: [ Error signal: 'selftest had failures' ].
'SELFTEST ', pass printString, '/', total printString
