"entity-core-protocol-smalltalk — L3 capability (§5): the system/capability/token shape, the
chain-walk primitives, and — the ONE net-new bit of peer code across the whole cohort — the
§4.10(b) chain-depth PRE-CHECK that maps an over-deep chain to 400 chain_depth_exceeded
BEFORE the per-link authz walk (structural excess ≠ authz denial; an *unreachable* parent is
NOT a depth problem and stays 403). (EntityCore-Capability.)

Verdict trichotomy (§5.2 / §5.2a), mapped to a status once at the dispatch boundary:
  #authn  -> 401 authentication_failed   (bad/absent request signature)
  #authz  -> 403 capability_denied        (chain invalid / grantee mismatch / scope)
  #unresolvable -> 401 unresolvable_grantee (a grantee peer entity is absent)
  #depth  -> 400 chain_depth_exceeded      (§4.10(b) structural pre-check)
  #allow  -> proceed

At S3 the capability layer is wired STRUCTURALLY (the seed grant from the handshake is a
root single-sig token). Full attenuation/multisig/revocation depth is an S4 concern; here we
build the primitives + the two MUSTs (depth pre-check ordering + the trichotomy) so they are
NOT rediscovered at S4.

Verdicts are Symbols (#allow/#authn/#authz/#unresolvable/#depth) — idiomatic Smalltalk, no
integer enum. The class holds the §4.10(b) MAX-CHAIN-DEPTH constant (64) as a class method.

LIVE-IMAGE NOTE: EcIdentity resolves at send-time; the envelope is passed in as an EcEnvelope."

| pkg cls |
pkg := 'EntityCore-Capability'.
cls := (Object << #EcCapability package: pkg) install.

"§4.10(b) informative default max capability-chain depth."
cls class compile: 'maxChainDepth  ^ 64'.

"── token field reads (a system/capability/token EcEntity) ──"
cls class compile: 'granteeOf: aTokenEntity  ^ aTokenEntity bytesAt: ''grantee'''.
cls class compile: 'parentOf: aTokenEntity  ^ aTokenEntity bytesAt: ''parent'''.

"findSignatureFor:in: — scan an EcEnvelope''s included set for a system/signature entity whose
 `target` byte field == the given content-hash ByteArray. Answers the signature entity or nil."
cls class compile: 'findSignatureFor: aTargetHashBytes in: anEnvelope
	^ anEnvelope included
		detect: [ :e |
			e type = ''system/signature''
				and: [ (e bytesAt: ''target'') = aTargetHashBytes ] ]
		ifNone: [ nil ]'.

"── §4.10(b) chain-depth PRE-CHECK (BEFORE any signature verification) ──"
"exceedsDepth:in: — follow `parent` pointers WITHOUT verifying signatures, counting depth.
 Answers true iff depth > maxChainDepth. An UNREACHABLE parent is NOT a depth problem (it
 stops the count and answers false — the real authz walk handles the resolution failure as
 403/401). This is the structural pre-check the whole v7.75 cohort was missing (all nine
 returned 403 before the ruling)."
cls class compile: 'exceedsDepth: aTokenEntity in: anEnvelope
	| cur depth parentHash parent |
	cur := aTokenEntity.
	depth := 1.
	[ true ] whileTrue: [
		parentHash := self parentOf: cur.
		parentHash isNil ifTrue: [ ^ false ].                 "no parent -> root, within depth"
		parent := anEnvelope includedForHash: parentHash.
		parent isNil ifTrue: [ ^ false ].                     "unreachable parent -> NOT a depth issue"
		cur := parent.
		depth := depth + 1.
		depth > self maxChainDepth ifTrue: [ ^ true ] ]'.

"── §6.5 step ''verify integrity'': the AUTHN leg (the author''s request signature over the
    exec content_hash). Runs BEFORE handler resolution so a signed request to an unregistered
    path resolves-first to 404, and an UNSIGNED request is 401 regardless of the path. ──"
"verifyAuthn:in: — answers a verdict Symbol (#allow / #authn)."
cls class compile: 'verifyAuthn: anExecEntity in: anEnvelope
	| sig signer author signerPeer pubkey |
	sig := self findSignatureFor: anExecEntity contentHash in: anEnvelope.
	sig isNil ifTrue: [ ^ #authn ].
	signer := sig bytesAt: ''signer''.
	signer isNil ifTrue: [ ^ #authn ].
	"§3.5/§5.1: the exec MUST carry an author, and the signature''s signer MUST equal it."
	author := anExecEntity bytesAt: ''author''.
	(author isNil or: [ author ~= signer ]) ifTrue: [ ^ #authn ].
	signerPeer := anEnvelope includedForHash: signer.
	signerPeer isNil ifTrue: [ ^ #authn ].
	pubkey := signerPeer bytesAt: ''public_key''.
	pubkey isNil ifTrue: [ ^ #authn ].
	(EcIdentity verifySignatureEntity: sig withPubkey: pubkey) ifFalse: [ ^ #authn ].
	^ #allow'.

"── §6.5 step ''check permission'': the AUTHZ leg (token resolve + §4.10(b) depth pre-check +
    grantee binding). Runs AFTER handler resolution (§6.6 resolution-first: a 404 on an
    unregistered path beats a 403). At S3 the seed grant is a root single-sig token, so the
    deep-chain / attenuation legs are S4; here we enforce the depth pre-check ORDER + the
    grantee-resolvable trichotomy. ──"
"verifyAuthz:in: — answers #allow / #authz / #unresolvable / #depth."
cls class compile: 'verifyAuthz: anExecEntity in: anEnvelope
	| capHash token grantee granteePeer |
	capHash := anExecEntity bytesAt: ''capability''.
	capHash isNil ifTrue: [ ^ #authz ].
	token := anEnvelope includedForHash: capHash.
	token isNil ifTrue: [ ^ #authz ].
	"§4.10(b) depth pre-check BEFORE the walk (structural excess ≠ authz denial)."
	(self exceedsDepth: token in: anEnvelope) ifTrue: [ ^ #depth ].
	grantee := self granteeOf: token.
	grantee isNil ifTrue: [ ^ #unresolvable ].
	granteePeer := anEnvelope includedForHash: grantee.
	granteePeer isNil ifTrue: [ ^ #unresolvable ].
	^ #allow'.

"verdictError: — map a non-#allow verdict to a { status. code } pair for the dispatch boundary."
cls class compile: 'verdictStatusCode: aVerdict
	aVerdict = #authn ifTrue: [ ^ { 401. ''authentication_failed'' } ].
	aVerdict = #authz ifTrue: [ ^ { 403. ''capability_denied'' } ].
	aVerdict = #unresolvable ifTrue: [ ^ { 401. ''unresolvable_grantee'' } ].
	aVerdict = #depth ifTrue: [ ^ { 400. ''chain_depth_exceeded'' } ].
	^ { 500. ''internal_error'' }'.

'EntityCore-Capability:EcCapability installed'
