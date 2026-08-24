"entity-core-protocol-smalltalk — SUnit conformance TestCase (EntityCore-Tests).

Regression coverage for the §5.2 `peers` grant dimension (2026-08-13 fix — see
protocol-generator/shared/findings/peers-grant-dimension-oracle-gap.md). The
`validate-peer` oracle carries ZERO vectors that mint a grant with an explicit `peers`
restriction (grep-verified in the handoff doc), so this suite is the ONLY thing that will
ever catch a regression here (AGENTS.md: 'conformance-green can be vacuous').

Exercises `EcCapAuthz class>>checkPermission:cap:local:in:` directly with hand-built
EcEntity/EcVal fixtures (the tests/s3-selftest.st idiom) — no signatures/chain/envelope
needed since every fixture cap omits `granter` (frames as local, §PR-8), so `anEnvelope` is
passed nil throughout.

Run headless: `pharo <image> test EntityCore-Tests`."

| pkg cls |
pkg := 'EntityCore-Tests'.
cls := ((TestCase << #EcCapAuthzTest) package: pkg; install).

"── fixture peer_ids (§1.5 syntactically valid: Base58, >= 46 chars) ──"
cls compile: 'localPeer   ^ ''LocaPeerAAAA1EFGHJKLMNPQRSTUVWXYZabcdefghijkmn'''.
cls compile: 'otherPeer   ^ ''therPeerBBBB2EFGHJKLMNPQRSTUVWXYZabcdefghijkmn'''.
cls compile: 'thirdPeer   ^ ''ThirdPeerCCCC3FGHJKLMNPQRSTUVWXYZabcdefghijkmn'''.

"── fixture builders ──"
"execFor:operation: — a system/dispatch/execute-shaped exec with the given URI + operation,
 no `resource` field (handler-only -> the resource dimension is vacuously covered, isolating
 the peers dimension under test)."
cls compile: 'execFor: aUri operation: anOp
	^ EcEntity type: ''system/dispatch/execute'' data: (EcVal map: {
		''uri'' -> (EcVal text: aUri).
		''operation'' -> (EcVal text: anOp) })'.

"grantWithPeers: — a grant covering every operation + handler; `peers` set to the given
 EcValue scope map, or OMITTED entirely when nil (the spec default-to-local case)."
cls compile: 'grantWithPeers: aPeersScopeOrNil
	| pairs |
	pairs := OrderedCollection new.
	pairs add: (''operations'' -> (EcVal map: { ''include'' -> (EcVal array: { EcVal text: ''*'' }) })).
	pairs add: (''handlers'' -> (EcVal map: { ''include'' -> (EcVal array: { EcVal text: ''*'' }) })).
	aPeersScopeOrNil ifNotNil: [ pairs add: (''peers'' -> aPeersScopeOrNil) ].
	^ EcVal map: pairs asArray'.

"capWithGrants: — a granter-less token (frames as local, §PR-8) carrying the given grants."
cls compile: 'capWithGrants: aGrantArray
	^ EcEntity type: ''system/capability/token'' data: (EcVal map: {
		''grants'' -> (EcVal array: aGrantArray) })'.

"── accept-path: peers omitted -> defaults to {include: [local]} -> a LOCAL target is covered
    (the pre-fix behaviour for the shipped floor grants must not regress). ──"
cls compile: 'testPeersDefaultAllowsLocalTarget
	| local exec cap |
	local := self localPeer.
	exec := self execFor: ''/'', local, ''/some/handler'' operation: ''get''.
	cap := self capWithGrants: { self grantWithPeers: nil }.
	self assert: (EcCapAuthz checkPermission: exec cap: cap local: local in: nil)'.

"── accept-path: an explicit `peers` include covering a FOREIGN target peer is honoured —
    §3.6 line 3228''s worked example (a peer serving /{remote_peer_id}/data/* locally). ──"
cls compile: 'testPeersIncludeAllowsForeignTarget
	| local other exec cap peersScope |
	local := self localPeer.
	other := self otherPeer.
	exec := self execFor: ''/'', other, ''/some/handler'' operation: ''get''.
	peersScope := EcVal map: { ''include'' -> (EcVal array: { EcVal text: other }) }.
	cap := self capWithGrants: { self grantWithPeers: peersScope }.
	self assert: (EcCapAuthz checkPermission: exec cap: cap local: local in: nil)'.

"── reject-path (the actual bug): `peers` omitted defaults to LOCAL ONLY — a request whose
    target_peer is a DIFFERENT peer must be denied, not silently allowed by the other three
    dimensions. This is exactly the scenario the pre-fix code got wrong: `operations` and
    `handlers` both cover ''*'', so pre-fix `grantCoversOpHandler:exec:local:granter:` (which
    never read `peers`) would have answered true here. ──"
cls compile: 'testPeersDefaultDeniesForeignTarget
	| local other exec cap |
	local := self localPeer.
	other := self otherPeer.
	exec := self execFor: ''/'', other, ''/some/handler'' operation: ''get''.
	cap := self capWithGrants: { self grantWithPeers: nil }.
	self deny: (EcCapAuthz checkPermission: exec cap: cap local: local in: nil)'.

"── reject-path: an explicit `peers` include that does NOT cover the target_peer must deny,
    even with `operations`/`handlers` wide open — proves `peers` is a genuine MUST-gate, not
    a vacuous rejection-only check (the multisig trap, AGENTS.md). ──"
cls compile: 'testPeersScopeDeniesUncoveredTarget
	| local other third exec cap peersScope |
	local := self localPeer.
	other := self otherPeer.
	third := self thirdPeer.
	exec := self execFor: ''/'', third, ''/some/handler'' operation: ''get''.
	peersScope := EcVal map: { ''include'' -> (EcVal array: { EcVal text: other }) }.
	cap := self capWithGrants: { self grantWithPeers: peersScope }.
	self deny: (EcCapAuthz checkPermission: exec cap: cap local: local in: nil)'.

'EntityCore-Tests:EcCapAuthzTest installed'
