"entity-core-protocol-smalltalk — the PEER assembly (EntityCore-Peer): L4 bootstrap + the
single-event-loop serve loop + the §6.5 dispatch chain + the §3.3 frame router + the §6.11
request_id demux reentry pump, plus the built-in MUST handlers (§4.1 connect, §6.3 tree get).

THE SINGLE-EVENT-LOOP MODEL (profile [async] style=single-event-loop): the Pharo VM runs all
green processes on ONE native OS thread. The peer serves one inbound frame to completion
before the next readiness wake. §4.8 store-safety is STRUCTURAL (no lock). The §6.11
handler-initiated outbound reentry is a MANUAL correlation pump: a handler that originates an
outbound EXECUTE re-enters the serve tick (keeps serving other inbound frames) until its
reply correlates by request_id (EcPending).

Wire roots (§3.3): ONLY system/protocol/execute and .../execute/response. An EXECUTE is
dispatched; an EXECUTE_RESPONSE is correlated to a pending outbound by request_id; ANY other
root type closes the connection. `hello`/`authenticate` are OPERATIONS on
system/protocol/connect (§4.1), not message types.

The v7.75 non-functional floor is baked in: §4.10(a) 16-MiB payload cap (EcNet, 413 at the
de-framer), §4.10(b) chain-depth pre-check -> 400 (EcCapability, BEFORE the authz walk),
§7b TCP_NODELAY + no-blocking-read on the cooperative loop (EcNet), §4.9 deliver-or-signal
(dispatch catches every EntityCoreError -> a coded response, never a silent drop).

LIVE-IMAGE NOTE (A-ST-010): all sibling classes resolve at send-time inside these method
bodies; the class is captured in a temp so this doit installs it then compiles its methods."

| pkg cls |
pkg := 'EntityCore-Peer'.
cls := ((Object << #EcPeer) slots: {
	#identity. #store. #handlers. #pending. #listener. #connections. #serving. #reentryDepth.
	#validateOn. #openGrantsOn. #nonceCounter };
	package: pkg; install).

cls class compile: 'reentryDepthCap  ^ 64'.
"traceError — EC_TRACE=1 in the env prints dispatch/frame errors to stderr (diagnosis only)."
cls class compile: 'traceError
	^ (Smalltalk os environment at: ''EC_TRACE'' ifAbsent: [ ''0'' ]) = ''1'''.

"── construction / bootstrap ──"
cls class compile: 'new  ^ super new initPeer'.
cls compile: 'initPeer
	store := EcStore new. handlers := Dictionary new. pending := EcPending new.
	connections := OrderedCollection new. serving := false. reentryDepth := 0.
	nonceCounter := 0. ^ self'.
"nextNonceCounter — a PEER-GLOBAL monotonic nonce counter (§4.6). MUST NOT be the per-connection
 outCounter: that resets to 0 on every fresh connection, so two connections would be issued the
 SAME deterministic nonce SHA256(1‖id_hash) → a captured authenticate replays across connections
 (F12 handshake_replay_cross_connection). A peer-global counter makes every issued nonce unique."
cls compile: 'nextNonceCounter  nonceCounter := nonceCounter + 1. ^ nonceCounter'.
cls compile: 'identity  ^ identity'.
cls compile: 'store  ^ store'.
cls compile: 'peerId  ^ identity peerId'.

"bootstrapWithSeed: — install the peer identity, publish the §9.5 core type floor, register the
 core MUST handlers (§4.1/§6.13) + their §6.2 manifests + N2 dispatch entities, and (under
 --validate) the §7a conformance handlers. See EcPeerHandlers2 for the S4 handler bodies."
cls compile: 'bootstrapWithSeed: aSeedByteArray
	identity := EcIdentity fromSeed: aSeedByteArray.
	store reset. pending reset.
	"§9.5: publish the 53-type core floor as tree entities under /<peer>/system/type/<name>."
	EcCoreTypes publishFor: identity peerId store: store.
	"§4.1 the sole pre-auth path + the §4.4 authority-gated handlers."
	self registerHandler: ''system/protocol/connect'' as: [ :ctx | self handleConnect: ctx ].
	self registerHandler: ''system/tree'' as: [ :ctx | self handleTreeFull: ctx ].
	self registerHandler: ''system/capability'' as: [ :ctx | self handleCapability: ctx ].
	self registerHandler: ''system/handler'' as: [ :ctx | self handleHandlers: ctx ].
	self registerHandler: ''system/type'' as: [ :ctx | self handleType: ctx ].
	"§6.2 handler-manifest interfaces at /<peer>/system/handler/<pattern> (the `handlers` gate)."
	self publishHandlerInterface: ''system/protocol/connect'' name: ''connect'' operations: #(''hello'' ''authenticate'').
	self publishHandlerInterface: ''system/tree'' name: ''tree'' operations: #(''get'' ''put'').
	self publishHandlerInterface: ''system/capability'' name: ''capability'' operations: #(''request'' ''delegate'' ''revoke'').
	self publishHandlerInterface: ''system/handler'' name: ''handler'' operations: #(''register'' ''unregister'').
	self publishHandlerInterface: ''system/type'' name: ''type'' operations: #(''validate'').
	"§6.2 N2 dispatch entities at /<peer>/<pattern> (handler_<name>_dispatch_type / _interface_ref)."
	self publishHandlerDispatch: ''system/protocol/connect''.
	self publishHandlerDispatch: ''system/tree''.
	self publishHandlerDispatch: ''system/capability''.
	self validateOn ifTrue: [
		self registerHandler: ''system/validate/echo'' as: [ :ctx | self handleValidateEcho: ctx ].
		self registerHandler: ''system/validate/dispatch-outbound'' as: [ :ctx | self handleValidateDispatchOutbound: ctx ].
		self publishHandlerInterface: ''system/validate/echo'' name: ''validate/echo'' operations: #(''echo'').
		self publishHandlerInterface: ''system/validate/dispatch-outbound'' name: ''validate/dispatch'' operations: #(''dispatch'') ].
	^ self'.

"registerHandler:as: — bind a handler block at a dispatch path (§6.13 peer-owner-write). The
 §6.6 tree-walk resolves by the longest bound prefix."
cls compile: 'registerHandler: aPathString as: aBlock
	handlers at: aPathString put: aBlock'.

"resolveHandler: — the longest bound handler-path prefix of a bare handler path (§6.6
 backward tree-walk). Answers the handler path String, or nil (dispatcher -> 404).

 F62 (2026-09-09): the walk consults the ENTITY TREE as well as the in-image `handlers`
 map. §6.6 defines resolution AS the tree walk and calls a dispatch index an optimisation
 whose results MUST produce equivalent results to it. This map is written only at
 bootstrap, while the wire register op binds its system/handler entity (WRITE 1) into the
 store -- so the two were not equivalent, and the peer answered 404 handler_not_found at a
 pattern where it had just answered 200 to a register and where the oracle can retrieve
 the handler entity. Consulting the store makes them equivalent BY CONSTRUCTION rather
 than by keeping two containers in step: nothing has to remember to mirror a write, and
 unregister -- which unbinds the path -- needs no second teardown. The type test is
 load-bearing: system/handler/<pattern> carries a system/handler/interface entity, which
 is a manifest and not a dispatch target."
cls compile: 'resolveHandler: aPathString
	| p idx ent |
	p := aPathString.
	[ p notEmpty ] whileTrue: [
		(handlers includesKey: p) ifTrue: [ ^ p ].
		ent := store getAt: (self peerAbs: p).
		(ent notNil and: [ ent type = ''system/handler'' ]) ifTrue: [ ^ p ].
		idx := p lastIndexOf: $/.
		idx = 0 ifTrue: [ ^ nil ].
		p := p copyFrom: 1 to: idx - 1 ].
	^ nil'.

"── networking ──"
"listenOn: — bind + listen; answers the actually-bound port."
cls compile: 'listenOn: aPort
	listener := EcNet listenOn: aPort.
	^ listener localPort'.

"── the §3.3 frame router ──"
"onFrame:from: — decode a frame payload, route by root type. Any decode error signals an
 EntityCoreError caught by the caller (§4.9). A non-EXECUTE/RESPONSE root closes the conn."
cls compile: 'onFrame: aPayloadByteArray from: aConn
	| env root |
	env := EcEnvelope fromWireBytes: aPayloadByteArray.
	root := env root.
	root type = EcWire typeExecute ifTrue: [ ^ self handleExecute: root envelope: env on: aConn ].
	root type = EcWire typeResponse ifTrue: [
		^ pending deliverReplyFor: (root textAt: ''request_id'') root: root ].
	"any other root type: close the connection (§3.3)."
	self closeConnection: aConn'.

"── the §6.5 dispatch chain for a decoded inbound EXECUTE ──"
"handleExecute:envelope:on: — dispatch + send the EXECUTE_RESPONSE on the connection. §4.9
 deliver-or-signal: any handler THROW maps to a 500 result rather than a silent drop."
cls compile: 'handleExecute: anExec envelope: anEnvelope on: aConn
	| rid res |
	rid := anExec textAt: ''request_id''.
	"§4.9 deliver-or-signal: ANY handler/authz error (EntityCoreError OR a live DNU/other Error)
	 maps to a 500 coded response rather than a silent drop or a crashed serve loop. A dynamic
	 substrate (no compile-time type check, A-ST no_compile_gate) can raise a DNU deep in a
	 handler on an unanticipated request shape — catching Error (not just EntityCoreError) keeps
	 the single-event-loop alive and always answers."
	res := [ self dispatch: anExec envelope: anEnvelope on: aConn ]
		on: Error
		do: [ :e |
			EcPeer traceError ifTrue: [ Stdio stderr << ''[dispatch-error] ''; << e class name; << '': ''; << (e messageText ifNil: [ '''' ]); << (String with: Character lf); flush ].
			EcHandlerResult error: 500 code: ''internal_error'' message: e messageText ].
	self sendResponse: res requestId: rid on: aConn'.

"dispatch:envelope:on: — the §6.5 order: connect is pre-auth; everything else runs
 authn -> resolve(404) -> authz(403) -> handler. A §6.6 resolution miss is 404 (404 beats 403)."
cls compile: 'dispatch: anExec envelope: anEnvelope on: aConn
	| uri handlerPath authn resolved authz block ctx |
	uri := (anExec textAt: ''uri'') ifNil: [ ^ EcHandlerResult error: 400 code: ''invalid_uri'' message: ''missing uri'' ].
	handlerPath := self handlerPathOf: uri.
	"connect is the sole pre-auth path (§4.1)."
	(handlerPath beginsWith: ''system/protocol/connect'') ifTrue: [
		^ self runHandler: ''system/protocol/connect'' exec: anExec envelope: anEnvelope on: aConn ].
	"0. §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used
	     to sit one rung DOWN, after verifyAuthn:, so a pre-establishment EXECUTE naming a
	     FOREIGN namespace took the 401 an unsigned request takes. The reason §4.7 gives: a
	     401 directs the caller to authenticate and retry, and for a foreign-namespace
	     address that retry cannot succeed at any authentication state — so the 401 names a
	     remedy that does not exist. §6.5 step 3 calls it a gate, not an ordering
	     preference. (NO APOSTROPHE MAY APPEAR IN THIS FILE: every method body is embedded
	     in an outer Smalltalk string literal, so a bare one terminates it mid-comment.)"
	(self uriTargetsLocalPeer: uri) ifFalse: [
		^ EcHandlerResult error: 400 code: ''invalid_request'' message: ''not local peer'' ].
	"1. integrity / authn (an unsigned request is 401 on any LOCAL path)."
	authn := EcCapability verifyAuthn: anExec in: anEnvelope.
	authn = #allow ifFalse: [ ^ self verdictError: authn ].
	"1a. §1.4 / §6.5 step 3 — the ADDRESS gate, BEFORE handler resolution and before
	     authz. handlerPathOf: strips the addressing prefix unconditionally, which is
	     exactly what §6.5 forbids reaching the refusal by: strip the foreign peer id,
	     resolve the LOCAL handler at the remaining path, and let §5.2 Dimension 4
	     decide. That answers 403/404 for what is specified as 400 — and it ALLOWS the
	     request outright whenever the presented grant carries a matching `peers` scope.
	     Measured before this gate existed: status 200, the live escalation."
	(self uriTargetsLocalPeer: uri) ifFalse: [
		^ EcHandlerResult error: 400 code: ''invalid_request'' message: ''not local peer'' ].
	"2. resolve the handler by URI (§6.6); miss -> 404 (resolution-first)."
	resolved := self resolveHandler: handlerPath.
	resolved isNil ifTrue: [ ^ EcHandlerResult error: 404 code: ''handler_not_found'' message: ''no handler resolved'' ].
	"3. permission / authz on the resolved handler: the full §5.5 chain walk (root trust +
	    per-link sig/grantee/expiry/attenuation), §5.1 revocation, §4.10(b) depth pre-check,
	    grantee==author binding, and the §5.2 permission-scope gate (EcCapAuthz). Our OWN peer
	    entity is added to the included set so a root single-sig cap whose granter == our id_hash
	    (the seed grant) resolves the granter peer_id (root-at-local) without the client having to
	    echo our peer entity back."
	anEnvelope include: identity peerEntity.
	authz := EcCapAuthz authorizeExec: anExec local: identity peerId store: store in: anEnvelope.
	authz = #allow ifFalse: [ ^ self verdictError: authz ].
	^ self runHandler: resolved exec: anExec envelope: anEnvelope on: aConn'.

"handlerPathOf: — strip the addressing prefix (entity://<peer>/ or /<peer>/) so §6.6 sees a
 bare handler path. A bare ''system/protocol/connect'' is already a handler path (no strip)."
cls compile: 'handlerPathOf: aUri
	| u addressed idx |
	u := aUri. addressed := false.
	(u beginsWith: ''entity://'') ifTrue: [ u := u copyFrom: 10 to: u size. addressed := true ].
	(u beginsWith: ''/'') ifTrue: [ u := u copyFrom: 2 to: u size. addressed := true ].
	addressed ifFalse: [ ^ u ].
	idx := u indexOf: $/.
	idx = 0 ifTrue: [ ^ u ].
	^ u copyFrom: idx + 1 to: u size'.

"uriTargetsLocalPeer: — §1.4 inbound dispatch: does this URI address THIS peer? True for a
 bare/peer-relative path (no addressing prefix at all) and for an addressed one whose peer
 segment is our own peer id. The companion of handlerPathOf:, and it MUST be asked before
 that method throws the peer segment away."
cls compile: 'uriTargetsLocalPeer: aUri
	| u idx seg |
	u := aUri.
	(u beginsWith: ''entity://'') ifTrue: [ u := u copyFrom: 10 to: u size ]
		ifFalse: [ (u beginsWith: ''/'') ifTrue: [ u := u copyFrom: 2 to: u size ]
			ifFalse: [ ^ true ] ].
	idx := u indexOf: $/.
	seg := idx = 0 ifTrue: [ u ] ifFalse: [ u copyFrom: 1 to: idx - 1 ].
	^ seg = identity peerId'.

"runHandler:exec:envelope:on: — invoke a registered handler block with a fresh context.

 The two misses are DIFFERENT failures and F62 is why they are separated here. No block and
 no handler entity in the tree is a resolution miss -> 404. No block but a system/handler
 entity bound at the path is a handler this peer RESOLVED and cannot RUN: the wire register
 op forwards the manifest verbatim, including its expression_path, and this peer has no
 6.13(a) entity-native evaluator to run one with. That is a missing feature, not a broken
 promise, and 501 is the honest answer -- it is also what the three peers already in that
 state (datalog, nim, oz) and the reference peer answer. `no_handler_body` appears nowhere
 in the v0.8.2.11 spec and the cohort spells this failure four ways; that vocabulary gap is
 registered as F60 and is deliberately NOT invented around here."
cls compile: 'runHandler: aHandlerPath exec: anExec envelope: anEnvelope on: aConn
	| block ctx |
	block := handlers at: aHandlerPath ifAbsent: [ nil ].
	block isNil ifTrue: [
		^ (store getAt: (self peerAbs: aHandlerPath)) isNil
			ifTrue: [ EcHandlerResult error: 404 code: ''handler_not_found'' message: ''no handler bound'' ]
			ifFalse: [ EcHandlerResult error: 501 code: ''no_handler_body'' message: ''handler resolved; this peer evaluates no installed body'' ] ].
	ctx := EcHandlerContext peer: self connection: aConn exec: anExec envelope: anEnvelope.
	^ block value: ctx'.

"verdictError: — map a non-#allow capability verdict to a coded error result."
cls compile: 'verdictError: aVerdict
	| sc |
	sc := EcCapability verdictStatusCode: aVerdict.
	^ EcHandlerResult error: (sc at: 1) code: (sc at: 2) message: nil'.

"sendResponse:requestId:on: — build the EXECUTE_RESPONSE envelope (root = response; included
 = whatever the handler contributed) and send it framed."
cls compile: 'sendResponse: aResult requestId: rid on: aConn
	| resp env |
	resp := EcWire response: (rid ifNil: [ '''' ]) status: aResult status result: aResult result.
	env := EcEnvelope root: resp.
	aResult included do: [ :e | env include: e ].
	aConn sendFrame: env asWireBytes'.

"── the single-event-loop serve tick + loop ──"
"serveTick — one cooperative tick: NON-BLOCKING accept poll (0 timeout) so a pending connection
 is never starved by a blocking accept-wait, then drain EVERY currently-ready connection of ALL
 its available frames. Answers whether ANY work happened (a new conn accepted or a frame served),
 so serveForever can block briefly ONLY when fully idle (the cooperative-yield point, §7b — no
 indefinite block on the one green process). The prior `waitForAcceptFor: 1` per tick serialized
 badly: with pipelined tree.put/get traffic every tick blocked up to 1s in accept even while
 existing connections had data waiting → the oracle''s per-request i/o timeout (F: tree_operations
 core_tree_listing_1 / core_tree_delete_1 / path_flex). §4.10(c) admission cap: refuse a new
 connection past maxConns (sized above the r3 flood + a keep-serving probe slot)."
cls compile: 'serveTick: acceptTimeout
	| newConn worked accepted |
	worked := false.
	"ALWAYS drain the accept queue this tick (up to a batch cap) so a rapid r3 flood (256 dials)
	 never clogs the kernel backlog and blocks the post-flood probe from reaching us. Beyond the
	 §4.10(c) working-set cap (maxConns) we still accept() — then IMMEDIATELY close the socket (a
	 fast explicit self-bounded refusal that drains the backlog) rather than stop accepting (which
	 would leave the probe stuck behind un-accepted flood connections). First accept honors the
	 caller''s timeout (the idle-yield point); the rest are non-blocking polls."
	accepted := 0.
	[ accepted < 128 ] whileTrue: [
		newConn := EcNet tryAccept: listener timeout: (accepted = 0 ifTrue: [ acceptTimeout ] ifFalse: [ 0 ]).
		newConn isNil ifTrue: [ accepted := 999 ]
			ifFalse: [
				connections size < EcPeer maxConns
					ifTrue: [ connections add: newConn ]
					ifFalse: [ newConn close ].          "over the cap: refuse (drain the backlog, stay alive)"
				worked := true. accepted := accepted + 1 ] ].
	"snapshot (a handler may mutate the list); drain each ready connection of all available frames."
	connections copy do: [ :c |
		[ c isOpen and: [ c dataAvailable ] ] whileTrue: [ self serveConn: c. worked := true ] ].
	"reap closed connections."
	connections := connections reject: [ :c | c isOpen not ].
	^ worked'.
"maxConns — §4.10(c) working-set ceiling. Sized ABOVE the resource_bounds r3 flood (256) plus
 headroom for the post-flood keep-serving probe, so the peer accepts the WHOLE flood AND still
 hands out a slot for the follow-up handshake (the §4.10(c) `accepted all AND kept serving` WARN
 path). ExternalSemaphoreTable grows dynamically; tryAccept: is error-safe, so 256+ live sockets
 don''t fell the peer. Past the cap the loop closes the excess (a bounded self-refusal)."
cls class compile: 'maxConns  ^ 400'.

"serveConn: — read one frame from a ready connection and route it. A malformed-frame THROW is
 swallowed (§4.9 keep-serving); EOF/oversize handled per EcNet readFrame contract."
cls compile: 'serveConn: aConn
	| frame |
	frame := aConn readFrame.
	frame == #eof ifTrue: [ ^ self closeConnection: aConn ].
	frame == #oversize ifTrue: [ ^ self ].                  "413-class: drained + kept (§4.10a)"
	[ self onFrame: frame from: aConn ]
		on: Error do: [ :e |
			"§4.9: swallow ANY frame-handling error (a malformed-frame THROW or a live DNU in the
			 router/decoder) and keep serving — never let one bad frame crash the event loop."
			EcPeer traceError ifTrue: [ Stdio stderr << ''[frame-error] ''; << e class name; << '': ''; << (e messageText ifNil: [ '''' ]); << (String with: Character lf); flush ] ]'.

cls compile: 'closeConnection: aConn
	aConn close.
	connections remove: aConn ifAbsent: [ ]'.

"serveForever — the top-level serve loop. A NON-BLOCKING accept poll (0 timeout) keeps ready
 connections from being starved; when a tick did NO work (fully idle) we yield with a short
 bounded wait so the loop doesn''t busy-spin the CPU (still bounded — never an indefinite block)."
cls compile: 'serveForever
	serving := true.
	[ serving ] whileTrue: [
		(self serveTick: 0) ifFalse: [ (Delay forMilliseconds: 2) wait ] ]'.
cls compile: 'stop  serving := false'.

"── §6.11 the reentry pump (handler-originated outbound) ──"
"dispatchOutbound:envelope:on: — send an outbound EXECUTE on a connection and await its
 correlated reply (§6.11), re-entering the serve tick to keep serving other inbound frames.
 Answers the reply root entity, or nil on timeout / a shed reentry. Bounded by a reentry-depth
 cap (shed -> nil rather than overflow the green-process stack) + a retry budget (§4.9)."
cls compile: 'dispatchOutbound: anExec envelope: anEnvelope on: aConn
	| rid record budget |
	reentryDepth >= EcPeer reentryDepthCap ifTrue: [ ^ nil ].
	reentryDepth := reentryDepth + 1.
	[ rid := anExec textAt: ''request_id''.
	  record := pending open: rid.
	  aConn sendFrame: anEnvelope asWireBytes.
	  budget := 200.
	  [ record isDone or: [ budget <= 0 ] ] whileFalse: [
		self serveTick: 0.                                   "keep serving; 0s = non-blocking poll"
		budget := budget - 1 ].
	  pending close: rid.
	  ^ record isDone ifTrue: [ record replyRoot ] ifFalse: [ nil ] ]
		ensure: [ reentryDepth := reentryDepth - 1 ]'.

'EntityCore-Peer:EcPeer (core) installed'
