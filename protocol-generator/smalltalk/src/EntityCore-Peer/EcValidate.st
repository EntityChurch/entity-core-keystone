"entity-core-protocol-smalltalk — §7a conformance handlers (behind --validate), compiled onto
EcPeer (EntityCore-Peer). Two handlers the Go validator drives black-box (GUIDE-CONFORMANCE §7a):

  system/validate/echo:echo                  — verbatim echo of the params entity (§7a.1).
  system/validate/dispatch-outbound:dispatch — originate exactly ONE outbound EXECUTE back to
    the validator''s echo over the SAME inbound connection (§6.11 reentry; §7a.2a), then wrap
    the downstream {status, result} in a primitive/any result entity.

Cap-passing (§7a.2a Go ruling): the three reentry-authority entities travel IN-BAND, nested as
CBOR-encoded entity blobs under the params keys reentry_capability / reentry_granter /
reentry_cap_signature — NOT via envelope `included`. We decode them, then re-emit them into the
OUTBOUND EXECUTE''s included set (so the validator-as-B finds its own cap chain there).

These handlers are registered only under --validate (EcPeer bootstrap), off in production.

LIVE-IMAGE NOTE: EcEntity / EcWire / EcEnvelope / EcVal resolve at send-time."

| ecPeer |
ecPeer := Smalltalk at: #EcPeer.

"blobToEntity: — a value that is either a nested entity wire-map or a bytes-CBOR blob of one,
 as an EcEntity (re-validating the hash), or nil."
ecPeer compile: 'blobToEntity: aValue
	(aValue isNil or: [ aValue isAbsent ]) ifTrue: [ ^ nil ].
	^ [ EcEntity fromWireValue: aValue ] on: EntityCoreError do: [ :e | nil ]'.

"── system/validate/echo:echo — verbatim (§7a.1). Returning the params ENTITY itself satisfies
    the oracle''s result.data == params.data assertion with no re-encode round-trip. ──"
ecPeer compile: 'handleValidateEcho: ctx
	| params |
	ctx operation = ''echo'' ifFalse: [ ^ EcHandlerResult error: 501 code: ''unsupported_operation'' message: nil ].
	params := ctx params.
	params isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	^ EcHandlerResult ok: params'.

"── system/validate/dispatch-outbound:dispatch (§7a.2a reentry) ──
    params (primitive/any) data: {target, operation, value, reentry_capability, reentry_granter,
    reentry_cap_signature}. value is the {value:X} map for the downstream echo''s params data. ──"
ecPeer compile: 'handleValidateDispatchOutbound: ctx
	| params target op valueV capEnt granterEnt capSigEnt outEnv reply |
	ctx operation = ''dispatch'' ifFalse: [ ^ EcHandlerResult error: 501 code: ''unsupported_operation'' message: nil ].
	params := ctx params.
	params isNil ifTrue: [ ^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	target := params textAt: ''target''.
	op := params textAt: ''operation''.
	valueV := params field: ''value''.
	capEnt := self blobToEntity: (params field: ''reentry_capability'').
	granterEnt := self blobToEntity: (params field: ''reentry_granter'').
	capSigEnt := self blobToEntity: (params field: ''reentry_cap_signature'').
	(target isNil or: [ op isNil or: [ valueV isAbsent
		or: [ capEnt isNil or: [ granterEnt isNil or: [ capSigEnt isNil ] ] ] ] ]) ifTrue: [
		^ EcHandlerResult error: 400 code: ''invalid_params'' message: nil ].
	outEnv := self buildOutboundExec: target operation: op value: valueV
		cap: capEnt granter: granterEnt capSig: capSigEnt on: ctx connection.
	reply := self dispatchOutbound: outEnv root envelope: outEnv on: ctx connection.
	reply isNil ifTrue: [ ^ EcHandlerResult error: 503 code: ''no_outbound_seam'' message: nil ].
	^ self wrapReply: reply'.

"buildOutboundExec:... — build+sign the outbound EXECUTE (fresh request_id, author=us,
 capability=cap hash, params=primitive/any(value)) and an envelope carrying the reentry cap
 chain + our exec signature in `included`."
ecPeer compile: 'buildOutboundExec: aTarget operation: anOp value: aValue cap: aCapEnt granter: aGranterEnt capSig: aCapSigEnt on: aConn
	| paramsEnt rid exec sigEnt env |
	paramsEnt := EcEntity type: ''primitive/any'' data: aValue.
	rid := ''o'', aConn nextOut printString.
	exec := EcWire execRequestId: rid uri: aTarget operation: anOp
		params: paramsEnt author: identity idHash capability: aCapEnt contentHash.
	sigEnt := identity signatureEntityFor: exec contentHash.
	env := EcEnvelope root: exec.
	env include: aCapEnt; include: aGranterEnt; include: aCapSigEnt.
	env include: identity peerEntity; include: sigEnt.
	^ env'.

"wrapReply: — wrap the downstream {status, result} into a primitive/any result entity (§7a.1)."
ecPeer compile: 'wrapReply: aReplyRoot
	| dstatus drV wrapped |
	dstatus := (aReplyRoot uintAt: ''status'') ifNil: [ 0 ].
	drV := aReplyRoot field: ''result''.
	wrapped := EcEntity type: ''primitive/any'' data: (EcVal map: {
		''status'' -> (EcVal uint: dstatus).
		''result'' -> (drV isAbsent ifTrue: [ EcVal emptyMap ] ifFalse: [ drV ]) }).
	^ EcHandlerResult ok: wrapped'.

'EntityCore-Peer:EcPeer validate handlers installed'
