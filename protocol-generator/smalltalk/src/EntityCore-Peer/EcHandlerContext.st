"entity-core-protocol-smalltalk — the handler-dispatch context (§6.6, EntityCore-Peer).

The §6.13 handler-interface contract: a handler is a message-send that receives an
EcHandlerContext (the peer, the connection, the request EXECUTE entity, the inbound envelope
carrying the request''s `included` authority set) and answers an EcHandlerResult (a status +
a result EcEntity). Community-installed handlers arrive above this interface; the core peer
registers the MUST handlers (system/protocol/connect, system/tree, ...) as blocks bound in a
registry. This is the extension boundary — the dispatcher never knows a handler''s internals,
only this context/result shape.

LIVE-IMAGE NOTE: EcWire resolves at send-time."

| pkg ctx result |
pkg := 'EntityCore-Peer'.

"── EcHandlerContext — what a handler is handed. ──"
ctx := ((Object << #EcHandlerContext) slots: { #peer. #connection. #exec. #envelope };
	package: pkg; install).
ctx class compile: 'peer: aPeer connection: aConn exec: anExec envelope: anEnvelope
	^ self new setPeer: aPeer connection: aConn exec: anExec envelope: anEnvelope'.
ctx compile: 'setPeer: aPeer connection: aConn exec: anExec envelope: anEnvelope
	peer := aPeer. connection := aConn. exec := anExec. envelope := anEnvelope. ^ self'.
ctx compile: 'peer  ^ peer'.
ctx compile: 'connection  ^ connection'.
ctx compile: 'exec  ^ exec'.
ctx compile: 'envelope  ^ envelope'.
"operation / uri / params — convenience reads off the request EXECUTE entity."
ctx compile: 'operation  ^ exec textAt: ''operation'''.
ctx compile: 'uri  ^ exec textAt: ''uri'''.
ctx compile: 'requestId  ^ exec textAt: ''request_id'''.
"params — the params entity carried in the exec (an EcEntity), or nil."
ctx compile: 'params
	| v |
	v := exec field: ''params''.
	v isAbsent ifTrue: [ ^ nil ].
	^ [ EcEntity fromWireValue: v ] on: EntityCoreError do: [ :e | nil ]'.

"── EcHandlerResult — a handler''s answer: status + result entity (+ an outbound included set
    a handler may contribute, e.g. authenticate''s grant). ──"
result := ((Object << #EcHandlerResult) slots: { #status. #result. #included };
	package: pkg; install).
result class compile: 'status: aStatus result: aResultEntity
	^ self new setStatus: aStatus result: aResultEntity'.
result class compile: 'ok: aResultEntity  ^ self status: 200 result: aResultEntity'.
"error:code:message: — a coded error result (a system/protocol/error entity)."
result class compile: 'error: aStatus code: codeString message: msgString
	^ self status: aStatus result: (EcWire error: codeString message: msgString)'.
result compile: 'setStatus: aStatus result: aResultEntity
	status := aStatus. result := aResultEntity. included := OrderedCollection new. ^ self'.
result compile: 'status  ^ status'.
result compile: 'result  ^ result'.
result compile: 'included  ^ included'.
"includeInResponse: — add an entity to the outbound response envelope''s included set."
result compile: 'includeInResponse: anEntity  included add: anEntity. ^ anEntity'.

'EntityCore-Peer:EcHandlerContext + EcHandlerResult installed'
