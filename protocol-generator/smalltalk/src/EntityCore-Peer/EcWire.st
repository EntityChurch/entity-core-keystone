"entity-core-protocol-smalltalk — the two wire message builders (§3.2 EXECUTE, §3.3
EXECUTE_RESPONSE) as materialized EcEntity objects (EntityCore-Peer).

Only these two are wire message ROOTS (§3.3): `hello`/`authenticate` are OPERATIONS on
system/protocol/connect, NOT message types; any other root type is invalid → the connection
is closed (handled in EcDispatch). A system/protocol/error entity is the `result` of a
non-200 EXECUTE_RESPONSE.

Field reads on a decoded root use EcEntity>>textAt:/uintAt: directly; the small helpers here
name the protocol fields for readability.

LIVE-IMAGE NOTE: EcEntity / EcVal resolve at send-time."

| pkg cls |
pkg := 'EntityCore-Peer'.
cls := (Object << #EcWire package: pkg) install.

cls class compile: 'typeExecute  ^ ''system/protocol/execute'''.
cls class compile: 'typeResponse  ^ ''system/protocol/execute/response'''.
cls class compile: 'typeError  ^ ''system/protocol/error'''.
cls class compile: 'typeAny  ^ ''primitive/any'''.

"emptyParams — §3.2: params with no content is a primitive/any whose data is the canonical
 empty map (single byte 0xa0)."
cls class compile: 'emptyParams
	^ EcEntity type: self typeAny data: EcVal emptyMap'.

"execRequestId:uri:operation:params:author:capability: — build a system/protocol/execute
 entity. author/capability are content-hash ByteArrays; pass nil to omit (a connect-path
 request carries neither). params is a materialized EcEntity (embedded as its wire map)."
cls class compile: 'execRequestId: rid uri: uri operation: op params: paramsEntity author: authHashOrNil capability: capHashOrNil
	| pairs |
	pairs := OrderedCollection new.
	pairs add: (''request_id'' -> (EcVal text: rid)).
	pairs add: (''uri'' -> (EcVal text: uri)).
	pairs add: (''operation'' -> (EcVal text: op)).
	pairs add: (''params'' -> paramsEntity asWireMap).
	authHashOrNil ifNotNil: [ pairs add: (''author'' -> (EcVal bytes: authHashOrNil)) ].
	capHashOrNil ifNotNil: [ pairs add: (''capability'' -> (EcVal bytes: capHashOrNil)) ].
	^ EcEntity type: self typeExecute data: (EcVal map: pairs asArray)'.

"response:status:result: — build a system/protocol/execute/response entity (§3.3). status is
 a uint; result is a materialized EcEntity (embedded as its wire map)."
cls class compile: 'response: rid status: status result: resultEntity
	^ EcEntity type: self typeResponse data: (EcVal map: {
		''request_id'' -> (EcVal text: rid).
		''status'' -> (EcVal uint: status).
		''result'' -> resultEntity asWireMap })'.

"error:message: — a system/protocol/error entity. Pass nil message to omit it."
cls class compile: 'error: codeString message: messageStringOrNil
	| pairs |
	pairs := OrderedCollection new.
	pairs add: (''code'' -> (EcVal text: codeString)).
	messageStringOrNil ifNotNil: [ pairs add: (''message'' -> (EcVal text: messageStringOrNil)) ].
	^ EcEntity type: self typeError data: (EcVal map: pairs asArray)'.

'EntityCore-Peer:EcWire installed'
