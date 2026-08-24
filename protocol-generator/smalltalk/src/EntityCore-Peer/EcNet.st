"entity-core-protocol-smalltalk — transport: native non-blocking BSD sockets + framing +
the §4.10(a) 16-MiB inbound cap (EntityCore-Peer).

Pharo''s `Socket` class is a GENUINE in-process BSD-socket path over the VM''s SocketPlugin
(A-ST native_sockets) — NO co-process daemon (contrast Rexx''s A-RX-008 FIFO pivot). The peer
is a SINGLE-EVENT-LOOP over one green process (the COBOL/Rexx/Forth pattern): §7b store-safety
is STRUCTURAL, and the readiness discipline (§7b) is EXISTENTIAL here — a blocking read on the
one green process stalls the whole cooperative scheduler. So every read is GATED by a bounded
`waitForDataFor:` / `dataAvailable` readiness test with a timeout; nothing blocks the scheduler
indefinitely (the profile blocking_discipline). TCP_NODELAY is set on every accepted/dialed
socket (§7b transport menu).

Frame := [4-byte BE length][payload] (§1.6). A length prefix > MAX-FRAME is the §4.10(a)
violation: we DRAIN-and-keep the connection (a 413-class rejection at the de-framer; never a
silent close, never buffering the oversize body — §4.9 keep-serving).

EcConnection wraps one Socket + the read state. EcNet holds the socket-class helpers.

LIVE-IMAGE NOTE: EcConnection resolves at send-time inside EcNet methods."

| pkg net conn |
pkg := 'EntityCore-Peer'.

"── EcNet — socket-class helpers (listen / dial / accept / options). ──"
net := (Object << #EcNet package: pkg) install.

"§4.10(a) 16-MiB inbound frame cap (informative default)."
net class compile: 'maxFrame  ^ 16 * 1024 * 1024'.
"readiness poll timeout (seconds) — the cooperative-yield bound on a read gate."
net class compile: 'readTimeout  ^ 5'.

net class compile: 'ensureNetwork  Socket initializeNetwork'.

"nodelay: — set TCP_NODELAY on a socket (§7b). Best-effort (some VMs name the option differently)."
net class compile: 'nodelay: aSocket
	[ aSocket setOption: ''TCP_NODELAY'' value: 1 ] on: Error do: [ :e | ]'.

"listenOn: — a TCP listener bound to a port (0 => ephemeral). Answers the Socket."
net class compile: 'listenOn: aPort
	| s |
	self ensureNetwork.
	s := Socket newTCP.
	"backlog LARGE (300) so the cooperative loop accepts the whole r3 flood (256 dials) into the
	 working set each tick without the kernel refusing — the §4.10(c) `accepted all AND kept
	 serving` path (the post-flood handshake probe still succeeds). ExternalSemaphoreTable grows
	 dynamically (no hard socket cap); tryAccept: is error-safe against a transient registration
	 race, so the peer stays alive across the burst."
	s listenOn: aPort backlogSize: 300.
	^ s'.

"tryAccept: — a non-blocking accept poll (bounded timeout). Answers a new EcConnection or nil.
 Sets TCP_NODELAY on the accepted socket. ERROR-SAFE: the Pharo VM caps the number of registered
 external objects (sockets) via the ExternalSemaphoreTable; a heavy connection flood (r3, 256
 dials) can overflow it and `Socket>>acceptFrom:` THROWs from OUTSIDE the serve-loop error frame —
 crashing the peer. Catching here turns a full-table accept into a polite refusal (answer nil,
 keep serving the existing connections + the post-flood probe) — the §4.10(c) self-bounded
 admission SHOULD, not a fall-over."
net class compile: 'tryAccept: aListenerSocket timeout: secs
	^ [ | s |
		s := aListenerSocket waitForAcceptFor: secs.
		s isNil ifTrue: [ nil ] ifFalse: [ self nodelay: s. EcConnection on: s ] ]
		on: Error do: [ :e | nil ]'.

"dial: — connect to 127.0.0.1:port, set TCP_NODELAY. Signals EcConnectionBrokenError on fail."
net class compile: 'dial: aPort
	| s |
	self ensureNetwork.
	s := Socket newTCP.
	s connectTo: (NetNameResolver addressForName: ''127.0.0.1'') port: aPort
		waitForConnectionFor: self readTimeout.
	s isConnected ifFalse: [ ^ EcConnectionBrokenError signal: ''dial failed'' ].
	self nodelay: s.
	^ EcConnection on: s'.

"── EcConnection — one socket + framing state. ──"
conn := ((Object << #EcConnection) slots: {
	#socket. #established. #issuedNonce. #outCounter }; package: pkg; install).

conn class compile: 'on: aSocket  ^ self new setSocket: aSocket'.
conn compile: 'setSocket: aSocket
	socket := aSocket. established := false. issuedNonce := nil. outCounter := 0. ^ self'.
conn compile: 'socket  ^ socket'.
conn compile: 'isEstablished  ^ established'.
conn compile: 'establish  established := true'.
conn compile: 'issuedNonce  ^ issuedNonce'.
conn compile: 'issuedNonce: aByteArray  issuedNonce := aByteArray'.
conn compile: 'nextOut  outCounter := outCounter + 1. ^ outCounter'.
conn compile: 'isOpen  ^ socket notNil and: [ socket isConnected ]'.
conn compile: 'dataAvailable  ^ socket dataAvailable'.
conn compile: 'close
	socket ifNotNil: [ [ socket closeAndDestroy ] on: Error do: [ :e | ]. socket := nil ]'.

"recvExactly: — read exactly n bytes, gating each read on readiness. Answers a ByteArray, or
 nil on EOF / a broken connection. A 0-length recv after readiness signals an orderly EOF."
conn compile: 'recvExactly: n
	| out got chunk r |
	n = 0 ifTrue: [ ^ ByteArray new: 0 ].
	out := ByteArray new: n.
	got := 0.
	[ got < n ] whileTrue: [
		socket isConnected ifFalse: [ ^ nil ].
		(socket waitForDataFor: EcNet readTimeout ifClosed: [ ^ nil ] ifTimedOut: [ nil ]).
		socket dataAvailable ifTrue: [
			chunk := ByteArray new: n - got.
			r := socket receiveAvailableDataInto: chunk.
			r = 0 ifTrue: [ ^ nil ].                          "orderly EOF"
			out replaceFrom: got + 1 to: got + r with: chunk startingAt: 1.
			got := got + r ] ].
	^ out'.

"drain: — read and discard n bytes (an oversize §4.10 body). Keeps the connection (§4.9)."
conn compile: 'drain: n
	| left chunk r |
	left := n.
	[ left > 0 and: [ socket isConnected ] ] whileTrue: [
		(socket waitForDataFor: EcNet readTimeout ifClosed: [ ^ self ] ifTimedOut: [ ^ self ]).
		socket dataAvailable ifTrue: [
			chunk := ByteArray new: (left min: 4096).
			r := socket receiveAvailableDataInto: chunk.
			r = 0 ifTrue: [ ^ self ].
			left := left - r ] ]'.

"readFrame — read one [len:4 BE][payload] frame. Answers:
   a ByteArray  — a valid frame payload
   #eof         — EOF / broken connection (caller closes)
   #oversize    — §4.10(a): len > maxFrame; body drained, connection kept (413-class)."
conn compile: 'readFrame
	| hdr len |
	hdr := self recvExactly: 4.
	hdr isNil ifTrue: [ ^ #eof ].
	len := ((hdr at: 1) bitShift: 24) + ((hdr at: 2) bitShift: 16)
		+ ((hdr at: 3) bitShift: 8) + (hdr at: 4).
	(len < 0 or: [ len > EcNet maxFrame ]) ifTrue: [
		self drain: len.
		^ #oversize ].
	^ self recvExactly: len ifNil: [ #eof ]'.

"a small ifNil: helper so readFrame reads cleanly."
conn compile: 'recvExactly: n ifNil: aBlock
	| r |
	r := self recvExactly: n.
	^ r isNil ifTrue: [ aBlock value ] ifFalse: [ r ]'.

"sendFrame: — send [len:4 BE][payload] (§1.6)."
conn compile: 'sendFrame: aPayloadByteArray
	| len hdr |
	len := aPayloadByteArray size.
	hdr := ByteArray new: 4.
	hdr at: 1 put: ((len bitShift: -24) bitAnd: 16rFF).
	hdr at: 2 put: ((len bitShift: -16) bitAnd: 16rFF).
	hdr at: 3 put: ((len bitShift: -8) bitAnd: 16rFF).
	hdr at: 4 put: (len bitAnd: 16rFF).
	socket sendData: hdr.
	socket sendData: aPayloadByteArray'.

'EntityCore-Peer:EcNet + EcConnection installed'
