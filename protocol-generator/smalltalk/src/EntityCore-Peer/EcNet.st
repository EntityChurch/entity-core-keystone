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
	#socket. #established. #issuedNonce. #helloPeerId. #outCounter }; package: pkg; install).

conn class compile: 'on: aSocket  ^ self new setSocket: aSocket'.
conn compile: 'setSocket: aSocket
	socket := aSocket. established := false. issuedNonce := nil. helloPeerId := nil.
	outCounter := 0. ^ self'.
conn compile: 'socket  ^ socket'.
conn compile: 'isEstablished  ^ established'.
conn compile: 'establish  established := true'.
conn compile: 'issuedNonce  ^ issuedNonce'.
conn compile: 'issuedNonce: aByteArray  issuedNonce := aByteArray'.
"§4.7 row 8 names TWO inputs on one row, and the second needs the hello leg remembered:
 deriving peer_id from public_key proves the identity is SELF-CONSISTENT and says nothing
 about whether it is the identity this connection has been negotiating with."
conn compile: 'helloPeerId  ^ helloPeerId'.
conn compile: 'helloPeerId: aString  helloPeerId := aString'.
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
		socket isConnected ifFalse: [ ^ got = 0 ifTrue: [ nil ] ifFalse: [ #short ] ].
		(socket waitForDataFor: EcNet readTimeout ifClosed: [ ^ got = 0 ifTrue: [ nil ] ifFalse: [ #short ] ] ifTimedOut: [ nil ]).
		socket dataAvailable ifTrue: [
			chunk := ByteArray new: n - got.
			r := socket receiveAvailableDataInto: chunk.
			r = 0 ifTrue: [ ^ got = 0 ifTrue: [ nil ] ifFalse: [ #short ] ].
			out replaceFrom: got + 1 to: got + r with: chunk startingAt: 1.
			got := got + r ] ].
	^ out'.

"drain: IS GONE, AND ITS ABSENCE IS THE POINT. readFrame used to answer #oversize only AFTER
 reading and discarding the declared body, so the connection could be kept framed. That is
 exactly the polite-looking behaviour §4.10(a) forbids — `reject BEFORE fully buffering` — and it
 is a denial of service against ourselves: a sender that declares 4 GiB and then sends nothing
 parks the reader for the whole read timeout while no 413 is ever emitted. Measured on the wire
 (pa-probe D1): `DROPPED — nothing on the wire and the connection stayed open`.

 The over-limit condition is knowable from FOUR BYTES, with nothing allocated and nothing spent,
 which is why §4.10(a)'s SHOULD became a MUST at 0.8.2.25 (N14). readFrame now answers #oversize
 at the prefix and the caller emits 413 and closes: the framing is lost either way, so closing is
 a CHOICE IN ADDITION to answering rather than instead of it."

"recvExactly: answers nil when the stream ended with NOTHING read, and #short when it ended
 PART WAY THROUGH. The two used to collapse into nil, exactly as io.ReadFull collapses EOF and
 UnexpectedEOF — and §4.11 (0.8.2.25) makes them different events: a clean close at a frame
 boundary is an ordinary hangup owed nothing, while a stream that ends mid-frame is a TRUNCATED
 frame owed `400 invalid_request`. Only the frame boundary knows which, so readFrame below is
 where the distinction is USED and this is where it has to be MADE."

"readFrame — read one [len:4 BE][payload] frame. Answers:
   a ByteArray  — a valid frame payload
   #eof         — a clean close at a frame boundary (caller closes, answers nothing)
   #truncated   — §4.11: a partial length prefix, or a declared body that never arrived
   #oversize    — §4.10(a)/§4.11 N14: len > maxFrame, detected AT THE PREFIX with nothing
                  buffered (caller emits 413, then closes)."
conn compile: 'readFrame
	| hdr len body |
	hdr := self recvExactly: 4.
	hdr isNil ifTrue: [ ^ #eof ].
	hdr == #short ifTrue: [ ^ #truncated ].
	len := ((hdr at: 1) bitShift: 24) + ((hdr at: 2) bitShift: 16)
		+ ((hdr at: 3) bitShift: 8) + (hdr at: 4).
	(len < 0 or: [ len > EcNet maxFrame ]) ifTrue: [ ^ #oversize ].
	body := self recvExactly: len.
	(body isNil or: [ body == #short ]) ifTrue: [ ^ #truncated ].
	^ body'.

"a small ifNil: helper so readFrame reads cleanly."
conn compile: 'recvExactly: n ifNil: aBlock
	| r |
	r := self recvExactly: n.
	^ r isNil ifTrue: [ aBlock value ] ifFalse: [ r ]'.

"sendFrameHalfOpen: — the §4.11 framing-refusal writer. Answers whether the frame reached the wire.

 THE RUNTIME, NOT THIS PEER, DECIDES WHETHER A REFUSAL REACHES THE WIRE — and Pharo decides NO
 once the far end has half-closed. That is the third runtime in this cohort to make the decision
 and the FIRST WITH NO KNOB. Node has `allowHalfOpen`, the BEAM has `exit_on_close: false`; Pharo
 has no half-open support in `Socket` at all. Traced rather than inferred, in the stderr this peer keeps:

   sendData:      -> ConnectionClosed: connection closed while sending data
   sendSomeData:  -> ConnectionClosed   (the lower primitive, past the liveness guard)

 `isConnected` answers false the moment the far end sends FIN, and BOTH write paths gate on it.
 So the §4.11 TRUNCATION arm is detected correctly, reaches its refusal, and cannot deliver it:
 `readFrame` answers #truncated, `serveConn:` answers 400 invalid_request, and the image refuses
 to write it. That is a disclosed gap, not a silent one — the arm stays because it is right and
 becomes deliverable the day the socket layer supports a half-open write, and because a peer that
 DETECTS the condition and says so is a different artifact from one that never looked.

 The OVERSIZE arm is unaffected and delivers normally: the far end has not closed there, which is
 exactly why §4.10(a) N14 made that emission a MUST — the condition is knowable from four bytes
 with the connection intact.

 Bounded and QUIET: one report, not one per pass. A refusal that cannot be delivered is worth a
 line, and sixty-four lines is worth none."
conn compile: 'sendFrameHalfOpen: aPayloadByteArray
	| len hdr buf sent n |
	len := aPayloadByteArray size.
	hdr := ByteArray new: 4.
	hdr at: 1 put: ((len bitShift: -24) bitAnd: 16rFF).
	hdr at: 2 put: ((len bitShift: -16) bitAnd: 16rFF).
	hdr at: 3 put: ((len bitShift: -8) bitAnd: 16rFF).
	hdr at: 4 put: (len bitAnd: 16rFF).
	buf := hdr , aPayloadByteArray.
	sent := 0.
	[ sent < buf size ] whileTrue: [
		n := [ socket sendSomeData: buf startIndex: sent + 1 count: buf size - sent ]
			on: Error
			do: [ :e |
				Stdio stderr << ''[refuse-undeliverable] '' << e class name
					<< '' after '' << sent printString << ''/'' << buf size printString
					<< '' bytes (this runtime cannot write a half-closed socket)''
					<< (String with: Character lf); flush.
				^ false ].
		n = 0 ifTrue: [ ^ false ].
		sent := sent + n ].
	^ true'.

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
