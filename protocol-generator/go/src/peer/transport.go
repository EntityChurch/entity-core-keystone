package peer

// transport.go — Transport (L4): TCP listener + per-connection reader goroutine
// (§1.6 framing, §4.8 inbound concurrency, §6.11 reentry). Plus the CLIENT
// dialer/handshake that drives the two-peer loopback.
//
// CONCURRENCY MODEL (profile [concurrency].style = goroutines): one reader
// goroutine per connection demuxes inbound frames (§6.11). An EXECUTE_RESPONSE
// routes to its awaiting outbound caller by request_id through a per-conn
// response-channel map; an inbound EXECUTE is dispatched on ITS OWN goroutine
// (§4.8) so a handler that originates an outbound EXECUTE (§6.13(b)) and awaits
// its response does NOT block the reader. Writes are serialized by a mutex.
//
// TCP_NODELAY (profile [concurrency].tcp_nodelay = true): SetNoDelay(true) on
// EVERY accepted/dialed connection from day one — Nagle + delayed-ACK on small
// req/resp frames was THE §7b throughput killer across the cohort. We never hold
// the store lock across I/O (the store copies out under its lock; writes happen
// outside it).

import (
	"net"
	"sync"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// transportIO is a per-connection IO endpoint shared by server + client.
type transportIO struct {
	conn      net.Conn
	writeLock sync.Mutex

	pendingMu sync.Mutex
	pending   map[string]chan Envelope // request_id -> response channel
	closed    bool
}

func newTransportIO(c net.Conn) *transportIO {
	// TCP_NODELAY from day one (§7b).
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return &transportIO{conn: c, pending: make(map[string]chan Envelope)}
}

func (io *transportIO) writeFramed(env Envelope) error {
	payload, err := FrameOfEnvelope(env)
	if err != nil {
		return err
	}
	io.writeLock.Lock()
	defer io.writeLock.Unlock()
	return WriteFrame(io.conn, payload)
}

// routeResponse delivers an EXECUTE_RESPONSE to its awaiting caller (§6.11 demux).
func (io *transportIO) routeResponse(env Envelope) {
	requestID, _ := env.Root.Text("request_id")
	io.pendingMu.Lock()
	ch := io.pending[requestID]
	io.pendingMu.Unlock()
	if ch != nil {
		select {
		case ch <- env:
		default:
		}
	}
}

// outbound (§6.13(b)) sends a request envelope and awaits its correlated
// EXECUTE_RESPONSE. Returns ok=false if the connection closes first.
func (io *transportIO) outbound(req Envelope) (Envelope, bool) {
	requestID, _ := req.Root.Text("request_id")
	ch := make(chan Envelope, 1)
	io.pendingMu.Lock()
	if io.closed {
		io.pendingMu.Unlock()
		return Envelope{}, false
	}
	io.pending[requestID] = ch
	io.pendingMu.Unlock()

	defer func() {
		io.pendingMu.Lock()
		delete(io.pending, requestID)
		io.pendingMu.Unlock()
	}()

	if err := io.writeFramed(req); err != nil {
		return Envelope{}, false
	}
	env, ok := <-ch
	return env, ok
}

// closeIO marks the connection closed and wakes all awaiting callers.
func (io *transportIO) closeIO() {
	io.pendingMu.Lock()
	if io.closed {
		io.pendingMu.Unlock()
		return
	}
	io.closed = true
	for _, ch := range io.pending {
		close(ch)
	}
	io.pendingMu.Unlock()
	_ = io.conn.Close()
}

// readLoop (§6.11 demux): EXECUTE_RESPONSE -> route; EXECUTE -> dispatch on its
// own goroutine (§4.8). onExecute handles one inbound EXECUTE + writes its reply.
func (io *transportIO) readLoop(onExecute func(Envelope)) {
	for {
		payload, err := ReadFrame(io.conn)
		if err != nil {
			if err == ErrFrameTooLarge {
				// §4.10(a): rejected before buffering; close + keep the peer
				// serving other connections (this loop just ends).
			}
			return
		}
		env, err := EnvelopeOfFrame(payload)
		if err != nil {
			continue // malformed frame: skip, keep reading
		}
		if env.Root.Type == "system/protocol/execute/response" {
			io.routeResponse(env)
		} else {
			go onExecute(env) // §4.8 inbound on its own goroutine
		}
	}
}

// ── server ──────────────────────────────────────────────────────────────────

// Listener is a running TCP listener for a peer.
type Listener struct {
	peer *Peer
	ln   net.Listener
}

// Listen binds 127.0.0.1:port (0 = auto-assign) and starts accepting. Returns the
// Listener (with Addr() for the bound port).
func (p *Peer) Listen(port int) (*Listener, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		return nil, err
	}
	l := &Listener{peer: p, ln: ln}
	go l.acceptLoop()
	return l, nil
}

// Addr returns the listener's bound address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Port returns the bound TCP port.
func (l *Listener) Port() int { return l.ln.Addr().(*net.TCPAddr).Port }

// Close stops accepting new connections.
func (l *Listener) Close() error { return l.ln.Close() }

func (l *Listener) acceptLoop() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		go l.serveConnection(c)
	}
}

func (l *Listener) serveConnection(c net.Conn) {
	tio := newTransportIO(c)
	cn := &conn{}
	// wire the §6.13(b) outbound seam to this connection's io (§6.11 reentry).
	cn.outbound = tio.outbound
	onExecute := func(env Envelope) {
		// per-request isolation: a panic on one adversarial request must NOT tear
		// down the connection (§4.9 no-crash; §3.3 every EXECUTE gets a response).
		defer func() {
			if r := recover(); r != nil {
				requestID, _ := env.Root.Text("request_id")
				_ = tio.writeFramed(NewEnvelope(MakeResponse(requestID, 500, ErrorResult("internal_error", ""))))
			}
		}()
		resp, ok := l.peer.dispatch(cn, env)
		if ok {
			_ = tio.writeFramed(resp)
		}
	}
	tio.readLoop(onExecute)
	tio.closeIO()
}

// ══════════════════════════════════════════════════════════════════════════════
// Client side — the dialer + initiator handshake (drives the two-peer loopback)
// ══════════════════════════════════════════════════════════════════════════════

// ClientConnection is an authenticated initiator-side session.
type ClientConnection struct {
	io         *transportIO
	reqCounter int

	// populated by Handshake (the §4.4 authenticated session):
	remotePeerID string
	capability   Entity
	granterPeer  Entity
	capSignature Entity
}

// RemotePeerID returns the responder's peer_id learned during the handshake.
func (cc *ClientConnection) RemotePeerID() string { return cc.remotePeerID }

// Capability returns the §4.4 capability token the responder minted.
func (cc *ClientConnection) Capability() (Entity, bool) {
	return cc.capability, cc.capability.Hash != nil
}

func (cc *ClientConnection) nextRequestID() string {
	cc.reqCounter++
	return "req-" + itoa(cc.reqCounter)
}

// Dial opens a client connection and starts its reader goroutine. The client
// reader routes EXECUTE_RESPONSEs (a core responder sends no inbound EXECUTEs).
func Dial(host string, port int) (*ClientConnection, error) {
	c, err := net.Dial("tcp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		return nil, err
	}
	tio := newTransportIO(c)
	cc := &ClientConnection{io: tio}
	go tio.readLoop(func(Envelope) {})
	return cc, nil
}

// send sends a request envelope and awaits its correlated EXECUTE_RESPONSE.
func (cc *ClientConnection) send(req Envelope) (Envelope, bool) { return cc.io.outbound(req) }

// Close tears down the client connection.
func (cc *ClientConnection) Close() { cc.io.closeIO() }

// ── initiator handshake (§4.1 forward leg: hello -> authenticate) ───────────

// HandshakeError reports a non-200 handshake step.
type HandshakeError struct {
	Step   string
	Status uint64
	Code   string
}

func (e *HandshakeError) Error() string {
	return e.Step + " failed: status " + itoa(int(e.Status)) + " " + e.Code
}

func requireOK(env Envelope, step string) error {
	status, _ := env.Root.Uint("status")
	if status == 200 {
		return nil
	}
	code := ""
	if res, ok := responseResult(env); ok {
		code, _ = res.Text("code")
	}
	return &HandshakeError{Step: step, Status: status, Code: code}
}

// Handshake drives the §4.1 forward handshake as initiator (hello then
// authenticate). On success, populates cc with the §4.4 capability the responder
// minted. local is our identity.
func (cc *ClientConnection) Handshake(local Identity) error {
	// ── hello ──
	hello := mustEntity("system/protocol/connect/hello", cbor.NewMap(
		cbor.Entry("peer_id", cbor.Text(local.PeerID())),
		cbor.Entry("nonce", cbor.Bytes(randomBytes(32))),
		cbor.Entry("protocols", strList("entity-core/1.0")),
		cbor.Entry("timestamp", cbor.Uint(nowMillis())),
		cbor.Entry("hash_formats", strList("ecfv1-sha256")),
		cbor.Entry("key_types", strList("ed25519")),
	))
	r1, ok := cc.send(NewEnvelope(MakeExecute(cc.nextRequestID(), "system/protocol/connect", "hello", hello)))
	if !ok {
		return &HandshakeError{Step: "hello", Status: 0, Code: "connection_broken"}
	}
	if err := requireOK(r1, "hello"); err != nil {
		return err
	}
	remoteHello, ok := responseResult(r1)
	if !ok {
		return &HandshakeError{Step: "hello", Code: "bad_response"}
	}
	cc.remotePeerID, _ = remoteHello.Text("peer_id")
	remoteNonce, _ := remoteHello.Bytes("nonce")

	// ── authenticate ──
	auth := mustEntity("system/protocol/connect/authenticate", cbor.NewMap(
		cbor.Entry("peer_id", cbor.Text(local.PeerID())),
		cbor.Entry("public_key", cbor.Bytes(local.PublicKey())),
		cbor.Entry("key_type", cbor.Text("ed25519")),
		cbor.Entry("nonce", cbor.Bytes(remoteNonce)),
	))
	authSig := local.SignEntity(auth)
	r2, ok := cc.send(NewEnvelope(
		MakeExecute(cc.nextRequestID(), "system/protocol/connect", "authenticate", auth),
		local.PeerEntity(),
		authSig,
	))
	if !ok {
		return &HandshakeError{Step: "authenticate", Code: "connection_broken"}
	}
	if err := requireOK(r2, "authenticate"); err != nil {
		return err
	}
	// parse the §4.4 initial capability grant
	grant, ok := responseResult(r2)
	if !ok {
		return &HandshakeError{Step: "authenticate", Code: "bad_grant"}
	}
	tokenH, _ := grant.Bytes("token")
	token, ok := r2.Included.Get(tokenH)
	if !ok {
		return &HandshakeError{Step: "authenticate", Code: "missing_token"}
	}
	granterH, _ := token.Bytes("granter")
	granterPeer, gok := r2.Included.Get(granterH)
	capSig, sok := findSignature(token.Hash, r2.Included)
	if !gok || !sok {
		return &HandshakeError{Step: "authenticate", Code: "missing_grant_authority"}
	}
	cc.capability = token
	cc.granterPeer = granterPeer
	cc.capSignature = capSig
	return nil
}

func responseResult(env Envelope) (Entity, bool) {
	rc, ok := env.Root.Field("result")
	if !ok || rc.Kind != cbor.KindMap {
		return Entity{}, false
	}
	e, err := EntityOfCbor(rc)
	if err != nil {
		return Entity{}, false
	}
	return e, true
}

// ResponseStatus returns the status of an EXECUTE_RESPONSE envelope.
func ResponseStatus(env Envelope) uint64 {
	s, _ := env.Root.Uint("status")
	return s
}

// ResponseResult decodes the result entity from an EXECUTE_RESPONSE envelope.
func ResponseResult(env Envelope) (Entity, bool) { return responseResult(env) }

// ── authenticated EXECUTE (§5.8 full authority chain in `included`) ─────────

// Execute builds, signs, and sends an authenticated EXECUTE; awaits the
// correlated EXECUTE_RESPONSE. The full authority chain travels in `included`.
func (cc *ClientConnection) Execute(local Identity, uri, operation string, params Entity, resource ...cbor.Value) (Envelope, bool) {
	opts := []execOpt{
		withAuthor(local.IdentityHash()),
		withCapability(cc.capability.Hash),
	}
	if len(resource) > 0 {
		opts = append(opts, withResource(resource[0]))
	}
	exec := MakeExecute(cc.nextRequestID(), uri, operation, params, opts...)
	execSig := local.SignEntity(exec)
	env := NewEnvelope(exec,
		cc.capability,
		cc.granterPeer,
		local.PeerEntity(),
		cc.capSignature,
		execSig)
	return cc.send(env)
}
