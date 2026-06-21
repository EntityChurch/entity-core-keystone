package peer

// peer.go — Peer assembly: bootstrap, the four MUST system handlers (§6.2: tree,
// handler, capability, connect), the §6.5 dispatch chain, §6.6 resolution, §6.9
// bootstrap (incl. §6.9a peer-authority bootstrap), and per-connection state.
//
// Dispatch idiom: operation dispatch is a Go method table — each handler is a
// value implementing handleOp(op string, ctx *dispatchCtx) outcome, where the
// per-operation switch lives inside the handler method (the idiomatic Go
// single-dispatch ladder; contrast the Common-Lisp peer's CLOS multiple
// dispatch). Unknown operations fall to the default 501 arm. The §6.6 backward
// tree-walk resolves a request URI to a bootstrapped handler instance.

import (
	"crypto/rand"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// Peer is a bootstrapped Entity Core peer.
type Peer struct {
	identity    Identity
	store       *Store
	localPeer   string
	openGrants  bool // --debug-open-grants: mint a wide admin cap
	conformance bool // --validate: §7a system/validate/* handlers

	handlers map[string]handler // pattern -> handler instance
}

// Identity returns the peer's identity.
func (p *Peer) Identity() Identity { return p.identity }

// Store returns the peer's store (for emit-consumer registration in tests/hosts).
func (p *Peer) Store() *Store { return p.store }

// LocalPeer returns the peer's local peer_id.
func (p *Peer) LocalPeer() string { return p.localPeer }

// conn is per-connection state (§4.2).
type conn struct {
	established bool
	issuedNonce []byte // nonce we issued in our hello response
	helloPeerID string // initiator's claimed peer_id from hello
	outbound    outboundFn
	outCounter  int
}

// outboundFn sends an EXECUTE envelope over the connection and awaits its
// correlated EXECUTE_RESPONSE (§6.13(b) reentry seam). nil when the request did
// not arrive over a reentrant connection.
type outboundFn func(req Envelope) (Envelope, bool)

// outcome is a handler result: a status, a result entity, and any included
// protocol entities to carry back.
type outcome struct {
	status   uint64
	result   Entity
	included []Entity
}

func okOutcome(result Entity, included ...Entity) outcome {
	return outcome{status: 200, result: result, included: included}
}

func errOutcome(status uint64, code, message string) outcome {
	return outcome{status: status, result: ErrorResult(code, message)}
}

// dispatchCtx is the §6.6 HandlerContext threaded into a handler.
type dispatchCtx struct {
	exec      Entity
	conn      *conn
	included  Included
	callerCap Entity
	hasCap    bool
}

// handler is a bootstrapped system handler.
type handler interface {
	handleOp(op string, ctx *dispatchCtx) outcome
}

// ── randomness (nonce; §4.6 SHOULD >=32-byte CSPRNG) ────────────────────────

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// ── grant construction (§4.4 / §5.4) ────────────────────────────────────────

func scopeCbor(incl, excl []string) cbor.Value {
	if len(excl) > 0 {
		return cbor.NewMap(
			cbor.Entry("include", strList(incl...)),
			cbor.Entry("exclude", strList(excl...)),
		)
	}
	return cbor.NewMap(cbor.Entry("include", strList(incl...)))
}

type grantSpec struct {
	handlers   []string
	resources  []string
	operations []string
	peers      []string // nil = absent
}

func (gs grantSpec) toCbor() cbor.Value {
	pairs := []cbor.Pair{
		cbor.Entry("handlers", scopeCbor(gs.handlers, nil)),
		cbor.Entry("resources", scopeCbor(gs.resources, nil)),
		cbor.Entry("operations", scopeCbor(gs.operations, nil)),
	}
	if gs.peers != nil {
		pairs = append(pairs, cbor.Entry("peers", scopeCbor(gs.peers, nil)))
	}
	return cbor.NewMap(pairs...)
}

func grantsCbor(specs ...grantSpec) cbor.Value {
	vs := make([]cbor.Value, len(specs))
	for i, gs := range specs {
		vs[i] = gs.toCbor()
	}
	return valList(vs...)
}

// discoveryFloor is the §4.4 floor every authenticated identity gets.
func discoveryFloor() []grantSpec {
	return []grantSpec{
		{handlers: []string{"system/tree"}, resources: []string{"system/type/*", "system/handler/*"}, operations: []string{"get"}},
		{handlers: []string{"system/capability"}, resources: []string{}, operations: []string{"request"}},
	}
}

// openGrantsScope is the degenerate [default -> *] (= --debug-open-grants).
func openGrantsScope() []grantSpec {
	return []grantSpec{{handlers: []string{"*"}, resources: []string{"*", "/*/*"}, operations: []string{"*"}, peers: []string{"*"}}}
}

// ownerGrants is full owner authority over /{peer_id}/* (§6.9a).
func (p *Peer) ownerGrants() []grantSpec {
	return []grantSpec{{handlers: []string{"*"}, resources: []string{"*"}, operations: []string{"*"}, peers: []string{p.localPeer}}}
}

// ── token mint (§4.4 / §6.9a) ───────────────────────────────────────────────

// mintToken mints + signs a capability token granted by us to granteeHash.
func (p *Peer) mintToken(granteeHash []byte, grants cbor.Value, parent []byte) (token, sig Entity) {
	pairs := []cbor.Pair{
		cbor.Entry("granter", cbor.Bytes(p.identity.IdentityHash())),
		cbor.Entry("grantee", cbor.Bytes(granteeHash)),
		cbor.Entry("grants", grants),
		cbor.Entry("created_at", cbor.Uint(nowMillis())),
	}
	if parent != nil {
		pairs = append(pairs, cbor.Entry("parent", cbor.Bytes(parent)))
	}
	token = mustEntity("system/capability/token", cbor.NewMap(pairs...))
	sig = p.identity.SignEntity(token)
	return token, sig
}

// ── §6.9a seed policy (authenticate-time grant derivation) ──────────────────

// seedEntryGrants returns the raw grants list from a seed-policy entry, handling
// both §6.9a.0 shapes: a cap token (detached-signature — verify the sig at the
// §3.5 pointer) or a policy-entry.
func (p *Peer) seedEntryGrants(e Entity) (cbor.Value, bool) {
	switch e.Type {
	case "system/capability/token":
		sigPath := "/" + p.localPeer + "/system/signature/" + hexOf(e.Hash)
		sgn, ok := p.store.GetAt(sigPath)
		if ok && VerifySignature(sgn, p.identity.PeerEntity()) {
			if g, ok := e.Field("grants"); ok && g.Kind == cbor.KindArray {
				return g, true
			}
		}
	case "system/capability/policy-entry":
		if g, ok := e.Field("grants"); ok && g.Kind == cbor.KindArray {
			return g, true
		}
	}
	return cbor.Value{}, false
}

// deriveSeedGrants is the §6.9a authenticate-time derivation: dual-form lookup
// (hex -> Base58 -> default), then UNION the matched scope with the §4.4
// discovery floor.
func (p *Peer) deriveSeedGrants(remotePeer Entity, remotePeerID string) cbor.Value {
	base := "/" + p.localPeer + "/system/capability/policy/"
	var entry Entity
	var found bool
	for _, key := range []string{hexOf(remotePeer.Hash), remotePeerID, "default"} {
		if e, ok := p.store.GetAt(base + key); ok {
			entry, found = e, true
			break
		}
	}
	floor := grantsCbor(discoveryFloor()...)
	if !found {
		return floor
	}
	policyGrants, ok := p.seedEntryGrants(entry)
	if !ok {
		return floor
	}
	// UNION: append the matched policy grants onto the floor.
	merged := append([]cbor.Value(nil), floor.Array...)
	merged = append(merged, policyGrants.Array...)
	return cbor.Value{Kind: cbor.KindArray, Array: merged}
}

// ── §6.13(b) handler-facing outbound dispatch ───────────────────────────────

// outboundDispatch builds, signs (as the local peer), and sends an outbound
// EXECUTE through the §6.11 reentry seam on the serving connection, returning the
// correlated EXECUTE_RESPONSE envelope, or false if no reentrant connection.
func (p *Peer) outboundDispatch(c *conn, uri, operation string, params Entity, capability, granterPeer, capSig Entity, resource cbor.Value) (Envelope, bool) {
	if c.outbound == nil {
		return Envelope{}, false
	}
	c.outCounter++
	requestID := "out-" + itoa(c.outCounter)
	exec := MakeExecute(requestID, uri, operation, params,
		withAuthor(p.identity.IdentityHash()),
		withCapability(capability.Hash),
		withResource(resource))
	execSig := p.identity.SignEntity(exec)
	env := NewEnvelope(exec,
		capability,
		granterPeer,
		p.identity.PeerEntity(),
		capSig,
		execSig)
	return c.outbound(env)
}

// ── dispatcher-level signature ingestion (§6.5) ─────────────────────────────

func (p *Peer) ingestSignatures(env Envelope) {
	for _, e := range env.Included {
		if e.Type != "system/signature" {
			continue
		}
		p.store.PutEntity(e)
		signerH, ok := e.Bytes("signer")
		if !ok {
			continue
		}
		signerPeer, ok := env.Included.Get(signerH)
		if !ok {
			continue
		}
		p.store.PutEntity(signerPeer)
		target, tok := e.Bytes("target")
		pk, pok := signerPeer.Bytes("public_key")
		if tok && pok {
			pid := peerIDOfPublicKey(pk)
			p.store.Bind("/"+pid+"/system/signature/"+hexOf(target), e)
		}
	}
}

// ── handler resolution (§6.6) — backward tree-walk ──────────────────────────

// resolveHandler returns the longest prefix of path bound to a system/handler
// entity, plus the matched pattern, or ok=false.
func (p *Peer) resolveHandler(path string) (pattern string, ok bool) {
	segs := splitSlash(path)
	for i := len(segs); i >= 1; i-- {
		prefix := joinSlash(segs[:i])
		if e, ok := p.store.GetAt(prefix); ok && e.Type == "system/handler" {
			return prefix, true
		}
	}
	return "", false
}

// stripLocal strips the /{local}/ prefix from a resolved pattern.
func (p *Peer) stripLocal(pattern string) string {
	prefix := "/" + p.localPeer + "/"
	if startsWith(prefix, pattern) {
		return pattern[len(prefix):]
	}
	return pattern
}

// ── entity-native dispatch (§6.13(a)) ───────────────────────────────────────
//
// A dynamically-registered handler has no in-process body; evaluate the body at
// its expression_path. The minimal compute/literal shape is supported; richer
// bodies -> 501.
func (p *Peer) entityNativeDispatch(handlerPath string) outcome {
	he, ok := p.store.GetAt(handlerPath)
	if !ok {
		return errOutcome(404, "handler_not_found", handlerPath)
	}
	exprPath, ok := he.Text("expression_path")
	if !ok {
		return errOutcome(501, "no_handler_body", handlerPath)
	}
	abs, _ := canonicalize(p.localPeer, exprPath)
	expr, ok := p.store.GetAt(abs)
	if !ok {
		return errOutcome(404, "expression_not_found", abs)
	}
	if expr.Type == "compute/literal" {
		if value, ok := expr.Field("value"); ok {
			return okOutcome(mustEntity("compute/result", cbor.NewMap(
				cbor.Entry("value", value),
				cbor.Entry("expression", cbor.Bytes(expr.Hash)),
			)))
		}
		return errOutcome(400, "unexpected_params", "compute/literal missing value")
	}
	return errOutcome(501, "unsupported_expression", expr.Type)
}

// ── dispatch chain (§6.5) ───────────────────────────────────────────────────

// dispatch runs the §6.5 dispatch chain, returning an EXECUTE_RESPONSE envelope,
// or ok=false for a non-EXECUTE root (§3.3 server side ignores non-EXECUTE).
func (p *Peer) dispatch(c *conn, env Envelope) (Envelope, bool) {
	exec := env.Root
	if exec.Type != "system/protocol/execute" {
		return Envelope{}, false
	}
	requestID, _ := exec.Text("request_id")
	uri, _ := exec.Text("uri")
	oc := p.runChain(c, env, exec, uri)
	resp := MakeResponse(requestID, oc.status, oc.result)
	return NewEnvelope(resp, oc.included...), true
}

func (p *Peer) runChain(c *conn, env Envelope, exec Entity, uri string) outcome {
	operation, _ := exec.Text("operation")

	// The connect handler is reached pre-authentication (the handshake itself).
	if uri == "system/protocol/connect" {
		h := p.handlers["system/protocol/connect"]
		return h.handleOp(operation, &dispatchCtx{exec: exec, conn: c, included: env.Included})
	}

	p.ingestSignatures(env)

	switch verifyRequest(p.localPeer, p.store, env) {
	case VerdictAuthnFail:
		return errOutcome(401, "authentication_failed", "")
	case VerdictAuthzDeny:
		return errOutcome(403, "capability_denied", "")
	case VerdictChainTooDeep:
		return errOutcome(400, "chain_depth_exceeded", "")
	case VerdictUnresolvableGrantee:
		return errOutcome(401, "unresolvable_grantee", "")
	}
	// VerdictAllow:
	path, pathOK := canonicalize(p.localPeer, normalizeURI(uri))
	if !pathOK {
		return errOutcome(400, "invalid_path", uri)
	}
	// §1.4: inbound dispatch must target the local peer.
	if extractPeer(p.localPeer, path) != p.localPeer {
		return errOutcome(404, "handler_not_found", "not local peer")
	}
	pattern, ok := p.resolveHandler(path)
	if !ok {
		return errOutcome(404, "handler_not_found", path)
	}
	capH, _ := exec.Bytes("capability")
	callerCap, capOK := env.Included.Get(capH)
	if !capOK {
		return errOutcome(403, "capability_denied", "")
	}
	resolve := capResolve(env.Included, p.store)
	granterPeer := resolveGranterPeerID(resolve, callerCap)
	if granterPeer == "" {
		granterPeer = p.localPeer
	}
	if !checkPermission(p.localPeer, granterPeer, exec, callerCap, pattern) {
		return errOutcome(403, "capability_denied", "")
	}
	stripped := p.stripLocal(pattern)
	if inst, ok := p.handlers[stripped]; ok {
		return inst.handleOp(operation, &dispatchCtx{
			exec: exec, conn: c, included: env.Included,
			callerCap: callerCap, hasCap: true,
		})
	}
	return p.entityNativeDispatch(pattern)
}

// ── small numeric helper ────────────────────────────────────────────────────

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// splitSlash splits a path on '/' (keeping empty segments, like the spec walk).
func splitSlash(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func joinSlash(segs []string) string {
	out := ""
	for i, s := range segs {
		if i > 0 {
			out += "/"
		}
		out += s
	}
	return out
}
