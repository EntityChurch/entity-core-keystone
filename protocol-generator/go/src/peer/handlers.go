package peer

// handlers.go — the four MUST system handlers (connect / tree / capability /
// handlers) + the §7a conformance handlers (echo / dispatch-outbound). Each
// handler implements handleOp(op, ctx) with an internal operation switch (the
// idiomatic Go single-dispatch ladder); an unknown operation falls to 501.

import (
	"crypto/ed25519"

	entitycore "github.com/entity-core/entity-core-protocol-go"
	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

func op501(op string) outcome { return errOutcome(501, "unsupported_operation", op) }

// ── connect handler (§4.1, §4.6) ────────────────────────────────────────────

type connectHandler struct{ p *Peer }

func (h connectHandler) handleOp(op string, ctx *dispatchCtx) outcome {
	switch op {
	case "hello":
		return h.hello(ctx)
	case "authenticate":
		return h.authenticate(ctx)
	default:
		return op501(op)
	}
}

func paramsEntity(exec Entity) (Entity, bool) { return exec.SubEntity("params") }

func strArray(exec Entity, key string) ([]string, bool) {
	params, ok := paramsEntity(exec)
	if !ok {
		return nil, false
	}
	v, ok := params.Field(key)
	if !ok {
		return nil, false
	}
	return textElems(v), true
}

func (h connectHandler) hello(ctx *dispatchCtx) outcome {
	p, c, exec := h.p, ctx.conn, ctx.exec
	if c.established {
		return errOutcome(409, "connection_already_established", "")
	}
	// §4.5 negotiation: reject disjoint hash_formats / key_types up front.
	if f, ok := strArray(exec, "hash_formats"); ok && !contains(f, "ecfv1-sha256") {
		return errOutcome(400, "incompatible_hash_format", "")
	}
	if k, ok := strArray(exec, "key_types"); ok && !contains(k, "ed25519") {
		return errOutcome(400, "unsupported_key_type", "")
	}
	var initiatorPeer string
	if params, ok := paramsEntity(exec); ok {
		initiatorPeer, _ = params.Text("peer_id")
	}
	nonce := randomBytes(32)
	c.helloPeerID = initiatorPeer
	c.issuedNonce = nonce
	return okOutcome(mustEntity("system/protocol/connect/hello", cbor.NewMap(
		cbor.Entry("peer_id", cbor.Text(p.localPeer)),
		cbor.Entry("nonce", cbor.Bytes(nonce)),
		cbor.Entry("protocols", strList("entity-core/1.0")),
		cbor.Entry("timestamp", cbor.Uint(nowMillis())),
		cbor.Entry("hash_formats", strList("ecfv1-sha256")),
		cbor.Entry("key_types", strList("ed25519")),
	)))
}

func (h connectHandler) authenticate(ctx *dispatchCtx) outcome {
	p, c, exec := h.p, ctx.conn, ctx.exec
	if c.established {
		return errOutcome(409, "connection_already_established", "")
	}
	if c.issuedNonce == nil {
		return errOutcome(401, "invalid_nonce", "") // authenticate before hello
	}
	auth, ok := paramsEntity(exec)
	if !ok {
		return errOutcome(401, "authentication_failed", "")
	}
	// §4.6 hardening: reject an unsupported key_type, a non-32-byte public_key,
	// or a non-0x01 peer_id.
	if kt, ok := auth.Text("key_type"); ok && kt != "ed25519" {
		return errOutcome(400, "unsupported_key_type", "")
	}
	if pub, ok := auth.Bytes("public_key"); ok && len(pub) != 32 {
		return errOutcome(400, "unsupported_key_type", "")
	}
	if pid, ok := auth.Text("peer_id"); ok {
		if parsed, err := entitycore.ParsePeerID(pid); err == nil && parsed.KeyType != entitycore.KeyTypeEd25519 {
			return errOutcome(400, "unsupported_key_type", "")
		}
	}
	pub, hasPub := auth.Bytes("public_key")
	echoed, _ := auth.Bytes("nonce")
	claimed, _ := auth.Text("peer_id")

	// step 1: nonce-echo
	if !bytesEqual(echoed, c.issuedNonce) {
		return errOutcome(401, "invalid_nonce", "")
	}
	if !hasPub {
		return errOutcome(401, "authentication_failed", "")
	}
	// step 2: proof of possession
	sgn, sgnOK := findSignature(auth.Hash, ctx.included)
	sigOK := false
	if sgnOK {
		if sb, ok := sgn.Bytes("signature"); ok && len(pub) == ed25519.PublicKeySize {
			sigOK = ed25519.Verify(ed25519.PublicKey(pub), auth.Hash, sb)
		}
	}
	if !sigOK {
		return errOutcome(401, "authentication_failed", "")
	}
	// step 3: identity binding
	if claimed == "" || claimed != peerIDOfPublicKey(pub) {
		return errOutcome(401, "identity_mismatch", "")
	}
	if c.helloPeerID != "" && c.helloPeerID != claimed {
		return errOutcome(401, "identity_mismatch", "")
	}
	// success: mint the §4.4 / §6.9a initial capability for the remote.
	remotePeer := PeerEntityOfPublicKey(pub)
	grants := p.deriveSeedGrants(remotePeer, claimed)
	token, sig := p.mintToken(remotePeer.Hash, grants, nil)
	c.established = true
	return okOutcome(
		mustEntity("system/capability/grant", cbor.NewMap(
			cbor.Entry("token", cbor.Bytes(token.Hash)),
		)),
		token,
		p.identity.PeerEntity(),
		sig,
	)
}

// ── tree handler (§6.3) ─────────────────────────────────────────────────────

type treeHandler struct{ p *Peer }

func (h treeHandler) handleOp(op string, ctx *dispatchCtx) outcome {
	switch op {
	case "get":
		return h.get(ctx)
	case "put":
		return h.put(ctx)
	default:
		return op501(op)
	}
}

func execResourceTarget(exec Entity) (string, bool) {
	r, ok := exec.Field("resource")
	if !ok || r.Kind != cbor.KindMap {
		return "", false
	}
	targetsV, ok := MapField(r, "targets")
	if !ok {
		return "", false
	}
	targets := asList(targetsV)
	if len(targets) == 0 || targets[0].Kind != cbor.KindText {
		return "", false
	}
	return targets[0].Text, true
}

// pathFlexOK validates a caller-supplied resource target (§1.4 / §5.4).
func pathFlexOK(target string) bool {
	for i := 0; i < len(target); i++ {
		if target[i] == 0 {
			return false
		}
	}
	segs := splitSlash(target)
	var body []string
	if startsWith("/", target) {
		if len(segs) >= 2 && segs[0] == "" {
			if !isPeerID(segs[1]) {
				return false
			}
			body = segs[1:]
		} else {
			return false
		}
	} else {
		body = segs
	}
	if len(body) > 0 && body[len(body)-1] == "" {
		body = body[:len(body)-1]
	}
	for _, s := range body {
		if s == "" || s == "." || s == ".." {
			return false
		}
	}
	return true
}

func (h treeHandler) isDeletionMarker(hexHash string) bool {
	raw, err := decodeHex(hexHash)
	if err != nil {
		return false
	}
	e, ok := h.p.store.GetByHash(raw)
	return ok && e.Type == "system/deletion-marker"
}

func (h treeHandler) buildListing(path string) outcome {
	rows := h.p.store.Listing(path)
	entries := make([]cbor.Pair, 0, len(rows))
	count := 0
	for _, row := range rows {
		if row.Hash != "" && !row.HasChildren && h.isDeletionMarker(row.Hash) {
			continue
		}
		var data cbor.Value
		if row.Hash != "" {
			raw, _ := decodeHex(row.Hash)
			data = cbor.NewMap(
				cbor.Entry("has_children", cbor.Bool(row.HasChildren)),
				cbor.Entry("hash", cbor.Bytes(raw)),
			)
		} else {
			data = cbor.NewMap(cbor.Entry("has_children", cbor.Bool(row.HasChildren)))
		}
		entries = append(entries, cbor.Pair{
			Key: cbor.Text(row.Segment),
			Val: mustEntity("system/tree/listing-entry", data).ToCbor(),
		})
		count++
	}
	return okOutcome(mustEntity("system/tree/listing", cbor.NewMap(
		cbor.Entry("path", cbor.Text(path)),
		cbor.Entry("entries", cbor.NewMap(entries...)),
		cbor.Entry("count", cbor.Uint(uint64(count))),
		cbor.Entry("offset", cbor.Uint(0)),
	)))
}

func (h treeHandler) get(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	target, hasTarget := execResourceTarget(exec)
	switch {
	case hasTarget && !pathFlexOK(target):
		return errOutcome(400, "invalid_path", target)
	case !hasTarget:
		return h.buildListing("/" + p.localPeer + "/")
	case target == "" || target[len(target)-1] == '/':
		c, _ := canonicalize(p.localPeer, target)
		return h.buildListing(c)
	default:
		path, _ := canonicalize(p.localPeer, target)
		e, ok := p.store.GetAt(path)
		if !ok {
			return errOutcome(404, "not_found", path)
		}
		var mode string
		if params, ok := paramsEntity(exec); ok {
			mode, _ = params.Text("mode")
		}
		if mode == "hash" {
			return okOutcome(mustEntity("system/hash", cbor.NewMap(cbor.Entry("hash", cbor.Bytes(e.Hash)))))
		}
		return okOutcome(e)
	}
}

func (h treeHandler) put(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	target, hasTarget := execResourceTarget(exec)
	if !hasTarget {
		return errOutcome(400, "ambiguous_resource", "tree: missing resource target")
	}
	if !pathFlexOK(target) {
		return errOutcome(400, "invalid_path", target)
	}
	path, _ := canonicalize(p.localPeer, target)
	params, _ := paramsEntity(exec)
	entity, hasEntity := params.SubEntity("entity")
	expected, hasExpected := params.Bytes("expected_hash")
	current := p.store.HashAt(path)

	casOK := true
	if hasExpected {
		zero33 := make([]byte, 33)
		if bytesEqual(expected, zero33) {
			casOK = current == ""
		} else {
			casOK = current != "" && current == hexOf(expected)
		}
	}
	if !casOK {
		return errOutcome(409, "hash_mismatch", path)
	}
	if !hasEntity {
		return errOutcome(400, "unexpected_params", "put: missing entity")
	}
	p.store.Bind(path, entity)
	return okOutcome(mustEntity("system/hash", cbor.NewMap(cbor.Entry("hash", cbor.Bytes(entity.Hash)))))
}

// ── capability handler (§6.2) ───────────────────────────────────────────────

type capabilityHandler struct{ p *Peer }

func (h capabilityHandler) handleOp(op string, ctx *dispatchCtx) outcome {
	switch op {
	case "request":
		return h.request(ctx)
	case "delegate":
		return h.delegate(ctx)
	case "revoke":
		return h.revoke(ctx)
	case "configure":
		return h.configure(ctx)
	default:
		return op501(op)
	}
}

func isZeroHash(h []byte) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

func reqGrants(params Entity) cbor.Value {
	if g, ok := params.Field("grants"); ok && g.Kind == cbor.KindArray {
		return g
	}
	return cbor.Value{Kind: cbor.KindArray}
}

// mintBounded mints a token bounded as a subset of callerCap (§6.2 subset).
func (h capabilityHandler) mintBounded(ctx *dispatchCtx, reqGrantsV cbor.Value, granteeHash, parent []byte) outcome {
	p := h.p
	bounded := false
	if ctx.hasCap {
		parentGrants := grantsOfToken(ctx.callerCap)
		bounded = true
		for _, cg := range asList(reqGrantsV) {
			c := parseGrant(cg)
			hit := false
			for _, pg := range parentGrants {
				// self-issued mint: granter = local peer -> both frames local.
				if grantSubset(p.localPeer, p.localPeer, p.localPeer, c, pg) {
					hit = true
					break
				}
			}
			if !hit {
				bounded = false
				break
			}
		}
	}
	if !bounded {
		return errOutcome(403, "scope_exceeds_authority", "")
	}
	token, sig := p.mintToken(granteeHash, reqGrantsV, parent)
	return okOutcome(
		mustEntity("system/capability/grant", cbor.NewMap(cbor.Entry("token", cbor.Bytes(token.Hash)))),
		token,
		p.identity.PeerEntity(),
		sig,
	)
}

func (h capabilityHandler) request(ctx *dispatchCtx) outcome {
	exec := ctx.exec
	params, _ := paramsEntity(exec)
	author, ok := exec.Bytes("author")
	if !ok {
		return errOutcome(403, "capability_denied", "")
	}
	return h.mintBounded(ctx, reqGrants(params), author, nil)
}

func (h capabilityHandler) delegate(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	params, _ := paramsEntity(exec)
	author, _ := exec.Bytes("author")
	ph, hasParent := params.Bytes("parent")
	switch {
	case !hasParent:
		return errOutcome(400, "unexpected_params", "delegate: parent required")
	case isZeroHash(ph):
		return errOutcome(400, "unexpected_params", "delegate: zero parent")
	case !bytesEqual(author, p.identity.IdentityHash()):
		return errOutcome(501, "unsupported_operation", "delegate: same-peer-only in v1")
	default:
		return h.mintBounded(ctx, reqGrants(params), author, ph)
	}
}

func (h capabilityHandler) revoke(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	params, _ := paramsEntity(exec)
	tokenH, ok := params.Bytes("token")
	switch {
	case !ok:
		return errOutcome(400, "unexpected_params", "revoke: missing token")
	case isZeroHash(tokenH):
		return errOutcome(400, "unexpected_params", "revoke: zero token")
	default:
		marker := mustEntity("system/capability/revocation", cbor.NewMap(
			cbor.Entry("token", cbor.Bytes(tokenH)),
			cbor.Entry("revoked_at", cbor.Uint(nowMillis())),
		))
		p.store.Bind("/"+p.localPeer+"/system/capability/revocations/"+hexOf(tokenH), marker)
		return okOutcome(EmptyParams())
	}
}

func (h capabilityHandler) configure(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	params, _ := paramsEntity(exec)
	pp, ok := params.Text("peer_pattern")
	if !ok {
		return errOutcome(400, "unexpected_params", "configure: missing peer_pattern")
	}
	isHex := len(pp) == 66 && allHexLower(pp)
	if pp != "default" && !isHex && !isPeerID(pp) {
		return errOutcome(400, "invalid_peer_pattern", pp)
	}
	p.store.Bind("/"+p.localPeer+"/system/capability/policy/"+pp, params)
	return okOutcome(EmptyParams())
}

// ── handlers handler (§6.2 / §6.13(a)) — register/unregister ────────────────

type handlersHandler struct{ p *Peer }

func (h handlersHandler) handleOp(op string, ctx *dispatchCtx) outcome {
	switch op {
	case "register":
		return h.register(ctx)
	case "unregister":
		return h.unregister(ctx)
	default:
		return op501(op)
	}
}

// registerPattern derives the install pattern from resource.targets[0].
func registerPattern(exec Entity) (string, outcome, bool) {
	target, ok := execResourceTarget(exec)
	if !ok {
		return "", errOutcome(400, "ambiguous_resource", "register/unregister require exactly one resource target"), false
	}
	prefix := "system/handler/"
	if !startsWith(prefix, target) || len(target) == len(prefix) {
		return "", errOutcome(400, "invalid_resource", "resource target MUST be system/handler/{pattern}"), false
	}
	return target[len(prefix):], outcome{}, true
}

func (h handlersHandler) register(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	pattern, bad, ok := registerPattern(exec)
	if !ok {
		return bad
	}
	req, ok := paramsEntity(exec)
	if !ok {
		return errOutcome(400, "unexpected_params", "register: missing params")
	}
	if req.Type != "system/handler/register-request" {
		return errOutcome(400, "unexpected_params", "register expects register-request, got "+req.Type)
	}
	abs := func(rel string) string { return "/" + p.localPeer + "/" + rel }
	interfaceRel := "system/handler/" + pattern

	manifest, _ := req.Field("manifest")
	name := pattern
	if n, ok := MapField(manifest, "name"); ok && n.Kind == cbor.KindText {
		name = n.Text
	}
	operations := emptyMap()
	if o, ok := MapField(manifest, "operations"); ok {
		operations = o
	}
	exprPath, hasExpr := MapField(manifest, "expression_path")
	internalScope, hasInternal := MapField(manifest, "internal_scope")

	grantScope := cbor.Value{Kind: cbor.KindArray}
	if rs, ok := req.Field("requested_scope"); ok && rs.Kind == cbor.KindArray {
		grantScope = rs
	} else if hasInternal && internalScope.Kind == cbor.KindArray {
		grantScope = internalScope
	}

	// (1) handler manifest at the pattern path.
	handlerPairs := []cbor.Pair{cbor.Entry("interface", cbor.Text(interfaceRel))}
	if hasExpr && exprPath.Kind == cbor.KindText {
		handlerPairs = append(handlerPairs, cbor.Entry("expression_path", exprPath))
	}
	if hasInternal {
		handlerPairs = append(handlerPairs, cbor.Entry("internal_scope", internalScope))
	}
	p.store.Bind(abs(pattern), mustEntity("system/handler", cbor.NewMap(handlerPairs...)))

	// (2) associated types at system/type/{type_name}.
	if types, ok := req.Field("types"); ok && types.Kind == cbor.KindMap {
		for _, kv := range types.Map {
			if kv.Key.Kind != cbor.KindText {
				continue
			}
			data := kv.Val
			if data.Kind != cbor.KindMap {
				data = cbor.NewMap(cbor.Entry("def", kv.Val))
			}
			p.store.Bind(abs("system/type/"+kv.Key.Text), mustEntity("system/type", data))
		}
	}

	// (3) self-issued signed handler grant + (4) grant-signature at §3.5.
	token, sig := p.mintToken(p.identity.IdentityHash(), grantScope, nil)
	p.store.Bind(abs("system/capability/grants/"+pattern), token)
	p.store.Bind(abs("system/signature/"+hexOf(token.Hash)), sig)

	// (5) handler interface entity (discovery index).
	p.store.Bind(abs(interfaceRel), mustEntity("system/handler/interface", cbor.NewMap(
		cbor.Entry("pattern", cbor.Text(pattern)),
		cbor.Entry("name", cbor.Text(name)),
		cbor.Entry("operations", operations),
	)))

	tokenData, _ := token.Field("grants")
	_ = tokenData
	return okOutcome(mustEntity("system/handler/register-result", cbor.NewMap(
		cbor.Entry("pattern", cbor.Text(pattern)),
		cbor.Entry("grant", token.Data),
	)))
}

func (h handlersHandler) unregister(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	pattern, bad, ok := registerPattern(exec)
	if !ok {
		return bad
	}
	abs := func(rel string) string { return "/" + p.localPeer + "/" + rel }
	if g, ok := p.store.GetAt(abs("system/capability/grants/" + pattern)); ok {
		p.store.Unbind(abs("system/signature/" + hexOf(g.Hash)))
		p.store.Unbind(abs("system/capability/grants/" + pattern))
	}
	p.store.Unbind(abs(pattern))
	p.store.Unbind(abs("system/handler/" + pattern))
	return okOutcome(EmptyParams())
}

// ── §7a conformance handlers (system/validate namespace) ────────────────────

type echoHandler struct{ p *Peer }

func (h echoHandler) handleOp(op string, ctx *dispatchCtx) outcome {
	if op != "echo" {
		return op501(op)
	}
	p, ok := paramsEntity(ctx.exec)
	if !ok {
		return errOutcome(400, "invalid_params", "echo requires a params entity")
	}
	return okOutcome(p)
}

type dispatchOutboundHandler struct{ p *Peer }

func (h dispatchOutboundHandler) handleOp(op string, ctx *dispatchCtx) outcome {
	if op != "dispatch" {
		return op501(op)
	}
	p := h.p
	params, ok := paramsEntity(ctx.exec)
	if !ok {
		return errOutcome(400, "invalid_params", "dispatch-outbound requires a params entity")
	}
	target, _ := params.Text("target")
	operation, _ := params.Text("operation")
	value, hasValue := params.Field("value")
	capability, hasCap := params.SubEntity("reentry_capability")
	granterPeer, hasGranter := params.SubEntity("reentry_granter")
	capSig, hasSig := params.SubEntity("reentry_cap_signature")
	if !hasValue || !hasCap || !hasGranter || !hasSig {
		return errOutcome(400, "invalid_params", "dispatch-outbound requires value + reentry authority")
	}
	inner := mustEntity("primitive/any", value)
	resource := ResourceTarget("system/handler/" + target)
	env, ok := p.outboundDispatch(ctx.conn, target, operation, inner, capability, granterPeer, capSig, resource)
	if !ok {
		return errOutcome(503, "no_outbound_seam", "no live §6.11 reentry connection")
	}
	status, _ := env.Root.Uint("status")
	resultCbor, hasResult := env.Root.Field("result")
	if !hasResult {
		resultCbor = emptyMap()
	}
	return okOutcome(mustEntity("primitive/any", cbor.NewMap(
		cbor.Entry("status", cbor.Uint(status)),
		cbor.Entry("result", resultCbor),
	)))
}

// ── small helpers ───────────────────────────────────────────────────────────

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func allHexLower(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
