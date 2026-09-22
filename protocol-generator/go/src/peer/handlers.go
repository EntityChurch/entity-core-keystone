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
		// §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
		// 400 invalid_request, not the 501 every other handler answers. The table
		// separates a STATE conflict from an UNKNOWN operation because they select
		// different remedies — "an unknown connect operation is not out of order at
		// all; it exists in no state". Row 10 is scoped "in any state", so this arm
		// covers pre-handshake AND established; the sequence cases are refused
		// earlier, in hello/authenticate, with 409.
		//
		// Scoped to this handler deliberately: the generic registered-handler rule
		// (unknown op on a registered handler -> 501 unsupported_operation) is a
		// different contract and is separately gated. Moving op501 itself would
		// trade one green check for another.
		return errOutcome(400, "invalid_request", op)
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
	// §4.7 out-of-order row: a second hello on a HALF-OPEN connection (hello done,
	// authenticate not yet) is an operation we implement arriving in a state that
	// forbids it — the same class as connection_already_established above, and it
	// takes the same 409. A half-open connection is NOT established, so the row
	// above cannot reach it; §4.7's 0.8.2.8 note names this gap explicitly because
	// two adjacent rules each look like they cover it and neither does.
	if c.issuedNonce != nil {
		return errOutcome(409, "connection_sequence_error", "")
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
	// §4.5 mutual verifiability, responder side. key_types is an ACCEPT-SET, not a
	// value to collapse: "each peer's own identity key_type MUST appear in the other
	// peer's advertised key_types set … the responder MUST reject with 400
	// unsupported_key_type". The initiator's OWN key_type is not in the key_types
	// array at all — it rides in its peer_id — so a hello may advertise a perfectly
	// good accept-set and still name an identity we cannot verify. Checking only the
	// array leaves this MUST unenforced at hello, which is where §4.5 wants it (the
	// "symmetric earliest-reject guarantee"); authenticate would catch it one leg
	// later, which is conformant but is the non-canonical reject point.
	//
	// An UNPARSEABLE peer_id is deliberately left alone: it is not a key_type we
	// cannot verify, it is a malformed field, and authenticate already refuses it.
	if initiatorPeer != "" {
		if parsed, err := entitycore.ParsePeerID(initiatorPeer); err == nil &&
			parsed.KeyType != entitycore.KeyTypeEd25519 {
			return errOutcome(400, "unsupported_key_type", "")
		}
	}
	// §4.5 `protocols`. It is the one negotiated field that is Required with NO
	// default, so there is no floor to fall back to, and its two failure modes
	// carry different codes on purpose (§4.5 table row / §4.7 row 1):
	//
	//   absent or empty     -> 400 invalid_request        (a malformed hello)
	//   non-empty, disjoint -> 400 incompatible_protocol  (we compared, share nothing)
	//
	// "a caller that named no version cannot be told the comparison failed" — the
	// remedies differ (send the field vs change the version) and §4.7 exists so the
	// code selects the remedy. The vocabulary is §8.4's protocol version
	// identifiers, today the single value entity-core/1.0 — NOT this document's
	// section numbering, which §4.5 names as the plausible wrong value.
	//
	// ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
	// precedence between the three, so a hello that is disjoint in more than one
	// dimension may be refused on any of them — but the choice is observable, and
	// the reference peer refuses key_types first. Checking protocols first is
	// equally spec-legal and makes AGILITY-UNKNOWN-1 answer incompatible_protocol,
	// because that probe's own hello carries protocols ["entity-core/v7"] — a
	// spec-line name, not a §8.4 identifier. Matching the reference's precedence is
	// the interoperable choice; the probe's identifier is routed separately, since
	// it makes that check's result depend on an unruled precedence.
	protos, hasProtos := strArray(exec, "protocols")
	if !hasProtos || len(protos) == 0 {
		return errOutcome(400, "invalid_request", "protocols")
	}
	if !contains(protos, "entity-core/1.0") {
		return errOutcome(400, "incompatible_protocol", "")
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
		// RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
		// single-use nonce. The anti-replay property is the MUST and the mechanism
		// (established-state tracking) is impl-defined, but the STATUS is pinned to
		// 401 invalid_nonce — a 409 state-conflict under-signals the replay.
		return errOutcome(401, "invalid_nonce", "")
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
	token, sig := p.mintToken(remotePeer.Hash, grants, nil, nil)
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

// buildListing renders a directory listing, FILTERED per §6.3 (0.8.2.21/.22).
//
// "When any handler returns a multi-entry result whose entries are tree paths,
// each entry MUST be individually checked using check_path_permission. Entries
// for which check_path_permission returns DENY MUST be omitted. The result's
// `count` field MUST reflect the filtered entry count, not the source tree's
// total count."
//
// This is the read path at its highest volume and it is the reason 0.8.2.21
// refused to carve reads out of the caller-specified-path rule: an unfiltered
// listing discloses the EXISTENCE of every binding under a prefix to a caller
// whose capability covers none of them.
//
// The DIRECTORY itself is deliberately not checked — §6.3 makes each ENTRY the
// subject, and testing the prefix would deny a listing to a caller whose grant
// covers children but not the node above them, which is the ordinary shape of a
// narrowed grant.
func (h treeHandler) buildListing(ctx *dispatchCtx, path string) outcome {
	rows := h.p.store.Listing(path)
	entries := make([]cbor.Pair, 0, len(rows))
	count := 0
	for _, row := range rows {
		if row.Hash != "" && !row.HasChildren && h.isDeletionMarker(row.Hash) {
			continue
		}
		if !h.entryVisible(ctx, path, row.Segment) {
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

// entryVisible answers §6.3's per-entry listing check for one child segment.
// An unauthenticated context (no capability) is the bootstrap/internal path and
// is not filtered — the filter's subject is "the caller's verified capability",
// and where there is none there is no caller to narrow.
func (h treeHandler) entryVisible(ctx *dispatchCtx, dir, segment string) bool {
	if ctx == nil || !ctx.hasCap {
		return true
	}
	child := dir
	if child == "" || child[len(child)-1] != '/' {
		child += "/"
	}
	child += segment
	return checkPathPermission(h.p.localPeer, "get", child, ctx.callerCap, ctx.pattern)
}

// isPatternPath reports whether a resource target is a §5.4 PATTERN rather than
// a concrete path. A resource-requiring operation takes a concrete path
// (0.8.2.20), and a trailing "/" is a listing request rather than a pattern —
// only a `*` makes it one.
func isPatternPath(t string) bool {
	for i := 0; i < len(t); i++ {
		if t[i] == '*' {
			return true
		}
	}
	return false
}

func (h treeHandler) get(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	// §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
	// resource.targets: a handler that counts the effective list and then
	// indexes targets[0] has implemented the arithmetic completely and is still
	// reading a path no authorization covered.
	eff, hasResource := effectiveTargets(p.localPeer, exec)
	switch {
	case !hasResource:
		// THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN
		// SPECIFICATION IS WHAT SAYS SO. §3.3's "an empty effective list IS the
		// absent case" is scoped "for an operation that REQUIRES a resource"
		// (0.8.2.24, N7); `get` does not. For a resource-OPTIONAL operation
		// 0.8.2.25 (N10) decides the present-but-empty case by whether the
		// absent case is WIDER than the request — BROAD-RESULT refuses it,
		// OPTIONAL-FILTER answers it empty — and requires the operation to
		// declare which it is.
		//
		// EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
		// resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
		// listing", self-excluded case "400 path_required". So both arms below
		// are pinned by text and neither is this peer's choice. (This branch
		// previously carried an ambiguity note arguing the absent case might owe
		// path_required too; it was routed as F86 and §2.2a answers it — the
		// behaviour is unchanged and the justification is no longer ours.)
		return h.buildListing(ctx, "/"+p.localPeer+"/")
	case len(eff) == 0:
		// The self-excluded request: `resource` PRESENT, every target carved out
		// by the caller's own exclude. Serving it the absent case "answers a
		// request for one excluded path with a listing of the tree"
		// (EXTENSION-TREE §2.2a) — the root listing is wider than what was
		// asked for, which is what BROAD-RESULT means.
		return errOutcome(400, "path_required", "tree: effective target list is empty")
	case len(eff) > 1:
		return errOutcome(400, "ambiguous_resource", "tree: more than one effective target")
	}
	target := eff[0]
	switch {
	case !pathFlexOK(target):
		return errOutcome(400, "invalid_path", target)
	case target == "" || target[len(target)-1] == '/':
		c, _ := canonicalize(p.localPeer, target)
		return h.buildListing(ctx, c)
	case isPatternPath(target):
		return errOutcome(400, "malformed_resource", target)
	default:
		path, _ := canonicalize(p.localPeer, target)
		// §6.3: the handler MUST verify the CALLER's capability covers the path
		// it is about to read. Not a secondary check — the dispatch-level check
		// never saw this path if the caller excluded it.
		if ctx.hasCap && !checkPathPermission(p.localPeer, "get", path, ctx.callerCap, ctx.pattern) {
			return errOutcome(403, "capability_denied", path)
		}
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

// admitPut implements §6.3's `put` admission ladder (normative, 0.8.2.11).
//
// `put` is a RECEIPT path: the submitter authors the entity, the peer validates
// what it received (§1.8 item 1) and MUST NOT author a submitted entity's
// content_hash on the submitter's behalf. Two ordered steps:
//
//  1. STRUCTURE — the value is an entity when it is a map carrying a non-empty
//     text `type`, a PRESENT `data` (any CBOR value; null is a legal payload),
//     and a `content_hash` that is a well-formed system/hash whose total byte
//     length matches its format code (§1.2). Any failure → 400 invalid_request.
//     A well-formed hash naming a format code this peer cannot verify is the
//     separate §1.2 ingest-dispatch case → 400 unsupported_content_hash_format.
//  2. HASH — carried content_hash vs content_hash({type, data}). Disagreement
//     → 400 hash_mismatch.
//
// Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
// inputs are exactly what step 1 establishes, so a submission that is both
// malformed and mis-hashed is step 1's and answers invalid_request.
//
// Structural admission is not semantic validation — `data` is never checked
// against the type named by `type`. Step 1 asks *is this an entity*, never
// *is this a well-formed instance of its type*.
func admitPut(v cbor.Value) (Entity, outcome, bool) {
	bad := func(code, msg string) (Entity, outcome, bool) {
		return Entity{}, errOutcome(400, code, msg), false
	}
	// Step 1 — structure.
	if v.Kind != cbor.KindMap {
		return bad("invalid_request", "put: entity is not a map")
	}
	typV, ok := MapField(v, "type")
	if !ok || typV.Kind != cbor.KindText || typV.Text == "" {
		return bad("invalid_request", "put: entity.type absent, empty or not a text string")
	}
	data, ok := MapField(v, "data")
	if !ok {
		return bad("invalid_request", "put: entity.data absent")
	}
	chV, ok := MapField(v, "content_hash")
	if !ok || chV.Kind != cbor.KindBytes {
		return bad("invalid_request", "put: entity.content_hash absent or not a byte string")
	}
	code, n, err := entitycore.DecodeHashFormat(chV.Bytes)
	if err != nil {
		return bad("invalid_request", "put: entity.content_hash is not a well-formed system/hash")
	}
	digestLen, supported := entitycore.HashDigestLen(code)
	if !supported {
		// §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it.
		// Deliberately NOT invalid_request: the shape is fine, the algorithm
		// is the thing we do not have.
		return bad("unsupported_content_hash_format", "put: unsupported content_hash_format")
	}
	if len(chV.Bytes) != n+digestLen {
		return bad("invalid_request", "put: content_hash length does not match its format code")
	}
	// Step 2 — hash.
	match, err := (entitycore.Entity{Type: typV.Text, Data: data}).VerifyContentHash(chV.Bytes)
	if err != nil || !match {
		return bad("hash_mismatch", "put: content_hash does not match content_hash({type, data})")
	}
	// The carried hash is the entity's address — recomputing it here would be
	// the authoring arm §6.3 forbids. It provably equals the computed value.
	return Entity{Type: typV.Text, Data: data, Hash: append([]byte(nil), chV.Bytes...)}, outcome{}, true
}

func (h treeHandler) put(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	// Same ladder as `get`, with the two empties COLLAPSED rather than split:
	// EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's
	// "an empty effective list IS the absent case" applies in its unscoped form
	// and both empties answer `path_required`. That is the same table `get`'s
	// branch cites, read one row down — the field is per-operation and neither
	// answer is derivable from the handler's source.
	//
	// Note the code change 0.8.2.20 forced: this branch answered
	// `ambiguous_resource` for a MISSING target,
	// which 0.8.2.20 names as the exact inversion it forbids ("answering
	// ambiguous_resource for an absent resource inverts them"). The remedies
	// differ — *supply a resource* is not *disambiguate your request* — and the
	// code is what selects between them.
	eff, hasResource := effectiveTargets(p.localPeer, exec)
	switch {
	case !hasResource, len(eff) == 0:
		return errOutcome(400, "path_required", "tree: put requires a resource target")
	case len(eff) > 1:
		return errOutcome(400, "ambiguous_resource", "tree: more than one effective target")
	}
	target := eff[0]
	if !pathFlexOK(target) {
		return errOutcome(400, "invalid_path", target)
	}
	if isPatternPath(target) {
		return errOutcome(400, "malformed_resource", target)
	}
	path, _ := canonicalize(p.localPeer, target)
	if ctx.hasCap && !checkPathPermission(p.localPeer, "put", path, ctx.callerCap, ctx.pattern) {
		return errOutcome(403, "capability_denied", path)
	}
	params, _ := paramsEntity(exec)
	rawEntity, hasEntity := params.Field("entity")
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
	entity, refusal, admitted := admitPut(rawEntity)
	if !admitted {
		return refusal
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
	// §5.6 MIN_DEFINED temporal ceiling (CAP-5/CAP-6). Sample created_at ONCE and
	// convert the duration terms against that same instant.
	//
	// Note what this is NOT: an authorization decision. An over-long ttl_ms from a
	// bounded caller MINTS a clamped token and returns 200 — "rejecting it is
	// non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
	// (parent: null), so §5.6's parent-child attenuation never reaches it; without
	// this clamp, temporal attenuation is the one dimension a requester could
	// escape, and policy withdrawal would have no bounded latency.
	createdAt := nowMillis()
	params, _ := paramsEntity(ctx.exec)
	expiresAt, hasExpiry := minDefinedExpiry(
		term(p.parentExpiry(ctx, parent)),          // absolute
		term(callerCapExpiry(ctx)),                 // absolute
		term(durationTerm(createdAt, params, "ttl_ms")), // duration -> absolute
	)
	var expiryPtr *uint64
	if hasExpiry {
		expiryPtr = &expiresAt
	}
	token, sig := p.mintTokenAt(createdAt, granteeHash, reqGrantsV, parent, expiryPtr)
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

// isReservedSystemPattern reports whether pattern falls under the reserved
// system/* namespace (§6.2: user-installed handlers MUST NOT register there).
func isReservedSystemPattern(pattern string) bool {
	return pattern == "system" || startsWith("system/", pattern)
}

func (h handlersHandler) register(ctx *dispatchCtx) outcome {
	p, exec := h.p, ctx.exec
	pattern, bad, ok := registerPattern(exec)
	if !ok {
		return bad
	}
	if isReservedSystemPattern(pattern) {
		return errOutcome(403, "forbidden_pattern", "section 6.2: user-installed handlers MUST NOT register at system/* paths: "+pattern)
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
	token, sig := p.mintToken(p.identity.IdentityHash(), grantScope, nil, nil)
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
	// GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the
	// single-granter case is an array of ONE. They were singular, which made
	// §1.4's multi-signature-root rule ungateable on the wire: driving it needs
	// two granter identities and two signatures, and a single-credential carrier
	// cannot express that input.
	granterPeers, hasGranters := params.SubEntities("reentry_granters")
	capSigs, hasSigs := params.SubEntities("reentry_cap_signatures")
	// ⚠ TRANSITIONAL: the SINGULAR spellings are still accepted, as an array of
	// one, because THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned
	// oracle (78db4a9, executed set 7aa6f3de…, 778 checks) is what all 46 tracked
	// reports are measured against and it sends the SINGULAR names; a plural-only
	// peer reads the triple as absent there, takes the ambient arm, and refuses —
	// measured, 2 of 778 severities moving PASS -> FAIL on `dispatch_outbound_reentry`
	// and `t1_2_concurrent_reentry`. Accepting both keeps the cohort 0-FAIL at BOTH
	// check sets, which is strictly better evidence than either alone.
	//
	// ⛔ REMOVE THIS FALLBACK AT THE ORACLE RE-PIN, and not before. The exit
	// condition is that `tools/oracle-pin.env`'s `ref` names an oracle whose
	// dispatch-outbound probe sends the plural carriers; at that point the singular
	// spelling is dead wire vocabulary and keeping it would be an untested branch.
	if !hasGranters {
		if g, ok := params.SubEntity("reentry_granter"); ok {
			granterPeers, hasGranters = []Entity{g}, true
		}
	}
	if !hasSigs {
		if s, ok := params.SubEntity("reentry_cap_signature"); ok {
			capSigs, hasSigs = []Entity{s}, true
		}
	}
	// The triple is ALL-OR-NONE (GUIDE-CONFORMANCE §7a.1): supplying all three
	// selects the PRESENTED arm, omitting all three selects the AMBIENT arm, and a
	// PARTIAL set is 400 invalid_params — a partial credential is malformed, not
	// ambient. An empty array is partial, not present: it carries no credential.
	nPresent := 0
	for _, present := range []bool{hasCap, hasGranters && len(granterPeers) > 0, hasSigs && len(capSigs) > 0} {
		if present {
			nPresent++
		}
	}
	if !hasValue {
		return errOutcome(400, "invalid_params", "dispatch-outbound requires value")
	}
	if nPresent != 0 && nPresent != 3 {
		return errOutcome(400, "invalid_params", "dispatch-outbound reentry authority is all-or-none")
	}
	hasCred := nPresent == 3
	inner := mustEntity("primitive/any", value)
	// `target` arrives as any of §1.4's three spellings and the validator sends the
	// SCHEMED ABSOLUTE form (`entity://{peer}/system/validate/echo`). Both the
	// handler-pattern dimension and the resource target want the PEER-RELATIVE path
	// — §1.4's PD-2 block says so for Dimension 1, and a resource target carrying a
	// scheme is not a path at all. It was latent while nothing consulted it.
	relTarget := peerRelativeOf(p.localPeer, target)
	resource := ResourceTarget("system/handler/" + relTarget)

	// §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer,
	// all four dimensions, on THIS handler's own grant — with a target-minted
	// credential relaxing Dimension 4 and nothing else. Consulting only the
	// presented credential here is the §6.8 confused-deputy bypass.
	//
	// The target peer is the connection's remote: on the §6.11 reentry seam the
	// uri is peer-relative and the destination is decided by the connection, so
	// extract_peer of that uri would answer the LOCAL peer and Dimension 4 would
	// pass vacuously.
	// ctx.pattern is the ABSOLUTE resolved pattern (`/{local}/system/validate/...`)
	// because §6.6's tree walk works on absolute store keys, while the grant path
	// is `{local}/system/capability/grants/{PEER-RELATIVE pattern}`. Concatenating
	// the absolute form yields a doubled peer segment, the lookup misses, and the
	// handler fails closed with "no handler grant" on a peer whose grant is right
	// there — a 403 that reads as an authority verdict and is a path bug.
	ownGrant, hasOwn := p.store.GetAt(grantPathFor(p.localPeer, ctx.pattern))
	if !hasOwn {
		// §6.8: a handler with no valid grant does not run. Fail closed rather
		// than falling back to the credential, which is the substitution the
		// section forbids by name.
		return errOutcome(403, "capability_denied", "no handler grant for "+ctx.pattern)
	}
	// §7a.2a: the presented-authority arm verifies against a BUNDLE MERGED FROM THE
	// PARENT ENVELOPE'S `included`. The credential, its granters and its link
	// signatures arrive NESTED IN PARAMS (GUIDE-CONFORMANCE §7a.2a ratified shape
	// (a), in-band), so they are not in `ctx.included` and a verifier handed
	// `ctx.included` alone cannot resolve a single link — every credential then
	// reads as invalid, the relaxation never happens, and the legitimate reentry is
	// refused 403.
	bundle := make(Included, len(ctx.included)+len(granterPeers)+len(capSigs)+1)
	for k, v := range ctx.included {
		bundle[k] = v
	}
	if hasCred {
		bundle.Add(capability)
		for _, e := range granterPeers {
			bundle.Add(e)
		}
		for _, e := range capSigs {
			bundle.Add(e)
		}
	}
	// §1.4: `target_peer = extract_peer(uri, local_peer_id)`. The validator sends
	// the absolute form, so the URI names the target and this is literal. Where the
	// uri is PEER-RELATIVE there is no peer in it to extract and the §6.11 seam's
	// destination is the connection's remote, so that is the fallback — without it
	// Dimension 4 would pass vacuously on the default `{include: [local]}` and the
	// exemption would never be exercised.
	targetPeer := extractPeer(p.localPeer, target)
	if targetPeer == p.localPeer && ctx.conn.helloPeerID != "" {
		targetPeer = ctx.conn.helloPeerID
	}
	if !checkOutboundSubDispatch(p.localPeer, targetPeer, relTarget, operation,
		p.store, ownGrant, resource, capability, hasCred, bundle) {
		// §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic
		// transport- or gateway-class code here would launder an authorization
		// verdict into a route fault, and the ambient and presented branches would
		// then disagree about what the same gate decided.
		return errOutcome(403, "capability_denied", "outbound sub-dispatch not authorized by the handler grant")
	}

	env, ok := p.outboundDispatch(ctx.conn, target, operation, inner, capability, granterPeers, capSigs, resource)
	if !ok {
		return errOutcome(503, "no_outbound_seam", "no live section 6.11 reentry connection")
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
