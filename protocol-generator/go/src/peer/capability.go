package peer

// capability.go — Capability system (L3): the §5 verification core. Pattern
// matching (§5.4), request verification (§5.2 verify-request / check-permission),
// delegation-chain verification (§5.5), attenuation (§5.6), the §4.10(b)
// chain-depth pre-check. Derived from the §5 pseudocode (spec-first).
//
// The verdict is one of the values below (§5.10 Layer-1 determinism). The
// dispatcher maps Deny -> 403, the unresolvable-grantee carve-out -> 401, and the
// §4.10(b) over-depth structural excess -> 400 chain_depth_exceeded.

import (
	"time"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// MaxChainDepth is the §4.10(b) finite max capability-chain depth (64, the
// informative default).
const MaxChainDepth = 64

// Verdict is the §5.2 request verification result.
type Verdict int

const (
	// VerdictAllow — the request is authorized.
	VerdictAllow Verdict = iota
	// VerdictAuthnFail — authentication failed (-> 401).
	VerdictAuthnFail
	// VerdictAuthzDeny — authorization denied (-> 403).
	VerdictAuthzDeny
	// VerdictChainTooDeep — structural over-depth (-> 400 chain_depth_exceeded),
	// distinct from an authz denial (§4.10(b) arch ruling).
	VerdictChainTooDeep
	// VerdictUnresolvableGrantee — a grantee that cannot be resolved (§5.5 401
	// carve-out, distinct from a 403 authz denial).
	VerdictUnresolvableGrantee
)

// resolveFn resolves a content_hash to an entity (included-first, then store).
type resolveFn func(h []byte) (Entity, bool)

// ── grant / scope parse ─────────────────────────────────────────────────────

type scope struct {
	incl []string
	excl []string
}

func parseScope(v cbor.Value) scope {
	if v.Kind != cbor.KindMap {
		return scope{}
	}
	inclV, _ := MapField(v, "include")
	exclV, _ := MapField(v, "exclude")
	return scope{incl: textElems(inclV), excl: textElems(exclV)}
}

type grantRec struct {
	handlers   scope
	resources  scope
	operations scope
	peers      *scope // nil when absent
}

func parseGrant(v cbor.Value) grantRec {
	sc := func(k string) scope {
		f, _ := MapField(v, k)
		return parseScope(f)
	}
	g := grantRec{handlers: sc("handlers"), resources: sc("resources"), operations: sc("operations")}
	if pv, ok := MapField(v, "peers"); ok {
		ps := parseScope(pv)
		g.peers = &ps
	}
	return g
}

func grantsOfToken(token Entity) []grantRec {
	gv, ok := token.Field("grants")
	if !ok {
		return nil
	}
	var out []grantRec
	for _, el := range asList(gv) {
		out = append(out, parseGrant(el))
	}
	return out
}

// ── §5.4 pattern matching ───────────────────────────────────────────────────

func startsWith(prefix, s string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// normalizeURI (§1.4): strip the entity:// scheme to an absolute path.
func normalizeURI(uri string) string {
	if startsWith("entity://", uri) {
		return "/" + uri[len("entity://"):]
	}
	return uri
}

// canonicalize resolves peer-relative paths to absolute /{local}/... form.
// Reserved directory-relative + ambiguous bare-wildcard forms are rejected with
// ok=false (the §1.4/§5.4 errors).
func canonicalize(localPeer, path string) (string, bool) {
	switch {
	case startsWith("./", path) || startsWith("../", path):
		return "", false
	case startsWith("*/", path):
		return "", false
	case startsWith("/", path):
		return path, true
	default:
		return "/" + localPeer + "/" + path, true
	}
}

// canon is canonicalize with a best-effort fallthrough (returns the input
// unchanged on the reserved forms) for the matching helpers, where a non-match
// is the desired outcome rather than an error.
func canon(localPeer, path string) string {
	c, ok := canonicalize(localPeer, path)
	if !ok {
		return path
	}
	return c
}

// matchesPattern reports whether (canonical, absolute) path matches pattern.
func matchesPattern(path, pattern string) bool {
	switch {
	case pattern == "*":
		return true
	case startsWith("/*/", pattern):
		remainder := pattern[3:]
		i := indexByteFrom(path, '/', 1)
		if i < 0 {
			return false
		}
		return matchesPattern(path[i+1:], remainder)
	case len(pattern) >= 2 && pattern[len(pattern)-2:] == "/*":
		return startsWith(pattern[:len(pattern)-1], path)
	default:
		return path == pattern
	}
}

func indexByteFrom(s string, b byte, start int) int {
	for i := start; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func covered(localPeer, value string, pats []string) bool {
	cv := canon(localPeer, value)
	for _, p := range pats {
		if matchesPattern(cv, canon(localPeer, p)) {
			return true
		}
	}
	return false
}

func matchesScope(localPeer, value string, s scope) bool {
	return covered(localPeer, value, s.incl) && !covered(localPeer, value, s.excl)
}

// ── §5.2 check-permission ───────────────────────────────────────────────────

func firstSegment(uri string) string {
	if startsWith("/", uri) {
		uri = uri[1:]
	}
	if i := indexByte(uri, '/'); i >= 0 {
		return uri[:i]
	}
	return uri
}

func isPeerID(seg string) bool {
	if len(seg) < 46 {
		return false
	}
	for i := 0; i < len(seg); i++ {
		if !inBase58Alphabet(seg[i]) {
			return false
		}
	}
	return true
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func inBase58Alphabet(c byte) bool {
	for i := 0; i < len(base58Alphabet); i++ {
		if base58Alphabet[i] == c {
			return true
		}
	}
	return false
}

func extractPeer(localPeer, uri string) string {
	first := firstSegment(normalizeURI(uri))
	if isPeerID(first) {
		return first
	}
	return localPeer
}

// checkResourceScope is the concrete-target subset check. The grant's own
// resource patterns canonicalize against the GRANTER's peer_id (§PR-8 / V2(a));
// the caller-supplied targets/exclude stay on the LOCAL frame (§5.4). For the
// self-issued dominant path granter == local, so this is byte-identical to the
// pre-fix behaviour.
func checkResourceScope(localPeer, granterPeer string, resource cbor.Value, s scope) bool {
	targetsV, _ := MapField(resource, "targets")
	targets := textElems(targetsV)
	exclV, _ := MapField(resource, "exclude")
	callerExcl := textElems(exclV)
	if len(targets) == 0 {
		return false
	}
	coveredLocal := func(pats []string, v string) bool {
		for _, p := range pats {
			if matchesPattern(v, canon(localPeer, p)) {
				return true
			}
		}
		return false
	}
	coveredGrant := func(pats []string, v string) bool {
		for _, p := range pats {
			if matchesPattern(v, canon(granterPeer, p)) {
				return true
			}
		}
		return false
	}
	for _, tgt := range targets {
		ct := canon(localPeer, tgt)
		switch {
		case coveredLocal(callerExcl, ct):
			// excluded by caller — admitted (caller narrowed it out)
		case !coveredGrant(s.incl, ct):
			return false
		case coveredGrant(s.excl, ct):
			return false
		}
	}
	return true
}

// resolveGranterPeerID (§PR-8): the frame for canonicalizing cap's grant
// resource patterns is the granter's peer_id. Single-sig granter -> derive
// peer_id from its public_key; unresolvable -> "".
func resolveGranterPeerID(resolve resolveFn, cap Entity) string {
	gh, ok := cap.Bytes("granter")
	if !ok {
		return ""
	}
	g, ok := resolve(gh)
	if !ok {
		return ""
	}
	pk, ok := g.Bytes("public_key")
	if !ok {
		return ""
	}
	return peerIDOfPublicKey(pk)
}

// checkPermission gates the wire request at the dispatch authorization boundary
// (§3.2.3). granterPeer is the §PR-8 canonicalization frame for the cap's grant
// resource patterns; every other dimension stays on the local frame.
func checkPermission(localPeer, granterPeer string, exec Entity, token Entity, handlerPattern string) bool {
	operation, _ := exec.Text("operation")
	uri, _ := exec.Text("uri")
	targetPeer := extractPeer(localPeer, uri)
	resource, hasResource := exec.Field("resource")

	for _, g := range grantsOfToken(token) {
		if !matchesScope(localPeer, operation, g.operations) {
			continue
		}
		if !matchesScope(localPeer, handlerPattern, g.handlers) {
			continue
		}
		peers := scope{incl: []string{localPeer}}
		if g.peers != nil {
			peers = *g.peers
		}
		if !matchesScope(localPeer, targetPeer, peers) {
			continue
		}
		if hasResource && resource.Kind == cbor.KindMap {
			if !checkResourceScope(localPeer, granterPeer, resource, g.resources) {
				continue
			}
		}
		return true
	}
	return false
}

// ── §5.5 / §5.6 chain verification + attenuation ────────────────────────────

func capResolve(included Included, store *Store) resolveFn {
	return func(h []byte) (Entity, bool) {
		if e, ok := included.Get(h); ok {
			return e, true
		}
		return store.GetByHash(h)
	}
}

// findSignature finds a system/signature in included whose target == target.
func findSignature(target []byte, included Included) (Entity, bool) {
	for _, e := range included {
		if e.Type != "system/signature" {
			continue
		}
		if tg, ok := e.Bytes("target"); ok && bytesEqual(tg, target) {
			return e, true
		}
	}
	return Entity{}, false
}

// scopeSubset (§5.5a): child include patterns must be covered by parent include;
// parent exclude patterns must be covered by child exclude. childPeer/parentPeer
// are the per-link granter frames (resource dimension only).
func scopeSubset(childPeer, parentPeer string, child, parent scope) bool {
	for _, cp := range child.incl {
		cc := canon(childPeer, cp)
		hit := false
		for _, pp := range parent.incl {
			if matchesPattern(cc, canon(parentPeer, pp)) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	for _, pe := range parent.excl {
		cpe := canon(parentPeer, pe)
		hit := false
		for _, ce := range child.excl {
			if matchesPattern(cpe, canon(childPeer, ce)) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func grantSubset(localPeer, childPeer, parentPeer string, child, parent grantRec) bool {
	if !scopeSubset(localPeer, localPeer, child.handlers, parent.handlers) {
		return false
	}
	if !scopeSubset(localPeer, localPeer, child.operations, parent.operations) {
		return false
	}
	if !scopeSubset(childPeer, parentPeer, child.resources, parent.resources) {
		return false
	}
	cp := scope{incl: []string{localPeer}}
	if child.peers != nil {
		cp = *child.peers
	}
	pp := scope{incl: []string{localPeer}}
	if parent.peers != nil {
		pp = *parent.peers
	}
	return scopeSubset(localPeer, localPeer, cp, pp)
}

func isAttenuated(localPeer, childPeer, parentPeer string, child, parent Entity) bool {
	cg := grantsOfToken(child)
	pg := grantsOfToken(parent)
	for _, c := range cg {
		hit := false
		for _, p := range pg {
			if grantSubset(localPeer, childPeer, parentPeer, c, p) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	pe, pok := parent.Uint("expires_at")
	ce, cok := child.Uint("expires_at")
	switch {
	case pok && !cok:
		return false // child infinite, parent finite
	case pok && cok:
		return ce <= pe
	default:
		return true
	}
}

func cborTrue(v cbor.Value) bool { return v.Kind == cbor.KindBool && v.Bool }

// checkDelegationCaveats (§5.7): parent's delegation_caveats constrain its direct
// child. Returns true if the child is admissible.
func checkDelegationCaveats(parent, child Entity, depth uint64) bool {
	caveats, ok := parent.Field("delegation_caveats")
	if !ok || caveats.Kind != cbor.KindMap {
		return true
	}
	if nd, ok := MapField(caveats, "no_delegation"); ok && cborTrue(nd) {
		return false
	}
	if m, ok := MapField(caveats, "max_delegation_depth"); ok && m.Kind == cbor.KindUint {
		if depth >= m.Uint {
			return false
		}
	}
	if mt, ok := MapField(caveats, "max_delegation_ttl"); ok && mt.Kind == cbor.KindUint {
		ex, exok := child.Uint("expires_at")
		cr, crok := child.Uint("created_at")
		switch {
		case exok && crok:
			if ex-cr > mt.Uint {
				return false
			}
		case exok:
			// created_at absent — cannot bound, admit
		default:
			return false // infinite child lifetime exceeds any limit
		}
	}
	return true
}

// linkGranterPeer (§5.5a) is the per-link canonicalization frame for cap's
// resource patterns = its granter's peer_id. A root with no granter hash falls
// to localPeer; an unresolvable granter returns "" + false (hard-fail / deny).
func linkGranterPeer(resolve resolveFn, localPeer string, cap Entity) (string, bool) {
	gh, ok := cap.Bytes("granter")
	if !ok {
		return localPeer, true // multi-sig root -> local frame
	}
	g, ok := resolve(gh)
	if !ok {
		return "", false
	}
	pk, ok := g.Bytes("public_key")
	if !ok {
		return "", false
	}
	return peerIDOfPublicKey(pk), true
}

// collectChain walks to the root via parent hashes, returning the chain
// root-last==false (ordered child..root) and ok.
func collectChain(cap Entity, resolve resolveFn) ([]Entity, bool) {
	var chain []Entity
	current := cap
	depth := 0
	for {
		if depth > MaxChainDepth {
			return nil, false
		}
		chain = append(chain, current)
		ph, ok := current.Bytes("parent")
		if !ok {
			return chain, true
		}
		parent, ok := resolve(ph)
		if !ok {
			return nil, false
		}
		current = parent
		depth++
	}
}

// chainExceedsDepth is the §4.10(b) structural-bound pre-check: true if the
// authority chain rooted at capability exceeds MaxChainDepth. Walks parent
// pointers WITHOUT verifying signatures — depth is a purely structural property,
// gated BEFORE the per-link authz walk so over-depth -> 400 chain_depth_exceeded
// (structural excess), distinct from a 403 capability_denied authz failure (arch
// ruling, v7.75 §4.10(b)). An UNREACHABLE parent is NOT a depth problem — it
// returns false here and is left for the chain walk to deny (403).
func chainExceedsDepth(store *Store, capability Entity, included Included) bool {
	resolve := capResolve(included, store)
	current := capability
	depth := 0
	for {
		if depth > MaxChainDepth {
			return true
		}
		ph, ok := current.Bytes("parent")
		if !ok {
			return false // root reached within bound
		}
		parent, ok := resolve(ph)
		if !ok {
			return false // unreachable — not a depth problem
		}
		current = parent
		depth++
	}
}

// verifyCapabilityChain is the §5.5 single-sig path. Returns VerdictAllow /
// VerdictAuthzDeny / VerdictUnresolvableGrantee.
func verifyCapabilityChain(localPeer string, store *Store, capability Entity, included Included) Verdict {
	resolve := capResolve(included, store)
	chain, ok := collectChain(capability, resolve)
	if !ok {
		return VerdictAuthzDeny
	}
	root := chain[len(chain)-1]
	// root granter must be the local peer
	rootOK := false
	if gh, ok := root.Bytes("granter"); ok {
		if g, ok := resolve(gh); ok {
			if pk, ok := g.Bytes("public_key"); ok && peerIDOfPublicKey(pk) == localPeer {
				rootOK = true
			}
		}
	}
	if !rootOK {
		return VerdictAuthzDeny
	}

	now := nowMillis()
	n := len(chain)
	for i := 0; i < n; i++ {
		current := chain[i]
		// signature: signer == granter, verify against granter identity
		gh, ok := current.Bytes("granter")
		if !ok {
			return VerdictAuthzDeny
		}
		sgn, sok := findSignature(current.Hash, included)
		granter, gok := resolve(gh)
		if !sok || !gok {
			return VerdictAuthzDeny
		}
		signer, sigok := sgn.Bytes("signer")
		if !sigok || !bytesEqual(signer, gh) || !VerifySignature(sgn, granter) {
			return VerdictAuthzDeny
		}
		// grantee resolution -> 401 carve-out
		geh, ok := current.Bytes("grantee")
		if !ok {
			return VerdictUnresolvableGrantee
		}
		if _, ok := resolve(geh); !ok {
			return VerdictUnresolvableGrantee
		}
		// temporal validity
		if nb, ok := current.Uint("not_before"); ok && now < nb {
			return VerdictAuthzDeny
		}
		if ex, ok := current.Uint("expires_at"); ok && ex < now {
			return VerdictAuthzDeny
		}
		// delegation link to parent
		if i < n-1 {
			parent := chain[i+1]
			childPeer, cok := linkGranterPeer(resolve, localPeer, current)
			parentPeer, pok := linkGranterPeer(resolve, localPeer, parent)
			if !cok || !pok {
				return VerdictAuthzDeny
			}
			pg, pgok := parent.Bytes("grantee")
			cg, cgok := current.Bytes("granter")
			if !pgok || !cgok || !bytesEqual(pg, cg) ||
				!isAttenuated(localPeer, childPeer, parentPeer, current, parent) ||
				!checkDelegationCaveats(parent, current, uint64(i)) {
				return VerdictAuthzDeny
			}
		}
	}
	return VerdictAllow
}

func isRevoked(localPeer string, store *Store, capability Entity, included Included) bool {
	resolve := capResolve(included, store)
	rootHash := capability.Hash
	if chain, ok := collectChain(capability, resolve); ok {
		rootHash = chain[len(chain)-1].Hash
	}
	check := func(h []byte) bool {
		_, ok := store.GetAt("/" + localPeer + "/system/capability/revocations/" + hexOf(h))
		return ok
	}
	return check(capability.Hash) || check(rootHash)
}

// ── §5.2 verify-request (3-way verdict + carve-outs) ────────────────────────

// verifyRequest returns the §5.2 verdict over the request envelope.
func verifyRequest(localPeer string, store *Store, env Envelope) Verdict {
	exec := env.Root
	included := env.Included
	sgn, ok := findSignature(exec.Hash, included)
	if !ok {
		return VerdictAuthnFail
	}
	authorH, ok := exec.Bytes("author")
	if !ok {
		return VerdictAuthnFail
	}
	signer, ok := sgn.Bytes("signer")
	if !ok || !bytesEqual(signer, authorH) {
		return VerdictAuthnFail
	}
	author, ok := included.Get(authorH)
	if !ok {
		return VerdictAuthnFail
	}
	if !VerifySignature(sgn, author) {
		return VerdictAuthnFail
	}
	capH, ok := exec.Bytes("capability")
	if !ok {
		return VerdictAuthzDeny
	}
	cap, ok := included.Get(capH)
	if !ok {
		return VerdictAuthzDeny
	}
	// §4.10(b): structural over-depth -> 400 chain_depth_exceeded, BEFORE the
	// per-link authz walk.
	if chainExceedsDepth(store, cap, included) {
		return VerdictChainTooDeep
	}
	switch verifyCapabilityChain(localPeer, store, cap, included) {
	case VerdictAuthzDeny:
		return VerdictAuthzDeny
	case VerdictUnresolvableGrantee:
		return VerdictUnresolvableGrantee
	case VerdictAllow:
		grantee, ok := cap.Bytes("grantee")
		if !ok || !bytesEqual(grantee, authorH) {
			return VerdictAuthzDeny
		}
		if isRevoked(localPeer, store, cap, included) {
			return VerdictAuthzDeny
		}
		return VerdictAllow
	default:
		return VerdictAuthzDeny
	}
}

// nowMillis returns the current Unix time in milliseconds.
func nowMillis() uint64 { return uint64(time.Now().UnixMilli()) }
