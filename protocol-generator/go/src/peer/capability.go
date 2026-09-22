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

// neverMatch is the unmatchable value (0.8.2.20). Unreachable as a canonical path
// by CONSTRUCTION: its first segment cannot be a peer_id, since isPeerID requires
// >= 46 Base58 characters and '-' is outside the Base58 alphabet.
const neverMatch = "/never-match"

// canonicalize resolves peer-relative paths to absolute /{local}/... form.
//
// TOTAL (0.8.2.20): the string return is "a canonical path OR neverMatch", never
// empty. The bool is kept for the §1.4 address gate and the tree-path consumers,
// which want the diagnostic and are exactly the callers 0.8.2.20 says SHOULD have
// it — under the spec they would reach the same refusal through
// validate_absolute_path, which neverMatch fails by construction.
func canonicalize(localPeer, path string) (string, bool) {
	switch {
	case startsWith("./", path) || startsWith("../", path):
		return neverMatch, false
	case startsWith("*/", path):
		return neverMatch, false
	case startsWith("/", path):
		return path, true
	default:
		return "/" + localPeer + "/" + path, true
	}
}

// canon is canonicalize for the matching helpers, which have no error channel.
//
// THIS USED TO RETURN THE INPUT UNCHANGED on the reserved forms, under a comment
// saying a non-match was the desired outcome. It is the desired outcome in an
// INCLUDE and the opposite of it in an EXCLUDE: `../nope` came back as the literal
// `../nope`, matched nothing, and the grant exclude carved out nothing, so the
// grant was silently wider than its author wrote (measured on the wire
// 2026-09-14). The sentinel is what lets the exclude-reading sites tell the two
// positions apart.
func canon(localPeer, path string) string {
	c, _ := canonicalize(localPeer, path)
	return c
}

// excludeIsUnmatchable reports whether any exclude pattern canonicalizes to the
// sentinel. AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21): the sentinel is
// fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
// fail-OPEN in an exclude (carves out nothing), so the reading is chosen where the
// POSITION is known and matchesPattern stays uniform over its operands.
//
// EVERY CALL SITE MUST GUARD IT ON PATH-SCOPE (0.8.2.24, N2/N3). This used to be
// asked of every dimension, transcribing §5.2's loop before that loop grew its
// type dispatch. neverMatch is a §5.4 PATH-canonicalization sentinel and has no
// meaning on an id-scope dimension, whose patterns are literal identifiers that
// §5.2's own id-scope arm forbids putting through the §5.4 transforms. Asking it
// outside the type dispatch ran an id pattern through those transforms purely to
// classify it and then DENIED THE WHOLE DIMENSION on a property unrelated to
// whether the exclude carves anything out: an `operations` exclude of `*/apply` —
// an ordinary namespaced operation name, a literal matching nothing under the
// id-scope grammar — canonicalized to the sentinel and denied every operation.
// Over-denial, and invisible on any well-formed grant.
func excludeIsUnmatchable(frame string, excl []string) bool {
	for _, p := range excl {
		if canon(frame, p) == neverMatch {
			return true
		}
	}
	return false
}

// matchesPattern reports whether (canonical, absolute) path matches pattern.
func matchesPattern(path, pattern string) bool {
	switch {
	// neverMatch never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
	// rule rather than a property of the string: the arm below returns true for a
	// bare "*", so safety must not rest on a value merely looking unmatchable.
	case path == neverMatch || pattern == neverMatch:
		return false
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

// scopeKind selects the §5.2 matcher for a grant dimension (0.8.1, F40). It has no
// zero-value default on purpose — every call site names its dimension, so a new one
// cannot silently inherit the wrong matcher, which is exactly the F40 defect.
type scopeKind int

const (
	kindID   scopeKind = iota // operations, peers — system/capability/id-scope
	kindPath                  // handlers, resources — system/capability/path-scope
)

// matchesIDPattern is the §5.2 id-scope match (0.8.1, F40): literal comparison with
// exactly two wildcard forms — bare "*" and a trailing "/*" segment-prefix. None of
// the §5.4 path transforms apply, so a pattern carrying path syntax ("/*/get") is
// matched as a literal string: a non-match, never a fault.
func matchesIDPattern(value, pattern string) bool {
	switch {
	case pattern == "*":
		return true
	case len(pattern) >= 2 && pattern[len(pattern)-2:] == "/*":
		return startsWith(pattern[:len(pattern)-1], value)
	default:
		return value == pattern
	}
}

func covered(localPeer, value string, pats []string, kind scopeKind) bool {
	if kind == kindID {
		for _, p := range pats {
			if matchesIDPattern(value, p) {
				return true
			}
		}
		return false
	}
	cv := canon(localPeer, value)
	for _, p := range pats {
		if matchesPattern(cv, canon(localPeer, p)) {
			return true
		}
	}
	return false
}

func matchesScope(localPeer, value string, s scope, kind scopeKind) bool {
	// SCOPED TO PATH-SCOPE (0.8.2.24). §5.2's exclude loop tests the sentinel
	// INSIDE `if dimension_type == "system/capability/path-scope"`, and §5.4's
	// rule is likewise "a capability carrying an unmatchable PATH-SCOPE pattern
	// is INVALID ... It does NOT reach `operations` or `peers` [MUST]". The two
	// id-scope dimensions reach `covered`'s literal arm below unguarded, which is
	// correct: under the id-scope grammar every non-`*` pattern is a literal and
	// a literal is never structurally unmatchable, so there is nothing here for
	// the sentinel to detect. (§5.4 says so outright and leaves the id-scope form
	// of the carves-out-nothing hazard deliberately open rather than minting a
	// second sentinel for it — so this is a scope boundary, not an omission.)
	if kind == kindPath && excludeIsUnmatchable(localPeer, s.excl) {
		return false // 0.8.2.21 — deny, do not carve out nothing
	}
	return covered(localPeer, value, s.incl, kind) && !covered(localPeer, value, s.excl, kind)
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
	// An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
	// target: the coverage test below is correct in isolation and is simply never
	// reached on a sentinel, because matchesPattern answers false.
	//
	// UNGUARDED ON PURPOSE, unlike matchesScope's (0.8.2.24): `s` here is always
	// the RESOURCES dimension, which §5.2 fixes as path-scope, so the type test
	// this call site would perform is a constant. Naming the dimension in the
	// signature is what makes that checkable — a frame argument on an id-scope
	// call site is the defect.
	if excludeIsUnmatchable(granterPeer, s.excl) {
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
		if !matchesScope(localPeer, operation, g.operations, kindID) {
			continue
		}
		if !matchesScope(localPeer, handlerPattern, g.handlers, kindPath) {
			continue
		}
		peers := scope{incl: []string{localPeer}}
		if g.peers != nil {
			peers = *g.peers
		}
		if !matchesScope(localPeer, targetPeer, peers, kindID) {
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

// ── §5.6 temporal ceiling (CAP-5 / CAP-6) ───────────────────────────────────

// addTTL converts a DURATION term to an absolute timestamp, reporting whether
// the term contributes a ceiling at all.
//
// §5.6 rule 3: a term whose conversion createdAt+ttl is not representable is
// treated as ABSENT, exactly as a null term is. It MUST NOT wrap and MUST NOT
// saturate to a representable maximum — saturation encodes differently from
// absence and manufactures expires_at == 2^64-1, a finite bound no reader can
// distinguish from a deliberate one.
//
// ttl == 0 is NOT a special case here and deliberately so: §5.6 rule 2 makes 0
// a DEFINED value yielding createdAt (expire immediately). The absent/null field
// is the only "no bound" spelling. Falling out of the arithmetic naturally is
// what keeps the two from ever collapsing into each other.
func addTTL(createdAt, ttl uint64) (uint64, bool) {
	sum := createdAt + ttl
	if sum < createdAt { // uint64 wrap => not representable => drop the term
		return 0, false
	}
	return sum, true
}

// minDefinedExpiry is §5.6's MIN_DEFINED construction: the minimum over the
// DEFINED terms only, with no expiry at all if no term is defined.
//
// Callers pass each term already shaped: absolute timestamps (parent.expires_at,
// caller_capability.expires_at) enter directly; durations (policy_entry.ttl_ms,
// request.ttl_ms) MUST be converted with addTTL first. Mixing a duration in
// unconverted yields a timestamp near the epoch and silently clamps every token
// to already-expired — the failure mode §5.6 calls out by name.
func minDefinedExpiry(terms ...struct {
	v  uint64
	ok bool
}) (uint64, bool) {
	out, have := uint64(0), false
	for _, t := range terms {
		if !t.ok {
			continue
		}
		if !have || t.v < out {
			out, have = t.v, true
		}
	}
	return out, have
}

func term(v uint64, ok bool) struct {
	v  uint64
	ok bool
} {
	return struct {
		v  uint64
		ok bool
	}{v, ok}
}

// durationTerm reads a DURATION field (ttl_ms) off a params/policy entity and
// converts it to an absolute timestamp relative to createdAt, per §5.6 rule 1.
// Reports ok=false when the field is absent (no term) or when the conversion
// overflows (rule 3: drop, never wrap or saturate).
//
// A present ttl_ms of 0 returns (createdAt, true) — DEFINED, expire immediately.
func durationTerm(createdAt uint64, e Entity, key string) (uint64, bool) {
	ttl, ok := e.Uint(key)
	if !ok {
		return 0, false
	}
	return addTTL(createdAt, ttl)
}

// callerCapExpiry is the absolute caller_capability.expires_at term (§5.6). A
// request presenting no capability contributes no term.
func callerCapExpiry(ctx *dispatchCtx) (uint64, bool) {
	if !ctx.hasCap {
		return 0, false
	}
	return ctx.callerCap.Uint("expires_at")
}

// parentExpiry is the absolute parent.expires_at term (§5.6), for the delegate
// path. `request` mints a ROOT token (parent nil) and contributes no term here —
// which is exactly why the caller-cap term above has to carry the ceiling.
func (p *Peer) parentExpiry(ctx *dispatchCtx, parent []byte) (uint64, bool) {
	if parent == nil {
		return 0, false
	}
	tok, ok := p.resolveToken(ctx, parent)
	if !ok {
		return 0, false
	}
	return tok.Uint("expires_at")
}

// resolveToken finds a token entity by content hash, preferring the frame's own
// included set and falling back to the local store.
func (p *Peer) resolveToken(ctx *dispatchCtx, hash []byte) (Entity, bool) {
	if ctx != nil {
		if e, ok := ctx.included.Get(hash); ok {
			return e, true
		}
	}
	if e, ok := p.store.GetAt("/" + p.localPeer + "/system/capability/tokens/" + hexOf(hash)); ok {
		return e, true
	}
	return Entity{}, false
}

// ── §6.2 CAP-6a: unrepresentable temporal fields on INGEST ──────────────────

// temporalFieldsRepresentable reports whether every CAP-6a temporal field on a
// RECEIVED token is either absent (legal) or representable as primitive/uint.
//
// This is the reader-side half of CAP-6 and it is where a peer fails OPEN. Our
// Uint() accessor returns (0,false) both when a field is ABSENT and when it is
// PRESENT but not a uint — a negative integer or a bignum — so the temporal
// checks below silently skipped a token carrying expires_at:-1 and honored it.
// §6.2 CAP-6a is explicit: such a token "is malformed. A verifier MUST refuse it
// and MUST NOT treat the unrepresentable field as absent." An absent (null)
// expires_at stays legal and is deliberately NOT rejected here.
//
// Refusal must be the §5.2 capability_denied disposition (a status-bearing
// response), never a decode-layer silent drop or a transport close.
func temporalFieldsRepresentable(tok Entity) bool {
	for _, key := range []string{"expires_at", "not_before", "created_at"} {
		v, present := tok.Field(key)
		if !present {
			continue // absent is legal
		}
		if v.Kind != cbor.KindUint {
			return false // present but undecodable as uint64 => malformed
		}
	}
	return true
}

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

// isMultisig reports whether cap carries a §3.6 K-of-N quorum granter (a
// {signers, threshold} map) rather than a single granter hash.
func isMultisig(cap Entity) bool {
	v, ok := cap.Field("granter")
	return ok && v.Kind == cbor.KindMap
}

// multisigRootOK verifies a §3.6 / §5.5 multi-signature quorum root: M3
// structure (root-only, N>=2, 2<=threshold<=N, distinct signers), §5.5 M6 (the
// local peer is one of the signers), §5.5 M4 (at least threshold DISTINCT
// signers each carry a valid signature over the root content hash).
func multisigRootOK(localPeer string, resolve resolveFn, root Entity, included Included) bool {
	gv, ok := root.Field("granter")
	if !ok || gv.Kind != cbor.KindMap {
		return false
	}
	sv, ok := MapField(gv, "signers")
	if !ok || sv.Kind != cbor.KindArray {
		return false
	}
	tv, ok := MapField(gv, "threshold")
	if !ok || tv.Kind != cbor.KindUint {
		return false
	}
	threshold := tv.Uint
	signers := make([][]byte, 0, len(sv.Array))
	for _, e := range sv.Array {
		if e.Kind != cbor.KindBytes {
			return false
		}
		signers = append(signers, e.Bytes)
	}
	n := uint64(len(signers))
	// M3: root-only, quorum shape, distinct signers.
	if _, ok := root.Bytes("parent"); ok {
		return false // multi-sig is root-only
	}
	if n < 2 || threshold < 2 || threshold > n {
		return false
	}
	for i := 0; i < len(signers); i++ {
		for j := i + 1; j < len(signers); j++ {
			if bytesEqual(signers[i], signers[j]) {
				return false // duplicate signer
			}
		}
	}
	// M6: the local peer MUST be a quorum member.
	localIn := false
	for _, sh := range signers {
		if s, ok := resolve(sh); ok {
			if pk, ok := s.Bytes("public_key"); ok && peerIDOfPublicKey(pk) == localPeer {
				localIn = true
				break
			}
		}
	}
	if !localIn {
		return false
	}
	// M4: count DISTINCT signers with a valid signature over the root content hash.
	// (signers are already distinct by M3, so each contributes at most once.)
	valid := uint64(0)
	for _, sh := range signers {
		s, ok := resolve(sh)
		if !ok {
			continue
		}
		if sgn, ok := findSignatureBy(root.Hash, sh, included); ok && VerifySignature(sgn, s) {
			valid++
		}
	}
	return valid >= threshold
}

// findSignatureBy returns the signature over target authored by signerHash.
// Multi-sig needs the per-signer signature, not just the first for the target.
func findSignatureBy(target, signerHash []byte, included Included) (Entity, bool) {
	for _, e := range included {
		if e.Type != "system/signature" {
			continue
		}
		if tg, ok := e.Bytes("target"); !ok || !bytesEqual(tg, target) {
			continue
		}
		if sg, ok := e.Bytes("signer"); ok && bytesEqual(sg, signerHash) {
			return e, true
		}
	}
	return Entity{}, false
}

// verifyCapabilityChain is the §5.5 authorization path (single-sig delegation
// chains + §3.6 multi-signature quorum roots). Returns VerdictAllow /
// VerdictAuthzDeny / VerdictUnresolvableGrantee.
//
// The root must be locally rooted: a single-signature root whose `granter`
// resolves to this peer, or a §3.6 quorum root this peer is a member of.
func verifyCapabilityChain(localPeer string, store *Store, capability Entity, included Included) Verdict {
	return verifyCapabilityChainRootedAt(localPeer, localPeer, store, capability, included)
}

// verifyCapabilityChainRootedAt is verifyCapabilityChain with the expected ROOT
// granter named separately from the verifying peer.
//
// §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is
// minted by the TARGET peer, so root-trust is relaxed away from the local peer —
// and every other clause (per-link signatures, grantee resolution, temporal
// validity, attenuation, caveats) is unchanged. It is parameterized rather than
// forked because a second copy of a chain walk is a second copy that drifts, and
// the clauses below are where the authority decision actually lives.
//
// ⛔ A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When
// rootPeer != localPeer the quorum arm is REFUSED outright rather than verified:
// *minted by the target* means the target SOLELY minted it, and a K-of-N root is
// a GROUP's authority — its co-signers authorized it too. Verifying the quorum
// here and accepting it would let any one signer's target confer the whole
// group's grant, which is E3/F66's over-acceptance. §5.5's M6 also requires the
// LOCAL peer in the signer set, so the quorum arm has no meaning in a foreign
// frame even on its own terms.
func verifyCapabilityChainRootedAt(localPeer, rootPeer string, store *Store, capability Entity, included Included) Verdict {
	resolve := capResolve(included, store)
	chain, ok := collectChain(capability, resolve)
	if !ok {
		return VerdictAuthzDeny
	}
	root := chain[len(chain)-1]
	if isMultisig(root) {
		if rootPeer != localPeer {
			return VerdictAuthzDeny
		}
		// §3.6 / §5.5 K-of-N quorum root (M3/M4/M6). No single granter.
		if !multisigRootOK(localPeer, resolve, root, included) {
			return VerdictAuthzDeny
		}
	} else {
		// root granter must resolve to rootPeer
		rootOK := false
		if gh, ok := root.Bytes("granter"); ok {
			if g, ok := resolve(gh); ok {
				if pk, ok := g.Bytes("public_key"); ok && peerIDOfPublicKey(pk) == rootPeer {
					rootOK = true
				}
			}
		}
		if !rootOK {
			return VerdictAuthzDeny
		}
	}

	now := nowMillis()
	n := len(chain)
	for i := 0; i < n; i++ {
		current := chain[i]
		// signature: signer == granter, verify against granter identity. A §3.6
		// multi-sig root has no single granter — it is authorized by the quorum
		// verified above (root-only, so it is chain[n-1]); grantee + temporal
		// checks below still apply.
		if gh, ok := current.Bytes("granter"); ok {
			sgn, sok := findSignature(current.Hash, included)
			granter, gok := resolve(gh)
			if !sok || !gok {
				return VerdictAuthzDeny
			}
			signer, sigok := sgn.Bytes("signer")
			if !sigok || !bytesEqual(signer, gh) || !VerifySignature(sgn, granter) {
				return VerdictAuthzDeny
			}
		} else if !isMultisig(current) {
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
		//
		// CAP-6a FIRST: a present-but-unrepresentable expires_at/not_before/
		// created_at is MALFORMED and must be refused outright. This has to run
		// BEFORE the two range checks below, because those use Uint(), which
		// cannot tell "absent" from "present but not a uint" — so on its own it
		// would skip the check and honor the token (fail-open).
		if !temporalFieldsRepresentable(current) {
			return VerdictAuthzDeny
		}
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

// ── §5.2 effective targets and §6.3 check_path_permission ───────────────────

// effectiveTargets derives §5.2's effective target list (0.8.2.20): the caller's
// own `resource.exclude` removes entries from the request BEFORE anything else
// looks at it.
//
// The survivors are returned in the caller's OWN SPELLING, not canonicalized —
// 0.8.2.21 is explicit that `effective_targets` yields raw survivors, and the
// distinction is load-bearing here because the value flows on to `store.GetAt`,
// which canonicalizes for itself.
//
// The second return says whether a `resource` was present at all. An ABSENT
// resource and a resource whose every target was excluded are different inputs
// to §3.3 — the first is "no resource", the second is an empty effective list —
// and for a resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT
// REQUESTS with different answers, not merely different inputs to one.
//
// THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11):
// "where an implementation projects resource.targets onto the effective set
// ahead of the handler, that projection MUST NOT be lossy about its own
// emptiness — narrow when narrowing leaves something, and retain the raw pair
// when narrowing would empty it." A function returning only a list cannot
// satisfy that: collapsing `[qA] exclude [qA]` to `[]` deletes the two-empties
// discriminator before any handler can read it, and the handler's refusal arm
// becomes dead code that only a WIRE drive can detect. Returning the flag
// beside the survivors keeps the discriminator by construction.
//
// "Every seam that narrows is exempted alike, inbound-wire and in-process
// sub-dispatch, or one request receives two different answers according to which
// door it arrived through." This peer has exactly ONE narrowing seam — this
// function, called by the handler — and §6.5's dispatch chain does not project:
// `runChain` passes `exec` through untouched and `checkPermission` reads
// `resource` for itself. So there is no second door to keep in step, and adding
// a projection at dispatch would create one.
func effectiveTargets(localPeer string, exec Entity) ([]string, bool) {
	r, ok := exec.Field("resource")
	if !ok || r.Kind != cbor.KindMap {
		return nil, false
	}
	targetsV, ok := MapField(r, "targets")
	if !ok {
		return nil, false
	}
	targets := textElems(targetsV)
	exclV, _ := MapField(r, "exclude")
	callerExcl := textElems(exclV)
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		ct := canon(localPeer, t)
		dropped := false
		for _, x := range callerExcl {
			// The caller-exclude arm is fail-OPEN on an unmatchable pattern
			// (§5.4's table rules it separately from the grant arm): canon
			// answers neverMatch and matchesPattern then answers false, so the
			// target simply survives. That asymmetry is 0.8.2.21's whole point
			// and it is inherited here rather than restated.
			if matchesPattern(ct, canon(localPeer, x)) {
				dropped = true
				break
			}
		}
		if !dropped {
			out = append(out, t)
		}
	}
	return out, true
}

// checkPathPermission is §6.3's handler-level path check.
//
// IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the enforcement wherever
// the subject is derived after dispatch, and the dispatch-level check can be
// made VACUOUS by caller-controlled input: a caller who excludes the one target
// its capability does not cover removes that target from `check_permission`'s
// view entirely, and a handler that then acts on it has authorized nothing.
//
// THREE DIMENSIONS, NOT FOUR. `peers` is not consulted here — the path is local
// by construction at this point (§1.4's inbound rule refuses a foreign namespace
// at §6.5 step 3, before any handler runs), and §6.3's signature names only
// handlers, operations and resources.
//
// THE FRAME IS `local_peer_id`, NOT THE GRANTER, AND THAT IS THE SPEC'S OWN
// SIGNATURE RATHER THAN A CHOICE. §6.3's block reads
// `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)`
// — there is no granter parameter to pass. The first cut of this function
// threaded the per-link granter frame in by analogy with §5.5a and was wrong:
// §5.5a governs chain ATTENUATION, where the subject is a pattern being
// compared against a parent's pattern; this call site compares a CONCRETE local
// path the handler is about to touch. The sibling `python` peer had it right
// and said so at the definition, which is what caught it.
//
// There is no caller-exclude set at this call site: the subject is a single
// concrete path, and the caller's exclusions have already been applied in
// deriving it. Every grant exclude covering the subject therefore denies —
// which `matchesScope` already implements, including 0.8.2.21's sentinel rule,
// so this function is three calls to it and nothing else.
//
// An empty `resources.include` is a legal grant shape (§5.2: handlers that touch
// no tree paths) and DENIES every path here, which is what that note says it
// should — `covered` over an empty include list is false.
func checkPathPermission(localPeer, operation, path string, token Entity, handlerPattern string) bool {
	// canonicalize is total and may answer NEVER_MATCH, which matches no grant
	// (§5.4) — so a malformed path falls through to DENY rather than being
	// matched against anything.
	cp := canon(localPeer, path)
	for _, g := range grantsOfToken(token) {
		if !matchesScope(localPeer, handlerPattern, g.handlers, kindPath) {
			continue
		}
		if !matchesScope(localPeer, operation, g.operations, kindID) {
			continue
		}
		if !matchesScope(localPeer, cp, g.resources, kindPath) {
			continue
		}
		return true
	}
	return false
}

// ── §1.4 PD-2: outbound sub-dispatch authorization ──────────────────────────

// checkOutboundSubDispatch is §1.4's PD-2 gate: `check_permission` run before a
// locally-originated sub-dispatch LEAVES the peer, with all four dimensions
// applied.
//
// ONE GATE AND ONE EXEMPTION, in §1.4's own words:
//
//   - The EXECUTING HANDLER'S GRANT decides all four dimensions (§6.8),
//     evaluated in the LOCAL frame. Dimension 1's pattern is the target uri's
//     PEER-RELATIVE path.
//   - A valid capability MINTED BY THE TARGET PEER naming this peer as `grantee`
//     relaxes Dimension 4 (`peers`) AND ONLY DIMENSION 4, to the peers that
//     capability covers. It is evaluated in the TARGET's frame.
//
// "The target answers WHERE; the handler's grant answers WHAT." A credential is
// NOT a grant: with no handler grant there is nothing to supply Dimensions 1-3,
// so the sub-dispatch is refused however good the credential is. That is the
// COMPOSE, and the BYPASS it is distinguished from is a peer that treats the
// credential as a standalone authorizer and steers past its own grant — §6.8's
// confused-deputy substitution. Both obvious vectors agree under either reading
// (sources agree -> allow, no source -> refuse), so the only input that separates
// them is a VALID credential presented to a handler whose own grant does NOT
// cover the request, which MUST refuse.
//
// A credential failing any verification clause relaxes NOTHING and the handler
// grant gates unrelaxed — it does not turn the verdict into an error.
//
// `targetPeer` is supplied by the caller rather than derived here: on the §6.11
// reentry seam the uri is PEER-RELATIVE and the destination is the connection's
// remote, so `extract_peer(uri, local)` would answer the LOCAL peer and
// Dimension 4 would pass vacuously on the default `{include: [local]}` — the
// exemption would then never be exercised and a bypass would read as a compose.
// The peer this dispatch is addressed to is what Dimension 4 is about.
//
// hasCred=false is the ambient arm: Dimension 4 is decided by the handler's
// grant alone.
func checkOutboundSubDispatch(
	localPeer, targetPeer, handlerPattern, operation string,
	store *Store,
	handlerGrant Entity,
	resource cbor.Value,
	cred Entity,
	hasCred bool,
	included Included,
) bool {
	// Computed FIRST and consulted LAST, so that no credential can stand in for
	// Dimensions 1-3.
	var relaxTo *scope
	if hasCred {
		if s, ok := targetMintedPeersRelaxation(localPeer, targetPeer, store, cred, included); ok {
			relaxTo = s
		}
	}

	for _, g := range grantsOfToken(handlerGrant) {
		if !matchesScope(localPeer, handlerPattern, g.handlers, kindPath) {
			continue
		}
		if !matchesScope(localPeer, operation, g.operations, kindID) {
			continue
		}
		if !checkResourceScope(localPeer, localPeer, resource, g.resources) {
			continue
		}
		// Dimension 4. §5.2's default for an absent `peers` scope is
		// {include: [local_peer_id]}, so a foreign target fails unless this grant
		// names it or a target-minted credential relaxes it.
		peers := scope{incl: []string{localPeer}}
		if g.peers != nil {
			peers = *g.peers
		}
		if matchesScope(localPeer, targetPeer, peers, kindID) {
			return true
		}
		if relaxTo != nil && matchesScope(localPeer, targetPeer, *relaxTo, kindID) {
			return true
		}
	}
	return false
}

// targetMintedPeersRelaxation verifies a presented reentry credential against
// §1.4's clauses and, where they all hold, answers the `peers` scope Dimension 4
// relaxes to.
//
// Every clause is required and failing any relaxes nothing:
//   - the chain ROOT `granter` resolves to the TARGET peer, and is NOT a
//     multi-signature root — a K-of-N root is a GROUP's authority and never
//     relaxes Dimension 4 (verifyCapabilityChainRootedAt refuses the quorum arm
//     in a foreign frame, which is where that rule lands);
//   - the LEAF `grantee` is the local peer;
//   - valid (per-link signatures, temporal, attenuation, caveats) and not
//     revoked.
func targetMintedPeersRelaxation(localPeer, targetPeer string, store *Store, cred Entity, included Included) (*scope, bool) {
	if targetPeer == localPeer {
		// Nothing to relax — the default already covers this peer. Treating a
		// self-targeted credential as a relaxation would make the exemption
		// reachable with no foreign mint at all.
		return nil, false
	}
	if verifyCapabilityChainRootedAt(localPeer, targetPeer, store, cred, included) != VerdictAllow {
		return nil, false
	}
	if isRevoked(localPeer, store, cred, included) {
		return nil, false
	}
	geh, ok := cred.Bytes("grantee")
	if !ok {
		return nil, false
	}
	resolve := capResolve(included, store)
	ge, ok := resolve(geh)
	if !ok {
		return nil, false
	}
	if pk, pkOK := ge.Bytes("public_key"); !pkOK || peerIDOfPublicKey(pk) != localPeer {
		return nil, false
	}
	// The credential's own `peers` scope is what Dimension 4 relaxes TO. Absent
	// means the granter — the target peer — which is the ordinary reentry shape:
	// "you may dispatch back to me."
	for _, g := range grantsOfToken(cred) {
		if g.peers != nil {
			return g.peers, true
		}
		s := scope{incl: []string{targetPeer}}
		return &s, true
	}
	return nil, false
}

// grantPathFor is the store key of a handler's OWN grant (§6.8:
// `system/capability/grants/{pattern}`), tolerant of the pattern arriving in
// either form.
//
// §6.6's tree walk answers an ABSOLUTE pattern (`/{local}/system/tree`) because
// store keys are absolute, while the grant path is built from the PEER-RELATIVE
// pattern. The two are one segment apart and concatenating the wrong one yields a
// doubled peer segment whose lookup misses — which fails closed as "no handler
// grant" and is indistinguishable, at the wire, from a genuine authority refusal.
func grantPathFor(localPeer, pattern string) string {
	prefix := "/" + localPeer + "/"
	if startsWith(prefix, pattern) {
		pattern = pattern[len(prefix):]
	}
	return "/" + localPeer + "/system/capability/grants/" + pattern
}

// peerRelativeOf strips the §1.4 scheme and leading peer segment from a URI,
// answering the PEER-RELATIVE path.
//
// §1.4 admits three spellings of one address — `system/tree`,
// `/{peer}/system/tree` and `entity://{peer}/system/tree` — and §1.4's PD-2 block
// requires Dimension 1's handler pattern to be the target uri's peer-relative
// path, because a grant names HANDLERS and a handler pattern never carries a peer
// segment. Matching a grant against the absolute or schemed form matches nothing,
// silently, which reads as an authority refusal.
//
// The first segment is dropped ONLY when it is a peer_id. A peer-relative
// `system/protocol/connect` must not lose `system` — the standing defect on
// `smalltalk` and `forth`, where an unconditional strip made every self-minted
// grant unusable.
func peerRelativeOf(localPeer, uri string) string {
	p := normalizeURI(uri)
	if !startsWith("/", p) {
		return p
	}
	segs := splitSlash(p) // leading "" from the absolute form
	if len(segs) >= 3 && segs[0] == "" && isPeerID(segs[1]) {
		return joinSlash(segs[2:])
	}
	if len(segs) >= 2 && segs[0] == "" {
		return joinSlash(segs[1:])
	}
	return p
}
