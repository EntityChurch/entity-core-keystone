// arc-probe — measure, on the wire, what the 0.8.2.12 → 0.8.2.23 arc actually
// costs the 46-peer cohort.
//
// WHY THIS EXISTS. The cohort is pinned at spec snapshot `v0.8.2.11`. Twelve
// revisions have landed since, almost all of them in the §5 scope algebra and its
// consumers, and this seat has spent two weeks reviewing them without measuring
// any of them. `AGENTS.md` is explicit about why that is the wrong order: a
// source read is a hypothesis, a grep keyed on vocabulary under-reports itself,
// and the last four cohort-scale questions answered on the wire came back
// surprising in BOTH directions (`put`-admission 0 of 46, H1 26 of 46, the §4.7
// corner 36 of 45). Implementing before probing writes N versions of a rule
// without knowing which peers already satisfy it.
//
// WHAT IT DRIVES. Four families, chosen because each is (a) a behaviour a
// revision in this arc introduced or changed, (b) reachable from a core peer's
// wire surface, and (c) separable from its neighbours by a control. What it does
// NOT reach is enumerated in `notDriven` below and printed in every report —
// a probe that publishes a count must publish the surface that count ranges over.
//
//	A — §3.3 / §5.4 effective-targets ladder            (0.8.2.20, 0.8.2.21)
//	B — §1.8 / §3.1 resolution integrity                (0.8.2.23)
//	C — §5.2 / §5.6 scope typing supplied by the call site (0.8.2.22)
//	E — §5.2 unmatchable grant exclude denies everything   (0.8.2.21)
//
// THE LAUNCH CONFIGURATION IS PART OF THE MEASUREMENT. Families A and E are
// authorization-shaped, and every `run-s4.sh` in the cohort boots its peer with
// the degenerate `default → *` seed policy (`--debug-open-grants`), under which
// nothing is outside the caller's grant and an authorization probe has nothing to
// measure. `run.sh` removes exactly that one flag and nothing else, so the peer
// falls back to the §6.9a discovery floor — a real, shipped grant:
//
//	handlers system/tree       resources system/type/*, system/handler/*  operations get
//	handlers system/capability resources (none)                           operations request
//
// CONTROLS. Every family has a positive control, and the two families whose
// finding is an ACCEPTANCE (B, E) also have an antecedent: an input that MUST be
// refused for a reason other than the one under test. Without it a refusal in the
// measurement arm is unfalsifiable — any unrelated fault produces one — which is
// the objection this seat filed against another repo's deny-only check and then
// had to answer for its own (F70).
//
// This is a MEASUREMENT, not a gate. It always exits 0 and nothing here gates a
// conformance number.
//
// Usage:
//
//	arc-probe -addr 127.0.0.1:7777 [-json-out report.json] [-peer name]
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// ---------- the impostor ----------
//
// A second, real Ed25519 identity. Family B's whole question is whether a peer
// will attribute THIS key's signature to the probe's identity because an
// attacker-supplied map key said so, so the impostor must be a genuine keypair
// whose entity is perfectly valid and whose only defect is the address it is
// filed under.

var impostorSeed = bytes.Repeat([]byte{0x44}, 32)

var (
	impPriv ed25519.PrivateKey
	impPub  []byte
	impEnt  []byte
	impHash []byte
)

// bogusKey is a hash-shaped value (§1.2 format code 0x00 + 32 bytes) that is not
// the content hash of any entity in existence. It is the wrong ADDRESS in family
// B's capability arm — nothing about the entity filed under it is forged.
var bogusKey = append([]byte{0x00}, bytes.Repeat([]byte{0xA7}, 32)...)

func initImpostor() {
	impPriv = ed25519.NewKeyFromSeed(impostorSeed)
	impPub = []byte(impPriv.Public().(ed25519.PublicKey))
	d := cmap(
		pair{txt("public_key"), bstr(impPub)},
		pair{txt("key_type"), txt("ed25519")},
	)
	impEnt = entity("system/peer", d)
	impHash = contentHash("system/peer", d)
}

// ---------- targets ----------
//
// Both are INSIDE the discovery floor's resources grant and both are bound at
// peer init, which is the point: family A is about the effective-targets ladder,
// so the grant must not be a variable. f68-probe deliberately used an
// out-of-grant target; using one here would make every row answerable by "403,
// not covered" and measure nothing about §3.3's rows.
const (
	qA      = "system/type/primitive/any"
	qB      = "system/type/primitive/string"
	pattern = "system/type/*"
	// §5.4: `canonicalize` maps a directory-relative path to NEVER_MATCH. It is
	// star-free, contains no character §1.4 forbids, and is a value a conformant
	// peer's own validator classifies as malformed input.
	unmatchable = "../nope"
)

// ---------- envelope construction, with mutations ----------

type exec struct {
	tag, uri, op string
	params       []byte
	targets      []string
	excludes     []string

	// Family B mutations. Exactly one of these is set per case.
	//
	// misKeyAuthor files the IMPOSTOR's `system/peer` entity under the PROBE's
	// identity hash and signs the request with the impostor's key, `signer`
	// naming the probe's hash. The entity is valid and self-consistent; it is
	// wrong only under the key. §5.2 step 2 resolves `author` by that key.
	misKeyAuthor bool
	// impostorIdentity is the ANTECEDENT: the same impostor, correctly keyed,
	// acting as itself. It MUST be refused — the capability's grantee is the
	// probe — which is what makes a 200 in the mis-keyed arm attributable to the
	// address rather than to the peer accepting any signer at all.
	impostorIdentity bool
	// misKeyCapability points `capability` at `bogusKey` and files the REAL
	// token under it. Nothing is forged: the lookup is simply addressed by a
	// value nothing verified.
	misKeyCapability bool
	// bogusCapAbsent is that arm's antecedent: the same bogus address with
	// nothing filed under it. MUST be refused.
	bogusCapAbsent bool

	// Family E: drive under a capability other than the handshake's.
	capHash []byte
	capMat  []pair
}

// do builds, signs and sends one EXECUTE. It is f68-probe's `authedExecuteRes`
// with the mutation points opened up — kept here rather than in wire.go because
// every line of it is this probe's question.
func (s *session) do(e exec) (map[string]interface{}, error) {
	authorHash := s.selfHash
	signPriv := s.priv
	authorEnt := s.selfEnt
	if e.impostorIdentity {
		authorHash, signPriv, authorEnt = impHash, impPriv, impEnt
	}

	capHash := s.capHash
	capMat := s.capMat
	if e.capHash != nil {
		capHash = e.capHash
	}
	if e.capMat != nil {
		capMat = e.capMat
	}
	realCap := capHash
	if e.misKeyCapability || e.bogusCapAbsent {
		capHash = bogusKey
	}

	fields := []pair{
		{txt("request_id"), txt(s.rid(e.tag))},
		{txt("uri"), txt(e.uri)},
		{txt("operation"), txt(e.op)},
		{txt("params"), e.params},
		{txt("author"), bstr(authorHash)},
		{txt("capability"), bstr(capHash)},
	}
	if len(e.targets) > 0 {
		tv := make([][]byte, 0, len(e.targets))
		for _, t := range e.targets {
			tv = append(tv, txt(t))
		}
		rf := []pair{{txt("targets"), arr(tv...)}}
		if len(e.excludes) > 0 {
			ev := make([][]byte, 0, len(e.excludes))
			for _, x := range e.excludes {
				ev = append(ev, txt(x))
			}
			rf = append(rf, pair{txt("exclude"), arr(ev...)})
		}
		fields = append(fields, pair{txt("resource"), cmap(rf...)})
	}
	rootData := cmap(fields...)
	rootHash := contentHash("system/protocol/execute", rootData)

	// The signature. In the mis-keyed arm the IMPOSTOR signs and `signer` names
	// the probe's hash — which is the same address the forged map entry sits at,
	// so a peer that resolves the signer by key verifies the impostor's
	// signature against the impostor's own key and finds it perfectly valid.
	sigPriv, sigSigner := signPriv, authorHash
	if e.misKeyAuthor {
		sigPriv, sigSigner = impPriv, s.selfHash
	}
	sigData := cmap(
		pair{txt("target"), bstr(rootHash)},
		pair{txt("signer"), bstr(sigSigner)},
		pair{txt("algorithm"), txt("ed25519")},
		pair{txt("signature"), bstr(ed25519.Sign(sigPriv, rootHash))},
	)

	inc := []pair{
		{bstr(contentHash("system/signature", sigData)), entity("system/signature", sigData)},
	}
	if e.misKeyAuthor {
		// The substitution. Any handshake-forwarded entry already sitting at our
		// identity hash is dropped first: `cmap` keeps the first of a duplicate
		// pair, so leaving it in would silently win and the case would send a
		// correctly-keyed envelope while claiming to be the forgery.
		dropped := 0
		for _, p := range capMat {
			if bytes.Equal(p.k, bstr(s.selfHash)) {
				dropped++
				continue
			}
			inc = append(inc, p)
		}
		s.lastCollision = dropped
		inc = append(inc, pair{bstr(s.selfHash), impEnt})
	} else {
		inc = append(inc, pair{bstr(authorHash), authorEnt})
		inc = append(inc, capMat...)
	}
	if e.misKeyCapability {
		for _, p := range capMat {
			if bytes.Equal(p.k, bstr(realCap)) {
				inc = append(inc, pair{bstr(bogusKey), append([]byte(nil), p.v...)})
				break
			}
		}
	}

	env := cmap(
		pair{txt("root"), entity("system/protocol/execute", rootData)},
		pair{txt("included"), cmap(inc...)},
	)
	m, _, err := s.send(env)
	return m, err
}

// ---------- grants ----------

// scopeOf emits a grant dimension. `typ` is written into the scope as a `type`
// key when non-empty: that is the field §5.2's `matches_scope` used to read off
// the received entity, and family C's whole question is whether a peer consults
// it.
func scopeOf(typ string, incl, excl []string) []byte {
	ps := []pair{}
	if typ != "" {
		ps = append(ps, pair{txt("type"), txt(typ)})
	}
	iv := make([][]byte, 0, len(incl))
	for _, x := range incl {
		iv = append(iv, txt(x))
	}
	ps = append(ps, pair{txt("include"), arr(iv...)})
	if excl != nil {
		ev := make([][]byte, 0, len(excl))
		for _, x := range excl {
			ev = append(ev, txt(x))
		}
		ps = append(ps, pair{txt("exclude"), arr(ev...)})
	}
	return cmap(ps...)
}

const (
	pathScope = "system/capability/path-scope"
	idScope   = "system/capability/id-scope"
)

// treeGetGrant is a subset of the discovery floor's first grant: handlers
// system/tree, operations get, resources under system/type. Everything about it
// is well-typed unless an argument says otherwise.
func treeGetGrant(hType, oType, rType string, rExcl []string) []byte {
	return cmap(
		pair{txt("handlers"), scopeOf(hType, []string{"system/tree"}, nil)},
		pair{txt("operations"), scopeOf(oType, []string{"get"}, nil)},
		pair{txt("resources"), scopeOf(rType, []string{pattern}, rExcl)},
	)
}

func requestParams(grants ...[]byte) []byte {
	return entity("system/capability/request",
		cmap(pair{txt("grants"), arr(grants...)}))
}

// mint drives `system/capability:request` and returns the minted token's hash
// plus the material needed to present it. A mint that does not return a token is
// not an error here — REFUSING a malformed grant is one of the conformant
// answers family C and family E are measuring — so the disposition is returned
// rather than raised.
func (s *session) mint(tag string, grants ...[]byte) (hash []byte, mat []pair, st int, code string) {
	env, err := s.do(exec{tag: tag, uri: "system/capability", op: "request",
		params: requestParams(grants...)})
	if err != nil {
		return nil, nil, 0, "error: " + err.Error()
	}
	st, code, _ = statusOf(env)
	tok, _ := resultField(env, "token").([]byte)
	if len(tok) == 0 {
		return nil, nil, st, code
	}
	if raw := s.lastRaw; len(raw) > 0 {
		if inc, err := rawIncluded(raw); err == nil {
			mat = inc
		}
	}
	return tok, mat, st, code
}

// ---------- what this probe does NOT reach ----------
//
// Published in every report. A count with no stated surface grows while its
// coverage does not, and nobody can tell.

var notDriven = []string{
	"§6.8 handler/caller authority INTERSECTION for derived paths (0.8.2.22) — the discovery " +
		"floor cannot produce a PARTIALLY covered listing (its resources grant is whole " +
		"subtrees), so there is nothing for filter_listing to filter. Driving it needs an " +
		"authored grant, which this probe deliberately does not use: the point of the floor is " +
		"that the result is about the peers as they ship.",
	"§6.3 handler_pattern is the OWNING handler, REQUIRED and fail-closed (0.8.2.23) — a core " +
		"peer has one path-resource handler (system/tree), so owner and runner coincide at every " +
		"reachable call site and the wire cannot separate the readings. Source-level question.",
	"§6.8 outbound sub-dispatch authorization, PD-2 (0.8.2.17/.18/.19) — needs a second peer and " +
		"an outbound dispatch; that is validate-peer's `-reference-peer` surface, not a probe's.",
	"§5.4 effective_targets returns RAW survivors, not canonical forms (0.8.2.21) — the value is " +
		"consumed internally and no response field echoes it back. Unobservable from the wire.",
	"§5.2a's author/capability rows are driven; the CHAIN granter/per-link signer and the " +
		"grantee rows are not — they need a delegated chain this probe does not build.",
}

// ---------- cases ----------

type caseSpec struct {
	id     string
	family string
	role   string // control | antecedent | measurement | differential
	expect string // what 0.8.2.23 requires, in one clause
	note   string
	run    func(s *session, st *runState) (map[string]interface{}, error)
}

// runState carries what one case learned to the next within a family. Only
// family E needs it (its measurement runs under a capability its control had to
// mint first).
type runState struct {
	mintedOK   []byte
	mintedOKM  []pair
	mintedBad  []byte
	mintedBadM []pair
	mintBadSt  int
	mintBadCod string
	mintOKSt   int
	mintOKCod  string
}

var cases = []caseSpec{
	// ---- family A: the effective-targets ladder ----
	{"A0_control_single_target", "A", "control",
		"200 — a single in-grant, bound target is the ordinary case",
		"POSITIVE CONTROL. If this is not 200 the peer's answers below are about our envelope.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "a0", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}})
		}},
	{"A1_effective_set_empty", "A", "measurement",
		"400 path_required — an empty effective list IS the absent case (§3.3, 0.8.2.20)",
		"targets:[qA] exclude:[qA]. Both in-grant, so authorization is not the variable: the " +
			"only question is whether the handler resolves through effective_targets.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "a1", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}, excludes: []string{qA}})
		}},
	{"A2_ambiguous", "A", "measurement",
		"400 ambiguous_resource — more than one effective entry (§3.3, 0.8.2.20)",
		"targets:[qA,qB], both in-grant and both bound. A peer indexing targets[0] answers 200 " +
			"with qA and cannot tell the caller it ignored qB.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "a2", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA, qB}})
		}},
	{"A3_selection", "A", "differential",
		"200 on qB — the subject is SELECTED from the effective set, never targets[0]",
		"targets:[qA,qB] exclude:[qA]. Effective set is {qB}, size 1, so the COUNT rule says " +
			"proceed — and a raw targets[0] selector proceeds on qA. This is F71's arm with the " +
			"grant removed as a variable: both targets are in-grant, so a 200 on qA is a " +
			"selection defect and nothing else.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "a3", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA, qB}, excludes: []string{qA}})
		}},
	{"A4_pattern_subject", "A", "measurement",
		"400 malformed_resource — a resource-requiring operation takes a CONCRETE path (0.8.2.20)",
		"targets:[system/type/*]. The single effective entry is a pattern. Expected to be the " +
			"least-implemented row of the four: it is the only one with no pre-.20 antecedent.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "a4", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{pattern}})
		}},
	{"A5_caller_exclude_unmatchable", "A", "measurement",
		"200 on qA — canonicalize is TOTAL; an unmatchable CALLER exclude carves out nothing (0.8.2.20/.21)",
		"targets:[qA] exclude:[../nope]. This is the fail-OPEN direction of the sentinel and it " +
			"is the correct one HERE (§5.4's table rules the caller arm separately from the grant " +
			"arm). A 400 means the peer raised on a path it cannot canonicalize — the error " +
			"return 0.8.2.20 removed because no call site could consume it.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "a5", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}, excludes: []string{unmatchable}})
		}},

	// ---- family B: resolution integrity ----
	{"B0_control_correct_keys", "B", "control",
		"200 — the same request the forgery arm mutates, built correctly",
		"POSITIVE CONTROL for family B specifically: it goes through this probe's own envelope " +
			"builder rather than f68-probe's, so a fault in `do` shows up here and not as a " +
			"cohort finding.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "b0", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}})
		}},
	{"B1a_antecedent_impostor_as_itself", "B", "antecedent",
		"refused — the impostor holds no capability of its own",
		"ANTECEDENT. The impostor signs as ITSELF, correctly keyed. The handshake capability's " +
			"grantee is the probe, so this MUST be refused (401 unresolvable_grantee or 403). " +
			"Without this row a 200 in B1 could mean the peer authorizes any signer, which is a " +
			"different and much larger defect — and a refusal in B1 could mean the impostor is " +
			"simply unknown. This is what makes B1 attributable to the ADDRESS.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "b1a", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}, impostorIdentity: true})
		}},
	{"B1_author_miskeyed", "B", "measurement",
		"refused — §1.8 resolution integrity: 400 hash_mismatch (bind) or 401 authentication_failed (discard)",
		"THE FORGERY. `author` names the probe's identity hash; the entity filed under that hash " +
			"is the IMPOSTOR's, valid and self-consistent, wrong only under the key; the request " +
			"is signed by the impostor's key with `signer` naming the same hash. A peer that " +
			"resolves by key verifies a real signature against a real public key and attributes " +
			"it to an identity whose private key nobody in this exchange holds. A 200 here is the " +
			"defect `entity-core-rust` drove and `entity-core-go` confirmed live.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "b1", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}, misKeyAuthor: true})
		}},
	{"B2a_antecedent_bogus_cap_absent", "B", "antecedent",
		"refused — nothing is filed at that address",
		"ANTECEDENT for the capability arm: the same bogus address with NOTHING under it MUST be " +
			"refused. If it is not, the peer is not reading `capability` at all and B2 measures " +
			"nothing.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "b2a", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}, bogusCapAbsent: true})
		}},
	{"B2_capability_miskeyed", "B", "measurement",
		"refused — 400 hash_mismatch (bind) or 403 capability_denied (discard → the lookup misses)",
		"The REAL, valid, peer-minted token, filed under an address that is not its hash, with " +
			"`capability` pointing there. Nothing is forged — this arm isolates the address from " +
			"the entity, which is exactly the half self-consistency validation cannot see.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "b2", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}, misKeyCapability: true})
		}},

	// ---- family C: the scope type is the dimension's, not the token's ----
	{"C0_control_welltyped_request", "C", "control",
		"200 — a well-typed subset of the caller's own grant mints",
		"POSITIVE CONTROL for the mint path. Every C and E row below needs `request` to work; if " +
			"this is not 200, none of them is a reading about scope types.",
		func(s *session, st *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "c0", uri: "system/capability", op: "request",
				params: requestParams(treeGetGrant(pathScope, idScope, pathScope, nil))})
		}},
	{"C1_operations_declared_path_scope", "C", "measurement",
		"403 capability_denied — a scope whose declared type contradicts its dimension is malformed (0.8.2.22)",
		"`operations` is an id-scope dimension by this specification; the grant declares it " +
			"path-scope. THIS IS THE ROW THAT SIZES J4 CLAUSE 2. A 200 means the peer never read " +
			"the field — which is the state clause 1 says is correct, and is why clause 2 obliges " +
			"nearly every implementation to ADD a read of a field whose absence makes it safe.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "c1", uri: "system/capability", op: "request",
				params: requestParams(treeGetGrant(pathScope, pathScope, pathScope, nil))})
		}},
	{"C2_resources_declared_id_scope", "C", "measurement",
		"403 capability_denied — same rule, the other direction (0.8.2.22)",
		"`resources` is path-scope; the grant declares it id-scope. Both directions are driven " +
			"because a peer could plausibly guard one dimension and not the other.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "c2", uri: "system/capability", op: "request",
				params: requestParams(treeGetGrant(pathScope, idScope, idScope, nil))})
		}},
	{"C3_scope_type_absent", "C", "differential",
		"200 — a scope with no declared type is the shape 46 of 46 peers emit",
		"DIFFERENTIAL. If C1/C2 are refused, this says whether the refusal is about the " +
			"CONTRADICTION or about the presence of a `type` key at all.",
		func(s *session, _ *runState) (map[string]interface{}, error) {
			return s.do(exec{tag: "c3", uri: "system/capability", op: "request",
				params: requestParams(treeGetGrant("", "", "", nil))})
		}},

	// ---- family E: an unmatchable grant exclude denies everything ----
	{"E0_control_minted_cap_works", "E", "control",
		"mint 200, then get 200 — the two-step machinery works",
		"POSITIVE CONTROL. Mints a narrowed capability with NO exclude and drives a get under " +
			"it. Everything E1 does, minus the one value under test.",
		func(s *session, st *runState) (map[string]interface{}, error) {
			h, m, code, msg := s.mint("e0mint", treeGetGrant(pathScope, idScope, pathScope, nil))
			st.mintedOK, st.mintedOKM, st.mintOKSt, st.mintOKCod = h, m, code, msg
			if len(h) == 0 {
				return nil, fmt.Errorf("mint did not return a token (%d %s)", code, msg)
			}
			return s.do(exec{tag: "e0", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}, capHash: h, capMat: m})
		}},
	{"E1_unmatchable_grant_exclude", "E", "measurement",
		"either a refused MINT (§5.4: such a capability is invalid) or, if minted, 403 on use (0.8.2.21)",
		"The grant's resources exclude is `../nope`, which canonicalizes to NEVER_MATCH. §5.2's " +
			"ruling: an unmatchable GRANT exclude MUST DENY — fail-closed, the opposite direction " +
			"from the caller arm in A5, and the asymmetry is the whole of 0.8.2.21. A 200 here is " +
			"a grant SILENTLY WIDER than its author wrote. Both dispositions are recorded because " +
			"refusing at mint is the net §5.4 says this arm is not the only gate for.",
		func(s *session, st *runState) (map[string]interface{}, error) {
			h, m, code, msg := s.mint("e1mint", treeGetGrant(pathScope, idScope, pathScope,
				[]string{unmatchable}))
			st.mintedBad, st.mintedBadM, st.mintBadSt, st.mintBadCod = h, m, code, msg
			if len(h) == 0 {
				return nil, fmt.Errorf("mint refused (%d %s) — a conformant answer, recorded", code, msg)
			}
			return s.do(exec{tag: "e1", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}, capHash: h, capMat: m})
		}},
	{"E2_matchable_grant_exclude", "E", "measurement",
		"403 — the grant's own exclude covers the very target requested",
		"THE CONTROL E1 DOES NOT HAVE, and a measurement in its own right. E1's exclude is " +
			"UNMATCHABLE, so a peer that never consults grant excludes AT ALL answers it exactly " +
			"as a peer that does consult them and finds the sentinel carves out nothing — the two " +
			"are indistinguishable from E1 alone. This case excludes the very target being " +
			"requested, which any exclude-reading peer must refuse. A 200 here is not 0.8.2.21's " +
			"defect; it is a strictly larger one: the exclude dimension is not read on the " +
			"dispatch path.",
		func(s *session, st *runState) (map[string]interface{}, error) {
			h, m, code, msg := s.mint("e2mint", treeGetGrant(pathScope, idScope, pathScope,
				[]string{qA}))
			if len(h) == 0 {
				return nil, fmt.Errorf("mint refused (%d %s) — recorded", code, msg)
			}
			return s.do(exec{tag: "e2", uri: "system/tree", op: "get", params: emptyParams(),
				targets: []string{qA}, capHash: h, capMat: m})
		}},
}

// ---------- reading a response ----------

type caseResult struct {
	ID       string `json:"id"`
	Family   string `json:"family"`
	Role     string `json:"role"`
	Expect   string `json:"expected_under_0_8_2_23"`
	Status   int    `json:"status"`
	Code     string `json:"code"`
	Message  string `json:"message,omitempty"`
	RType    string `json:"result_type,omitempty"`
	Subject  string `json:"subject_acted_on,omitempty"`
	Conforms string `json:"conforms"`
	Note     string `json:"note"`
	Err      string `json:"error,omitempty"`
}

// subjectOf names WHICH target a 200 came from. Family A's differential turns on
// it entirely: qA and qB are both `system/type` entities, so the result TYPE is
// identical and only a data field separates them. A status-only reading of A3
// cannot tell "selected from the effective set" from "indexed targets[0]", which
// is the question.
func subjectOf(env map[string]interface{}) string {
	res, _ := rootData(env)["result"].(map[string]interface{})
	if res == nil {
		return ""
	}
	d, _ := res["data"].(map[string]interface{})
	for _, k := range []string{"name", "path", "target", "pattern"} {
		if v, ok := d[k].(string); ok && v != "" {
			return k + "=" + v
		}
	}
	if t, ok := res["type"].(string); ok {
		return "type=" + t
	}
	return ""
}

// which maps a subject string onto the two family-A targets. Anything it cannot
// classify is reported verbatim rather than guessed at.
func which(subject string) string {
	switch {
	case subject == "":
		return ""
	case bytes.Contains([]byte(subject), []byte("primitive/any")):
		return "qA"
	case bytes.Contains([]byte(subject), []byte("primitive/string")):
		return "qB"
	}
	return "?"
}

// verdictFor grades one case against the revision that introduced its rule. It
// is deliberately narrow: "conforms" here means "answered what 0.8.2.23 requires
// of this input", NOT "is a conformant peer". Every peer in this cohort is
// `778 · 0F` at a check set that drives none of these rows.
func verdictFor(c caseSpec, r caseResult, st *runState) string {
	switch c.id {
	case "A0_control_single_target", "B0_control_correct_keys", "C0_control_welltyped_request",
		"C3_scope_type_absent", "E0_control_minted_cap_works":
		if r.Status == 200 {
			return "yes"
		}
		return "CONTROL FAILED"
	case "A1_effective_set_empty":
		if r.Status == 400 && r.Code == "path_required" {
			return "yes"
		}
		if r.Status == 400 {
			return "partial — 400 with code " + r.Code + ", not path_required"
		}
		return "no"
	case "A2_ambiguous":
		if r.Status == 400 && r.Code == "ambiguous_resource" {
			return "yes"
		}
		if r.Status == 400 {
			return "partial — 400 with code " + r.Code + ", not ambiguous_resource"
		}
		return "no"
	case "A3_selection":
		switch which(r.Subject) {
		case "qB":
			return "yes"
		case "qA":
			return "no — acted on the EXCLUDED target (targets[0])"
		}
		if r.Status == 400 {
			// csharp and typescript refuse this on a RAW arity check
			// (`targets.Count != 1 → 400`), which is the arm F71 warned the
			// count-only form would OPEN. It is a refusal, so nothing is
			// bypassed — and it is not the selection 0.8.2.20 requires, because
			// the effective set here has exactly one entry and the request is
			// legitimate.
			return "no — refused a single-entry effective set on a raw arity check (" + r.Code + ")"
		}
		return "unclassified"
	case "A4_pattern_subject":
		if r.Status == 400 && r.Code == "malformed_resource" {
			return "yes"
		}
		if r.Status == 400 {
			return "partial — 400 with code " + r.Code + ", not malformed_resource"
		}
		if r.Status == 404 {
			return "no — the pattern was resolved as a LITERAL path and missed"
		}
		return "no"
	case "A5_caller_exclude_unmatchable":
		if r.Status == 200 && which(r.Subject) == "qA" {
			return "yes — total canonicalization; the unmatchable caller exclude carved out nothing"
		}
		if r.Status == 200 {
			return "partial — 200 but the subject is " + r.Subject
		}
		// A 400 here is NOT a defect and grading it as one would have been this
		// probe's own version of a check whose PASS branch rewards the wrong
		// behaviour. 0.8.2.20's comment on `canonicalize` says in terms that the
		// diagnostic it removed "belongs at admission (§6.5), which has a caller
		// to answer" — so a peer refusing the malformed path at admission has
		// put it exactly where the revision points. What the rule forbids is a
		// raise from inside the MATCHER, and that is not observable from here.
		if r.Status == 400 {
			return "yes (admission) — refused the malformed path at §6.5 with a caller to " +
				"answer, code=" + r.Code + "; this probe cannot see whether the matcher itself raises"
		}
		return "no — " + fmt.Sprintf("%d %s", r.Status, r.Code)
	case "B1a_antecedent_impostor_as_itself", "B2a_antecedent_bogus_cap_absent":
		if r.Status != 200 && r.Status != 0 {
			return "yes"
		}
		return "ANTECEDENT FAILED"
	case "B1_author_miskeyed", "B2_capability_miskeyed":
		// The MECHANISM is readable off the disposition and it is worth reading,
		// because §1.8 admits two and 0.8.2.23 assigns them different rows. A
		// decode-boundary refusal is mechanism (a), bind-the-key: the envelope
		// never reached §5.2. A §5.2a row is mechanism (b), discard-the-key: the
		// lookup simply missed. Collapsing them into "refused" throws away the
		// only evidence this probe can offer about which half of the ruling a
		// peer implements — and the CODE is a second finding, because 0.8.2.23
		// pins `hash_mismatch` at the decode boundary and the cohort does not
		// necessarily spell it that way.
		switch {
		case r.Status == 200:
			return "no — RESOLVED THROUGH AN UNVERIFIED ADDRESS"
		case r.Status == 0:
			return "unclassified — no response"
		case r.Status == 400 && r.Code == "hash_mismatch":
			return "yes — bind-key (a), at the decode boundary, with the pinned code"
		case r.Status == 400:
			return "yes — bind-key (a), at the decode boundary, code=" + r.Code +
				" (0.8.2.23 pins hash_mismatch there)"
		case r.Status == 401 && c.id == "B1_author_miskeyed":
			return "yes — discard-key (b), §5.2a author row, code=" + r.Code
		case r.Status == 403 && c.id == "B2_capability_miskeyed":
			return "yes — discard-key (b), §5.2a capability row, code=" + r.Code
		}
		return "yes — refused " + fmt.Sprintf("%d %s", r.Status, r.Code) +
			", which is not the row §5.2a assigns this lookup"
	case "C1_operations_declared_path_scope", "C2_resources_declared_id_scope":
		if r.Status == 403 {
			return "yes"
		}
		if r.Status == 200 {
			return "no — the declared type was not read"
		}
		return "partial — refused " + fmt.Sprintf("%d %s", r.Status, r.Code) + ", not 403"
	case "E2_matchable_grant_exclude":
		switch {
		case r.Status == 403:
			return "yes — the grant exclude denied its own target"
		case r.Status == 200:
			return "no — GRANT EXCLUDES ARE NOT READ ON THE DISPATCH PATH: the grant " +
				"excludes exactly the target it was asked for and the request succeeded"
		case r.Status == 0:
			return "unclassified — no response"
		}
		return "partial — refused " + fmt.Sprintf("%d %s", r.Status, r.Code) + ", not the 403 §5.2 pins"
	case "E1_unmatchable_grant_exclude":
		if st.mintBadSt != 0 && st.mintBadSt != 200 {
			return "yes — refused at MINT (" + fmt.Sprintf("%d %s", st.mintBadSt, st.mintBadCod) + ")"
		}
		if r.Status == 403 {
			return "yes — minted, then denied on use"
		}
		if r.Status == 200 {
			return "no — minted AND honoured; the exclude carved out nothing"
		}
		if r.Status != 0 {
			// A refusal that is not 403 still means the grant did not silently
			// widen, which is the safety property. It is not the disposition
			// §5.2 pins, and saying "yes" would hide a real code divergence.
			return "partial — minted, then refused on use with " +
				fmt.Sprintf("%d %s", r.Status, r.Code) + ", not the 403 DENY §5.2 pins"
		}
		return "unclassified"
	}
	return "unclassified"
}

// diagnostics is printed ONLY when the positive control fails, which means the
// fault is ours. These are the values that say which §5.2 gate the probe tripped
// — without them "401 unresolvable_grantee" is a guess.
type diagnostics struct {
	AuthorHash  string   `json:"author_hash"`
	CapGrantee  string   `json:"capability_grantee"`
	GranteeSame bool     `json:"grantee_matches_author"`
	CapMatSize  int      `json:"forwarded_included_entries"`
	CapMatBad   int      `json:"forwarded_entries_failing_selfcheck"`
	CapMatNote  string   `json:"probe_selfcheck,omitempty"`
	Included    []string `json:"authenticate_included"`
}

type report struct {
	Peer      string       `json:"peer"`
	Addr      string       `json:"addr"`
	SpecArc   string       `json:"spec_arc"`
	Grant     string       `json:"caller_grant_shape"`
	Trusted   bool         `json:"trusted"`
	Control   string       `json:"control"`
	Cases     []caseResult `json:"cases"`
	Families  []string     `json:"family_verdicts"`
	Summary   string       `json:"summary"`
	NotDriven []string     `json:"not_driven"`
	Diag      *diagnostics `json:"diagnostics,omitempty"`
	Dedup     int          `json:"encoder_duplicate_keys_dropped"`
	Collision int          `json:"handshake_entries_displaced_by_the_forgery"`
}

func main() {
	addr, out, peer := "127.0.0.1:7777", "", ""
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "-addr", "--addr":
			addr = next()
		case "-out", "--out", "-json-out", "--json-out":
			out = next()
		case "-peer", "--peer":
			peer = next()
		default:
			if len(args[i]) > 0 && args[i][0] == '-' && i+1 < len(args) &&
				len(args[i+1]) > 0 && args[i+1][0] != '-' {
				i++
			}
		}
	}
	if peer == "" && out != "" {
		base := out
		if idx := bytes.LastIndexByte([]byte(base), '/'); idx >= 0 {
			base = base[idx+1:]
		}
		if n := len(base); n > 5 && base[n-5:] == ".json" {
			base = base[:n-5]
		}
		peer = base
	}
	initImpostor()

	to := 10 * time.Second
	r := report{Peer: peer, Addr: addr, Cases: []caseResult{}, NotDriven: notDriven,
		SpecArc: "0.8.2.12 → 0.8.2.23, measured against the cohort's v0.8.2.11 pin",
		Grant: "§6.9a discovery floor — the peer MUST NOT be launched with --debug-open-grants; " +
			"tools/arc-probe/run.sh removes exactly that flag from the peer's own harness"}

	state := &runState{}
	collision := 0
	// A fresh session per case. A peer that answers a refusal by closing the
	// connection would otherwise cascade one defect into every later row — the
	// shape `lean` turned into 81 FAILs.
	for _, c := range cases {
		cr := caseResult{ID: c.id, Family: c.family, Role: c.role, Expect: c.expect, Note: c.note}
		s, err := dialSession(addr, to)
		if err != nil {
			cr.Err = "session: " + err.Error()
			cr.Conforms = "unmeasured"
			r.Cases = append(r.Cases, cr)
			continue
		}
		env, err := c.run(s, state)
		if s.lastCollision > collision {
			collision = s.lastCollision
		}
		s.close()
		if err != nil {
			cr.Err = err.Error()
		}
		if env != nil {
			cr.Status, cr.Code, cr.RType = statusOf(env)
			cr.Message = messageOf(env)
			cr.Subject = subjectOf(env)
		}
		cr.Conforms = verdictFor(c, cr, state)
		r.Cases = append(r.Cases, cr)
	}
	r.Collision = collision
	r.Dedup = dedupDropped

	// VOID a family whose own control failed, and do it HERE rather than in
	// verdictFor, because a row cannot see its siblings.
	//
	// This is the antecedent rule catching the instrument: `asm-arm64` refuses
	// EVERY `system/capability:request`, so its 403 on the mistyped-scope rows
	// looks like the only peer in the cohort enforcing 0.8.2.22 clause 2 — and it
	// is a peer that refuses the whole operation. The untyped control (C3) is
	// what says so: it is refused identically. Counting that 403 as conformance
	// would have published a 1-of-46 where the truth is 0, in the direction
	// nobody re-checks.
	voidFamily := func(fam, why string) {
		for i := range r.Cases {
			if r.Cases[i].Family == fam && r.Cases[i].Role != "control" {
				r.Cases[i].Conforms = "VOID — " + why
			}
		}
	}
	for _, cr := range r.Cases {
		if cr.ID == "C0_control_welltyped_request" && cr.Status != 200 {
			voidFamily("C", fmt.Sprintf("this peer refuses a well-typed `request` (%d %s), so a "+
				"refusal of a MISTYPED one says nothing about the declared type", cr.Status, cr.Code))
		}
		if cr.ID == "E0_control_minted_cap_works" && cr.Status != 200 {
			voidFamily("E", fmt.Sprintf("the mint-and-use control failed (%d %s), so nothing here "+
				"is a reading about an unmatchable grant exclude", cr.Status, cr.Code))
		}
	}

	get := func(id string) caseResult {
		for _, cr := range r.Cases {
			if cr.ID == id {
				return cr
			}
		}
		return caseResult{}
	}
	a0, b0 := get("A0_control_single_target"), get("B0_control_correct_keys")
	r.Trusted = a0.Status == 200 && b0.Status == 200
	r.Control = fmt.Sprintf("A0 in-grant get -> %d %s | B0 same via this probe's builder -> %d %s",
		a0.Status, a0.Code, b0.Status, b0.Code)
	if !r.Trusted {
		r.Control += " | UNTRUSTED: the probe could not complete an ORDINARY in-grant request on " +
			"this peer, so every row is a probe-side fault and NOT a reading about the peer"
		if s, err := dialSession(addr, to); err == nil {
			r.Diag = &diagnostics{
				AuthorHash:  hex.EncodeToString(s.selfHash),
				CapGrantee:  s.diagGrantee,
				GranteeSame: s.diagGrantee == hex.EncodeToString(s.selfHash),
				CapMatSize:  len(s.capMat), CapMatBad: s.capMatBad,
				CapMatNote: s.capMatNote, Included: s.diagIncluded,
			}
			s.close()
		}
	}

	// Family verdicts. Each states the surface it ranges over, in the row, so a
	// count can never be read without it.
	aRows := []string{"A1_effective_set_empty", "A2_ambiguous", "A3_selection",
		"A4_pattern_subject", "A5_caller_exclude_unmatchable"}
	aYes := 0
	for _, id := range aRows {
		if get(id).Conforms == "yes" {
			aYes++
		}
	}
	b1a, b1 := get("B1a_antecedent_impostor_as_itself"), get("B1_author_miskeyed")
	b2a, b2 := get("B2a_antecedent_bogus_cap_absent"), get("B2_capability_miskeyed")
	c1, c2, c3 := get("C1_operations_declared_path_scope"),
		get("C2_resources_declared_id_scope"), get("C3_scope_type_absent")
	e1 := get("E1_unmatchable_grant_exclude")

	famA := fmt.Sprintf("A (§3.3/§5.4 effective-targets ladder, 0.8.2.20/.21): %d of 5 rows conform "+
		"— empty=%s · ambiguous=%s · selection=%s · pattern=%s · caller-exclude=%s",
		aYes, get("A1_effective_set_empty").Conforms, get("A2_ambiguous").Conforms,
		get("A3_selection").Conforms, get("A4_pattern_subject").Conforms,
		get("A5_caller_exclude_unmatchable").Conforms)

	famB := "B (§1.8 resolution integrity, 0.8.2.23): "
	switch {
	case !r.Trusted:
		famB += "VOID — positive control failed"
	case b1a.Conforms != "yes" || b2a.Conforms != "yes":
		famB += "VOID — an antecedent control failed, so a refusal below is unfalsifiable. " +
			"impostor-as-itself=" + b1a.Conforms + " · bogus-address-absent=" + b2a.Conforms
	default:
		famB += "author arm " + b1.Conforms + " · capability arm " + b2.Conforms
		if b1.Status == 200 || b2.Status == 200 {
			famB += " | ⛔ THE FORGERY REPRODUCES ON THIS PEER"
		}
		// A peer that FAILS the author arm cannot be credited with a mechanism on
		// the capability arm. The capability arm points at an address with nothing
		// filed under it, so the lookup MISSES on a key-trusting peer exactly as it
		// does on a key-discarding one — the refusal is an absence, not a check.
		// The author arm is the discriminator because there the entity IS present,
		// at the wrong address. Reading B2's 403 as "discard-key (b)" on one of
		// these peers would publish a mechanism claim the measurement cannot make.
		if b1.Status == 200 && b2.Status != 200 {
			famB += " | ⚠ the capability arm's refusal on this peer is a MISS, not a mechanism: " +
				"the author arm shows it resolves through the wire key, and B2's address simply " +
				"has nothing under it"
		}
	}

	famC := "C (§5.2/§5.6 scope typing, 0.8.2.22 clause 2): operations-mistyped=" + c1.Conforms +
		" · resources-mistyped=" + c2.Conforms + " · untyped-control=" + c3.Conforms
	e2 := get("E2_matchable_grant_exclude")
	famE := "E (§5.2 grant exclude, 0.8.2.21): unmatchable=" + e1.Conforms +
		" · matchable-control=" + e2.Conforms
	// E1 is only READABLE as a 0.8.2.21 result when the peer reads grant excludes at
	// all. Where E2 says it does not, E1's disposition carries no information about
	// the sentinel — the same answer follows from never looking.
	if e2.Status == 200 {
		famE += " | ⛔ E1 IS UNREADABLE ON THIS PEER: the exclude dimension is not consulted " +
			"at dispatch, so its answer to the sentinel is not a reading about the sentinel"
	}
	if get("E0_control_minted_cap_works").Conforms != "yes" {
		famE = "E (§5.2 grant exclude, 0.8.2.21): VOID — the mint control failed (" +
			fmt.Sprintf("mint %d %s", state.mintOKSt, state.mintOKCod) + ")"
	}
	r.Families = []string{famA, famB, famC, famE}

	owed, void := 0, 0
	for _, cr := range r.Cases {
		if cr.Role != "measurement" && cr.Role != "differential" {
			continue
		}
		switch {
		case hasPrefix(cr.Conforms, "yes"):
		case hasPrefix(cr.Conforms, "VOID"):
			// Unmeasured is its own state. Folding it into "owed" would make a
			// peer whose control failed look like a peer with a defect.
			void++
		default:
			owed++
		}
	}
	if r.Trusted {
		r.Summary = fmt.Sprintf("%d of %d measured rows do not yet answer what 0.8.2.23 requires; "+
			"%d unmeasured (family control failed)", owed, countRoles(), void)
	} else {
		r.Summary = "UNTRUSTED — nothing below is a reading about this peer"
	}

	bts, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(bts))
	if out != "" {
		_ = os.WriteFile(out, append(bts, '\n'), 0o644)
	}
	// Always 0. This measures; it does not gate.
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func countRoles() int {
	n := 0
	for _, c := range cases {
		if c.role == "measurement" || c.role == "differential" {
			n++
		}
	}
	return n
}

var _ = sort.Strings
