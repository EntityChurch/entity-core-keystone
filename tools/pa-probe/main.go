// pa-probe — the §4.11 PRE-ADMISSION REFUSAL wire census · Kind A (probe)
//
// Kind and obligations: docs/VERIFICATION-ARCHITECTURE.md. A probe measures; it does not
// judge, it does not gate, it never enters a published conformance number, and it always
// exits 0.
//
// ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────
//
// 0.8.2.25 landed §4.11: "A peer that refuses a frame pre-admission MUST put a coded
// EXECUTE_RESPONSE on the wire [MUST] — correlated by request_id where the id is
// available, and otherwise as a best-effort coded frame carrying no correlation", and
// "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]".
//
// §4.9(c)'s deliver-or-signal rule is scoped to "every request the peer ADMITS" and
// therefore reaches NONE of these inputs, which is precisely why §4.11 was written. The
// pinned check set (778 @ 7aa6f3de…) has no vector on this surface either — verified, not
// assumed, by driving the five causes against the reference peer.
//
// SO THE RULE HAS NO GATE, AND THE TWO VANGUARDS EACH VERIFIED IT WITH A LANGUAGE-NATIVE
// TEST. That works for go, python, rust, typescript. It does not scale to the substrates
// left in this sweep — three assembly ports, hand-authored WAT, Forth, COBOL, Oz, Pd,
// Smalltalk and two wasm transport seams — where authoring a socket-level unit test per
// peer costs more than the fix it verifies and, on several, is not available at all.
// A peer whose §4.11 arms are checked by READING is a peer where AGENTS.md's standing rule
// applies verbatim: a guard that was never executed is not a guard.
//
// ── WHAT IT DRIVES: SEVEN ARMS AND TWO CONTROLS ──────────────────────────────────────
//
// The seven arms are the wire-observable causes. Four of them (D1, D2, D3, D7) are
// FRAMING-layer events that no other instrument in this repo reaches: arc-probe's families
// all speak well-formed frames, and a peer can be 0-of-15 there while closing on an
// oversize prefix with no frame at all. That gap is the reason this is a separate probe
// rather than an eighth arc-probe family.
//
// ── THE CONTROLS, AND WHY BOTH ARE LOAD-BEARING ──────────────────────────────────────
//
//   P0 (positive, per peer)  A well-formed EXECUTE must be ANSWERED on this connection.
//                            Without it, "the peer emitted nothing" is equally explained
//                            by a hung or dead peer, and every row below would be a
//                            reading about our own dial. trusted:false suppresses the
//                            whole report, exactly as the other probes in this tree do.
//
//   D3 (negative)            A clean close at a FRAME BOUNDARY must emit NOTHING. This is
//                            the control the truncation arm cannot do without, and it is
//                            the one a naive fix breaks: the cheapest way to pass D2 is to
//                            answer every read error, which turns an ordinary hangup into
//                            a refusal of nothing. D2 and D3 differ in exactly one input
//                            byte — whether a length prefix was begun — so a peer that
//                            passes D2 and fails D3 has not implemented the distinction,
//                            it has deleted it.
//
// ── GRADING ─────────────────────────────────────────────────────────────────────────
//
// Each arm records what the wire showed and grades three ways, because the two
// non-conformant behaviours §4.11 names are SEPARATE failures and collapsing them loses
// the diagnosis a reader needs:
//
//   yes                  the coded frame arrived with the code its cause is assigned
//   no — WRONG CODE      a frame arrived; the code belongs to a different cause
//   no — DROPPED         nothing arrived and the connection stayed open (the weaker of the
//                        two "precisely because nothing surfaces it")
//   no — CLOSED          the connection went away with no coded frame (indistinguishable
//                        from a network fault, §4.6, and on a multiplexed connection it
//                        destroys unrelated ADMITTED requests)
//
// Authored from the spec text in protocol-generator/shared/spec-data/v0.8.2.25/, never
// from the oracle's source or from a peer's. The wire plumbing (wire.go) is copied from
// tools/arc-probe, which copied it from tools/put-probe: transport is not semantics, and
// that code has been driven against all 46 peers, so borrowing it removes a class of
// instrument bugs rather than adding one.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// ── report shape ─────────────────────────────────────────────────────────────────────

type caseResult struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	Expect   string `json:"expect"`
	Status   int    `json:"status"`
	Code     string `json:"code"`
	Observed string `json:"observed"`
	Conforms string `json:"conforms"`
	Note     string `json:"note"`
	Err      string `json:"err,omitempty"`
}

type report struct {
	Peer      string       `json:"peer"`
	Addr      string       `json:"addr"`
	Spec      string       `json:"spec"`
	Trusted   bool         `json:"trusted"`
	Control   string       `json:"control"`
	Cases     []caseResult `json:"cases"`
	Summary   string       `json:"summary"`
	NotDriven []string     `json:"not_driven"`
}

// notDriven is published in every report and is part of the result. "A count with no
// stated surface grows while its coverage does not" — the same rule arc-probe's README
// states, applied to the surface this probe leaves alone.
var notDriven = []string{
	"The CONNECT-AUTH cause (§4.6/§4.7 proof-of-possession, 401 authentication_failed) is " +
		"§4.11's fifth row and is NOT driven here: it belongs to the connect handler rather " +
		"than to the framing or decode boundary, and tools/kind-c/connect-errors already " +
		"drives the §4.7 table it lives in. Driving it here would be a second source of " +
		"truth on a surface that has one.",
	"CORRELATION is graded only where a request_id is recoverable (D4/D5/D7). §4.11 permits " +
		"the uncorrelated best-effort frame on D1/D2 by construction — no id ever arrived — " +
		"so those rows assert the FRAME and its CODE and say nothing about correlation.",
	"The peer's configured maximum is not discovered. D1 declares 4 GiB-1, which is over " +
		"every cap in this cohort, so a 413 is attributable; a peer whose real bound is " +
		"lower is still answering the row its own bound assigns. What is NOT measured is " +
		"where that bound sits (entity-system-conformance X4 asks for it to be declared).",
	"A peer that answers the frame and then keeps the connection OPEN on D1/D2 is graded " +
		"`yes` on §4.11 and is not graded on the close at all. §4.11 makes the close a " +
		"choice, not an obligation: 'closing is the only sound choice once the framing is " +
		"lost' is this repo's reading, not a MUST, and a probe that scored it would be " +
		"legislating.",
}

// ── raw-wire helpers ─────────────────────────────────────────────────────────────────

// outcome is what the wire did in response to one arm.
type outcome struct {
	env    map[string]interface{}
	closed bool // the peer closed (EOF/reset) without a frame
	silent bool // the deadline expired with the connection still open
}

// readOneFrame reads a single length-prefixed frame under the session deadline.
//
// EVERY READ CARRIES AN EXPLICIT DEADLINE AND THAT IS NOT A STYLE CHOICE. The
// non-conformant behaviour this probe measures IS "no response", so a reader without a
// deadline hangs on exactly the peers the probe exists to find — the defect AGENTS.md
// records costing a 50-minute plant batch on `ruby` and then repeating on `common-lisp`
// an hour later. `silent` is a RESULT here, reached in bounded time, never a hang.
func readOneFrame(c net.Conn, to time.Duration) outcome {
	_ = c.SetDeadline(time.Now().Add(to))
	hdr := make([]byte, 4)
	if _, err := readFull(c, hdr); err != nil {
		if isTimeout(err) {
			return outcome{silent: true}
		}
		return outcome{closed: true}
	}
	n := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n <= 0 || n > 1<<24 {
		return outcome{closed: true}
	}
	body := make([]byte, n)
	if _, err := readFull(c, body); err != nil {
		if isTimeout(err) {
			return outcome{silent: true}
		}
		return outcome{closed: true}
	}
	v, _, err := dec(body, 0)
	if err != nil {
		return outcome{closed: true}
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return outcome{closed: true}
	}
	return outcome{env: m}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// closeWrite half-closes our side so the peer observes a FIN at a point WE choose.
//
// The half-close is the whole instrument for D2 and D3. A truncated frame is only knowable
// at end-of-stream, so a probe that simply stopped writing would measure the peer's idle
// deadline instead of its truncation handling — and a probe that closed BOTH directions
// could not read the answer it is asking for.
func closeWrite(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.CloseWrite()
	}
}

// aliveAfter asks whether the connection SURVIVED a refusal, by sending a second
// well-formed EXECUTE and requiring an answer.
//
// §4.11's decode-boundary arms (D4/D5/D6/D7) refuse a COMPLETE frame: the framing is
// intact, so the correct behaviour is to answer and keep serving. A peer that answers and
// then closes has turned one bad frame into a denial of service for every later request on
// that connection — `lean`'s 81-FAIL cascade, which is in this repo's ratchet as the shape
// where the peer is completely healthy and every crash reflex finds nothing.
func aliveAfter(s *session) bool {
	env := wellFormedExecute(s, "alive")
	if _, err := s.c.Write(frame(env)); err != nil {
		return false
	}
	o := readOneFrame(s.c, s.to)
	return o.env != nil
}

// wellFormedExecute builds an ordinary, structurally valid EXECUTE.
//
// It deliberately targets the LOCAL peer's own `system/tree` with no resource: the point is
// to be well-formed and answerable, not to be authorized. Whatever status comes back — 200,
// 400, 403 — the peer ANSWERED, which is the only property P0 and aliveAfter assert. Tying
// the control to a particular status would make it a reading about the peer's grant
// configuration, and this probe runs under two different launch configurations.
func wellFormedExecute(s *session, tag string) []byte {
	data := cmap(
		pair{txt("request_id"), txt(s.rid(tag))},
		pair{txt("uri"), txt("entity://" + s.peerID + "/system/tree")},
		pair{txt("operation"), txt("get")},
		pair{txt("params"), emptyParams()},
	)
	return cmap(pair{txt("root"), entity("system/protocol/execute", data)},
		pair{txt("included"), cmap()})
}

// ── the arms ─────────────────────────────────────────────────────────────────────────

type arm struct {
	id     string
	role   string
	expect string
	note   string
	// run drives the arm on a FRESH session and reports what the wire did, plus
	// whether the connection was still usable afterwards (survived == nil means the
	// question does not apply to this arm).
	run func(s *session) (outcome, *bool)
}

func survived(b bool) *bool { return &b }

var arms = []arm{
	{
		id:     "P0_positive_control",
		role:   "control",
		expect: "a well-formed EXECUTE is ANSWERED (any status)",
		note: "The antecedent for every row below. If a structurally valid frame gets no " +
			"answer on this connection, the peer is hung or dead and a silence in D1..D7 is " +
			"a reading about our dial rather than about §4.11. trusted:false suppresses the " +
			"whole report.",
		run: func(s *session) (outcome, *bool) {
			if _, err := s.c.Write(frame(wellFormedExecute(s, "p0"))); err != nil {
				return outcome{closed: true}, nil
			}
			return readOneFrame(s.c, s.to), nil
		},
	},
	{
		id:     "D1_oversize_length_prefix",
		role:   "measurement",
		expect: "413 payload_too_large",
		note: "A 4-byte prefix declaring 4 GiB-1 and no body. §4.10(a)'s 'SHOULD ... and " +
			"otherwise MAY close after a best-effort coded frame' became a MUST at 0.8.2.25 " +
			"(N14) precisely because this condition is detected AT THE LENGTH PREFIX with the " +
			"connection intact and nothing spent — the peer has not allocated, has not " +
			"buffered, and has every resource needed to answer. A bare close here is §4.11's " +
			"named 'CLOSING with no coded frame'.",
		run: func(s *session) (outcome, *bool) {
			if _, err := s.c.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF}); err != nil {
				return outcome{closed: true}, nil
			}
			return readOneFrame(s.c, s.to), nil
		},
	},
	{
		id:     "D2_truncated_frame",
		role:   "measurement",
		expect: "400 invalid_request",
		note: "A prefix declaring 64 bytes, 8 bytes delivered, then FIN. §4.11's framing arm " +
			"names this input in as many words — 'un-parseable, truncated or non-canonical " +
			"CBOR, or a length prefix that never completes'. The FIN is what makes it " +
			"KNOWABLE: until end-of-stream a short frame is indistinguishable from a slow one, " +
			"which is why this arm half-closes rather than waiting.",
		run: func(s *session) (outcome, *bool) {
			if _, err := s.c.Write([]byte{0x00, 0x00, 0x00, 0x40}); err != nil {
				return outcome{closed: true}, nil
			}
			if _, err := s.c.Write(bytes.Repeat([]byte{0xA0}, 8)); err != nil {
				return outcome{closed: true}, nil
			}
			closeWrite(s.c)
			return readOneFrame(s.c, s.to), nil
		},
	},
	{
		id:     "D3_clean_close_control",
		role:   "control",
		expect: "NOTHING — a clean close is not a refusal",
		note: "FIN at a frame boundary, no partial prefix. There is no refusal here and " +
			"nobody to answer; emitting a coded frame would be refusing an ordinary hangup. " +
			"This is the control D2 cannot do without: the cheapest way to pass D2 is to " +
			"answer every read error, and that passes D2 by DELETING the distinction rather " +
			"than implementing it. The two arms differ by one input byte.",
		run: func(s *session) (outcome, *bool) {
			closeWrite(s.c)
			return readOneFrame(s.c, s.to), nil
		},
	},
	{
		id:     "D4_miskeyed_included_entry",
		role:   "measurement",
		expect: "400 hash_mismatch",
		note: "A complete, canonically-encoded frame whose `included` map files a valid " +
			"entity under a key that is not its content_hash (§3.1, §1.8). §5.2a (0.8.2.24 " +
			"N4/N5): a peer that refuses at the DECODE BOUNDARY MUST answer 400 hash_mismatch, " +
			"and 400 non_canonical_ecf is NOT conformant here — the bytes ARE canonical; what " +
			"is false is the claim the KEY makes, so `non_canonical_ecf`'s remedy (re-encode) " +
			"sends an honest caller to the wrong layer. A peer implementing §1.8 mechanism (b) " +
			"— discard the wire key, address by validated content_hash — never detects this at " +
			"the decode boundary at all; its lookup MISSES and §5.2a's own table assigns that " +
			"miss the row of the step that missed. Such a peer is graded `yes — mechanism (b)`, " +
			"because requiring the decode-boundary code of it would make a conformant " +
			"mechanism non-conformant (the K1.7 lesson).",
		run: func(s *session) (outcome, *bool) {
			ent := entity("system/peer", cmap(pair{txt("public_key"), bstr(bytes.Repeat([]byte{0x33}, 32))}))
			wrongKey := bytes.Repeat([]byte{0x00}, 33) // an ecfv1-sha256 shape that binds to nothing
			data := cmap(
				pair{txt("request_id"), txt(s.rid("d4"))},
				pair{txt("uri"), txt("entity://" + s.peerID + "/system/tree")},
				pair{txt("operation"), txt("get")},
				pair{txt("params"), emptyParams()},
			)
			env := cmap(
				pair{txt("root"), entity("system/protocol/execute", data)},
				pair{txt("included"), cmap(pair{bstr(wrongKey), ent})},
			)
			if _, err := s.c.Write(frame(env)); err != nil {
				return outcome{closed: true}, nil
			}
			o := readOneFrame(s.c, s.to)
			if o.env == nil {
				return o, survived(false)
			}
			return o, survived(aliveAfter(s))
		},
	},
	{
		id:     "D5_cbor_tag_in_a_data_field",
		role:   "measurement",
		expect: "400 non_canonical_ecf",
		note: "A CBOR tag (major 6) in a DATA-FIELD position. This arm keeps its own code and " +
			"that is deliberate: §4.11 rules `non_canonical_ecf` non-conformant 'on the framing " +
			"arm' and gives its reason in the same sentence — ENTITY-CBOR-ENCODING defines that " +
			"code for CBOR tag-policy violations specifically, which §6.3 still MUSTs at decode " +
			"time. The two rows are disjoint by CAUSE: a tag in a data field is the policy " +
			"violation; a tag in the envelope shape is a structurally invalid frame, because " +
			"those shapes are fixed maps with no position where a tag could legally sit.",
		run: func(s *session) (outcome, *bool) {
			tagged := append([]byte{0xC1}, uint64v(1)...) // tag(1) wrapping a uint
			data := cmap(
				pair{txt("request_id"), txt(s.rid("d5"))},
				pair{txt("uri"), txt("entity://" + s.peerID + "/system/tree")},
				pair{txt("operation"), txt("get")},
				pair{txt("params"), entity("primitive/any", cmap(pair{txt("x"), tagged}))},
			)
			env := cmap(pair{txt("root"), entity("system/protocol/execute", data)},
				pair{txt("included"), cmap()})
			if _, err := s.c.Write(frame(env)); err != nil {
				return outcome{closed: true}, nil
			}
			o := readOneFrame(s.c, s.to)
			if o.env == nil {
				return o, survived(false)
			}
			return o, survived(aliveAfter(s))
		},
	},
	{
		id:     "D6_undecodable_complete_frame",
		role:   "measurement",
		expect: "400 invalid_request",
		note: "A COMPLETE frame whose payload never becomes an Envelope — here an " +
			"indefinite-length array, which canonical ECF forbids and which is not a map at " +
			"all. §4.11's framing arm: 'non-canonical CBOR that never becomes an Envelope' " +
			"takes invalid_request. This is the row that separates a peer with a real " +
			"cause-to-code mapping from one that answers a single code for everything: a peer " +
			"still on the pre-.24 shape answers non_canonical_ecf here and is graded WRONG " +
			"CODE rather than DROPPED, which is a different repair.",
		run: func(s *session) (outcome, *bool) {
			if _, err := s.c.Write(frame([]byte{0x9F, 0xFF})); err != nil {
				return outcome{closed: true}, nil
			}
			o := readOneFrame(s.c, s.to)
			if o.env == nil {
				return o, survived(false)
			}
			return o, survived(aliveAfter(s))
		},
	},
	{
		id:     "D7_non_execute_root",
		role:   "measurement",
		expect: "400 invalid_request",
		note: "A well-formed envelope whose root is neither EXECUTE nor EXECUTE_RESPONSE " +
			"(§3.3). Everything decodes; the frame is simply not a request. This arm is the " +
			"one most likely to be a bare `break` out of a read loop — it looks like an " +
			"unroutable message rather than a refusal — and a `break` here closes the " +
			"connection on a caller who is owed a status and can still be correlated: the " +
			"request_id is right there in a decoded root.",
		run: func(s *session) (outcome, *bool) {
			data := cmap(
				pair{txt("request_id"), txt(s.rid("d7"))},
				pair{txt("note"), txt("not an execute")},
			)
			env := cmap(pair{txt("root"), entity("system/peer/announcement", data)},
				pair{txt("included"), cmap()})
			if _, err := s.c.Write(frame(env)); err != nil {
				return outcome{closed: true}, nil
			}
			o := readOneFrame(s.c, s.to)
			if o.env == nil {
				return o, survived(false)
			}
			return o, survived(aliveAfter(s))
		},
	},
}

// ── grading ──────────────────────────────────────────────────────────────────────────

// wantCode maps each measurement arm to the code its CAUSE is assigned.
var wantCode = map[string]struct {
	status int
	code   string
}{
	"D1_oversize_length_prefix":     {413, "payload_too_large"},
	"D2_truncated_frame":            {400, "invalid_request"},
	"D4_miskeyed_included_entry":    {400, "hash_mismatch"},
	"D5_cbor_tag_in_a_data_field":   {400, "non_canonical_ecf"},
	"D6_undecodable_complete_frame": {400, "invalid_request"},
	"D7_non_execute_root":           {400, "invalid_request"},
}

// mechanismBCodes are the §5.2a per-site rows a §1.8 mechanism-(b) peer reaches on D4.
//
// It never detects the mis-key: the lookup MISSES, and a miss inherits the row of the step
// that missed. Grading those as a defect would make a conformant mechanism non-conformant
// to satisfy a code the OTHER mechanism's detection point selects — which is exactly the
// objection this seat filed against a one-disposition-for-two-mechanisms ruling, and it
// would be indefensible to then commit it in an instrument.
var mechanismBCodes = map[string]bool{
	"authentication_failed": true,
	"capability_denied":     true,
	"unresolvable_grantee":  true,
}

func grade(a arm, cr caseResult, o outcome, surv *bool) string {
	switch a.id {
	case "P0_positive_control":
		if o.env != nil {
			return "yes"
		}
		if o.closed {
			return "no — the peer CLOSED on a well-formed EXECUTE"
		}
		return "no — the peer answered NOTHING to a well-formed EXECUTE"
	case "D3_clean_close_control":
		if o.env == nil {
			return "yes — nothing emitted, as a clean close requires"
		}
		return fmt.Sprintf("no — OVER-REFUSAL: a clean close at a frame boundary was answered "+
			"%d %s. There was no refusal here; D2's distinction has been deleted rather than "+
			"implemented.", cr.Status, cr.Code)
	}

	want := wantCode[a.id]
	if o.env == nil {
		if o.closed {
			return "no — CLOSED with no coded frame (§4.11 names this separately: a bare close " +
				"is indistinguishable from a network fault, §4.6)"
		}
		return "no — DROPPED: nothing on the wire and the connection stayed open (§4.11's " +
			"weaker failure, precisely because nothing surfaces it; the sender blocks to its " +
			"own §6.11(c) deadline)"
	}
	if a.id == "D4_miskeyed_included_entry" && mechanismBCodes[cr.Code] {
		return fmt.Sprintf("yes — §1.8 mechanism (b): the key was discarded, the lookup MISSED, "+
			"and §5.2a assigns the miss the row of the step that missed (%d %s)", cr.Status, cr.Code)
	}
	// A FRAME ARRIVED CARRYING NO STATUS AT ALL, which is a THIRD thing and must not be
	// printed as a wrong code. `wasm-wat` produced exactly this on D7 and the first cut
	// rendered it `WRONG CODE: answered 0 ,` — a message that reads as a mapping defect
	// and sends the next reader to the wrong file. The obligation §4.11 states is a CODED
	// response; an uncoded one satisfies the frame half and fails the code half for a
	// reason the peer's author needs told plainly.
	if cr.Status == 0 && cr.Code == "" {
		return "no — a frame arrived but carries NO STATUS AND NO CODE: §4.11's obligation " +
			"is a CODED EXECUTE_RESPONSE, so an uncoded frame answers the class and not the " +
			"cause"
	}
	if cr.Status == want.status && cr.Code == want.code {
		if surv != nil && !*surv {
			return fmt.Sprintf("no — the code is right (%d %s) and the CONNECTION DID NOT "+
				"SURVIVE: a complete frame was refused correctly and then every later request "+
				"on that connection was destroyed", cr.Status, cr.Code)
		}
		return "yes"
	}
	return fmt.Sprintf("no — WRONG CODE: answered %d %s, cause is assigned %d %s",
		cr.Status, cr.Code, want.status, want.code)
}

// ── main ─────────────────────────────────────────────────────────────────────────────

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
			// Every harness passes `-profile core` and friends. Skip an unknown
			// flag's value so it is not mistaken for the next flag.
			if len(args[i]) > 0 && args[i][0] == '-' && i+1 < len(args) &&
				len(args[i+1]) > 0 && args[i+1][0] != '-' {
				i++
			}
		}
	}
	if peer == "" && out != "" {
		base := out
		if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
			base = base[idx+1:]
		}
		peer = strings.TrimSuffix(base, ".json")
	}

	// REFUSE TO WRITE A TRACKED CONFORMANCE REPORT, structurally rather than by
	// convention. Every peer's run-s4.sh defaults -json-out to exactly that path, so a
	// bare ./run-s4.sh under ORACLE= is the invocation where the mistake is easiest to
	// make and hardest to see — a probe report where a 778-check report is expected is
	// well-formed, carries no run identity, and reads as a measurement.
	if strings.Contains(out, "status/CONFORMANCE-REPORT") {
		fmt.Fprintf(os.Stderr, "pa-probe: refusing to write a tracked conformance report: %s\n", out)
		os.Exit(4)
	}

	to := 10 * time.Second
	r := report{
		Peer: peer, Addr: addr, NotDriven: notDriven,
		Spec: "§4.11 pre-admission refusal (0.8.2.25), with §5.2a's decode-boundary code " +
			"split (0.8.2.24) and §4.10(a) N14; measured against spec-data/v0.8.2.25",
		Cases: []caseResult{},
	}

	// A FRESH SESSION PER ARM. A peer that answers a refusal by closing would otherwise
	// cascade one defect into every later row — the shape `lean` turned into 81 FAILs,
	// where the count is noise and the first failure in run order is the finding.
	for _, a := range arms {
		cr := caseResult{ID: a.id, Role: a.role, Expect: a.expect, Note: a.note}
		s, err := dialSession(addr, to)
		if err != nil {
			cr.Err = "session: " + err.Error()
			cr.Conforms = "unmeasured"
			r.Cases = append(r.Cases, cr)
			continue
		}
		o, surv := a.run(s)
		if o.env != nil {
			cr.Status, cr.Code, _ = statusOf(o.env)
		}
		switch {
		case o.env != nil:
			cr.Observed = fmt.Sprintf("coded frame: %d %s", cr.Status, cr.Code)
		case o.closed:
			cr.Observed = "connection closed, no frame"
		default:
			cr.Observed = "nothing within the deadline, connection open"
		}
		if surv != nil {
			cr.Observed += fmt.Sprintf("; connection survived=%v", *surv)
		}
		cr.Conforms = grade(a, cr, o, surv)
		s.close()
		r.Cases = append(r.Cases, cr)
	}

	// THE POSITIVE CONTROL SUPPRESSES EVERYTHING. Not "is noted beside" — suppresses:
	// a failed antecedent means the rows below are readings about our dial.
	r.Trusted = true
	for _, c := range r.Cases {
		if c.ID == "P0_positive_control" {
			r.Control = c.Observed
			if !strings.HasPrefix(c.Conforms, "yes") {
				r.Trusted = false
			}
		}
	}

	owed, measured, unmeasured := 0, 0, 0
	for i := range r.Cases {
		if r.Cases[i].Role != "measurement" {
			continue
		}
		if !r.Trusted {
			r.Cases[i].Conforms = "VOID — the positive control failed; this row is a reading " +
				"about the probe's dial, not about the peer"
		}
		switch {
		case r.Cases[i].Conforms == "unmeasured" || strings.HasPrefix(r.Cases[i].Conforms, "VOID"):
			unmeasured++
		default:
			measured++
			if !strings.HasPrefix(r.Cases[i].Conforms, "yes") {
				owed++
			}
		}
	}
	// THE DENOMINATOR IS PRINTED AND IT IS THE POINT. "A gate that examines zero things
	// prints the same word as one that examines forty-six" — so a run in which every arm
	// was suppressed must not read like a clean one.
	r.Summary = fmt.Sprintf("%d of %d measured arms do not answer what §4.11 requires; "+
		"%d unmeasured (control failed); controls: P0=%s D3=%s",
		owed, measured, unmeasured, verdictOf(r, "P0_positive_control"), verdictOf(r, "D3_clean_close_control"))

	b, _ := json.MarshalIndent(r, "", "  ")
	if out != "" {
		if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "pa-probe: write %s: %v\n", out, err)
		}
	}
	fmt.Println(string(b))
	// A probe always exits 0: it measures, it does not gate.
}

func verdictOf(r report, id string) string {
	for _, c := range r.Cases {
		if c.ID == id {
			if strings.HasPrefix(c.Conforms, "yes") {
				return "PASS"
			}
			return "FAIL"
		}
	}
	return "ABSENT"
}
