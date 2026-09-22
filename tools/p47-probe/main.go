// p47-probe — measure, on the wire, what a peer answers for a PRE-HELLO
// `authenticate` on `system/protocol/connect`.
//
// WHY THIS EXISTS. `entity-core-formalization`'s ROUTING-2026-08-30-PREHELLO-
// AUTHENTICATE reports that §4.7's own status table contradicts itself: row 6 says
// `401 invalid_nonce` (restating §4.6 step 1, with the citation), row 10 says
// `400 connection_sequence_error`, for the same input. Their census of the 46-peer
// cohort found a four-way split — but it is a SOURCE READ, and they say so plainly:
// "Not measured on the wire — no probe exists to measure it with."
//
// This is that probe. `validate-peer` has no vector for this input, which is the
// whole reason the divergence shipped unnoticed; measuring it is keystone's job,
// because "a source grep is not a conformance census — ask the running peer" is a
// standing rule here and it has been wrong in BOTH directions before.
//
// It is deliberately NOT added to the conformance suite. The correct answer is
// undecided (that is the routed question), so there is nothing to gate on. This
// reports what each peer does; architecture decides what it should do.
//
// THE TRAP THIS IS BUILT AROUND. A peer that implements §6.3 strictly answers
// `400 non_canonical_ecf` to a frame whose map keys are not in canonical
// length-then-lex order — and a bare `400` is INDISTINGUISHABLE from the row-10
// reading we are trying to measure. So two defences, both required:
//
//   1. Every map this emits is canonically ordered (length-then-lex on the encoded
//      key), so a conformant peer has no reason to reject the framing.
//   2. A CONTROL probe runs first on its own connection: a plain `hello`, which must
//      answer 200 with a `system/protocol/connect/hello` result. If the control does
//      not pass, this peer's test result is reported as UNTRUSTED and MUST NOT be
//      read as a §4.7 answer — the fault is ours, not the peer's.
//
// Reading a bare status without the control is how a probe bug becomes a cohort
// finding.
//
// Usage (matches the run-s4.sh oracle call shape, so it can be dropped in via
// ORACLE=... and inherits every peer's existing container + startup harness):
//
//	p47-probe -addr 127.0.0.1:7777 [-out report.json] [-peer name]
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"math/big"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

// ---------- minimal canonical-ECF CBOR encoder ----------

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	case n < 1<<32:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		b := []byte{major<<5 | 27}
		for i := 56; i >= 0; i -= 8 {
			b = append(b, byte(n>>uint(i)))
		}
		return b
	}
}

func txt(s string) []byte   { return append(head(3, uint64(len(s))), s...) }
func bstr(b []byte) []byte  { return append(head(2, uint64(len(b))), b...) }
func uint64v(n uint64) []byte { return head(0, n) }

type pair struct{ k, v []byte }

// cmap emits a canonical map: keys sorted by ENCODED LENGTH first, then bytewise
// lexicographically. This is the ECF rule, and getting it wrong is how this probe
// would measure §6.3 instead of §4.7.
func cmap(ps ...pair) []byte {
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i].k, ps[j].k
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		return bytes.Compare(a, b) < 0
	})
	out := head(5, uint64(len(ps)))
	for _, p := range ps {
		out = append(out, p.k...)
		out = append(out, p.v...)
	}
	return out
}

func arr(vs ...[]byte) []byte {
	out := head(4, uint64(len(vs)))
	for _, v := range vs {
		out = append(out, v...)
	}
	return out
}

// ---------- decoder (enough to read a response envelope) ----------

func dec(b []byte, p int) (interface{}, int, error) {
	if p >= len(b) {
		return nil, p, fmt.Errorf("truncated")
	}
	ib := b[p]
	major := ib >> 5
	ai := ib & 0x1f
	p++
	var arg uint64
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai == 24:
		arg = uint64(b[p])
		p++
	case ai == 25:
		arg = uint64(b[p])<<8 | uint64(b[p+1])
		p += 2
	case ai == 26:
		for i := 0; i < 4; i++ {
			arg = arg<<8 | uint64(b[p+i])
		}
		p += 4
	case ai == 27:
		for i := 0; i < 8; i++ {
			arg = arg<<8 | uint64(b[p+i])
		}
		p += 8
	default:
		return nil, p, fmt.Errorf("bad additional-info %d", ai)
	}
	switch major {
	case 0:
		return arg, p, nil
	case 1:
		return -1 - int64(arg), p, nil
	case 2:
		if p+int(arg) > len(b) {
			return nil, p, fmt.Errorf("truncated bytes")
		}
		return b[p : p+int(arg)], p + int(arg), nil
	case 3:
		if p+int(arg) > len(b) {
			return nil, p, fmt.Errorf("truncated text")
		}
		return string(b[p : p+int(arg)]), p + int(arg), nil
	case 4:
		out := []interface{}{}
		for i := uint64(0); i < arg; i++ {
			var v interface{}
			var err error
			v, p, err = dec(b, p)
			if err != nil {
				return nil, p, err
			}
			out = append(out, v)
		}
		return out, p, nil
	case 5:
		out := map[string]interface{}{}
		for i := uint64(0); i < arg; i++ {
			kv, np, err := dec(b, p)
			if err != nil {
				return nil, np, err
			}
			p = np
			var v interface{}
			v, p, err = dec(b, p)
			if err != nil {
				return nil, p, err
			}
			if ks, ok := kv.(string); ok {
				out[ks] = v
			}
		}
		return out, p, nil
	case 7:
		// simple values: 20 false, 21 true, 22 null
		switch arg {
		case 20:
			return false, p, nil
		case 21:
			return true, p, nil
		default:
			return nil, p, nil
		}
	}
	return nil, p, fmt.Errorf("unsupported major %d", major)
}

// ---------- wire ----------

func frame(env []byte) []byte {
	n := uint32(len(env))
	return append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, env...)
}

// exchange opens a FRESH connection, sends one frame, and reads one response.
// A fresh connection per exchange is essential: the whole question is what a peer
// does on a connection where no hello has been seen.
func exchange(addr string, env []byte, timeout time.Duration) (map[string]interface{}, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(frame(env)); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	hdr := make([]byte, 4)
	if _, err := readFull(c, hdr); err != nil {
		return nil, fmt.Errorf("no response header: %w", err)
	}
	n := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n <= 0 || n > 1<<24 {
		return nil, fmt.Errorf("implausible response length %d", n)
	}
	body := make([]byte, n)
	if _, err := readFull(c, body); err != nil {
		return nil, fmt.Errorf("truncated response: %w", err)
	}
	v, _, err := dec(body, 0)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("response is not a map")
	}
	return m, nil
}

// exchange2 sends TWO frames on ONE connection and returns the second response.
//
// This is the SEQUENCED control, and it is what makes the pre-hello number mean
// anything. It answers: "what does this peer say to the same authenticate when a
// hello HAS preceded it?" The nonce still will not match, so a peer that reasons
// about sequence should give a different answer here than it gave pre-hello.
//
// If the two answers are IDENTICAL, the peer is not distinguishing the pre-hello
// case at all and its pre-hello status is not a §4.7 reading — it is whatever that
// peer says to any authenticate it dislikes. Reporting that as a row-6/row-10
// position would be inventing a spec opinion the peer does not hold.
func exchange2(addr string, first, second []byte, timeout time.Duration) (map[string]interface{}, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	for i, env := range [][]byte{first, second} {
		if _, err := c.Write(frame(env)); err != nil {
			return nil, fmt.Errorf("write %d: %w", i, err)
		}
		hdr := make([]byte, 4)
		if _, err := readFull(c, hdr); err != nil {
			return nil, fmt.Errorf("no response header %d: %w", i, err)
		}
		n := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		if n <= 0 || n > 1<<24 {
			return nil, fmt.Errorf("implausible length %d", n)
		}
		body := make([]byte, n)
		if _, err := readFull(c, body); err != nil {
			return nil, fmt.Errorf("truncated %d: %w", i, err)
		}
		if i == 1 {
			v, _, err := dec(body, 0)
			if err != nil {
				return nil, fmt.Errorf("decode: %w", err)
			}
			m, ok := v.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("not a map")
			}
			return m, nil
		}
	}
	return nil, fmt.Errorf("unreachable")
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		if n > 0 {
			got += n
		}
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// ---------- frames ----------

// entity materializes {type, data, content_hash} with a REAL content hash.
//
// content_hash = varint(0x00) || SHA-256(canonical ECF of {type, data}) — the
// ecfv1-sha256 floor. A placeholder here is not a shortcut: §1.8 is
// validate-before-trust, so a peer recomputes the hash and rejects a mismatch,
// and at least one peer reports that rejection as `400 non_canonical_ecf` —
// which is precisely the status this probe exists to distinguish. Measured: with
// 33 zero bytes, the control hello came back `400 non_canonical_ecf` from `go`
// and the frame was structurally perfect. The control is what caught it.
func entity(typ string, data []byte) []byte {
	basis := cmap(pair{txt("type"), txt(typ)}, pair{txt("data"), data})
	sum := sha256.Sum256(basis)
	ch := append([]byte{0x00}, sum[:]...)
	return cmap(
		pair{txt("type"), txt(typ)},
		pair{txt("data"), data},
		pair{txt("content_hash"), bstr(ch)},
	)
}

func emptyParams() []byte { return entity("primitive/any", cmap()) }

func execEnv(reqID, op string, params []byte) []byte {
	data := cmap(
		pair{txt("request_id"), txt(reqID)},
		pair{txt("uri"), txt("system/protocol/connect")},
		pair{txt("operation"), txt(op)},
		pair{txt("params"), params},
	)
	root := entity("system/protocol/execute", data)
	return cmap(pair{txt("root"), root}, pair{txt("included"), cmap()})
}

// helloFrame — the CONTROL. A realistic hello on a fresh connection; must answer 200.
//
// The params are a full `system/protocol/connect/hello` rather than an empty
// primitive/any. The minimal form is accepted by 36 peers and REJECTED by the
// three TypeScript-family peers with `400 connection_sequence_error` — which, had
// the control not caught it, would have been recorded as those peers taking the
// §4.7 row-10 position when in fact they were objecting to the hello itself.
func helloFrame() []byte {
	pub := conformancePub()
	hn := make([]byte, 32)
	for i := range hn {
		hn[i] = 0x2b
	}
	d := cmap(
		pair{txt("peer_id"), txt(peerIDOf(pub))},
		// `nonce` is required by the TypeScript-family peers' hello schema
		// ("missing required field 'nonce'") and ignored by the rest. Its absence
		// was rejected with a code that reads exactly like a §4.7 row-10 answer.
		pair{txt("nonce"), bstr(hn)},
		pair{txt("protocols"), arr(txt("entity-core/1.0"))},
		pair{txt("hash_formats"), arr(txt("ecfv1-sha256"))},
		pair{txt("key_types"), arr(txt("ed25519"))},
		pair{txt("timestamp"), uint64v(1756500000000)},
	)
	return execEnv("p47-control", "hello", entity("system/protocol/connect/hello", d))
}

// preHelloAuthFrame — the MEASUREMENT. A structurally well-formed `authenticate`
// sent on a connection where no `hello` has ever been sent.
//
// The params are shaped as a real `system/protocol/connect/authenticate`
// ({peer_id, public_key, key_type, nonce}) rather than left empty, so that a peer
// which parses params BEFORE checking connection sequence still reaches its
// sequence check instead of bailing on a malformed body. The values are arbitrary:
// the input under test is the SEQUENCE, and no nonce was ever issued to echo.
func preHelloAuthFrame() []byte {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = 0x5a
	}
	pub := conformancePub()
	authData := cmap(
		pair{txt("peer_id"), txt(peerIDOf(pub))},
		pair{txt("public_key"), bstr(pub)},
		// key_type is TEXT ("ed25519"), not the numeric §1.5 registry code. Sending
		// the uint made peers answer `400 unsupported_key_type` and put four of them
		// in a spurious fifth behaviour class; the SEQUENCED control is what exposed
		// it (`go` gave the same 400 once a hello had preceded, so the status was
		// about the params, not the sequence).
		pair{txt("key_type"), txt("ed25519")},
		pair{txt("nonce"), bstr(nonce)},
	)
	params := entity("system/protocol/connect/authenticate", authData)
	return execEnv("p47-test", "authenticate", params)
}

// ---------- identity ----------
//
// The authenticate must carry a VALID identity, or a peer rejects it for a reason
// that has nothing to do with connection sequence and the measurement is garbage.
// The one thing deliberately left wrong is the NONCE — which is the input under
// test, and which no pre-hello connection could ever have.
//
// The seed is the cohort-standard conformance seed (0x11 x 32) that every peer's
// run-s4.sh provisions, so the derived peer_id is one the peer already knows.

func conformancePub() []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x11
	}
	return []byte(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

const b58alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58(b []byte) string {
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var out []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, b58alpha[mod.Int64()])
	}
	for _, c := range b { // leading zero bytes -> leading '1'
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// peerIDOf: Base58(key_type || hash_type || hash(pubkey)) (§1.5). For Ed25519 the
// pair is key_type=0x01, hash_type=0x00 "identity multihash" — the hash IS the
// public key. Self-checked in -dump against the known conformance peer_id.
func peerIDOf(pub []byte) string {
	return base58(append([]byte{0x01, 0x00}, pub...))
}

// ---------- report ----------

type result struct {
	Peer          string `json:"peer"`
	Addr          string `json:"addr"`
	ControlOK     bool   `json:"control_ok"`
	ControlStatus int    `json:"control_status"`
	ControlDetail string `json:"control_detail"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	Behaviour     string `json:"behaviour"`
	Message       string `json:"message,omitempty"`
	// The SEQUENCED control: same authenticate, but after a hello on the same
	// connection. Distinguishes "this peer reasons about connection sequence"
	// from "this peer says the same thing to any authenticate it dislikes".
	SeqStatus     int    `json:"seq_status"`
	SeqCode       string `json:"seq_code"`
	SeqDistinct   bool   `json:"sequence_distinguished"`
	Trusted       bool   `json:"trusted"`
	Note          string `json:"note,omitempty"`
}

// statusOf returns (status, code, resultType). The error MESSAGE is captured
// separately by statusMsg — when a peer has several branches sharing one code, the
// message is the only thing that says which one fired.
func statusMsg(env map[string]interface{}) string {
	root, _ := env["root"].(map[string]interface{})
	if root == nil {
		return ""
	}
	data, _ := root["data"].(map[string]interface{})
	if data == nil {
		return ""
	}
	if res, ok := data["result"].(map[string]interface{}); ok {
		if rd, ok := res["data"].(map[string]interface{}); ok {
			m, _ := rd["message"].(string)
			return m
		}
	}
	return ""
}

func statusOf(env map[string]interface{}) (int, string, string) {
	root, _ := env["root"].(map[string]interface{})
	if root == nil {
		return 0, "", "no root"
	}
	data, _ := root["data"].(map[string]interface{})
	if data == nil {
		return 0, "", "no root.data"
	}
	st := 0
	if s, ok := data["status"].(uint64); ok {
		st = int(s)
	}
	code := ""
	rtype := ""
	if res, ok := data["result"].(map[string]interface{}); ok {
		rtype, _ = res["type"].(string)
		if rd, ok := res["data"].(map[string]interface{}); ok {
			code, _ = rd["code"].(string)
		}
	}
	return st, code, rtype
}

func classify(status int, code string) string {
	switch {
	case status == 401 && code == "invalid_nonce":
		return "401-invalid_nonce (§4.7 row 6 / §4.6 step 1)"
	case status == 400 && code == "connection_sequence_error":
		return "400-connection_sequence_error (§4.7 row 10)"
	case status == 409:
		return fmt.Sprintf("409-%s (in NEITHER clause)", code)
	case status == 0:
		return "no-response (transport drop — §4.9(c))"
	default:
		return fmt.Sprintf("%d-%s (other)", status, code)
	}
}

func main() {
	// Args are parsed BY HAND, tolerating unknown flags, because this binary is
	// dropped into every peer's existing run-s4.sh via ORACLE= and therefore
	// receives whatever the harness passes the real validator — `-profile core
	// -json-out <path>`. Using the flag package would abort on `-profile`.
	// Adapting the probe to the harness beats forking 46 harnesses.
	addrV, outV, peerV := "127.0.0.1:7777", "", ""
	dumpV := false
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
			addrV = next()
		case "-out", "--out", "-json-out", "--json-out":
			outV = next()
		case "-peer", "--peer":
			peerV = next()
		case "-dump", "--dump":
			dumpV = true
		default:
			// Unknown flag. If it takes a value we would mis-consume it, so only
			// skip a following token when it does not itself look like a flag.
			if len(args[i]) > 0 && args[i][0] == '-' && i+1 < len(args) &&
				len(args[i+1]) > 0 && args[i+1][0] != '-' {
				i++
			}
		}
	}
	addr, out, peer, dump := &addrV, &outV, &peerV, &dumpV
	// Derive the peer name from the output path when the harness did not pass one
	// (the census call shape has no -peer).
	if *peer == "" && *out != "" {
		base := *out
		if idx := bytes.LastIndexByte([]byte(base), '/'); idx >= 0 {
			base = base[idx+1:]
		}
		if n := len(base); n > 5 && base[n-5:] == ".json" {
			base = base[:n-5]
		}
		*peer = base
	}
	_ = flag.CommandLine

	if *dump {
		const known = "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg"
		got := peerIDOf(conformancePub())
		fmt.Printf("derived peer_id: %s\n   known good  : %s\n   MATCH: %v\n\n",
			got, known, got == known)
		h := helloFrame()
		a := preHelloAuthFrame()
		fmt.Printf("hello env len=%d\n%x\n\n", len(h), h)
		fmt.Printf("auth  env len=%d\n%x\n", len(a), a)
		return
	}

	r := result{Peer: *peer, Addr: *addr}
	to := 8 * time.Second

	// --- control: a plain hello must work, or nothing below can be trusted.
	env, err := exchange(*addr, helloFrame(), to)
	if err != nil {
		r.ControlDetail = "control exchange failed: " + err.Error()
	} else {
		st, code, rtype := statusOf(env)
		r.ControlStatus = st
		if st == 200 && rtype == "system/protocol/connect/hello" {
			r.ControlOK = true
			r.ControlDetail = "hello -> 200 " + rtype
		} else {
			r.ControlDetail = fmt.Sprintf("hello -> %d %s %s | msg=%q", st, code, rtype, statusMsg(env))
		}
	}

	// --- measurement: authenticate with no preceding hello, fresh connection.
	env2, err2 := exchange(*addr, preHelloAuthFrame(), to)
	if err2 != nil {
		r.Status = 0
		r.Note = "test exchange: " + err2.Error()
	} else {
		st, code, _ := statusOf(env2)
		r.Status, r.Code = st, code
		r.Message = statusMsg(env2)
	}
	// --- sequenced control: hello THEN authenticate, one connection.
	if env3, err3 := exchange2(*addr, helloFrame(), preHelloAuthFrame(), to); err3 == nil {
		r.SeqStatus, r.SeqCode, _ = statusOf(env3)
	} else {
		r.SeqStatus = 0
		r.SeqCode = "(" + err3.Error() + ")"
	}
	r.SeqDistinct = !(r.SeqStatus == r.Status && r.SeqCode == r.Code)

	r.Behaviour = classify(r.Status, r.Code)
	if !r.SeqDistinct {
		r.Behaviour += " [NOT sequence-distinguished — same answer after a hello]"
	}
	r.Trusted = r.ControlOK
	if !r.Trusted && r.Note == "" {
		r.Note = "UNTRUSTED — control hello did not pass; this is a probe-side fault, " +
			"not a §4.7 answer. Do not report this peer's behaviour."
	}

	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(b))
	if *out != "" {
		_ = os.WriteFile(*out, append(b, '\n'), 0o644)
	}
	// Always exit 0: this measures, it does not gate. The correct answer is the
	// question architecture is being asked.
}
