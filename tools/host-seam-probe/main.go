// host-seam-probe — measure, on the wire, whether a peer DISPATCHES a handler body
// a third party installed. **Kind A (probe).**
//
// Kind and obligations: `docs/VERIFICATION-ARCHITECTURE.md`. A probe measures; it does
// not judge, it does not gate, and it never appears in a published conformance number.
//
// WHY THIS EXISTS. The keystone host contract's **H1** requires that a handler installed
// after construction is REACHABLE BY DISPATCH, and `docs/spec/SPEC-KEYSTONE-PEER.md` says
// in as many words that a profile naming only the registration call cannot tell a live
// host from a dead map. Nothing in the 778-check conformance set answers that question,
// and this was verified rather than assumed:
//
//   - `core_register_body_binding` asserts only that the §11.6.1 entities were BOUND — its
//     PASS message is "entity-native echo body bound at <path>". It never dispatches.
//   - `unsupported_operation_on_registered_handler` sounds like it does, and does not:
//     its `registeredURI` is `system/tree`, a BOOTSTRAP handler. "Registered" there means
//     present, not third-party-installed.
//   - `validate_echo_dispatch` dispatches `system/validate/echo`, also a built-in — the
//     oracle's own comment records that the dispatch half was deliberately "moved off
//     compute/literal", i.e. it stopped asserting that an installed body runs.
//
// So a peer can bind all four §11.6.1 writes, score 778 · 0F, and have nowhere for a body
// to execute. A source read across the cohort says roughly twenty peers are in exactly
// that state — but this repo has had FOUR peers wrongly nominated as hosts from source
// reads, by three different seats, and the standing rule is that a capability claim reads
// `unknown` until a harness executes it. Hence a probe, not a survey.
//
// WHAT IT MEASURES, per peer, in one session:
//
//  1. bind    — `system/tree:put` a `compute/literal` expression at <pattern>/expr
//  2. register— `system/handler:register` naming that `expression_path`
//  3. landed  — `system/tree:get` the handler entity the register was supposed to write
//  4. DISPATCH— an EXECUTE at <pattern>. THIS IS THE MEASUREMENT.
//
// The register request shape is the oracle's own (`sendCoreRegister`,
// `cmd/internal/validate/core_register_gate.go`) rather than one derived here, because
// that shape demonstrably round-trips on all 46 peers. Deriving a second one would put a
// probe-side variable in front of the thing being measured.
//
// CONTROLS, all three mandatory — a wire probe fails in the direction of the answer it is
// looking for, so a probe without controls is a rumour with a number attached:
//
//   - POSITIVE. A plain valid `put` MUST answer 200 on a fresh connection. If it does not,
//     the peer is reported `trusted: false` and its measurement is SUPPRESSED, because the
//     fault is ours. (This is the control that caught two probe faults in `put-probe`
//     before either could become a cohort finding.)
//   - LANDED. Step 3. `register -> 200` and `register -> 200 having bound nothing` are
//     different worlds, and only the second makes a 501 at step 4 uninteresting.
//   - DIFFERENTIAL / NEGATIVE. The same dispatch at a sibling path that was never
//     registered MUST answer 404. Without it, "200" cannot be distinguished from a peer
//     that answers 200 to everything, and "404" at step 4 cannot be distinguished from a
//     peer whose resolution never reached our path at all. It varies exactly ONE thing —
//     whether the register happened — which is the property the first draft of the
//     `kind-c` differential got wrong by varying two.
//
// The verdict vocabulary is deliberately not pass/fail. `BOUND-NOT-EVALUATED` is a
// perfectly conformant state for a core peer: §6.13(a) is the extension surface, and a
// peer that binds correctly and has no evaluator is honest. What it is NOT is a host.
//
// This is a MEASUREMENT. It always exits 0.
//
// Usage (deliberately the run-s4.sh oracle call shape, so it drops into all 46 peers'
// existing container + startup harnesses via ORACLE= with no harness edits):
//
//	host-seam-probe -addr 127.0.0.1:7777 [-json-out report.json] [-peer name] [-dump]
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// ---------- minimal canonical-ECF CBOR encoder ----------
//
// Canonical order is length-then-lex on the ENCODED key. Getting it wrong makes a
// conformant peer answer `400 non_canonical_ecf` (§6.3), which at this probe's
// statuses is indistinguishable from the admission answers under measurement.

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

func txt(s string) []byte     { return append(head(3, uint64(len(s))), s...) }
func bstr(b []byte) []byte    { return append(head(2, uint64(len(b))), b...) }
func uint64v(n uint64) []byte { return head(0, n) }

type pair struct{ k, v []byte }

// dedupDropped counts pairs cmap discarded as duplicate keys. Reported per-peer
// so the dedup can never be silent: a non-zero count that was NOT expected means
// the probe built a malformed map, and that is the probe's bug, not the peer's.
var dedupDropped int

// cmap encodes a canonical ECF map: length-then-lexicographic key order, and
// EACH KEY EXACTLY ONCE.
//
// The uniqueness half is not decoration. `authedExecute` unions our own peer
// entity into the handshake's forwarded `included` map, which already contains
// it (we are the grantee), so the naive concatenation emits the same byte-string
// key twice. A CBOR map with a duplicate key is not canonical ECF at all, and a
// decoder is entitled to refuse the whole frame — which is exactly what `csharp`
// did, in strict CTAP2 mode, on every case including the positive control. It
// was the ONLY peer of 46 strict enough to say so, so it read as the outlier and
// was published as "unmeasurable — refuses a valid put". It was right and the
// instrument was wrong.
func cmap(ps ...pair) []byte {
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i].k, ps[j].k
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		return bytes.Compare(a, b) < 0
	})
	uniq := ps[:0:0]
	for i, p := range ps {
		if i > 0 && bytes.Equal(p.k, ps[i-1].k) {
			dedupDropped++
			continue
		}
		uniq = append(uniq, p)
	}
	out := head(5, uint64(len(uniq)))
	for _, p := range uniq {
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

// ---------- decoder ----------
//
// Byte-string map keys are hex-encoded into the Go map, because the `included` map
// (§3.1) is keyed by content hash and this probe has to read it.

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
		if p >= len(b) {
			return nil, p, fmt.Errorf("truncated arg")
		}
		arg = uint64(b[p])
		p++
	case ai == 25:
		if p+2 > len(b) {
			return nil, p, fmt.Errorf("truncated arg")
		}
		arg = uint64(b[p])<<8 | uint64(b[p+1])
		p += 2
	case ai == 26:
		if p+4 > len(b) {
			return nil, p, fmt.Errorf("truncated arg")
		}
		for i := 0; i < 4; i++ {
			arg = arg<<8 | uint64(b[p+i])
		}
		p += 4
	case ai == 27:
		if p+8 > len(b) {
			return nil, p, fmt.Errorf("truncated arg")
		}
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
			switch k := kv.(type) {
			case string:
				out[k] = v
			case []byte:
				out[hex.EncodeToString(k)] = v
			}
		}
		return out, p, nil
	case 7:
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

// rawIncluded re-extracts the `included` map's entries as RAW ENCODED BYTES.
//
// The capability material a peer hands back at authenticate (the token, its granter
// identity, its signature) has to be forwarded VERBATIM on every subsequent
// authenticated EXECUTE: §5.2 step 3 resolves `included[execute.data.capability]` and
// then verifies the chain out of that same map. Re-encoding a decoded structure risks
// a byte difference that changes a content hash, and a changed hash is an
// unverifiable capability — so the original spans are sliced out and replayed, never
// rebuilt.
func rawIncluded(env []byte) ([]pair, error) {
	// Walk the top-level map manually to find "included" and keep its byte spans.
	if len(env) == 0 || env[0]>>5 != 5 {
		return nil, fmt.Errorf("envelope is not a map")
	}
	ai := env[0] & 0x1f
	var n uint64
	p := 1
	switch {
	case ai < 24:
		n = uint64(ai)
	case ai == 24:
		n = uint64(env[1])
		p = 2
	case ai == 25:
		n = uint64(env[1])<<8 | uint64(env[2])
		p = 3
	default:
		return nil, fmt.Errorf("implausible envelope map header")
	}
	for i := uint64(0); i < n; i++ {
		kStart := p
		kv, np, err := dec(env, p)
		if err != nil {
			return nil, err
		}
		p = np
		vStart := p
		_, np2, err := dec(env, p)
		if err != nil {
			return nil, err
		}
		p = np2
		if ks, ok := kv.(string); ok && ks == "included" {
			return rawMapEntries(env[vStart:p])
		}
		_ = kStart
	}
	return nil, nil // no included map: legal, just nothing to forward
}

func rawMapEntries(m []byte) ([]pair, error) {
	if len(m) == 0 || m[0]>>5 != 5 {
		return nil, fmt.Errorf("included is not a map")
	}
	ai := m[0] & 0x1f
	var n uint64
	p := 1
	switch {
	case ai < 24:
		n = uint64(ai)
	case ai == 24:
		n = uint64(m[1])
		p = 2
	case ai == 25:
		n = uint64(m[1])<<8 | uint64(m[2])
		p = 3
	default:
		return nil, fmt.Errorf("implausible included map header")
	}
	out := []pair{}
	for i := uint64(0); i < n; i++ {
		kStart := p
		_, np, err := dec(m, p)
		if err != nil {
			return nil, err
		}
		p = np
		vStart := p
		_, np2, err := dec(m, p)
		if err != nil {
			return nil, err
		}
		p = np2
		out = append(out, pair{k: append([]byte(nil), m[kStart:vStart]...),
			v: append([]byte(nil), m[vStart:p]...)})
	}
	return out, nil
}

// ---------- wire ----------

func frame(env []byte) []byte {
	n := uint32(len(env))
	return append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, env...)
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

// ---------- entities ----------

func entityBasis(typ string, data []byte) []byte {
	return cmap(pair{txt("type"), txt(typ)}, pair{txt("data"), data})
}

// contentHash is the ecfv1-sha256 floor (§1.2 format code 0x00): the varint format
// code followed by SHA-256 over the canonical ECF of {type, data}.
func contentHash(typ string, data []byte) []byte {
	sum := sha256.Sum256(entityBasis(typ, data))
	return append([]byte{0x00}, sum[:]...)
}

func entity(typ string, data []byte) []byte {
	return cmap(
		pair{txt("type"), txt(typ)},
		pair{txt("data"), data},
		pair{txt("content_hash"), bstr(contentHash(typ, data))},
	)
}

func emptyParams() []byte { return entity("primitive/any", cmap()) }

// ---------- identity ----------
//
// The probe authenticates as its OWN identity, not as the peer's. Every peer's
// run-s4.sh boots with `--debug-open-grants` (the degenerate `default -> *` seed
// policy), so any authenticated identity receives grants covering `system/tree:put`.
// Using the peer's own conformance seed (0x11 x 32) would make the probe claim the
// responder's identity, which is a different and needlessly odd input.

var probeSeed = bytes.Repeat([]byte{0x22}, 32)

func probeKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(probeSeed) }

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
	for _, c := range b {
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

// peerIDOf: Base58(key_type || hash_type || hash(pubkey)) (§1.5). Ed25519 is
// key_type=0x01 with hash_type=0x00 "identity multihash" — the hash IS the key.
func peerIDOf(pub []byte) string {
	return base58(append([]byte{0x01, 0x00}, pub...))
}

// ---------- session ----------

type session struct {
	c        net.Conn
	to       time.Duration
	priv     ed25519.PrivateKey
	pub      []byte
	peerID   string
	selfHash []byte // content hash of our own system/peer entity (the `author`)
	selfEnt  []byte // our system/peer entity, encoded
	capHash  []byte // the capability token's content hash (`capability`)
	capMat   []pair // the authenticate response's included map, forwarded verbatim
	seq      int

	// Diagnostics, reported when the positive control fails. A failed control means
	// the fault is the probe's, and these are the three values that say which of the
	// §5.2 gates it tripped — without them "401 unresolvable_grantee" is a guess.
	diagGrantee  string
	diagIncluded []string
	capMatBad    int // forwarded entries that fail the self-check below
	capMatNote   string
}

// verifyCapMat is a PROBE-SIDE CONTROL, and it exists because without it a slicing
// bug in rawIncluded and a peer defect are the same observation.
//
// Each forwarded entry is re-decoded and its {type, data} re-hashed; the result must
// equal the map key it was filed under (§3.1: "entities in the included map carry
// content_hash matching the map key"). If the byte spans were mis-sliced, the
// re-hash cannot match — so a mismatch means the probe is about to send garbage and
// MUST say so rather than let the peer's reaction be recorded as a §6.3 answer.
//
// Entries whose key is not an ecfv1-sha256 (0x00) hash are skipped rather than
// failed: this checks OUR slicing, not the peer's choice of hash format.
func (s *session) verifyCapMat() {
	bad := 0
	for _, e := range s.capMat {
		k, _, err := dec(e.k, 0)
		if err != nil {
			bad++
			continue
		}
		kb, ok := k.([]byte)
		if !ok || len(kb) == 0 || kb[0] != 0x00 {
			continue
		}
		v, _, err := dec(e.v, 0)
		if err != nil {
			bad++
			continue
		}
		m, ok := v.(map[string]interface{})
		if !ok {
			bad++
			continue
		}
		ch, ok := m["content_hash"].([]byte)
		if !ok || !bytes.Equal(ch, kb) {
			bad++
		}
	}
	s.capMatBad = bad
	if bad > 0 {
		s.capMatNote = fmt.Sprintf("PROBE FAULT: %d of %d forwarded included entries do not "+
			"hash to the key they are filed under — the byte spans were mis-sliced, so this "+
			"peer's answers are about OUR envelope and are not §6.3 readings", bad, len(s.capMat))
	}
}

func (s *session) send(env []byte) (map[string]interface{}, []byte, error) {
	_ = s.c.SetDeadline(time.Now().Add(s.to))
	if _, err := s.c.Write(frame(env)); err != nil {
		return nil, nil, fmt.Errorf("write: %w", err)
	}
	hdr := make([]byte, 4)
	if _, err := readFull(s.c, hdr); err != nil {
		return nil, nil, fmt.Errorf("no response header: %w", err)
	}
	n := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n <= 0 || n > 1<<24 {
		return nil, nil, fmt.Errorf("implausible response length %d", n)
	}
	body := make([]byte, n)
	if _, err := readFull(s.c, body); err != nil {
		return nil, nil, fmt.Errorf("truncated response: %w", err)
	}
	v, _, err := dec(body, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("decode: %w", err)
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("response is not a map")
	}
	return m, body, nil
}

func (s *session) rid(tag string) string {
	s.seq++
	return fmt.Sprintf("host-seam-probe-%s-%d", tag, s.seq)
}

// connectEnv builds an unauthenticated EXECUTE on the pre-authorized connect path
// (§4.2): no `author`, no `capability`, no signature.
func (s *session) connectEnv(rid, op string, params []byte) []byte {
	data := cmap(
		pair{txt("request_id"), txt(rid)},
		pair{txt("uri"), txt("system/protocol/connect")},
		pair{txt("operation"), txt(op)},
		pair{txt("params"), params},
	)
	return cmap(pair{txt("root"), entity("system/protocol/execute", data)},
		pair{txt("included"), cmap()})
}

func dialSession(addr string, to time.Duration) (*session, error) {
	c, err := net.DialTimeout("tcp", addr, to)
	if err != nil {
		return nil, err
	}
	priv := probeKey()
	pub := []byte(priv.Public().(ed25519.PublicKey))
	s := &session{c: c, to: to, priv: priv, pub: pub, peerID: peerIDOf(pub)}

	// §3.5 (v7.65): `system/peer` is {public_key, key_type} and `peer_id` MUST NOT
	// appear in the hashable basis — content_hash is a pure function of the key and
	// its type. Carrying `peer_id` here produces a DIFFERENT identity hash from the
	// one the responder derives for us, so its capability's `grantee` names an entity
	// our `included` map does not contain and the request dies `401
	// unresolvable_grantee`. That is exactly what the first run of this probe did.
	//
	// Worth flagging upstream: §4.6's own pseudocode still shows the pre-v7.65
	// three-field form (`peer_entity = Entity { type: "system/peer", data: { peer_id,
	// public_key, key_type } }`), which is what this probe was written against.
	peerData := cmap(
		pair{txt("public_key"), bstr(pub)},
		pair{txt("key_type"), txt("ed25519")},
	)
	s.selfEnt = entity("system/peer", peerData)
	s.selfHash = contentHash("system/peer", peerData)

	// --- leg 1: hello. The responder's nonce comes back in the result and MUST be
	// echoed by authenticate (§4.6 step 1); a fresh one is issued per connection.
	hn := bytes.Repeat([]byte{0x2b}, 32)
	helloData := cmap(
		pair{txt("peer_id"), txt(s.peerID)},
		pair{txt("nonce"), bstr(hn)},
		pair{txt("protocols"), arr(txt("entity-core/1.0"))},
		pair{txt("hash_formats"), arr(txt("ecfv1-sha256"))},
		pair{txt("key_types"), arr(txt("ed25519"))},
		pair{txt("timestamp"), uint64v(uint64(time.Now().UnixMilli()))},
	)
	env, _, err := s.send(s.connectEnv(s.rid("hello"), "hello",
		entity("system/protocol/connect/hello", helloData)))
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("hello: %w", err)
	}
	st, _, _ := statusOf(env)
	if st != 200 {
		c.Close()
		return nil, fmt.Errorf("hello -> %d %s", st, codeOf(env))
	}
	nonce, ok := resultField(env, "nonce").([]byte)
	if !ok || len(nonce) == 0 {
		c.Close()
		return nil, fmt.Errorf("hello response carried no nonce")
	}

	// --- leg 2: authenticate. Proof of possession over the authenticate entity's
	// content hash, with our peer entity and the signature in `included`.
	authData := cmap(
		pair{txt("peer_id"), txt(s.peerID)},
		pair{txt("public_key"), bstr(pub)},
		pair{txt("key_type"), txt("ed25519")},
		pair{txt("nonce"), bstr(nonce)},
	)
	authHash := contentHash("system/protocol/connect/authenticate", authData)
	sigData := cmap(
		pair{txt("target"), bstr(authHash)},
		pair{txt("signer"), bstr(s.selfHash)},
		pair{txt("algorithm"), txt("ed25519")},
		pair{txt("signature"), bstr(ed25519.Sign(priv, authHash))},
	)
	sigEnt := entity("system/signature", sigData)
	sigHash := contentHash("system/signature", sigData)

	rootData := cmap(
		pair{txt("request_id"), txt(s.rid("auth"))},
		pair{txt("uri"), txt("system/protocol/connect")},
		pair{txt("operation"), txt("authenticate")},
		pair{txt("params"), entity("system/protocol/connect/authenticate", authData)},
	)
	authEnv := cmap(
		pair{txt("root"), entity("system/protocol/execute", rootData)},
		pair{txt("included"), cmap(
			pair{bstr(s.selfHash), s.selfEnt},
			pair{bstr(sigHash), sigEnt},
		)},
	)
	env2, raw2, err := s.send(authEnv)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("authenticate: %w", err)
	}
	if st, _, _ := statusOf(env2); st != 200 {
		c.Close()
		return nil, fmt.Errorf("authenticate -> %d %s", st, codeOf(env2))
	}
	tok, ok := resultField(env2, "token").([]byte)
	if !ok || len(tok) == 0 {
		c.Close()
		return nil, fmt.Errorf("authenticate response carried no capability token")
	}
	s.capHash = tok
	// Forward the whole included map verbatim — the token, its granter identity and
	// its signature are all chain material §5.2 step 3 resolves out of this map.
	if inc, err := rawIncluded(raw2); err == nil {
		s.capMat = inc
	}
	s.verifyCapMat()
	if incMap, ok := env2["included"].(map[string]interface{}); ok {
		for k, v := range incMap {
			ty := ""
			if e, ok := v.(map[string]interface{}); ok {
				ty, _ = e["type"].(string)
				if ty == "system/capability/token" {
					if d, ok := e["data"].(map[string]interface{}); ok {
						if g, ok := d["grantee"].([]byte); ok {
							s.diagGrantee = hex.EncodeToString(g)
						}
					}
				}
			}
			s.diagIncluded = append(s.diagIncluded, k[:8]+"…="+ty)
		}
		sort.Strings(s.diagIncluded)
	}
	return s, nil
}

func (s *session) close() { _ = s.c.Close() }

// authedExecute builds, signs and sends a fully authenticated EXECUTE (§3.2/§5.2):
// `author` + `capability` in data, a target-matching signature in `included`, and the
// capability chain material forwarded from the handshake.
func (s *session) authedExecute(tag, uri, op string, params []byte, targets []string) (map[string]interface{}, error) {
	fields := []pair{
		{txt("request_id"), txt(s.rid(tag))},
		{txt("uri"), txt(uri)},
		{txt("operation"), txt(op)},
		{txt("params"), params},
		{txt("author"), bstr(s.selfHash)},
		{txt("capability"), bstr(s.capHash)},
	}
	if len(targets) > 0 {
		tv := make([][]byte, 0, len(targets))
		for _, t := range targets {
			tv = append(tv, txt(t))
		}
		fields = append(fields, pair{txt("resource"), cmap(pair{txt("targets"), arr(tv...)})})
	}
	rootData := cmap(fields...)
	rootHash := contentHash("system/protocol/execute", rootData)

	sigData := cmap(
		pair{txt("target"), bstr(rootHash)},
		pair{txt("signer"), bstr(s.selfHash)},
		pair{txt("algorithm"), txt("ed25519")},
		pair{txt("signature"), bstr(ed25519.Sign(s.priv, rootHash))},
	)
	inc := []pair{
		{bstr(s.selfHash), s.selfEnt},
		{bstr(contentHash("system/signature", sigData)), entity("system/signature", sigData)},
	}
	inc = append(inc, s.capMat...)

	env := cmap(
		pair{txt("root"), entity("system/protocol/execute", rootData)},
		pair{txt("included"), cmap(inc...)},
	)
	m, _, err := s.send(env)
	return m, err
}

// ---------- response readers ----------

func rootData(env map[string]interface{}) map[string]interface{} {
	root, _ := env["root"].(map[string]interface{})
	if root == nil {
		return nil
	}
	d, _ := root["data"].(map[string]interface{})
	return d
}

func statusOf(env map[string]interface{}) (int, string, string) {
	d := rootData(env)
	if d == nil {
		return 0, "", "no root.data"
	}
	st := 0
	if s, ok := d["status"].(uint64); ok {
		st = int(s)
	}
	code, rtype := "", ""
	if res, ok := d["result"].(map[string]interface{}); ok {
		rtype, _ = res["type"].(string)
		if rd, ok := res["data"].(map[string]interface{}); ok {
			code, _ = rd["code"].(string)
		}
	}
	return st, code, rtype
}

func codeOf(env map[string]interface{}) string { _, c, _ := statusOf(env); return c }

func messageOf(env map[string]interface{}) string {
	d := rootData(env)
	if d == nil {
		return ""
	}
	if res, ok := d["result"].(map[string]interface{}); ok {
		if rd, ok := res["data"].(map[string]interface{}); ok {
			m, _ := rd["message"].(string)
			return m
		}
	}
	return ""
}

func resultField(env map[string]interface{}, name string) interface{} {
	d := rootData(env)
	if d == nil {
		return nil
	}
	res, ok := d["result"].(map[string]interface{})
	if !ok {
		return nil
	}
	rd, ok := res["data"].(map[string]interface{})
	if !ok {
		return nil
	}
	return rd[name]
}

// ---------- the installed handler ----------
//
// The pattern sits under `app/validate/core-register/`, which is the prefix the oracle's
// own register gate uses and therefore the one prefix the connection grants are KNOWN to
// cover on all 46 peers (`core_register_body_binding` PASSes cohort-wide, and it SKIPs
// when the grants do not reach). Choosing a fresh prefix here would risk measuring the
// seed policy instead of the seam. The leaf differs from the oracle's so the two can
// never collide if both ever run against one peer.

const (
	seamPattern  = "app/validate/core-register/hostseam"
	seamExprPath = seamPattern + "/expr"
	// The never-registered sibling. Same prefix, so it has the same authorization
	// story and differs from seamPattern in exactly one respect: nothing registered it.
	seamAbsentPattern = "app/validate/core-register/hostseam-absent"
	// Matches the oracle's literal. Arbitrary as a value; what matters is that a 200
	// carrying it back is evidence the EXPRESSION was evaluated rather than that some
	// other branch answered 200.
	seamLiteral = uint64(42)
)

// computeLiteralEntity is the body: a `compute/literal` whose evaluation yields
// seamLiteral. This is the "impl-private body-binding seam" the oracle's step 1 plants,
// and it is the only body shape the core floor is required to evaluate.
func computeLiteralEntity() []byte {
	return entity("compute/literal", cmap(pair{txt("value"), uint64v(seamLiteral)}))
}

func putParams(ent []byte) []byte {
	return entity("system/tree/put-request", cmap(pair{txt("entity"), ent}))
}

// controlEntity is the positive control's payload — an ordinary valid entity.
func controlEntity() []byte {
	return entity("primitive/any", cmap(pair{txt("probe"), txt("host-seam")}))
}

// scopeAll is `wildcardScope` from the oracle: include-* on all three dimensions.
func scopeAll() []byte {
	star := cmap(pair{txt("include"), arr(txt("*"))})
	return arr(cmap(
		pair{txt("handlers"), star},
		pair{txt("operations"), star},
		pair{txt("resources"), star},
	))
}

// registerRequestEntity is `sendCoreRegister`'s payload, field for field:
// system/handler/register-request { manifest, requested_scope }.
func registerRequestEntity(pattern, exprPath string) []byte {
	opSpec := cmap(
		pair{txt("input_type"), txt("primitive/any")},
		pair{txt("output_type"), txt("primitive/any")},
	)
	// The manifest is a BARE MAP, not an entity. This cost the probe's first run:
	// wrapped as `entity("system/handler/manifest", …)` the peer's
	// `MapField(manifest, "expression_path")` looks at the ENTITY's top level —
	// {type, data, content_hash} — finds no `expression_path`, and binds a handler
	// with no body. Register still answers 200 and the entity still lands, so the
	// fault presents as "this peer has no evaluator". The oracle's own
	// `RegisterRequestData` has `Manifest HandlerManifestData` as a plain struct
	// field: `ToEntity` is called on the REQUEST, never on the manifest.
	manifest := cmap(
		pair{txt("pattern"), txt(pattern)},
		pair{txt("name"), txt(pattern)},
		pair{txt("operations"), cmap(pair{txt("compute"), opSpec})},
		pair{txt("internal_scope"), scopeAll()},
		pair{txt("expression_path"), txt(exprPath)},
	)
	return entity("system/handler/register-request", cmap(
		pair{txt("manifest"), manifest},
		pair{txt("requested_scope"), scopeAll()},
	))
}

// ---------- report ----------

type step struct {
	ID      string `json:"id"`
	What    string `json:"what"`
	Status  int    `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Err     string `json:"error,omitempty"`
}

type report struct {
	Peer    string `json:"peer"`
	Addr    string `json:"addr"`
	Trusted bool   `json:"trusted"`
	Control string `json:"positive_control"`

	Steps []step `json:"steps"`

	// The measurement and its two supporting controls, lifted out of Steps so a reader
	// cannot quote the verdict without also seeing what licenses it.
	RegisterStatus int    `json:"register_status"`
	Landed         string `json:"register_landed"`
	DispatchStatus int    `json:"dispatch_status"`
	DispatchCode   string `json:"dispatch_code,omitempty"`
	ResultType     string `json:"dispatch_result_type,omitempty"`
	ResultValue    string `json:"dispatch_result_value,omitempty"`
	NegControl     string `json:"negative_control"`

	Verdict string `json:"verdict"`
	Summary string `json:"summary"`

	DedupDropped int          `json:"encoder_duplicate_keys_dropped"`
	Diag         *diagnostics `json:"diagnostics,omitempty"`
}

type diagnostics struct {
	AuthorHash  string   `json:"author_hash"`
	CapGrantee  string   `json:"capability_grantee"`
	GranteeSame bool     `json:"grantee_matches_author"`
	CapMatSize  int      `json:"forwarded_included_entries"`
	CapMatBad   int      `json:"forwarded_entries_failing_selfcheck"`
	CapMatNote  string   `json:"probe_selfcheck,omitempty"`
	Included    []string `json:"authenticate_included"`
}

// verdict maps the measurement onto the H1 vocabulary. Every arm names what it
// licenses, because "501" alone is read as a failure and here it is usually a correct
// answer from a peer that simply is not a host.
func verdict(r *report) (string, string) {
	switch {
	case !r.Trusted:
		return "UNTRUSTED", "the probe could not complete a legal put on this peer, so no row " +
			"below is a statement about the peer"
	case r.RegisterStatus != 200:
		return "REGISTER-REFUSED", fmt.Sprintf(
			"system/handler:register answered %d — the seam was never installed, so the dispatch "+
				"row says nothing about H1", r.RegisterStatus)
	// The differential comes FIRST, ahead of the landed arms, because it is the more
	// fundamental gate: if a never-registered path answers the same thing as the
	// registered one, no row below is attributable to the registration at all — whatever
	// else is also wrong. `wasm-wat` is the peer that made the ordering matter: it both
	// drops the expression_path AND answers 501 to the absent sibling, and reporting only
	// the first would imply its dispatch row could be read once the drop was fixed.
	case r.NegControl != "404":
		return "CONTROL-FAILED", fmt.Sprintf(
			"the never-registered sibling answered %s, not 404 — this peer does not discriminate "+
				"a registered pattern from an absent one, so its dispatch row is not an H1 answer "+
				"regardless of what else the run found", r.NegControl)
	case strings.HasPrefix(r.Landed, "bound WITHOUT"):
		// Deliberately its own verdict rather than CONTROL-FAILED. A single peer cannot
		// distinguish "this peer discards the body reference" from "the probe sent a
		// malformed manifest" — but the COHORT can, and that is where the ambiguity is
		// resolved: the identical request either persisted on other peers or it did not.
		// Naming it a control failure would file a peer property as our bug; naming it a
		// peer defect from one observation would be the overclaim in the other direction.
		return "REGISTER-DROPPED-EXPRESSION-PATH", "register answered 200 and bound a handler " +
			"carrying NO expression_path, so there was no body to reach and step 4 is not an H1 " +
			"answer. Resolve against the cohort: if peers persisted the identical request, this " +
			"is the peer discarding the body reference at register; if none did, suspect the probe"
	case strings.HasPrefix(r.Landed, "NOT bound"):
		return "CONTROL-FAILED", "register answered 200 and bound nothing at the pattern — " +
			"step 4 cannot distinguish a missing evaluator from a missing handler"
	case r.DispatchStatus == 200 && r.ResultValue == fmt.Sprint(seamLiteral):
		return "EVALUATES", "an installed entity-native body was dispatched AND evaluated: the " +
			"literal came back through the wire. H1 is satisfiable on this peer in the " +
			"entity-native (model 3) shape"
	case r.DispatchStatus == 200:
		return "EVALUATES-UNVERIFIED", fmt.Sprintf(
			"dispatch answered 200 but the result did not carry the planted literal (type=%q "+
				"value=%q) — reachable, but this run cannot prove the expression is what ran",
			r.ResultType, r.ResultValue)
	case r.DispatchStatus == 501:
		return "BOUND-NOT-EVALUATED", fmt.Sprintf(
			"the §11.6.1 entities bound (%s) and dispatch answered 501/%s — the peer stores an "+
				"installed body and has no evaluator on the dispatch path. Conformant for a core "+
				"peer; NOT a host", r.Landed, r.DispatchCode)
	case r.DispatchStatus == 404:
		return "NOT-RESOLVED", fmt.Sprintf(
			"dispatch answered 404/%s at a pattern the register reported binding (%s) — §6.6 "+
				"resolution does not see what register wrote", r.DispatchCode, r.Landed)
	case r.DispatchStatus == 403:
		return "AUTHZ-REFUSED", "dispatch answered 403 — the connection grants do not reach the " +
			"installed pattern. Probe-side scope, not an H1 answer"
	default:
		return "OTHER", fmt.Sprintf("dispatch answered %d/%s", r.DispatchStatus, r.DispatchCode)
	}
}

func main() {
	// Args are parsed BY HAND, tolerating unknown flags, because this binary is dropped
	// into every peer's run-s4.sh via ORACLE= and therefore receives whatever the harness
	// passes the real validator (`-profile core -json-out <path>`, possibly
	// `-reference-peer <addr>`). The flag package would abort on those.
	addr, out, peer := "127.0.0.1:7777", "", ""
	dump := false
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
		case "-dump", "--dump":
			dump = true
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

	if dump {
		pub := []byte(probeKey().Public().(ed25519.PublicKey))
		fmt.Printf("probe peer_id: %s\n", peerIDOf(pub))
		fmt.Printf("pattern:       %s\n", seamPattern)
		fmt.Printf("expr path:     %s\n", seamExprPath)
		fmt.Printf("literal:       %d\n", seamLiteral)
		fmt.Printf("expr entity=%x\n", computeLiteralEntity())
		fmt.Printf("register req=%x\n", registerRequestEntity(seamPattern, seamExprPath))
		return
	}

	to := 10 * time.Second
	r := report{Peer: peer, Addr: addr, Steps: []step{}}

	rec := func(id, what string, env map[string]interface{}, err error) (int, string) {
		st := step{ID: id, What: what}
		var status int
		var code string
		if err != nil {
			st.Err = err.Error()
		} else {
			status, code, _ = statusOf(env)
			st.Status, st.Code = status, code
			st.Message = messageOf(env)
		}
		r.Steps = append(r.Steps, st)
		return status, code
	}

	// ---- positive control, on its own connection ------------------------------------
	//
	// First and separate: if a legal put does not answer 200 here, everything after is a
	// probe-side fault and must not be published as a peer answer.
	{
		s, err := dialSession(addr, to)
		if err != nil {
			r.Control = "session: " + err.Error()
		} else {
			env, err := s.authedExecute("control", "system/tree", "put",
				putParams(controlEntity()), []string{"local/hostseam/control"})
			s.close()
			st, code := rec("P_control_valid_put", "a plain valid put MUST answer 200", env, err)
			r.Trusted = st == 200
			r.Control = fmt.Sprintf("valid put -> %d %s", st, code)
			if err != nil {
				r.Control = "valid put -> " + err.Error()
			}
		}
	}
	if !r.Trusted {
		r.Control += " | UNTRUSTED: the probe could not complete a legal put on this peer, so " +
			"the measurement is SUPPRESSED rather than reported"
		if s, err := dialSession(addr, to); err == nil {
			r.Diag = &diagnostics{
				AuthorHash:  hex.EncodeToString(s.selfHash),
				CapGrantee:  s.diagGrantee,
				GranteeSame: s.diagGrantee == hex.EncodeToString(s.selfHash),
				CapMatSize:  len(s.capMat),
				CapMatBad:   s.capMatBad,
				CapMatNote:  s.capMatNote,
				Included:    s.diagIncluded,
			}
			s.close()
		}
		r.Verdict, r.Summary = verdict(&r)
		r.DedupDropped = dedupDropped
		emit(r, out)
		return
	}

	// ---- the sequence ---------------------------------------------------------------
	//
	// One session, because bind -> register -> dispatch is a state machine and re-dialling
	// between steps would test a different thing. A peer that answers a refusal by closing
	// the connection (the §6.3 transport-drop defect recorded five times in this repo)
	// shows up as an error on the FOLLOWING step, which the per-step `error` field makes
	// visible rather than silent.
	s, err := dialSession(addr, to)
	if err != nil {
		r.Summary = "session after control: " + err.Error()
		r.Verdict = "ERROR"
		r.DedupDropped = dedupDropped
		emit(r, out)
		return
	}
	defer s.close()

	// 1. bind the body.
	env, err := s.authedExecute("bind", "system/tree", "put",
		putParams(computeLiteralEntity()), []string{seamExprPath})
	bindSt, _ := rec("1_bind_expression", "put the compute/literal body at "+seamExprPath, env, err)

	// 2. register the handler naming it.
	env, err = s.authedExecute("register", "system/handler", "register",
		registerRequestEntity(seamPattern, seamExprPath),
		[]string{"system/handler/" + seamPattern})
	regSt, _ := rec("2_register_handler", "system/handler:register naming that expression_path", env, err)
	r.RegisterStatus = regSt

	// 3. LANDED control — did the register actually write the handler entity?
	env, err = s.authedExecute("landed", "system/tree", "get", emptyParams(), []string{seamPattern})
	landedSt, landedCode := rec("3_landed_control", "get the handler entity register should have bound", env, err)
	// `system/tree:get` answers with the entity itself, so result.data IS the handler's
	// data map. Reporting only "bound" is not enough and the probe's own first run is
	// why: the entity landed, register answered 200, and the handler carried NO
	// `expression_path` because the probe had wrapped the manifest wrongly — which
	// reads, at step 4, as "this peer has no evaluator". The control has to assert the
	// field the measurement depends on, not merely that something was written.
	switch {
	case err != nil:
		r.Landed = "inconclusive: " + err.Error()
	case landedSt == 200:
		hasExpr := false
		if d := rootData(env); d != nil {
			if res, ok := d["result"].(map[string]interface{}); ok {
				if rd, ok := res["data"].(map[string]interface{}); ok {
					if v, ok := rd["expression_path"].(string); ok && v != "" {
						hasExpr = true
					}
				}
			}
		}
		if hasExpr {
			r.Landed = "bound WITH expression_path"
		} else {
			r.Landed = "bound WITHOUT expression_path — the peer accepted the register and " +
				"dropped the body reference, so step 4 cannot be read as an H1 answer"
		}
	case landedSt == 404:
		r.Landed = "NOT bound (404) — register reported success and wrote nothing"
	default:
		r.Landed = fmt.Sprintf("inconclusive (%d %s)", landedSt, landedCode)
	}

	// 4. THE MEASUREMENT — dispatch to the installed pattern.
	env, err = s.authedExecute("dispatch", seamPattern, "compute", emptyParams(), []string{seamPattern})
	dSt, dCode := rec("4_DISPATCH", "EXECUTE at the installed pattern — the measurement", env, err)
	r.DispatchStatus, r.DispatchCode = dSt, dCode
	if err == nil {
		if d := rootData(env); d != nil {
			if res, ok := d["result"].(map[string]interface{}); ok {
				r.ResultType, _ = res["type"].(string)
				if rd, ok := res["data"].(map[string]interface{}); ok {
					if v, ok := rd["value"]; ok {
						r.ResultValue = fmt.Sprint(v)
					}
				}
			}
		}
	}

	// 5. NEGATIVE / DIFFERENTIAL control — the same dispatch at a never-registered
	// sibling. Exactly one thing differs: whether step 2 happened.
	env, err = s.authedExecute("neg", seamAbsentPattern, "compute", emptyParams(),
		[]string{seamAbsentPattern})
	nSt, nCode := rec("5_negative_control", "same dispatch at a never-registered sibling — MUST be 404", env, err)
	if err != nil {
		r.NegControl = "error: " + err.Error()
	} else {
		r.NegControl = fmt.Sprint(nSt)
		if nCode != "" {
			r.NegControl = fmt.Sprintf("%d %s", nSt, nCode)
		}
		if nSt == 404 {
			r.NegControl = "404"
		}
	}

	_ = bindSt
	r.Verdict, r.Summary = verdict(&r)
	r.DedupDropped = dedupDropped
	emit(r, out)
}

func emit(r report, out string) {
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Printf("host-seam-probe %s @ %s\n", r.Peer, r.Addr)
	for _, s := range r.Steps {
		switch {
		case s.Err != "":
			fmt.Printf("  %-22s ERROR %s\n", s.ID, s.Err)
		default:
			fmt.Printf("  %-22s %3d %s\n", s.ID, s.Status, s.Code)
		}
	}
	fmt.Printf("  control: %s\n", r.Control)
	fmt.Printf("  VERDICT: %s — %s\n", r.Verdict, r.Summary)
	if out != "" {
		if err := os.WriteFile(out, b, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "host-seam-probe: write %s: %v\n", out, err)
		}
	}
}
