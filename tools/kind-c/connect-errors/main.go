// kind-c/connect-errors — an INDEPENDENT CHECK of §4.7's connection-error table.
//
// KIND C. `docs/VERIFICATION-ARCHITECTURE.md` defines the three kinds and what each
// may conclude. This is the third: a keystone-authored check aimed at the SAME
// normative target as the oracle, authored from the SPEC and not from the oracle's
// source. Agreement is corroboration. Disagreement is a finding, and it is routed —
// never carried privately, because a silently divergent test set manufactures a
// second de-facto standard, which is the one thing this repo must not do.
//
// WHAT IT MAY CONCLUDE, AND THE TERM THIS WORK EXISTS UNDER.
//
//	An official full-green pass requires the independent test suite. This is not it.
//
// A peer is conformant because `validate-peer` — a suite this repo does not author —
// says so. Nothing here supplements that, overrides it, or enters a published number.
// Concretely and structurally: this binary REFUSES to write a path matching
// `status/CONFORMANCE-REPORT.*`, so it cannot reach the three gates that make a
// published number mean the oracle. `tools/kind-c-gate.py` asserts that boundary.
//
// DERIVATION. Every expectation below cites the sentence it came from, by section,
// in `protocol-generator/shared/spec-data/v0.8.2.11/ENTITY-CORE-PROTOCOL.md`. Where
// the spec permits more than one conformant answer the case is ADVISORY and both
// answers are recorded — flattening a MAY into a MUST is how a second test set
// starts legislating, and §4.5's key_type reject point is exactly such a case.
//
// WHY THIS SURFACE. `VERIFICATION-ARCHITECTURE.md` increment 4 asks for a surface we
// have just implemented from the spec, where the reading is fresh and independent by
// construction rather than by discipline. §4.7's table is that surface: it was
// implemented on `go` on 2026-09-07 from the spec text, and 45 peers are owed the
// same. This runs ahead of that propagation as its inner loop — but the propagation
// is landed by the oracle's verdict, never by this one.
//
// THE CONTROLS, BOTH REQUIRED. A probe fails in the direction of the answer it is
// looking for; this repo has published three confident wrong findings that way.
//
//  1. POSITIVE — a plain, valid hello on a fresh connection MUST answer 200. If it
//     does not, the fault is OURS: the peer is marked `trusted: false` and every
//     result is SUPPRESSED rather than reported.
//  2. DIFFERENTIAL — an unknown operation on a REGISTERED, non-connect handler MUST
//     answer `501 unsupported_operation` (§3.3's 501 row, §6.2). This is the control
//     that gives the two unknown-operation cases their meaning: §4.7 row 10's 400 is
//     scoped to the CONNECT handler, and a peer can satisfy row 10 by making every
//     unknown operation 400 — trading one contract for another and passing this
//     check for the wrong reason. Measured together, the trade is visible; measured
//     apart, it is not. It is the concrete reason to want a second lineage at all.
//
// Usage — argv is parsed by hand and tolerates the flags the real validator takes,
// so this drops into any peer's run-s4.sh via ORACLE= and inherits its container and
// startup harness unchanged:
//
//	kind-c-connect-errors -addr 127.0.0.1:7777 [-json-out report.json] [-peer name]
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
	return fmt.Sprintf("kind-c-%s-%d", tag, s.seq)
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

// ---------- spec-derived expectations ----------
//
// Every entry cites the sentence it was authored from. The citations are to
// protocol-generator/shared/spec-data/v0.8.2.11/ENTITY-CORE-PROTOCOL.md, which is a
// SHA-256-pinned verbatim snapshot (MANIFEST.md) — so "the spec says" here is a
// checkable claim about specific bytes, not a memory of one.

type want struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
}

func (w want) String() string { return fmt.Sprintf("%d %s", w.Status, w.Code) }

type observation struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
	Err     string `json:"error,omitempty"`
}

type kase struct {
	ID      string `json:"id"`
	Class   string `json:"class"` // MUST | ADVISORY
	Section string `json:"section"`
	Basis   string `json:"basis"`
	Want    want   `json:"want"`
	Alt     *want  `json:"also_conformant,omitempty"`
	AltNote string `json:"also_conformant_note,omitempty"`
	run     func(addr string, to time.Duration) observation
}

// ---------- frame builders ----------

// helloParams builds a `system/protocol/connect/hello`.
//
// `protocols == nil` OMITS the field; a non-nil pointer to an empty slice emits an
// EMPTY ARRAY. The distinction is the whole point of two of the cases below — §4.5
// makes `protocols` "Required with no default", and both shapes are the same refusal
// (`400 invalid_request`) while a non-empty disjoint set is a different one.
func helloParams(pid string, protocols *[]string, hashFormats, keyTypes []string) []byte {
	ps := []pair{
		{txt("peer_id"), txt(pid)},
		// The initiator nonce is carried because several peers' hello schema
		// requires it and the rest ignore it; its absence was measured (p47-probe)
		// to produce `400 connection_sequence_error` on three peers, which reads
		// exactly like a §4.7 answer and is an objection to the frame instead.
		{txt("nonce"), bstr(bytes.Repeat([]byte{0x2b}, 32))},
		{txt("timestamp"), uint64v(uint64(time.Now().UnixMilli()))},
	}
	if protocols != nil {
		vs := make([][]byte, 0, len(*protocols))
		for _, p := range *protocols {
			vs = append(vs, txt(p))
		}
		ps = append(ps, pair{txt("protocols"), arr(vs...)})
	}
	hv := make([][]byte, 0, len(hashFormats))
	for _, h := range hashFormats {
		hv = append(hv, txt(h))
	}
	ps = append(ps, pair{txt("hash_formats"), arr(hv...)})
	kv := make([][]byte, 0, len(keyTypes))
	for _, k := range keyTypes {
		kv = append(kv, txt(k))
	}
	ps = append(ps, pair{txt("key_types"), arr(kv...)})
	return entity("system/protocol/connect/hello", cmap(ps...))
}

func strs(v ...string) *[]string { s := v; return &s }

var (
	defProtocols   = strs("entity-core/1.0")
	defHashFormats = []string{"ecfv1-sha256"}
	defKeyTypes    = []string{"ed25519"}
)

// unverifiableKeyTypePeerID — a WELL-FORMED peer_id naming a key_type no peer can
// verify. §1.5's seed table reserves 0x0B–0xEF for "future real algorithms", so 0x40
// is allocated to nothing and cannot be implemented by anyone; §1.5 pins the answer:
// "Impls receiving a `key_type` they do not support MUST return 400
// unsupported_key_type (§4.7)".
//
// 0x02 (Ed448) and 0xFE (experimental-test) were both rejected as the input here for
// the same reason: peers legitimately implement them (Haskell's crypton and Elixir's
// OTP :crypto carry Ed448; 0xFE is the agility-validation stub), so a 200 would be a
// correct answer and the case would measure the peer's crypto inventory instead of
// its §4.5 gate.
func unverifiableKeyTypePeerID() string {
	pub := []byte(probeKey().Public().(ed25519.PublicKey))
	return base58(append([]byte{0x40, 0x00}, pub...))
}

// foreignPeerID — a syntactically valid Ed25519 peer_id that is not the peer under
// test. Derived from a different seed so it is a real identity-form id rather than a
// string that might be refused as malformed before the address gate is reached.
func foreignPeerID() string {
	seed := bytes.Repeat([]byte{0x77}, 32)
	pub := []byte(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	return peerIDOf(pub)
}

// authenticateFrame — a structurally complete `authenticate` with a real signature
// over its own params hash. Only the NONCE is wrong, because no nonce was ever
// issued on a connection that has seen no hello — which is the input under test.
// Everything else is valid so that a peer parsing params before checking sequence
// still reaches its sequence check.
func (s *session) authenticateFrame(nonce []byte) []byte {
	authData := cmap(
		pair{txt("peer_id"), txt(s.peerID)},
		pair{txt("public_key"), bstr(s.pub)},
		pair{txt("key_type"), txt("ed25519")},
		pair{txt("nonce"), bstr(nonce)},
	)
	authHash := contentHash("system/protocol/connect/authenticate", authData)
	sigData := cmap(
		pair{txt("target"), bstr(authHash)},
		pair{txt("signer"), bstr(s.selfHash)},
		pair{txt("algorithm"), txt("ed25519")},
		pair{txt("signature"), bstr(ed25519.Sign(s.priv, authHash))},
	)
	rootData := cmap(
		pair{txt("request_id"), txt(s.rid("auth"))},
		pair{txt("uri"), txt("system/protocol/connect")},
		pair{txt("operation"), txt("authenticate")},
		pair{txt("params"), entity("system/protocol/connect/authenticate", authData)},
	)
	return cmap(
		pair{txt("root"), entity("system/protocol/execute", rootData)},
		pair{txt("included"), cmap(
			pair{bstr(s.selfHash), s.selfEnt},
			pair{bstr(contentHash("system/signature", sigData)), entity("system/signature", sigData)},
		)},
	)
}

// plainExec — an EXECUTE with no author, no capability and no signature, on an
// arbitrary URI. Used for the two pre-establishment address cases.
func (s *session) plainExec(rid, uri, op string) []byte {
	data := cmap(
		pair{txt("request_id"), txt(rid)},
		pair{txt("uri"), txt(uri)},
		pair{txt("operation"), txt(op)},
		pair{txt("params"), emptyParams()},
	)
	return cmap(pair{txt("root"), entity("system/protocol/execute", data)},
		pair{txt("included"), cmap()})
}

// ---------- dialers ----------

// dialRaw opens a connection and prepares an identity WITHOUT performing the
// handshake. Every pre-establishment case needs this; `dialSession` (the full
// handshake) is only for the two cases whose input is defined as arriving on an
// ESTABLISHED connection.
func dialRaw(addr string, to time.Duration) (*session, error) {
	c, err := net.DialTimeout("tcp", addr, to)
	if err != nil {
		return nil, err
	}
	priv := probeKey()
	pub := []byte(priv.Public().(ed25519.PublicKey))
	s := &session{c: c, to: to, priv: priv, pub: pub, peerID: peerIDOf(pub)}
	peerData := cmap(
		pair{txt("public_key"), bstr(pub)},
		pair{txt("key_type"), txt("ed25519")},
	)
	s.selfEnt = entity("system/peer", peerData)
	s.selfHash = contentHash("system/peer", peerData)
	return s, nil
}

func obsErr(format string, a ...interface{}) observation {
	return observation{Err: fmt.Sprintf(format, a...)}
}

func obsOf(env map[string]interface{}) observation {
	st, code, _ := statusOf(env)
	return observation{Status: st, Code: code, Message: messageOf(env)}
}

// oneShot: fresh connection, one frame, read the answer.
func oneShot(addr string, to time.Duration, build func(s *session) []byte) observation {
	s, err := dialRaw(addr, to)
	if err != nil {
		return obsErr("dial: %v", err)
	}
	defer s.close()
	env, _, err := s.send(build(s))
	if err != nil {
		return obsErr("send: %v", err)
	}
	return obsOf(env)
}

// afterHello: fresh connection, a VALID hello that must answer 200, then the frame
// under test. The 200 is a per-case control — if the hello is refused, the
// connection is not half-open and whatever the second frame gets is not the answer
// to the question being asked.
func afterHello(addr string, to time.Duration, build func(s *session) []byte) observation {
	s, err := dialRaw(addr, to)
	if err != nil {
		return obsErr("dial: %v", err)
	}
	defer s.close()
	env, _, err := s.send(s.connectEnv(s.rid("hello"),
		"hello", helloParams(s.peerID, defProtocols, defHashFormats, defKeyTypes)))
	if err != nil {
		return obsErr("setup hello: %v", err)
	}
	if st, code, _ := statusOf(env); st != 200 {
		return obsErr("setup hello -> %d %s (connection never reached half-open; "+
			"the case below could not be asked)", st, code)
	}
	env2, _, err := s.send(build(s))
	if err != nil {
		return obsErr("send: %v", err)
	}
	return obsOf(env2)
}

// established: full handshake, then the frame under test.
func established(addr string, to time.Duration, build func(s *session) []byte) observation {
	s, err := dialSession(addr, to)
	if err != nil {
		return obsErr("handshake: %v", err)
	}
	defer s.close()
	env, _, err := s.send(build(s))
	if err != nil {
		return obsErr("send: %v", err)
	}
	return obsOf(env)
}

// helloCase is the shape shared by the five negotiation cases: one fresh
// connection, one hello varying exactly one field from the valid form.
func helloCase(protocols *[]string, hashFormats, keyTypes []string, pid string) func(string, time.Duration) observation {
	return func(addr string, to time.Duration) observation {
		return oneShot(addr, to, func(s *session) []byte {
			p := pid
			if p == "" {
				p = s.peerID
			}
			return s.connectEnv(s.rid("hello"), "hello",
				helloParams(p, protocols, hashFormats, keyTypes))
		})
	}
}

var cases = []kase{
	{
		ID:      "connect_unknown_operation_fresh",
		Class:   "MUST",
		Section: "§4.7 table row 10 (0.8.2.4)",
		Basis: "\"Unknown connect operation — an operation name the responder does not " +
			"implement, in any state | invalid_request | 400\". Scoped \"in any state\", so " +
			"this arm covers a fresh connection as well as an established one; and \"an " +
			"unknown connect operation is not out of order at all; it exists in no state\", " +
			"which is why it is NOT connection_sequence_error.",
		Want: want{400, "invalid_request"},
		run: func(addr string, to time.Duration) observation {
			return oneShot(addr, to, func(s *session) []byte {
				return s.connectEnv(s.rid("unkop"), "frobnicate", emptyParams())
			})
		},
	},
	{
		ID:      "connect_unknown_operation_established",
		Class:   "MUST",
		Section: "§4.7 table row 10 (0.8.2.4)",
		Basis: "The same row, exercised in the other state the words \"in any state\" reach. " +
			"Separated from the fresh-connection case because a peer that special-cases the " +
			"pre-handshake path satisfies one and not the other.",
		Want: want{400, "invalid_request"},
		run: func(addr string, to time.Duration) observation {
			return established(addr, to, func(s *session) []byte {
				return s.connectEnv(s.rid("unkop"), "frobnicate", emptyParams())
			})
		},
	},
	{
		ID:      "hello_second_on_half_open",
		Class:   "MUST",
		Section: "§4.7 out-of-order row + the 0.8.2.8 half-open note",
		Basis: "\"A connection that has completed hello but not authenticate is half-open: " +
			"it is not established. The out-of-order row above governs it — a connect " +
			"operation the responder implements, arriving in a state that forbids it\" -> " +
			"409 connection_sequence_error. The note exists because \"two adjacent rules " +
			"each look like they cover it and neither does\": connection_already_established " +
			"cannot reach a half-open connection, and the invalid_nonce row is scoped to a " +
			"pre-HELLO authenticate.",
		Want: want{409, "connection_sequence_error"},
		run: func(addr string, to time.Duration) observation {
			return afterHello(addr, to, func(s *session) []byte {
				return s.connectEnv(s.rid("hello2"), "hello",
					helloParams(s.peerID, defProtocols, defHashFormats, defKeyTypes))
			})
		},
	},
	{
		ID:      "hello_second_on_established",
		Class:   "MUST",
		Section: "§4.7 table, connection-already-established row",
		Basis: "\"Connection already established | connection_already_established | 409\". " +
			"Paired with the half-open case deliberately: the two inputs differ only in how " +
			"far the handshake got, they take DIFFERENT codes, and a peer that collapses them " +
			"fails the contract §4.7 states it exists to provide (\"clients key error handling " +
			"off result.data.code\").",
		Want: want{409, "connection_already_established"},
		run: func(addr string, to time.Duration) observation {
			return established(addr, to, func(s *session) []byte {
				return s.connectEnv(s.rid("hello3"), "hello",
					helloParams(s.peerID, defProtocols, defHashFormats, defKeyTypes))
			})
		},
	},
	{
		ID:      "hello_protocols_absent",
		Class:   "MUST",
		Section: "§4.5 (0.8.2.4) + §4.7's invalid_request paragraph",
		Basis: "\"A hello carrying no protocols field, or an empty list, MUST be rejected " +
			"with 400 invalid_request — it is a malformed request, not a version " +
			"incompatibility.\" protocols is \"Required with no default, so there is no floor " +
			"to fall back to\".",
		Want: want{400, "invalid_request"},
		run:  helloCase(nil, defHashFormats, defKeyTypes, ""),
	},
	{
		ID:      "hello_protocols_empty",
		Class:   "MUST",
		Section: "§4.5 (0.8.2.4)",
		Basis: "The second half of the same sentence — \"or an empty list\". Held as its own " +
			"case because a peer reading the field and testing only for presence passes the " +
			"absent case and fails this one.",
		Want: want{400, "invalid_request"},
		run:  helloCase(strs(), defHashFormats, defKeyTypes, ""),
	},
	{
		ID:      "hello_protocols_disjoint",
		Class:   "MUST",
		Section: "§4.5 + §4.7 table row 1",
		Basis: "\"400 incompatible_protocol is reserved for a non-empty set that does not " +
			"intersect the responder's: that code tells the caller 'we compared and share " +
			"nothing,' and a caller that named no version cannot be told the comparison " +
			"failed. The remedies differ — send the field versus change the version — and " +
			"§4.7 exists so the code selects the remedy.\" The value sent is a §8.4-shaped " +
			"identifier that no responder can support.",
		Want: want{400, "incompatible_protocol"},
		run:  helloCase(strs("entity-core/99.0"), defHashFormats, defKeyTypes, ""),
	},
	{
		ID:      "hello_hash_formats_disjoint",
		Class:   "MUST",
		Section: "§4.5 single-active-value + §4.7 table row 2",
		Basis: "\"An empty hash_formats intersection MUST be rejected with 400 " +
			"incompatible_hash_format (§4.7).\" Included as the third distinct 400 on one " +
			"frame shape: three negotiated fields, three codes, and the table is a " +
			"MUST-emit contract on the pair.",
		Want: want{400, "incompatible_hash_format"},
		run:  helloCase(defProtocols, []string{"ecfv1-sha3-512"}, defKeyTypes, ""),
	},
	{
		ID:      "hello_key_types_excludes_responder",
		Class:   "MUST",
		Section: "§4.5 mutual verifiability + §4.7 table row 3",
		Basis: "\"each peer's own identity key_type MUST appear in the other peer's " +
			"advertised key_types set … If either peer's own key_type is absent from the " +
			"other's set, the responder MUST reject with 400 unsupported_key_type\", and " +
			"\"The responder-side gate (own key_type ∈ initiator's set) is the MUST.\" The " +
			"advertised set is ed448 — a real, allocated code (§1.5 0x02) so the field parses, " +
			"and one no cohort peer's IDENTITY is bound to, which isolates the accept-set " +
			"logic from the peer's crypto inventory.",
		Want: want{400, "unsupported_key_type"},
		run:  helloCase(defProtocols, defHashFormats, []string{"ed448"}, ""),
	},
	{
		ID:      "prehello_authenticate",
		Class:   "MUST",
		Section: "§4.7 table row 6 + the FM-1 note (0.8.2.1), §4.6 step 1, §4.2",
		Basis: "\"An authenticate arriving before any hello nonce was issued is not the " +
			"out-of-order row: it is pinned to 401 invalid_nonce by §4.2, §4.6 step 1 and " +
			"row 6 above.\" Carried here because it is the one row of this table whose " +
			"reading was contested across the cohort, and a second lineage measuring it is " +
			"the cheapest form of corroboration available.",
		Want: want{401, "invalid_nonce"},
		run: func(addr string, to time.Duration) observation {
			return oneShot(addr, to, func(s *session) []byte {
				return s.authenticateFrame(bytes.Repeat([]byte{0x5a}, 32))
			})
		},
	},
	{
		ID:      "preestablish_own_namespace_nonconnect",
		Class:   "MUST",
		Section: "§4.7's 0.8.2.5 note + §4.2 third pre-authorization rule + §5.2a",
		Basis: "\"An EXECUTE naming any other path, arriving before the handshake completes, " +
			"is governed by §4.2's third pre-authorization rule and §5.2a: it carries no " +
			"verified signer, so it is auth-class and MUST be refused 401 " +
			"authentication_failed.\" And: \"Implementations MUST NOT emit connection_required " +
			"or handshake_failed\" — both were observed standing in for this rule, so the CODE " +
			"is asserted and not only the status.",
		Want: want{401, "authentication_failed"},
		run: func(addr string, to time.Duration) observation {
			return oneShot(addr, to, func(s *session) []byte {
				return s.plainExec(s.rid("preown"), "system/tree", "get")
			})
		},
	},
	{
		ID:      "preestablish_foreign_namespace",
		Class:   "MUST",
		Section: "§4.7's 0.8.2.6 address table + §1.4 inbound dispatch + §6.5 step 3",
		Basis: "\"Address is evaluated before authentication\" — the pre-establishment table " +
			"gives Foreign namespace -> invalid_request / 400, ahead of the 401 the row above " +
			"it takes, because \"a 401 directs the caller to authenticate and retry, and for a " +
			"foreign-namespace address that retry cannot succeed at any authentication state\". " +
			"§1.4: \"If the peer ID does not match the local peer, the peer MUST reject with " +
			"status 400 (invalid_request).\" The URI is §1.4's own entity:// example form.",
		Want: want{400, "invalid_request"},
		run: func(addr string, to time.Duration) observation {
			return oneShot(addr, to, func(s *session) []byte {
				return s.plainExec(s.rid("prefgn"), "entity://"+foreignPeerID()+"/system/tree", "get")
			})
		},
	},
	{
		ID:      "hello_initiator_key_type_unverifiable",
		Class:   "ADVISORY",
		Section: "§4.5 mutual verifiability + the v7.66 canonical-reject-point clarification",
		Basis: "The OTHER direction of mutual verifiability: the initiator's own key_type " +
			"rides in its peer_id, not in the key_types array, so a hello may advertise a " +
			"perfectly good accept-set and still name an identity the responder cannot verify. " +
			"§1.5: \"Impls receiving a key_type they do not support MUST return 400 " +
			"unsupported_key_type\". The key_type sent is 0x40, inside §1.5's 0x0B–0xEF " +
			"\"Reserved (future real algorithms)\" range, so it is allocated to nothing and no " +
			"peer can legitimately accept it.",
		Want: want{400, "unsupported_key_type"},
		Alt:  &want{200, ""},
		AltNote: "ADVISORY, and the spec is explicit that both answers conform: \"Hello " +
			"negotiation is the canonical earliest reject point … Implementations MAY ALSO " +
			"reject an unsupported key_type later in the handshake (at authenticate, on " +
			"peer_id decode …) AS A FALLBACK … rejecting at multiple surfaces is conformant\" " +
			"and \"hello-time reject is the canonical guidance for NEW implementations\". A 200 " +
			"here is therefore not a defect and MUST NOT be scored as one — it is a deferral " +
			"to a later surface, and this check does not follow it there. Recording the split " +
			"is the point: flattening a MAY into a MUST is how a second test set starts " +
			"legislating instead of measuring.",
		run: helloCase(defProtocols, defHashFormats, defKeyTypes, unverifiableKeyTypePeerID()),
	},
}

// ---------- controls ----------
//
// Two, and they answer different questions. A positive control catches a frame the
// peer objects to for reasons unrelated to the case; only the differential catches a
// frame that is well-formed and asks the WRONG QUESTION.

type control struct {
	ID      string      `json:"id"`
	Purpose string      `json:"purpose"`
	Want    want        `json:"want"`
	Got     observation `json:"got"`
	OK      bool        `json:"ok"`
}

// positiveControl — a plain, valid hello on a fresh connection. MUST answer 200.
//
// If it does not, every case in this run is measuring our envelope rather than the
// peer's §4.7 reading, so the peer is reported UNTRUSTED and its case results are
// suppressed. Measured precedent: a placeholder content_hash produced a bare 400 from
// `go` on a structurally perfect frame, and a numeric key_type produced 400
// unsupported_key_type from four peers — both would have published as findings.
func positiveControl(addr string, to time.Duration) control {
	c := control{
		ID: "positive_valid_hello",
		Purpose: "a valid hello must answer 200; anything else means the fault is ours " +
			"and this peer's results are suppressed rather than reported",
		Want: want{200, ""},
	}
	c.Got = oneShot(addr, to, func(s *session) []byte {
		return s.connectEnv(s.rid("control"), "hello",
			helloParams(s.peerID, defProtocols, defHashFormats, defKeyTypes))
	})
	c.OK = c.Got.Err == "" && c.Got.Status == 200
	return c
}

// differentialControl — an unknown operation on a REGISTERED, NON-CONNECT handler.
// MUST answer 501 unsupported_operation.
//
// THIS IS THE CONTROL THAT GIVES THE TWO UNKNOWN-OPERATION CASES THEIR MEANING, and
// it is the concrete argument for a second lineage rather than more coverage.
//
// §4.7 row 10's 400 is scoped to the CONNECT handler. §3.3's 501 row and §6.2 give
// the general rule for every other handler: "a handler IS registered at the path and
// does not implement the named operation" -> 501 unsupported_operation, and
// "unknown_operation is a synonym and MUST NOT be emitted". The two rules are
// adjacent, opposite, and easy to satisfy by moving one helper — a peer can pass
// row 10 by making EVERY unknown operation 400, which trades one contract for
// another and looks like a fix. Measured together the trade is visible; measured
// apart it is not.
//
// It requires a full handshake because a non-connect path is not pre-authorized
// (§4.2), and it asserts the CODE as well as the status because 0.8.2.7 blacklists
// four spellings of this one row.
func differentialControl(addr string, to time.Duration) control {
	c := control{
		ID: "differential_registered_handler_501",
		Purpose: "an unknown op on a registered NON-connect handler must still be 501 " +
			"unsupported_operation; a peer answering 400 here has made §4.7 row 10 " +
			"global and traded §3.3's 501 row away",
		Want: want{501, "unsupported_operation"},
	}
	s, err := dialSession(addr, to)
	if err != nil {
		c.Got = obsErr("handshake: %v", err)
		return c
	}
	defer s.close()
	env, err := s.authedExecute("diff", "system/tree", "frobnicate", emptyParams(), nil)
	if err != nil {
		c.Got = obsErr("send: %v", err)
		return c
	}
	c.Got = obsOf(env)
	c.OK = c.Got.Err == "" && c.Got.Status == 501 && c.Got.Code == "unsupported_operation"
	return c
}

// foreignAddressDifferential — the SAME foreign-namespace URI, on an ESTABLISHED
// connection. MUST answer 400 invalid_request (§1.4 inbound dispatch, §6.5 step 3).
//
// This is the differential the `preestablish_foreign_namespace` case requires, and
// the doc's rule is why it exists: a differential control is owed "wherever the input
// under test is a STATE rather than a VALUE". The state under test there is
// pre-establishment, and without this control two completely different explanations
// of a 401 are the same observation:
//
//	(a) the peer does not recognise our URI as foreign at all — a fault in THIS
//	    check, which would publish as a cohort defect; or
//	(b) the peer recognises it perfectly well and evaluates authentication first —
//	    which is the ordering §4.7's 0.8.2.6 note exists to forbid.
//
// If this control answers 400 and the pre-establishment case answered 401, the URI is
// fine and the ordering is the finding. If BOTH answer 401, suspect the instrument.
func foreignAddressDifferential(addr string, to time.Duration) control {
	c := control{
		ID: "differential_foreign_namespace_established",
		Purpose: "the same foreign-namespace URI after a full handshake must be 400 " +
			"invalid_request; it separates 'this check's URI is not recognised as " +
			"foreign' from 'the peer evaluates authentication before the address'",
		Want: want{400, "invalid_request"},
	}
	s, err := dialSession(addr, to)
	if err != nil {
		c.Got = obsErr("handshake: %v", err)
		return c
	}
	defer s.close()
	// FULLY AUTHENTICATED, and the first cut of this control was not — which made it
	// useless in the exact way it exists to prevent. Sent unsigned it answered `401
	// authentication_failed`, the same status as the case it was meant to
	// disambiguate, because an EXECUTE carrying no verified signer is auth-class by
	// §5.2a whatever its address. That varies TWO things at once (connection state
	// AND signature) and so discriminates nothing: a control that cannot separate
	// its own two explanations is not a control.
	//
	// Signed, authentication is satisfied and the address is the only question left,
	// so a 400 here means the URI IS recognised as foreign.
	env, err := s.authedExecute("fgnest", "entity://"+foreignPeerID()+"/system/tree",
		"get", emptyParams(), nil)
	if err != nil {
		c.Got = obsErr("send: %v", err)
		return c
	}
	c.Got = obsOf(env)
	c.OK = c.Got.Err == "" && c.Got.Status == 400 && c.Got.Code == "invalid_request"
	return c
}

// ---------- verdicts ----------

const (
	vPass       = "PASS"
	vFail       = "FAIL"
	vDeferred   = "DEFERRED"   // ADVISORY only: the other conformant answer
	vUnexpected = "UNEXPECTED" // ADVISORY only: neither conformant answer
	vError      = "ERROR"
)

func verdict(k kase, o observation) string {
	if o.Err != "" {
		return vError
	}
	if o.Status == k.Want.Status && (k.Want.Code == "" || o.Code == k.Want.Code) {
		return vPass
	}
	if k.Alt != nil && o.Status == k.Alt.Status && (k.Alt.Code == "" || o.Code == k.Alt.Code) {
		return vDeferred
	}
	if k.Class == "ADVISORY" {
		return vUnexpected
	}
	return vFail
}

// ---------- report ----------

type caseResult struct {
	kase
	Got     observation `json:"got"`
	Verdict string      `json:"verdict"`
}

type counts struct {
	Defined    int `json:"cases_defined"`
	Executed   int `json:"cases_executed"`
	Must       int `json:"must"`
	Advisory   int `json:"advisory"`
	Pass       int `json:"pass"`
	Fail       int `json:"fail"`
	Deferred   int `json:"deferred"`
	Unexpected int `json:"unexpected"`
	Error      int `json:"error"`
}

type report struct {
	Artifact string `json:"artifact"`
	Kind     string `json:"kind"`
	// The disclaimer is IN the artifact, not only in the README, because a JSON file
	// outlives the directory it was read from.
	NotAConformanceMeasurement string       `json:"not_a_conformance_measurement"`
	SpecSnapshot               string       `json:"spec_snapshot"`
	Sections                   []string     `json:"sections"`
	Peer                       string       `json:"peer"`
	Addr                       string       `json:"addr"`
	Trusted                    bool         `json:"trusted"`
	Note                       string       `json:"note,omitempty"`
	Controls                   []control    `json:"controls"`
	Counts                     counts       `json:"counts"`
	Cases                      []caseResult `json:"cases"`
	DedupDropped               int          `json:"encoder_dedup_dropped"`
}

const disclaimer = "This is a Kind C independent check (docs/VERIFICATION-ARCHITECTURE.md). " +
	"It is NOT a conformance measurement and MUST NOT be cited as one. An official " +
	"full-green pass requires the independent test suite — validate-peer — which this " +
	"repo does not author. Disagreement between this file and the oracle is a finding " +
	"to route, never a verdict to publish."

const specSnapshot = "v0.8.2.11 (protocol-generator/shared/spec-data/v0.8.2.11/, SHA-256-pinned in MANIFEST.md)"

func main() {
	// Parsed by hand, tolerating unknown flags, because this binary is dropped into
	// every peer's run-s4.sh via ORACLE= and therefore receives whatever the harness
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

	// THE PUBLICATION BOUNDARY, ENFORCED IN THE BINARY.
	//
	// Every peer's run-s4.sh defaults -json-out to that peer's TRACKED, signed-off
	// CONFORMANCE-REPORT.json, and a bare `./run-s4.sh` therefore hands us that path.
	// A Kind C artifact that writes it has silently republished a conformance number
	// from a suite this repo authored — the exact thing the operator's condition
	// forbids. Refusing here is structural: it does not depend on the caller reading
	// a README, and it fires on the invocation where the mistake is easiest to make.
	if out != "" && strings.Contains(filepath_ToSlash(out), "status/CONFORMANCE-REPORT") {
		fmt.Fprintf(os.Stderr,
			"kind-c/connect-errors: REFUSING to write %s\n"+
				"  That is a peer's tracked conformance report. This is a Kind C independent\n"+
				"  check, not a conformance measurement; an official green requires the\n"+
				"  independent suite (validate-peer). Write it under output/scratch/kind-c/.\n", out)
		os.Exit(4)
	}

	if dump {
		pub := []byte(probeKey().Public().(ed25519.PublicKey))
		fmt.Printf("probe peer_id            : %s\n", peerIDOf(pub))
		fmt.Printf("unverifiable-key peer_id : %s\n", unverifiableKeyTypePeerID())
		fmt.Printf("foreign peer_id          : %s\n\n", foreignPeerID())
		for _, k := range cases {
			fmt.Printf("%-42s %-8s want %-32s %s\n", k.ID, k.Class, k.Want.String(), k.Section)
		}
		return
	}

	if peer == "" && out != "" {
		base := out
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		base = strings.TrimSuffix(base, ".json")
		peer = base
	}

	to := 10 * time.Second
	rep := report{
		Artifact:                   "kind-c/connect-errors",
		Kind:                       "C",
		NotAConformanceMeasurement: disclaimer,
		SpecSnapshot:               specSnapshot,
		Sections:                   []string{"§4.7", "§4.5", "§4.2", "§1.4", "§1.5", "§3.3", "§6.2"},
		Peer:                       peer,
		Addr:                       addr,
	}

	// Controls FIRST. A failed positive control means the cases below are measuring
	// our envelope, so they are not run at all rather than run and discarded — a
	// suppressed result that was still computed invites someone to read it.
	pc := positiveControl(addr, to)
	rep.Controls = append(rep.Controls, pc)
	if !pc.OK {
		rep.Trusted = false
		rep.Note = fmt.Sprintf("UNTRUSTED — the positive control (a valid hello) answered "+
			"%d %s%s. The fault is the CHECK'S, not the peer's, until proven otherwise; no "+
			"case was executed and no conclusion may be drawn about this peer.",
			pc.Got.Status, pc.Got.Code, errSuffix(pc.Got))
		emit(rep, out)
		os.Exit(3)
	}
	rep.Trusted = true
	dc := differentialControl(addr, to)
	rep.Controls = append(rep.Controls, dc)
	fd := foreignAddressDifferential(addr, to)
	rep.Controls = append(rep.Controls, fd)

	for _, k := range cases {
		o := k.run(addr, to)
		rep.Cases = append(rep.Cases, caseResult{kase: k, Got: o, Verdict: verdict(k, o)})
	}

	// COUNTS, PRINTED AND ASSERTED. A gate that examines zero things prints the same
	// word as one that examines fourteen; this repo has shipped that defect at least
	// six times. `cases_executed` is compared against `cases_defined` below and a
	// mismatch is a hard error regardless of how the cases scored.
	rep.Counts.Defined = len(cases)
	rep.Counts.Executed = len(rep.Cases)
	for _, c := range rep.Cases {
		switch c.Class {
		case "MUST":
			rep.Counts.Must++
		case "ADVISORY":
			rep.Counts.Advisory++
		}
		switch c.Verdict {
		case vPass:
			rep.Counts.Pass++
		case vFail:
			rep.Counts.Fail++
		case vDeferred:
			rep.Counts.Deferred++
		case vUnexpected:
			rep.Counts.Unexpected++
		case vError:
			rep.Counts.Error++
		}
	}
	rep.DedupDropped = dedupDropped

	// Read the foreign-address pair TOGETHER, and say which of the two readings the
	// evidence supports rather than leaving the caller to infer it. A FAIL whose
	// differential also failed is not a finding about the peer — it is a reason to
	// distrust this check, and it must say so in its own output. (When one peer of a
	// cohort refuses what the others accept, the prior belongs on the instrument.)
	for _, c := range rep.Cases {
		if c.ID != "preestablish_foreign_namespace" || c.Verdict != vFail {
			continue
		}
		if fd.OK {
			rep.Note = "ORDERING CONFIRMED: this peer answers 400 invalid_request to the " +
				"same foreign-namespace URI once ESTABLISHED, so the address IS recognised " +
				"and the pre-establishment 401 is §4.7 0.8.2.6's evaluation order, not a " +
				"malformed URI from this check. Route it; do not fix a peer off this line alone."
		} else {
			rep.Note = "AMBIGUOUS — SUSPECT THIS CHECK, NOT THE PEER: the differential " +
				"(same URI, established connection) did not answer 400 invalid_request " +
				"either, so this peer may not be recognising the URI as foreign at all. " +
				"The case result above is NOT reportable as a finding until that is resolved."
		}
	}

	emit(rep, out)

	if rep.Counts.Executed != rep.Counts.Defined {
		fmt.Fprintf(os.Stderr, "kind-c/connect-errors: INTERNAL — executed %d of %d defined cases\n",
			rep.Counts.Executed, rep.Counts.Defined)
		os.Exit(5)
	}
	if !dc.OK {
		os.Exit(2)
	}
	if rep.Counts.Fail > 0 || rep.Counts.Error > 0 {
		os.Exit(1)
	}
}

func errSuffix(o observation) string {
	if o.Err == "" {
		return ""
	}
	return " (" + o.Err + ")"
}

// filepath_ToSlash without importing path/filepath — the only platform this runs on
// is Linux inside a container, and a one-line normalisation keeps the import list
// identical to the probe plumbing this file borrows.
func filepath_ToSlash(p string) string { return strings.ReplaceAll(p, "\\", "/") }

func emit(rep report, out string) {
	// Human output. The COUNT line is first because it is the one thing that
	// distinguishes a run from a no-op.
	fmt.Printf("kind-c/connect-errors — %s @ %s\n", rep.Peer, rep.Addr)
	fmt.Printf("  spec: %s\n", rep.SpecSnapshot)
	fmt.Printf("  NOT a conformance measurement. An official green requires validate-peer.\n")
	for _, c := range rep.Controls {
		status := "ok"
		if !c.OK {
			status = "FAILED"
		}
		fmt.Printf("  control %-38s %-6s got %d %s%s\n", c.ID, status, c.Got.Status, c.Got.Code,
			errSuffix(c.Got))
	}
	if !rep.Trusted {
		fmt.Printf("  UNTRUSTED — %s\n", rep.Note)
	}
	for _, c := range rep.Cases {
		fmt.Printf("  %-8s %-42s want %-34s got %d %s%s\n",
			c.Verdict, c.ID, c.Want.String(), c.Got.Status, c.Got.Code, errSuffix(c.Got))
	}
	fmt.Printf("  cases %d/%d executed · %d MUST · %d advisory · %dP %dF %dDEFERRED %dUNEXPECTED %dERR\n",
		rep.Counts.Executed, rep.Counts.Defined, rep.Counts.Must, rep.Counts.Advisory,
		rep.Counts.Pass, rep.Counts.Fail, rep.Counts.Deferred, rep.Counts.Unexpected, rep.Counts.Error)
	if rep.Trusted && rep.Note != "" {
		fmt.Printf("  note: %s\n", rep.Note)
	}
	if rep.DedupDropped > 0 {
		fmt.Printf("  encoder dropped %d duplicate map key(s) — expected 1 per authenticated "+
			"EXECUTE (our own peer entity is in the forwarded chain material)\n", rep.DedupDropped)
	}
	if out == "" {
		return
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kind-c/connect-errors: marshal: %v\n", err)
		return
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "kind-c/connect-errors: write %s: %v\n", out, err)
	}
}

// Keep the borrowed-plumbing imports honest: these are used by the copied session
// code (hex in dialSession's diagnostics, sha256/big/sort in the encoder+identity).
var _ = hex.EncodeToString
var _ = sha256.Sum256
var _ = big.NewInt
var _ = sort.Strings
