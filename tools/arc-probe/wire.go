// wire.go — canonical-ECF encoder/decoder, framing, identity and the §4 handshake.
//
// PROVENANCE: lines 63–684 of `tools/f68-probe/main.go`, copied VERBATIM rather
// than re-derived. Every comment in it records a defect that cost a session to
// find — the duplicate-key dedup (csharp refused a malformed frame and was
// published as the outlier), the `peer_id`-out-of-basis rule (§3.5 v7.65, which
// §4.6's own pseudocode still contradicts), and `verifyCapMat`, the probe-side
// control without which a slicing bug and a peer defect are one observation.
// Re-typing it would have re-created them.
//
// The one thing NOT copied is `authedExecute`: this probe has to mutate the parts
// of an envelope that one builds correctly by construction, so it carries its own
// builder in main.go.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sort"
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

	// lastRaw is the raw bytes of the most recent response, kept because
	// `rawIncluded` slices byte SPANS out of it: a capability minted mid-run has
	// to be re-presented verbatim, and re-encoding a decoded structure changes a
	// content hash, which is indistinguishable from a peer refusing it.
	lastRaw []byte
	// lastCollision counts handshake-forwarded entries the forgery arm had to
	// displace. Reported, never silent: a displaced entry means the substitution
	// was contending with real material and the reader needs to know.
	lastCollision int
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
	s.lastRaw = body
	return m, body, nil
}

func (s *session) rid(tag string) string {
	s.seq++
	return fmt.Sprintf("arc-probe-%s-%d", tag, s.seq)
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

// authedExecuteRes is authedExecute with a caller-supplied resource `exclude`

// ---------- response readers (same provenance) ----------
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
