package entitycore

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// corpusPath locates the vendored wire-conformance corpus. The ECF corpus is
// byte-stable (it did not change across the V7 line and is unchanged in V8 —
// ECF 1.5); test-vectors/v0.8.0 is the single retained snapshot.
func corpusPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatalf("conformance corpus not found in any candidate path: %v", candidates)
	return ""
}

// vector is one decoded conformance vector.
type vector struct {
	id          string
	description string
	kind        string
	input       cbor.Value
	hasInput    bool
	canonical   []byte
}

// loadVectors decodes the CBOR-array-of-maps corpus into vectors. Per §E.3, a
// decoder bug surfaces here — the harness exercises the decoder before any
// vector test.
func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(corpusPath(t))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	// The corpus array uses a top-level CBOR array; decode it with the
	// internal decoder. The vectors are canonical maps with no tags, so the
	// strict decoder accepts them.
	top, err := cbor.Decode(raw)
	if err != nil {
		t.Fatalf("decode corpus (decoder bug?): %v", err)
	}
	if top.Kind != cbor.KindArray {
		t.Fatalf("corpus top-level is not an array, got kind %d", top.Kind)
	}
	var vecs []vector
	for _, vm := range top.Array {
		if vm.Kind != cbor.KindMap {
			t.Fatalf("vector is not a map")
		}
		var v vector
		for _, p := range vm.Map {
			key := p.Key.Text
			switch key {
			case "id":
				v.id = p.Val.Text
			case "description":
				v.description = p.Val.Text
			case "kind":
				v.kind = p.Val.Text
			case "input":
				v.input = p.Val
				v.hasInput = true
			case "canonical":
				v.canonical = p.Val.Bytes
			}
		}
		vecs = append(vecs, v)
	}
	return vecs
}

// category returns the part of an id before the first '.', e.g. "float.7" ->
// "float".
func category(id string) string {
	if i := strings.IndexByte(id, '.'); i >= 0 {
		return id[:i]
	}
	return id
}

// mapGet looks up a text key in a decoded map Value.
func mapGet(v cbor.Value, key string) (cbor.Value, bool) {
	if v.Kind != cbor.KindMap {
		return cbor.Value{}, false
	}
	for _, p := range v.Map {
		if p.Key.Kind == cbor.KindText && p.Key.Text == key {
			return p.Val, true
		}
	}
	return cbor.Value{}, false
}

// entityFromValue builds an Entity from a decoded {type, data} map Value.
func entityFromValue(v cbor.Value) (Entity, error) {
	typeV, ok := mapGet(v, "type")
	if !ok || typeV.Kind != cbor.KindText {
		return Entity{}, fmt.Errorf("entity input missing text 'type'")
	}
	dataV, ok := mapGet(v, "data")
	if !ok {
		return Entity{}, fmt.Errorf("entity input missing 'data'")
	}
	return Entity{Type: typeV.Text, Data: dataV}, nil
}

func TestConformance(t *testing.T) {
	vecs := loadVectors(t)
	if len(vecs) == 0 {
		t.Fatal("no vectors loaded")
	}

	var encodeEqual, decodeReject, meta int
	for _, v := range vecs {
		switch v.kind {
		case "encode_equal":
			encodeEqual++
		case "decode_reject":
			decodeReject++
		default:
			meta++
		}
	}
	t.Logf("loaded %d vectors: %d encode_equal, %d decode_reject, %d other",
		len(vecs), encodeEqual, decodeReject, meta)

	for _, v := range vecs {
		v := v
		t.Run(v.id, func(t *testing.T) {
			switch v.kind {
			case "encode_equal":
				runEncodeEqual(t, v)
			case "decode_reject":
				runDecodeReject(t, v)
			default:
				t.Skipf("non-codec vector kind %q (%s)", v.kind, v.description)
			}
		})
	}
}

func runEncodeEqual(t *testing.T, v vector) {
	got, err := produce(v)
	if err != nil {
		t.Fatalf("%s: produce error: %v", v.id, err)
	}
	if !bytes.Equal(got, v.canonical) {
		t.Fatalf("%s byte mismatch\n  desc: %s\n  want: %x\n  got:  %x",
			v.id, v.description, v.canonical, got)
	}
}

// produce computes the bytes an encode_equal vector expects, dispatching by
// category. Class A categories re-encode `input` directly; Class B categories
// apply the content-hash / peer-id / signature / envelope construction.
func produce(v vector) ([]byte, error) {
	switch category(v.id) {
	case "content_hash":
		ent, err := entityFromValue(v.input)
		if err != nil {
			return nil, err
		}
		formatCode := uint64(FormatECFv1SHA256)
		if fc, ok := mapGet(v.input, "format_code"); ok && fc.Kind == cbor.KindUint {
			formatCode = fc.Uint
		}
		return ent.ContentHash(formatCode)

	case "peer_id":
		kt, _ := mapGet(v.input, "key_type")
		ht, _ := mapGet(v.input, "hash_type")
		dg, _ := mapGet(v.input, "digest")
		pid := PeerID{KeyType: kt.Uint, HashType: ht.Uint, Digest: dg.Bytes}
		// The canonical output is the peer-id string, ECF-encoded as a CBOR
		// text string (per the .diag: "the Base58-encoded peer-id string,
		// ECF-encoded as a CBOR text string").
		return cbor.Encode(cbor.Text(pid.Format()))

	case "signature":
		seedV, _ := mapGet(v.input, "seed")
		entV, _ := mapGet(v.input, "entity")
		ent, err := entityFromValue(entV)
		if err != nil {
			return nil, err
		}
		return ent.Sign(seedV.Bytes)

	default:
		// Class A: pure canonical re-encode of the decoded input. Also
		// covers "envelope" and "nested" — they are plain CBOR shapes whose
		// canonical output is the re-encoding of the input value.
		return cbor.Encode(v.input)
	}
}

func runDecodeReject(t *testing.T, v vector) {
	// Feed the wire bytes to the decoder; pass iff it rejects. For the
	// tag_reject category the bytes are an envelope/entity wrapper carrying a
	// tag somewhere in a data position — the recursive decode must reject it.
	_, err := cbor.Decode(v.canonical)
	if err == nil {
		t.Fatalf("%s: decoder ACCEPTED bytes that MUST be rejected\n  desc: %s\n  bytes: %x",
			v.id, v.description, v.canonical)
	}
}
