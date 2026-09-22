package peer

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// §4.11 pre-admission refusals (0.8.2.25) — the CLASSIFICATION half.
//
// §4.11's rule has two parts and they fail differently. "The frame obligation
// belongs to the class" is wire-visible and is driven over a socket; "the CODE
// belongs to the cause [MUST]" is a mapping, and a mapping is exactly the thing
// that regresses silently when a new failure joins an existing branch. These
// cases pin the mapping at the unit level so `run-s2.sh` carries it.
//
// The pinned check set (778) has NO vector on this surface, which is why the
// coverage is authored here rather than inherited.

// TestReadFrameDistinguishesCloseFromTruncation — a clean io.EOF at a frame
// boundary is an ordinary close and is owed nothing; a stream that ends
// MID-FRAME is a §4.11 framing refusal and is owed a coded frame. io.ReadFull
// collapses the two (io.EOF for "zero bytes read", io.ErrUnexpectedEOF for
// "some"), so the distinction has to be made where the frame boundary is known.
func TestReadFrameDistinguishesCloseFromTruncation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		want  error
	}{
		{"clean close at a frame boundary", nil, io.EOF},
		{"partial length prefix", []byte{0x00, 0x00}, ErrTruncatedFrame},
		{"prefix declares more than is sent", []byte{0x00, 0x00, 0x10, 0x00, 0xa1}, ErrTruncatedFrame},
		{"length prefix above MaxFrame", []byte{0x02, 0x00, 0x00, 0x00}, ErrFrameTooLarge},
	} {
		if _, err := ReadFrame(bytes.NewReader(tc.input)); err != tc.want {
			t.Errorf("%s: expected %v, got %v", tc.name, tc.want, err)
		}
	}
	// A zero-length frame is COMPLETE, not truncated: it reaches the decoder and
	// is refused there as bytes that never become an Envelope.
	if payload, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0})); err != nil || len(payload) != 0 {
		t.Errorf("empty frame: expected an empty payload and no error, got %v / %v", payload, err)
	}
}

// TestPreAdmissionRefusalCodeIsTheCauses — §4.11's table, one row at a time.
// "A single code for the class would answer an honest caller under the wrong
// reason and send them to the wrong layer."
func TestPreAdmissionRefusalCodeIsTheCauses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status uint64
		code   string
	}{
		// §4.10(a), mood raised to MUST at 0.8.2.25 (N14).
		{"oversize envelope", ErrFrameTooLarge, 413, "payload_too_large"},
		// §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
		// non_canonical_ecf NON-CONFORMANT here.
		{"mis-keyed included entry", ErrHashMismatch, 400, "hash_mismatch"},
		// ENTITY-CBOR-ENCODING §5.4 — the tag-policy arm keeps its own code.
		{"CBOR tag in a data field", cbor.ErrTagRejected, 400, "non_canonical_ecf"},
		// §4.7 / §4.11 framing arm: bytes that never become an Envelope.
		{"truncated frame", ErrTruncatedFrame, 400, "invalid_request"},
		{"un-parseable CBOR", cbor.ErrTruncated, 400, "invalid_request"},
		{"structurally not an envelope", ErrBadEntity, 400, "invalid_request"},
	} {
		status, code := preAdmissionRefusal(tc.err)
		if status != tc.status || code != tc.code {
			t.Errorf("%s: expected %d %s, got %d %s", tc.name, tc.status, tc.code, status, code)
		}
	}
	// framingRefusal separates "owed a frame" from "the connection simply ended".
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{ErrFrameTooLarge, true}, {ErrTruncatedFrame, true},
		{io.EOF, false}, {io.ErrClosedPipe, false},
	} {
		if got := framingRefusal(tc.err); got != tc.want {
			t.Errorf("framingRefusal(%v): expected %v, got %v", tc.err, tc.want, got)
		}
	}
}

// TestDecodeBoundaryCauseSplit — the two decode-boundary causes must reach
// preAdmissionRefusal as DIFFERENT errors. Before 0.8.2.24 this peer answered
// `400 non_canonical_ecf` for every one of them, which is the code-under-the-
// wrong-reason defect §5.2a names: a mis-keyed `included` entry carries no tag,
// its encoding is canonical, and *re-encode* is not the caller's remedy.
func TestDecodeBoundaryCauseSplit(t *testing.T) {
	good := mustEntity("primitive/any", cbor.NewMap(cbor.Entry("x", cbor.Uint(1))))
	root := mustEntity("system/protocol/execute", cbor.NewMap(
		cbor.Entry("request_id", cbor.Text("t1")),
		cbor.Entry("uri", cbor.Text("system/tree")),
		cbor.Entry("operation", cbor.Text("get")),
		cbor.Entry("params", EmptyParams().ToCbor()),
	))
	misKeyed := cbor.NewMap(
		cbor.Entry("root", root.ToCbor()),
		cbor.Pair{Key: cbor.Text("included"), Val: cbor.NewMap(
			cbor.Pair{Key: cbor.Bytes(bytes.Repeat([]byte{0x11}, 33)), Val: good.ToCbor()})},
	)
	if _, err := EnvelopeOfCbor(misKeyed); err != ErrHashMismatch {
		t.Errorf("mis-keyed included: expected ErrHashMismatch, got %v", err)
	} else if _, code := preAdmissionRefusal(err); code != "hash_mismatch" {
		t.Errorf("mis-keyed included: expected hash_mismatch, got %s", code)
	}

	// A CORRECTLY keyed entry whose entity carries a wrong content_hash is the
	// same class (§1.8 item 1) and takes the same code.
	tampered := cbor.NewMap(
		cbor.Entry("type", cbor.Text(good.Type)),
		cbor.Entry("data", good.Data),
		cbor.Entry("content_hash", cbor.Bytes(bytes.Repeat([]byte{0x22}, 33))),
	)
	if _, err := EntityOfCbor(tampered); err != ErrHashMismatch {
		t.Errorf("tampered content_hash: expected ErrHashMismatch, got %v", err)
	}

	// STRUCTURAL faults stay ErrBadEntity -> invalid_request. This is the
	// discriminator: if both causes collapsed into one error value the split
	// above would pass vacuously.
	noType := cbor.NewMap(cbor.Entry("data", cbor.Uint(1)))
	if _, err := EntityOfCbor(noType); err != ErrBadEntity {
		t.Errorf("entity with no type: expected ErrBadEntity, got %v", err)
	}
	notAnEnvelope := cbor.NewMap(cbor.Entry("nope", cbor.Uint(1)))
	if _, err := EnvelopeOfCbor(notAnEnvelope); err != ErrBadEntity {
		t.Errorf("not an envelope: expected ErrBadEntity, got %v", err)
	}

	// And the WELL-FORMED envelope must still decode, or every case above is
	// satisfied by a decoder that refuses everything.
	wellFormed := cbor.NewMap(
		cbor.Entry("root", root.ToCbor()),
		cbor.Pair{Key: cbor.Text("included"), Val: cbor.NewMap(
			cbor.Pair{Key: cbor.Bytes(good.Hash), Val: good.ToCbor()})},
	)
	env, err := EnvelopeOfCbor(wellFormed)
	if err != nil {
		t.Fatalf("well-formed envelope: expected no error, got %v", err)
	}
	if _, ok := env.Included[hex.EncodeToString(good.Hash)]; !ok {
		t.Error("well-formed envelope: the included entity did not survive decode")
	}
}

// TestNonExecuteRootIsAnswered — §6.5's "Other type?" arm as rewritten at
// 0.8.2.25 (N12/N17): "400 invalid_request, coded frame; MAY then close. NOT a
// bare close." §3.3 previously read "the connection MUST be closed", assigning
// no code and requiring no frame; this peer did something weaker still and wrote
// nothing at all, which is §4.11's silent-drop failure.
func TestNonExecuteRootIsAnswered(t *testing.T) {
	p, err := NewPeer(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	root := mustEntity("primitive/any", cbor.NewMap(cbor.Entry("request_id", cbor.Text("x-1"))))
	resp, ok := p.dispatch(&conn{}, NewEnvelope(root))
	if !ok {
		t.Fatal("a non-EXECUTE root must still produce a response envelope")
	}
	if resp.Root.Type != "system/protocol/execute/response" {
		t.Errorf("expected an EXECUTE_RESPONSE root, got %q", resp.Root.Type)
	}
	if status, _ := resp.Root.Uint("status"); status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
	res, okr := resp.Root.SubEntity("result")
	if !okr {
		t.Fatal("expected a result entity on the refusal")
	}
	if code, _ := res.Text("code"); code != "invalid_request" {
		t.Errorf("expected code invalid_request, got %q", code)
	}
	// Correlated where the id is recoverable; §4.11's best-effort uncorrelated
	// frame is the fallback, not the default.
	if rid, _ := resp.Root.Text("request_id"); rid != "x-1" {
		t.Errorf("expected the request_id to be echoed, got %q", rid)
	}
}
