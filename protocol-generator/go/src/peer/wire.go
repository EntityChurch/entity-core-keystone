package peer

// wire.go — Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3
// EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR payload]. The payload is a
// CBOR-encoded envelope (§3.1).
//
// Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3); hello /
// authenticate are OPERATIONS on system/protocol/connect, not message types.
//
// §4.10(a) resource bound: a finite max inbound payload (MaxFrame, 16 MiB) is
// enforced by checking the LENGTH PREFIX before buffering the body — an
// over-limit frame is rejected as 413 payload_too_large at read time, and since
// 0.8.2.25 (N14) that rejection MUST be EMITTED: §4.10(a)'s "SHOULD … and
// otherwise MAY close after a best-effort coded frame" became a MUST, because
// the over-size condition is detected at the length prefix with the connection
// intact and nothing spent. §4.11 is the emission shape for the whole class.
// The transport still closes afterwards — the body was never drained, so the
// framing is lost — but the close is now in addition to the frame, not instead
// of it. The recommended (informative) default is 16 MiB.

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// MaxFrame is the §4.10(a) finite inbound-payload bound (16 MiB, the informative
// default). A length prefix exceeding it is rejected before the body is read.
const MaxFrame = 16 * 1024 * 1024

// ErrFrameTooLarge signals a length prefix exceeding MaxFrame (→ 413
// payload_too_large). Reported BEFORE the body is buffered (§4.10(a)).
var ErrFrameTooLarge = errors.New("peer: inbound frame exceeds max payload (413 payload_too_large)")

// ErrTruncatedFrame signals a frame that never completed: a partial length prefix,
// or a prefix declaring N bytes followed by fewer. §4.11's framing arm names this
// input explicitly — "un-parseable, truncated or non-canonical CBOR, or a length
// prefix that never completes" — and answers `400 invalid_request`.
//
// IT IS A SEPARATE VALUE FROM io.EOF BECAUSE THE TWO ARE DIFFERENT EVENTS AND
// io.ReadFull COLLAPSES THEM. A clean io.EOF at a frame boundary is an ordinary
// close and is owed nothing; a stream that ends mid-frame is a REFUSAL and is
// owed a coded frame. io.ReadFull answers io.EOF for "zero bytes read" and
// io.ErrUnexpectedEOF for "some", so a prefix declaring 100 bytes followed by
// immediate close is indistinguishable from an idle hangup unless the distinction
// is made HERE, where the frame boundary is known.
var ErrTruncatedFrame = errors.New("peer: truncated inbound frame (400 invalid_request)")

// ReadFrame reads one length-prefixed frame and returns its CBOR payload. The
// length prefix is validated against MaxFrame before any body bytes are read
// (§4.10(a)). A clean io.EOF at a frame boundary propagates unchanged; anything
// that ends mid-frame becomes ErrTruncatedFrame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if n, err := io.ReadFull(r, hdr[:]); err != nil {
		if n > 0 {
			return nil, ErrTruncatedFrame // partial length prefix
		}
		return nil, err // nothing read: an ordinary close, not a refusal
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, ErrFrameTooLarge // §4.10(a): reject before buffering
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, ErrTruncatedFrame // declared n, delivered fewer
	}
	return body, nil
}

// WriteFrame writes payload as a length-prefixed frame.
func WriteFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// EnvelopeOfFrame decodes a frame payload into an Envelope.
func EnvelopeOfFrame(payload []byte) (Envelope, error) {
	v, err := cbor.Decode(payload)
	if err != nil {
		return Envelope{}, err
	}
	return EnvelopeOfCbor(v)
}

// preAdmissionRefusal maps a pre-admission failure to the (status, code) §4.11
// assigns its CAUSE. "The frame obligation belongs to the class; the CODE belongs
// to the cause [MUST]" — a single code for the class would answer an honest
// caller under the wrong reason and send them to the wrong layer.
//
//	connect-auth proof-of-possession   401 authentication_failed   (§4.6/§4.7 — the
//	                                                                connect handler's,
//	                                                                not this function's)
//	envelope over the configured max    413 payload_too_large       (§4.10(a), N14)
//	resolution integrity (mis-keyed)    400 hash_mismatch           (§5.2a, §1.8)
//	framing / never becomes an Envelope 400 invalid_request         (§4.7, §4.11)
//	root is neither EXECUTE nor
//	  EXECUTE_RESPONSE                  400 invalid_request         (§3.3, §4.11 — in
//	                                                                dispatch, not here)
//
// The CBOR tag-policy arm keeps `non_canonical_ecf` and that is deliberate.
// §4.11 rules that code non-conformant "on the framing arm" and gives its reason
// in the same sentence: ENTITY-CBOR-ENCODING §5.4 "defines that code for CBOR
// tag-policy violations specifically", which that document still MUSTs at decode
// time. The two texts are only compatible if the tag case is not read as part of
// the framing arm even though §4.11's row says "non-canonical CBOR" and a tagged
// frame is literally that. Reported as an ambiguity rather than resolved here;
// this branch takes the reading that keeps BOTH MUSTs satisfiable and preserves
// the behaviour the `tag_reject` vectors were written against.
func preAdmissionRefusal(err error) (uint64, string) {
	switch {
	case err == ErrFrameTooLarge:
		return 413, "payload_too_large"
	case err == ErrHashMismatch:
		return 400, "hash_mismatch"
	case errors.Is(err, cbor.ErrTagRejected):
		return 400, "non_canonical_ecf"
	default:
		return 400, "invalid_request"
	}
}

// framingRefusal reports whether a ReadFrame error is a REFUSAL owed a coded
// frame (§4.11) rather than an ordinary end of connection. A closed or reset
// socket is not a refusal of anything and there is nobody left to answer.
func framingRefusal(err error) bool {
	return err == ErrFrameTooLarge || err == ErrTruncatedFrame
}

// salvageRequestID recovers ONLY the request_id from a frame the strict decoder
// rejected, so the rejection can be delivered as a CORRELATED response rather
// than as the uncorrelated best-effort frame §4.11 falls back to.
//
// The frame stays rejected. Nothing else is read out of it: no entity is built,
// nothing is stored, and the offending tag is never interpreted. The envelope
// and entity-wrapper shapes are fixed maps with no legal tag position (§6.3), so
// a frame whose ONLY defect is a tag inside some entity's `data` still has a
// structurally sound root — which is exactly the case this recovers.
func salvageRequestID(payload []byte) (string, bool) {
	v, err := cbor.DecodeSalvage(payload)
	if err != nil || v.Kind != cbor.KindMap {
		return "", false
	}
	rootV, ok := MapField(v, "root")
	if !ok || rootV.Kind != cbor.KindMap {
		return "", false
	}
	dataV, ok := MapField(rootV, "data")
	if !ok || dataV.Kind != cbor.KindMap {
		return "", false
	}
	ridV, ok := MapField(dataV, "request_id")
	if !ok || ridV.Kind != cbor.KindText {
		return "", false
	}
	return ridV.Text, true
}

// FrameOfEnvelope encodes an Envelope to a frame payload.
func FrameOfEnvelope(env Envelope) ([]byte, error) {
	return cbor.Encode(env.ToCbor())
}

// ── EXECUTE builder (§3.2) ──────────────────────────────────────────────────

// execOpts carries optional EXECUTE fields.
type execOpts struct {
	author     []byte
	capability []byte
	resource   cbor.Value
	hasRes     bool
}

// execOpt configures an EXECUTE.
type execOpt func(*execOpts)

func withAuthor(h []byte) execOpt     { return func(o *execOpts) { o.author = h } }
func withCapability(h []byte) execOpt { return func(o *execOpts) { o.capability = h } }
func withResource(r cbor.Value) execOpt {
	return func(o *execOpts) { o.resource = r; o.hasRes = true }
}

// MakeExecute builds a system/protocol/execute entity (§3.2). params is the
// inner params entity carried verbatim in the data.
func MakeExecute(requestID, uri, operation string, params Entity, opts ...execOpt) Entity {
	var o execOpts
	for _, fn := range opts {
		fn(&o)
	}
	pairs := []cbor.Pair{
		cbor.Entry("request_id", cbor.Text(requestID)),
		cbor.Entry("uri", cbor.Text(uri)),
		cbor.Entry("operation", cbor.Text(operation)),
		cbor.Entry("params", params.ToCbor()),
	}
	if o.author != nil {
		pairs = append(pairs, cbor.Entry("author", cbor.Bytes(o.author)))
	}
	if o.capability != nil {
		pairs = append(pairs, cbor.Entry("capability", cbor.Bytes(o.capability)))
	}
	if o.hasRes {
		pairs = append(pairs, cbor.Entry("resource", o.resource))
	}
	return mustEntity("system/protocol/execute", cbor.NewMap(pairs...))
}

// ── EXECUTE_RESPONSE builder (§3.3) ─────────────────────────────────────────

// MakeResponse builds a system/protocol/execute/response entity (§3.3).
func MakeResponse(requestID string, status uint64, result Entity) Entity {
	return mustEntity("system/protocol/execute/response", cbor.NewMap(
		cbor.Entry("request_id", cbor.Text(requestID)),
		cbor.Entry("status", cbor.Uint(status)),
		cbor.Entry("result", result.ToCbor()),
	))
}

// ── error result + empty params ─────────────────────────────────────────────

// ErrorResult builds a system/protocol/error entity {code[, message]}.
func ErrorResult(code, message string) Entity {
	pairs := []cbor.Pair{cbor.Entry("code", cbor.Text(code))}
	if message != "" {
		pairs = append(pairs, cbor.Entry("message", cbor.Text(message)))
	}
	return mustEntity("system/protocol/error", cbor.NewMap(pairs...))
}

// EmptyParams is the empty-params shape (§3.2): a primitive/any whose data is
// the canonical empty map.
func EmptyParams() Entity { return mustEntity("primitive/any", emptyMap()) }

// ResourceTarget builds a resource {targets: [...]} value.
func ResourceTarget(targets ...string) cbor.Value {
	return cbor.NewMap(cbor.Entry("targets", strList(targets...)))
}
