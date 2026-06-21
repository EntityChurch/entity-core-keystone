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
// over-limit frame is rejected as 413 payload_too_large at read time (the
// transport closes the connection after the rejection rather than allocating the
// oversized buffer). The recommended (informative) default is 16 MiB.

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

// ReadFrame reads one length-prefixed frame and returns its CBOR payload. The
// length prefix is validated against MaxFrame before any body bytes are read
// (§4.10(a)). io.EOF / io.ErrUnexpectedEOF propagate to signal a closed conn.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, ErrFrameTooLarge // §4.10(a): reject before buffering
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
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
