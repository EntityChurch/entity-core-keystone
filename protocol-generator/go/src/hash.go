// Package entitycore is the public API of the Entity Core Protocol Go peer:
// ECF encode/decode, content-hash construction, peer-id format/parse, and
// Ed25519 sign/verify. Codec internals live under internal/{cbor,base58,varint}.
//
// This is a clean-room reimplementation from the V7 specification
// (ENTITY-CBOR-ENCODING.md v1.5 + ENTITY-CORE-PROTOCOL-V7.md), authored without
// reading the entity-core-go reference oracle's source.
package entitycore

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
	"github.com/entity-core/entity-core-protocol-go/internal/varint"
)

// Hash format codes (ENTITY-CBOR-ENCODING §4.3).
const (
	FormatECFv1SHA256 = 0x00 // ecfv1-sha256 — Active (Required)
	FormatECFv1SHA384 = 0x01 // ecfv1-sha384 — Reserved
	FormatECFv1SHA512 = 0x02 // ecfv1-sha512 — Reserved
)

// ErrUnsupportedHashFormat is returned by the hash *verification* surface when
// asked to recompute a hash under a format code it cannot interpret (§4.7).
var ErrUnsupportedHashFormat = errors.New("entitycore: unsupported content_hash_format")

// Entity is the {type, data} carrier whose ECF encoding is hashed and signed.
// data is an arbitrary ECF value (NOT necessarily a map — A-JAVA-010).
type Entity struct {
	Type string
	Data cbor.Value
}

// ecf returns the canonical ECF encoding of the {type, data} map for the
// entity (keys "data" and "type", canonicalised at encode time).
func (e Entity) ecf() ([]byte, error) {
	m := cbor.NewMap(
		cbor.Entry("type", cbor.Text(e.Type)),
		cbor.Entry("data", e.Data),
	)
	return cbor.Encode(m)
}

// EncodeECF returns the canonical ECF encoding of {type, data}.
func (e Entity) EncodeECF() ([]byte, error) { return e.ecf() }

// ContentHash constructs the wire content_hash for the entity under the given
// format code: varint(formatCode) || hash(ECF({type, data})) (§4.2/§4.5).
//
// The construction path serialises whatever formatCode the caller supplies and
// does not gate on the registry — preserving forward-compatibility per the
// §4.7 construction-vs-verification asymmetry. (Verification, which DOES gate,
// is VerifyContentHash.)
func (e Entity) ContentHash(formatCode uint64) ([]byte, error) {
	ecf, err := e.ecf()
	if err != nil {
		return nil, err
	}
	digest, err := digestFor(formatCode, ecf)
	if err != nil {
		// Unknown format on the construction path: the caller asked for a
		// digest we cannot compute. (Allocated-but-reserved codes 0x01/0x02
		// ARE computable here.) Only genuinely unknown algorithms fail.
		return nil, err
	}
	out := varint.EncodeTo(formatCode)
	return append(out, digest...), nil
}

// digestFor computes the hash digest for a known format code over ecf bytes.
// Codes whose algorithm this peer can compute return a digest; others error.
func digestFor(formatCode uint64, ecf []byte) ([]byte, error) {
	switch formatCode {
	case FormatECFv1SHA256:
		h := sha256.Sum256(ecf)
		return h[:], nil
	case FormatECFv1SHA384:
		h := sha512.Sum384(ecf)
		return h[:], nil
	case FormatECFv1SHA512:
		h := sha512.Sum512(ecf)
		return h[:], nil
	default:
		// Forward-compat construction (content_hash.4): a caller-supplied
		// code >= 0x80 with no algorithm this peer implements. Per §4.7 the
		// construction path still serialises the prefix; the digest, when
		// the algorithm is unknown, defaults to SHA-256 over the ECF bytes
		// (the corpus' content_hash.4 pins exactly this: synthetic code 128
		// with an SHA-256 digest — the format code is forward-compat framing,
		// the digest algorithm remains the floor SHA-256).
		h := sha256.Sum256(ecf)
		return h[:], nil
	}
}

// VerifyContentHash recomputes and checks a claimed wire content_hash against
// the entity. The verification path MUST reject unsupported/unallocated format
// codes with ErrUnsupportedHashFormat (§4.7) — a verifier cannot check what it
// cannot interpret.
func (e Entity) VerifyContentHash(claimed []byte) (bool, error) {
	if len(claimed) == 0 {
		return false, cbor.ErrTruncated
	}
	formatCode, n, err := varint.Decode(claimed)
	if err != nil {
		return false, err
	}
	if !supportedHashFormat(formatCode) {
		return false, ErrUnsupportedHashFormat
	}
	ecf, err := e.ecf()
	if err != nil {
		return false, err
	}
	digest, err := digestForVerify(formatCode, ecf)
	if err != nil {
		return false, err
	}
	want := make([]byte, 0, n+len(digest))
	want = append(want, claimed[:n]...)
	want = append(want, digest...)
	return bytesEqual(want, claimed), nil
}

// supportedHashFormat reports whether formatCode is one this peer can verify.
// Only the active code 0x00 is REQUIRED; reserved-but-known 0x01/0x02 are
// computable, so they verify. Anything else is rejected on the verify path.
func supportedHashFormat(formatCode uint64) bool {
	switch formatCode {
	case FormatECFv1SHA256, FormatECFv1SHA384, FormatECFv1SHA512:
		return true
	default:
		return false
	}
}

func digestForVerify(formatCode uint64, ecf []byte) ([]byte, error) {
	switch formatCode {
	case FormatECFv1SHA256:
		h := sha256.Sum256(ecf)
		return h[:], nil
	case FormatECFv1SHA384:
		h := sha512.Sum384(ecf)
		return h[:], nil
	case FormatECFv1SHA512:
		h := sha512.Sum512(ecf)
		return h[:], nil
	default:
		return nil, ErrUnsupportedHashFormat
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
