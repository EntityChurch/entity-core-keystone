package entitycore

import (
	"crypto/sha256"
	"errors"

	"github.com/entity-core/entity-core-protocol-go/internal/base58"
	"github.com/entity-core/entity-core-protocol-go/internal/varint"
)

// Key types (V7 §1.5).
const (
	KeyTypeEd25519 = 0x01
	KeyTypeEd448   = 0x02
)

// Hash types (V7 §1.5 canonical-form table).
const (
	HashTypeIdentity = 0x00 // identity-multihash: digest IS the raw key (no hash)
	HashTypeSHA256   = 0x01 // SHA-256-form: digest = SHA-256(key)
)

// ErrBadPeerID is returned when a peer-id string cannot be parsed.
var ErrBadPeerID = errors.New("entitycore: malformed peer-id")

// PeerID holds the abstract components of an Entity Core peer identifier.
type PeerID struct {
	KeyType  uint64
	HashType uint64
	Digest   []byte
}

// Format encodes the peer-id to its canonical Base58 string form (V7 §1.2/§7.3):
//
//	Base58( varint(key_type) || varint(hash_type) || digest )
//
// The key_type and hash_type are LEB128 varints (N1) so codes >= 0x80 produce
// multi-byte prefixes.
func (p PeerID) Format() string {
	buf := varint.EncodeTo(p.KeyType)
	buf = varint.Encode(buf, p.HashType)
	buf = append(buf, p.Digest...)
	return base58.Encode(buf)
}

// ParsePeerID parses a canonical Base58 peer-id string into its components,
// reading the key_type and hash_type as LEB128 varints (N1). The remainder is
// the digest.
func ParsePeerID(s string) (PeerID, error) {
	raw, err := base58.Decode(s)
	if err != nil {
		return PeerID{}, ErrBadPeerID
	}
	keyType, n1, err := varint.Decode(raw)
	if err != nil {
		return PeerID{}, ErrBadPeerID
	}
	hashType, n2, err := varint.Decode(raw[n1:])
	if err != nil {
		return PeerID{}, ErrBadPeerID
	}
	digest := make([]byte, len(raw)-n1-n2)
	copy(digest, raw[n1+n2:])
	return PeerID{KeyType: keyType, HashType: hashType, Digest: digest}, nil
}

// PeerIDFromPublicKey derives the canonical Base58 peer-id for a raw public key
// under the given key type, per the V7 §1.5 canonical-form table + size-cutoff
// rule: a key <= 32 bytes is identity-multihash form (hash_type=0x00, digest =
// the raw key, NO hash); a larger key is SHA-256-form (hash_type=0x01, digest =
// SHA-256(key)). So Ed25519 (32 B) -> (0x01, 0x00, pubkey); Ed448 (57 B) ->
// (0x02, 0x01, sha256(pubkey)). This is the §1.5 reading (NOT the stale §7.4
// SHA256(pubkey) skeleton, which fails the handshake) — corroborated across the
// spec-first cohort (A-ZIG-001 / A-OC-007 / A-CL-002).
func PeerIDFromPublicKey(pub []byte, keyType uint64) string {
	if len(pub) <= 32 {
		return PeerID{KeyType: keyType, HashType: HashTypeIdentity, Digest: pub}.Format()
	}
	d := sha256.Sum256(pub)
	return PeerID{KeyType: keyType, HashType: HashTypeSHA256, Digest: d[:]}.Format()
}
