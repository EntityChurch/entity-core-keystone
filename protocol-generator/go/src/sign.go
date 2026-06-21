package entitycore

import (
	"crypto/ed25519"
	"errors"
)

// ErrBadSeed is returned when an Ed25519 seed is not 32 bytes.
var ErrBadSeed = errors.New("entitycore: ed25519 seed must be 32 bytes")

// Sign produces the deterministic Ed25519 signature over the canonical-ECF
// encoding of the entity (RFC 8032), using the 32-byte seed. Ed25519 signing is
// deterministic by construction, so a fixed seed + fixed entity yields a fixed
// 64-byte signature.
func (e Entity) Sign(seed []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrBadSeed
	}
	msg, err := e.ecf()
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return ed25519.Sign(priv, msg), nil
}

// Verify checks an Ed25519 signature over the entity's canonical-ECF encoding
// against the given 32-byte public key.
func (e Entity) Verify(pub, sig []byte) (bool, error) {
	if len(pub) != ed25519.PublicKeySize {
		return false, errors.New("entitycore: ed25519 public key must be 32 bytes")
	}
	msg, err := e.ecf()
	if err != nil {
		return false, err
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig), nil
}

// PublicKeyFromSeed derives the Ed25519 public key for a 32-byte seed.
func PublicKeyFromSeed(seed []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrBadSeed
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return []byte(pub), nil
}
