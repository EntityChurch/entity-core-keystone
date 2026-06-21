package peer

// identity.go — Identity (L1): a peer's keypair + derived entities (§1.5, §3.5,
// §7.3). The identity is an Ed25519 seed; everything derives:
//
//	publicKey    = Ed25519 pub of seed                  (32 bytes)
//	peerID       = §1.5 canonical form (identity-multihash; hash_type=0x00)
//	peerEntity   = system/peer {public_key, key_type}   (§3.5; v7.65 — NO peer_id
//	               in the hashable basis)
//	identityHash = content_hash(peerEntity)
//
// Signing is over the full 33-byte content_hash (format byte + digest, §7.3), so
// a signature is bound to the hash format.

import (
	"crypto/ed25519"

	entitycore "github.com/entity-core/entity-core-protocol-go"
	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// Identity is a peer's keypair plus its derived peer entity and identity hash.
type Identity struct {
	seed       []byte
	publicKey  []byte
	peerID     string
	peerEntity Entity
	hash       []byte // content_hash of peerEntity
}

// PeerEntityOfPublicKey builds the system/peer entity for a raw public key
// (v7.65: no peer_id field in the hashable basis).
func PeerEntityOfPublicKey(publicKey []byte) Entity {
	return mustEntity("system/peer", cbor.NewMap(
		cbor.Entry("public_key", cbor.Bytes(publicKey)),
		cbor.Entry("key_type", cbor.Text("ed25519")),
	))
}

// peerIDOfPublicKey derives the canonical Ed25519 peer_id (§1.5 identity-
// multihash; A-GO/cohort: NOT the stale §7.4 SHA256(pubkey)).
func peerIDOfPublicKey(publicKey []byte) string {
	return entitycore.PeerIDFromPublicKey(publicKey, entitycore.KeyTypeEd25519)
}

// MakeIdentity constructs an identity from a 32-byte Ed25519 seed.
func MakeIdentity(seed []byte) (Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return Identity{}, entitycore.ErrBadSeed
	}
	pub, err := entitycore.PublicKeyFromSeed(seed)
	if err != nil {
		return Identity{}, err
	}
	peerEntity := PeerEntityOfPublicKey(pub)
	s := make([]byte, len(seed))
	copy(s, seed)
	return Identity{
		seed:       s,
		publicKey:  pub,
		peerID:     peerIDOfPublicKey(pub),
		peerEntity: peerEntity,
		hash:       peerEntity.Hash,
	}, nil
}

// PeerID returns the canonical Base58 peer-id.
func (id Identity) PeerID() string { return id.peerID }

// PublicKey returns the raw 32-byte Ed25519 public key.
func (id Identity) PublicKey() []byte { return id.publicKey }

// PeerEntity returns the system/peer entity.
func (id Identity) PeerEntity() Entity { return id.peerEntity }

// IdentityHash returns the content_hash of the peer entity.
func (id Identity) IdentityHash() []byte { return id.hash }

// SignEntity signs the target entity's content_hash and produces the
// system/signature entity (§3.5): target = signed entity hash, signer = our
// identity hash, signature = Ed25519 over the 33-byte content_hash.
func (id Identity) SignEntity(target Entity) Entity {
	priv := ed25519.NewKeyFromSeed(id.seed)
	sig := ed25519.Sign(priv, target.Hash)
	return mustEntity("system/signature", cbor.NewMap(
		cbor.Entry("target", cbor.Bytes(target.Hash)),
		cbor.Entry("signer", cbor.Bytes(id.hash)),
		cbor.Entry("algorithm", cbor.Text("ed25519")),
		cbor.Entry("signature", cbor.Bytes(sig)),
	))
}

// VerifySignature verifies a system/signature entity against the signer's
// system/peer entity. Reads public_key from the peer entity; the §5.2
// signer-hash binding check is the caller's responsibility.
func VerifySignature(signature, signerPeer Entity) bool {
	target, ok1 := signature.Bytes("target")
	sig, ok2 := signature.Bytes("signature")
	pub, ok3 := signerPeer.Bytes("public_key")
	if !ok1 || !ok2 || !ok3 || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), target, sig)
}
