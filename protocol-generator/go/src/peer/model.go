// Package peer implements the Entity Core Protocol V7 Layers 1-4 + foundation:
// the peer machinery (identity, wire framing, the store, the capability core,
// the four MUST system handlers + the §6.5 dispatch chain, and the TCP
// transport) on top of the S2 codec (package entitycore + internal/{cbor,
// base58,varint}).
//
// This is a clean-room reimplementation from the V7 specification, authored
// without reading the entity-core-go reference oracle's source.
//
// model.go holds the materialized entity {type, data, content_hash} (§1.1, §3.4)
// and the protocol envelope (§3.1), sitting directly on the S2 codec's Value
// model. An entity's content_hash covers ONLY {type, data} (§1.1); the wire form
// carries content_hash as a third field so entities are self-describing across
// serialization (§3.1). data is an ARBITRARY ECF value (NOT necessarily a map —
// A-JAVA-010); the field accessors return nothing when data is not a map.
package peer

import (
	"encoding/hex"
	"errors"

	entitycore "github.com/entity-core/entity-core-protocol-go"
	"github.com/entity-core/entity-core-protocol-go/internal/cbor"
)

// Entity is a materialized entity: its declared type, its arbitrary-ECF data
// value, and the 33-byte content_hash (format byte 0x00 ‖ 32-byte SHA-256
// digest) computed over the canonical ECF of {type, data}.
type Entity struct {
	Type string
	Data cbor.Value
	Hash []byte
}

// MakeEntity materializes an entity, computing its content_hash under the
// ecfv1-sha256 floor (format code 0x00).
func MakeEntity(typ string, data cbor.Value) (Entity, error) {
	h, err := entitycore.Entity{Type: typ, Data: data}.ContentHash(entitycore.FormatECFv1SHA256)
	if err != nil {
		return Entity{}, err
	}
	return Entity{Type: typ, Data: data, Hash: h}, nil
}

// mustEntity materializes an entity, panicking on a codec error. Used only for
// peer-internal construction where the inputs are known-encodable (programmer
// error if not — [error_model].panic_policy).
func mustEntity(typ string, data cbor.Value) Entity {
	e, err := MakeEntity(typ, data)
	if err != nil {
		panic("peer: unencodable internal entity: " + err.Error())
	}
	return e
}

// ── data-map field accessors (data is an arbitrary ECF value) ───────────────

// MapField returns the value bound to key in a map Value, or zero-Value+false.
func MapField(m cbor.Value, key string) (cbor.Value, bool) {
	if m.Kind != cbor.KindMap {
		return cbor.Value{}, false
	}
	for i := range m.Map {
		k := m.Map[i].Key
		if k.Kind == cbor.KindText && k.Text == key {
			return m.Map[i].Val, true
		}
	}
	return cbor.Value{}, false
}

// Field fetches key from the entity's data map.
func (e Entity) Field(key string) (cbor.Value, bool) { return MapField(e.Data, key) }

// Text returns key's value as a string if it is a text value.
func (e Entity) Text(key string) (string, bool) {
	v, ok := e.Field(key)
	if !ok || v.Kind != cbor.KindText {
		return "", false
	}
	return v.Text, true
}

// Bytes returns key's value as a byte slice if it is a byte string.
func (e Entity) Bytes(key string) ([]byte, bool) {
	v, ok := e.Field(key)
	if !ok || v.Kind != cbor.KindBytes {
		return nil, false
	}
	return v.Bytes, true
}

// Uint returns key's value as a uint64 if it is an unsigned integer.
func (e Entity) Uint(key string) (uint64, bool) {
	v, ok := e.Field(key)
	if !ok || v.Kind != cbor.KindUint {
		return 0, false
	}
	return v.Uint, true
}

// SubEntity decodes a nested entity carried at key (a map with type/data/
// content_hash).
func (e Entity) SubEntity(key string) (Entity, bool) {
	v, ok := e.Field(key)
	if !ok || v.Kind != cbor.KindMap {
		return Entity{}, false
	}
	sub, err := EntityOfCbor(v)
	if err != nil {
		return Entity{}, false
	}
	return sub, true
}

// ── wire form: an entity carries its content_hash ──────────────────────────

// ToCbor serializes the entity to its wire map {type, data, content_hash}.
func (e Entity) ToCbor() cbor.Value {
	return cbor.NewMap(
		cbor.Entry("type", cbor.Text(e.Type)),
		cbor.Entry("data", e.Data),
		cbor.Entry("content_hash", cbor.Bytes(e.Hash)),
	)
}

// ErrBadEntity signals a malformed wire entity or a content_hash fidelity
// violation (§1.8).
var ErrBadEntity = errors.New("peer: bad entity")

// EntityOfCbor parses a wire entity map, recomputes the hash from {type, data},
// and validates it against the carried content_hash (§1.8 fidelity:
// validate-before-trust). The recomputed hash is trusted, not the wire bytes.
func EntityOfCbor(m cbor.Value) (Entity, error) {
	typV, ok := MapField(m, "type")
	if !ok || typV.Kind != cbor.KindText {
		return Entity{}, ErrBadEntity
	}
	data, ok := MapField(m, "data")
	if !ok {
		return Entity{}, ErrBadEntity
	}
	e, err := MakeEntity(typV.Text, data)
	if err != nil {
		return Entity{}, err
	}
	if carried, ok := MapField(m, "content_hash"); ok && carried.Kind == cbor.KindBytes {
		if !bytesEqual(carried.Bytes, e.Hash) {
			return Entity{}, ErrBadEntity // §1.8 content_hash mismatch
		}
	}
	return e, nil
}

// ── envelope (§3.1) ─────────────────────────────────────────────────────────

// Included is the envelope's included-entity set, keyed by content_hash (hex).
type Included map[string]Entity

// Get returns the included entity with content_hash h, or false.
func (in Included) Get(h []byte) (Entity, bool) {
	e, ok := in[hex.EncodeToString(h)]
	return e, ok
}

// Add inserts an entity keyed by its content_hash.
func (in Included) Add(e Entity) { in[hex.EncodeToString(e.Hash)] = e }

// Envelope is the wire envelope {root, included} (§3.1).
type Envelope struct {
	Root     Entity
	Included Included
}

// NewEnvelope builds an envelope from a root entity and zero or more included
// entities (each keyed by its own content_hash).
func NewEnvelope(root Entity, included ...Entity) Envelope {
	in := make(Included, len(included))
	for _, e := range included {
		in.Add(e)
	}
	return Envelope{Root: root, Included: in}
}

// ToCbor serializes the envelope to its wire map {root, included}.
func (env Envelope) ToCbor() cbor.Value {
	inc := make([]cbor.Pair, 0, len(env.Included))
	for hexKey, e := range env.Included {
		raw, err := hex.DecodeString(hexKey)
		if err != nil {
			continue
		}
		inc = append(inc, cbor.Pair{Key: cbor.Bytes(raw), Val: e.ToCbor()})
	}
	return cbor.NewMap(
		cbor.Entry("root", env.Root.ToCbor()),
		cbor.Pair{Key: cbor.Text("included"), Val: cbor.NewMap(inc...)},
	)
}

// EnvelopeOfCbor parses a wire envelope map, validating that each included
// entity's content_hash equals its map key (§3.1).
func EnvelopeOfCbor(m cbor.Value) (Envelope, error) {
	rootC, ok := MapField(m, "root")
	if !ok || rootC.Kind != cbor.KindMap {
		return Envelope{}, ErrBadEntity
	}
	root, err := EntityOfCbor(rootC)
	if err != nil {
		return Envelope{}, err
	}
	included := make(Included)
	if incC, ok := MapField(m, "included"); ok && incC.Kind == cbor.KindMap {
		for _, pair := range incC.Map {
			if pair.Key.Kind != cbor.KindBytes {
				return Envelope{}, ErrBadEntity
			}
			e, err := EntityOfCbor(pair.Val)
			if err != nil {
				return Envelope{}, err
			}
			if !bytesEqual(pair.Key.Bytes, e.Hash) {
				return Envelope{}, ErrBadEntity // §3.1 key != content_hash
			}
			included.Add(e)
		}
	}
	return Envelope{Root: root, Included: included}, nil
}

// ── small helpers ───────────────────────────────────────────────────────────

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

// hexOf renders octets as lowercase hex (the address-space + tree-path
// convention: tree paths like system/signature/{hash} MUST be lowercase).
func hexOf(b []byte) string { return hex.EncodeToString(b) }
