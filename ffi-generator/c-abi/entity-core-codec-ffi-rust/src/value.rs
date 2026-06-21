//! The ECF data model used by the hand-written canonical encoder.
//!
//! This is the *encoder's* value type. It is intentionally small — exactly the
//! ECF type surface (ENTITY-CBOR-ENCODING.md): ints, byte/text strings, arrays,
//! maps, the four canonical floats, bool, null. No tags (forbidden, N2).
//!
//! Maps carry their pairs as an ordered `Vec`; canonical key ordering
//! (RFC 8949 §4.2.1, bytewise-lexicographic on the *encoded* key) is applied at
//! encode time, never trusted from insertion order.

/// A decoded/constructed ECF value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// Signed integer in CBOR major-type 0/1 range. i128 holds the full u64
    /// positive range and the full i64 negative range.
    Int(i128),
    /// IEEE-754 double; encoded to its shortest round-tripping CBOR form (§3.5).
    Float(f64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Map pairs in arbitrary order; sorted canonically at encode time.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
    /// Already-canonical CBOR bytes spliced in verbatim — used for the opaque
    /// `data` field of an entity (carried byte-faithfully, never re-encoded).
    PreEncoded(Vec<u8>),
}
