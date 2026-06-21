//! The ECF value tree.
//!
//! A faithful in-memory model of the CBOR data items the canonical codec
//! handles: the core types per `ENTITY-NATIVE-TYPE-SYSTEM.md` §4.2.1 and the
//! shapes exercised by the v1 conformance corpus. Integers carry the FULL
//! uint64 / nint range (the `int.10`/`[2^63, 2^64-1]` band): unsigned values up
//! to `u64::MAX` live in [`Value::UInt`], negative values whose `-1 - n`
//! argument may exceed `i64::MAX` live in [`Value::NInt`] as the raw `n`
//! (so the band `[-2^64, -1]` round-trips without a BigInt).

use std::cmp::Ordering;

/// A map key. ECF maps key on text strings, byte strings, integers, or bools
/// (the corpus exercises text + bytes + the mixed case `map_keys.5`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// Text-string key (major type 3).
    Text(String),
    /// Byte-string key (major type 2).
    Bytes(Vec<u8>),
    /// Unsigned-integer key (major type 0).
    UInt(u64),
    /// Negative-integer key, stored as the raw `n` where value = `-1 - n`.
    NInt(u64),
    /// Boolean key (major type 7).
    Bool(bool),
}

/// An ECF value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `null` (0xf6).
    Null,
    /// Boolean (0xf4 / 0xf5).
    Bool(bool),
    /// Unsigned integer, major type 0, full `u64` range.
    UInt(u64),
    /// Negative integer, major type 1, stored as raw `n` (value = `-1 - n`),
    /// full `u64` range of `n` so the `[-2^64, -1]` band is exact.
    NInt(u64),
    /// IEEE-754 double; the canonical encoder applies the shortest-float ladder.
    Float(f64),
    /// Text string, major type 3.
    Text(String),
    /// Byte string, major type 2.
    Bytes(Vec<u8>),
    /// Definite-length array, major type 4.
    Array(Vec<Value>),
    /// Definite-length map, major type 5. Entries are held insertion-order;
    /// the canonical encoder sorts them. Decode rejects duplicate keys.
    Map(Vec<(Key, Value)>),
}

impl Key {
    /// The canonical encoding of this key, used as the sort discriminator
    /// (RFC 8949 §4.2.1 deterministic ordering: encoded-length then bytewise —
    /// for our key space this coincides with bytewise-on-encoded-bytes, which
    /// is what the go oracle compares).
    pub fn encoded(&self) -> Vec<u8> {
        match self {
            Key::Text(s) => crate::cbor::encode(&Value::Text(s.clone())),
            Key::Bytes(b) => crate::cbor::encode(&Value::Bytes(b.clone())),
            Key::UInt(n) => crate::cbor::encode(&Value::UInt(*n)),
            Key::NInt(n) => crate::cbor::encode(&Value::NInt(*n)),
            Key::Bool(b) => crate::cbor::encode(&Value::Bool(*b)),
        }
    }
}

/// Total order on keys by canonical encoded bytes (RFC 8949 §4.2.1).
/// Length-then-lexicographic falls out of bytewise comparison of the encoded
/// form because the head byte already carries the major type + length class.
pub fn key_order(a: &Key, b: &Key) -> Ordering {
    a.encoded().cmp(&b.encoded())
}
