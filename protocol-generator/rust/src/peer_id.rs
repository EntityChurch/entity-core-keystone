//! Peer-id format/parse (V7 §1.2 / §7.3).
//!
//! peer-id = Base58(varint(key_type) || varint(hash_type) || digest).
//!
//! The canonical wire form of a peer-id *value* is the ECF text-string encoding
//! of the Base58 string. key_type/hash_type are LEB128 varints (codes >= 0x80
//! exercise the multi-byte prefix — peer_id.3). All framing routes through the
//! real varint primitive (invariant N1).

use crate::base58;
use crate::error::{CodecError, Result};
use crate::varint;

/// Format a peer-id string from its components.
pub fn format(key_type: u64, hash_type: u64, digest: &[u8]) -> String {
    let mut raw = varint::encode(key_type);
    raw.extend_from_slice(&varint::encode(hash_type));
    raw.extend_from_slice(digest);
    base58::encode(&raw)
}

/// A parsed peer-id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerId {
    /// The key-type code (e.g. 0x01 = Ed25519).
    pub key_type: u64,
    /// The hash-type code (e.g. 0x01 = SHA-256).
    pub hash_type: u64,
    /// The raw public-key/identity digest.
    pub digest: Vec<u8>,
}

/// Parse a peer-id string back into its components.
pub fn parse(s: &str) -> Result<PeerId> {
    let raw = base58::decode(s).ok_or(CodecError::Malformed)?;
    let (key_type, n1) = varint::decode(&raw)?;
    let (hash_type, n2) = varint::decode(&raw[n1..])?;
    let digest = raw[n1 + n2..].to_vec();
    Ok(PeerId {
        key_type,
        hash_type,
        digest,
    })
}
