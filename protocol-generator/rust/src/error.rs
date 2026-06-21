//! Codec error model.
//!
//! Hand-written error enum + `Display` (no `thiserror`/`anyhow`, per the S1
//! dep-minimization stance). Exhaustive match discriminates — the Rust analogue
//! of an ADT verdict. The decode-reject sentinels map to the spec wire code
//! `400 non_canonical_ecf` (ENTITY-CBOR-ENCODING §6.3); the harness records that
//! code for every rejected vector.

use std::fmt;

/// A codec failure. The variants are the discriminable rejection cases the
/// canonical decoder must distinguish (the S1 `sentinel_set`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// A non-canonical ECF datum that doesn't have a more specific variant.
    NonCanonicalEcf,
    /// Input ended mid-item.
    Truncated,
    /// A CBOR tag (major type 6) at any nesting depth — §6.3.
    TagRejected,
    /// Two map entries with equal keys — Rule 5.
    DuplicateKey,
    /// An integer not in shortest argument form — Rule 1.
    NonMinimalInt,
    /// A float not in shortest-preserving form (decode-side Rule 4 check).
    NonMinimalFloat,
    /// An indefinite-length item (0x5f/0x7f/0x9f/0xbf) — Rule 3.
    IndefiniteLength,
    /// Map keys not in canonical order — Rule 2 / §4.2.1.
    UnsortedKeys,
    /// A reserved/unsupported simple value or additional-info 28..30.
    Malformed,
    /// Trailing bytes after a complete top-level item.
    TrailingData,
}

impl CodecError {
    /// The spec wire error code (ENTITY-CBOR-ENCODING §6.3 / §500). Every
    /// canonical-rejection case maps to `non_canonical_ecf` in the v1 surface.
    pub fn wire_code(&self) -> &'static str {
        "non_canonical_ecf"
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CodecError::NonCanonicalEcf => "non-canonical ECF",
            CodecError::Truncated => "truncated input",
            CodecError::TagRejected => "CBOR tag rejected (major type 6)",
            CodecError::DuplicateKey => "duplicate map key",
            CodecError::NonMinimalInt => "non-minimal integer encoding",
            CodecError::NonMinimalFloat => "non-minimal float encoding",
            CodecError::IndefiniteLength => "indefinite-length item forbidden",
            CodecError::UnsortedKeys => "map keys not in canonical order",
            CodecError::Malformed => "malformed CBOR item",
            CodecError::TrailingData => "trailing data after item",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CodecError {}

/// Codec result alias.
pub type Result<T> = std::result::Result<T, CodecError>;
