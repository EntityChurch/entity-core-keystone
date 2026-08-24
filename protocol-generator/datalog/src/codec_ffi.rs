//! codec_ffi.rs — the ONLY crypto/CBOR/bytes surface of the Datalog peer host.
//!
//! Thin, safe Rust wrappers over the `extern "C"` C-ABI `libentitycore_codec`
//! (ABI 1.1; ffi-generator/c-abi/spec/{entitycore_codec.h,ENTITY-CODEC-C-ABI-V1.md}).
//! Every canonical-CBOR / content_hash / peer-id / Ed25519 / Ed448 / SHA operation
//! the peer performs crosses THIS boundary — the S1 seam decision (codec_strategy =
//! ffi). Datalog never touches a key or a byte; the host establishes facts here
//! (`verified_signer`, `now`, `scope_covers`) and the engine derives `allow` (S3).
//!
//! Design notes:
//!   * All fallible C-ABI calls return an `int32_t` (EC_* code); `EC_OK` (0) is
//!     success. We map every non-OK code to a typed [`CodecError`].
//!   * Variable-length outputs honour the §5 OUT_OF_SPACE grow-and-retry protocol:
//!     on `EC_OUT_OF_SPACE` the required size is written to `*out_len`; we grow the
//!     buffer to that size and retry once.
//!   * N4 (entity fidelity): [`decode_entity`] returns the exact original wire bytes
//!     of the decoded entity (the C-ABI hands back a borrowed span of the input);
//!     the host forwards THOSE, never a re-encode of the decoded form.
//!   * Opaque values (signatures, digests, keys) are plain byte buffers the host
//!     owns; Datalog only ever sees readable IDs + fields (S3).

use std::os::raw::c_char;

/// C-ABI error codes (spec §6; the numeric values are part of the ABI).
pub const EC_OK: i32 = 0;
pub const EC_INVALID_ARGUMENT: i32 = -1;
pub const EC_OUT_OF_SPACE: i32 = -2;
pub const EC_DECODE_ERROR: i32 = -3;
pub const EC_ENCODE_ERROR: i32 = -4;
pub const EC_HASH_MISMATCH: i32 = -5;
pub const EC_SIGNATURE_INVALID: i32 = -6;
pub const EC_KEY_INVALID: i32 = -7;
pub const EC_PEERID_INVALID: i32 = -8;
pub const EC_ARENA_EXHAUSTED: i32 = -9;
pub const EC_INTERNAL_ERROR: i32 = -99;

/// Fixed lengths (spec / header).
pub const EC_SHA256_LEN: usize = 32;
pub const EC_SHA384_LEN: usize = 48;
pub const EC_ED25519_PUB_LEN: usize = 32;
pub const EC_ED25519_SEED_LEN: usize = 32;
pub const EC_ED25519_SIG_LEN: usize = 64;
pub const EC_CONTENT_HASH_LEN: usize = 33;
pub const EC_ED448_SEED_LEN: usize = 57;
pub const EC_ED448_PUB_LEN: usize = 57;
pub const EC_ED448_SIG_LEN: usize = 114;

/// Typed image of a non-OK C-ABI return code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    InvalidArgument,
    /// Caller buffer too small AND the retry protocol did not converge.
    OutOfSpace,
    /// Decode failed — malformed input, a rejected major-type-6 tag (N2), or an
    /// unsupported content_hash_format code (the §5.2 fail-closed decode surface).
    Decode,
    Encode,
    HashMismatch,
    SignatureInvalid,
    KeyInvalid,
    PeerId,
    ArenaExhausted,
    /// The impl does not (yet) implement this algorithm — e.g. Ed448 is
    /// validated-not-required at the C-ABI floor.
    Internal,
    /// A code the ABI never documented.
    Unknown(i32),
}

impl CodecError {
    fn from_code(code: i32) -> Self {
        match code {
            EC_INVALID_ARGUMENT => CodecError::InvalidArgument,
            EC_OUT_OF_SPACE => CodecError::OutOfSpace,
            EC_DECODE_ERROR => CodecError::Decode,
            EC_ENCODE_ERROR => CodecError::Encode,
            EC_HASH_MISMATCH => CodecError::HashMismatch,
            EC_SIGNATURE_INVALID => CodecError::SignatureInvalid,
            EC_KEY_INVALID => CodecError::KeyInvalid,
            EC_PEERID_INVALID => CodecError::PeerId,
            EC_ARENA_EXHAUSTED => CodecError::ArenaExhausted,
            EC_INTERNAL_ERROR => CodecError::Internal,
            other => CodecError::Unknown(other),
        }
    }
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "codec C-ABI error: {self:?}")
    }
}

impl std::error::Error for CodecError {}

/// Seam result alias.
pub type Result<T> = std::result::Result<T, CodecError>;

/// Opaque caller-owned arena for decoded entity bodies (spec §4.5).
#[repr(C)]
struct EcArena {
    _private: [u8; 0],
}

#[allow(non_snake_case)]
mod ffi {
    use super::{c_char, EcArena};
    extern "C" {
        // ECF / hash / entity (§4.1).
        pub fn ec_encode_ecf(
            type_ptr: *const u8,
            type_len: usize,
            data_ptr: *const u8,
            data_len: usize,
            out_ptr: *mut u8,
            out_cap: usize,
            out_len: *mut usize,
        ) -> i32;
        pub fn ec_content_hash(
            type_ptr: *const u8,
            type_len: usize,
            data_ptr: *const u8,
            data_len: usize,
            out_ptr: *mut u8,
        ) -> i32;
        pub fn ec_content_hash_with_format(
            type_ptr: *const u8,
            type_len: usize,
            data_ptr: *const u8,
            data_len: usize,
            format_code: u64,
            out_ptr: *mut u8,
            out_cap: usize,
            out_len: *mut usize,
        ) -> i32;
        pub fn ec_decode_entity(
            bytes_ptr: *const u8,
            len: usize,
            arena: *mut EcArena,
            out_type_ptr: *mut *const u8,
            out_type_len: *mut usize,
            out_data_ptr: *mut *const u8,
            out_data_len: *mut usize,
            out_orig_ptr: *mut *const u8,
            out_orig_len: *mut usize,
        ) -> i32;
        // LEB128 format-code primitives (§3.1 / N1).
        pub fn ec_hash_format_code_encode(
            code: u64,
            out_ptr: *mut u8,
            out_cap: usize,
            out_len: *mut usize,
        ) -> i32;
        pub fn ec_hash_format_code_decode(
            in_ptr: *const u8,
            in_len: usize,
            out_code: *mut u64,
            out_consumed: *mut usize,
        ) -> i32;
        // Test/differential hook (F6): canonical CBOR in -> canonical CBOR out.
        pub fn ec_encode_bare_value(
            in_ptr: *const u8,
            in_len: usize,
            out_ptr: *mut u8,
            out_cap: usize,
            out_len: *mut usize,
        ) -> i32;
        // Peer ID (§4.2).
        pub fn ec_peerid_parse(
            base58_ptr: *const u8,
            base58_len: usize,
            out_key_type: *mut u64,
            out_hash_type: *mut u64,
            out_digest_ptr: *mut u8,
            out_digest_len: *mut usize,
        ) -> i32;
        pub fn ec_peerid_format(
            key_type: u64,
            hash_type: u64,
            digest_ptr: *const u8,
            digest_len: usize,
            out_ptr: *mut u8,
            out_cap: usize,
            out_len: *mut usize,
        ) -> i32;
        // Crypto (§4.3).
        pub fn ec_ed25519_sign(
            priv_ptr: *const u8,
            msg_ptr: *const u8,
            msg_len: usize,
            out_sig: *mut u8,
        ) -> i32;
        pub fn ec_ed25519_verify(
            pub_ptr: *const u8,
            msg_ptr: *const u8,
            msg_len: usize,
            sig_ptr: *const u8,
        ) -> i32;
        pub fn ec_ed25519_seed_to_pubkey(seed_ptr: *const u8, out_pub: *mut u8) -> i32;
        pub fn ec_sha256(data_ptr: *const u8, data_len: usize, out_ptr: *mut u8) -> i32;
        pub fn ec_sha384(data_ptr: *const u8, data_len: usize, out_ptr: *mut u8) -> i32;
        // Crypto agility (§4.3a) — Ed448, validated-not-required.
        pub fn ec_ed448_seed_to_pubkey(seed_ptr: *const u8, out_pub: *mut u8) -> i32;
        pub fn ec_ed448_sign(
            priv_ptr: *const u8,
            msg_ptr: *const u8,
            msg_len: usize,
            out_sig: *mut u8,
        ) -> i32;
        pub fn ec_ed448_verify(
            pub_ptr: *const u8,
            msg_ptr: *const u8,
            msg_len: usize,
            sig_ptr: *const u8,
        ) -> i32;
        // Envelope verification (§4.4).
        pub fn ec_envelope_verify_root_hash(envelope_ptr: *const u8, envelope_len: usize) -> i32;
        // Arena (§4.5).
        pub fn ec_arena_new() -> *mut EcArena;
        pub fn ec_arena_free(arena: *mut EcArena);
        // Introspection (§4.6).
        pub fn ec_abi_version() -> *const c_char;
        pub fn ec_impl_info() -> *const c_char;
    }
}

/// Run a variable-length C-ABI call under the OUT_OF_SPACE grow-and-retry protocol.
/// `call(ptr, cap, &mut out_len)` returns the ABI code; on `EC_OUT_OF_SPACE` the
/// required size is in `out_len`.
fn call_var<F>(mut call: F) -> Result<Vec<u8>>
where
    F: FnMut(*mut u8, usize, *mut usize) -> i32,
{
    let mut cap: usize = 64;
    for _ in 0..8 {
        let mut buf = vec![0u8; cap];
        let mut out_len: usize = 0;
        let rc = call(buf.as_mut_ptr(), cap, &mut out_len as *mut usize);
        if rc == EC_OK {
            buf.truncate(out_len);
            return Ok(buf);
        }
        if rc == EC_OUT_OF_SPACE {
            cap = out_len.max(cap.saturating_mul(2));
            continue;
        }
        return Err(CodecError::from_code(rc));
    }
    Err(CodecError::OutOfSpace)
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return "<null>".to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned() }
}

// ── Introspection / provenance ───────────────────────────────────────────────

/// The C-ABI spec version string (e.g. "1.1"), identical across conforming impls.
pub fn abi_version() -> String {
    cstr(unsafe { ffi::ec_abi_version() })
}

/// Implementation provenance (e.g. "c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71 /
/// libsodium 1.0.22"). This — not the filename — is how the host records which
/// codec it linked. Used to RESOLVE A-DL-003 by pairing it with the byte-identity
/// corpus run (the v7.71-labelled codec producing byte-exact v0.8.0 output IS the
/// proof the core wire is unchanged across V7→V8).
pub fn impl_info() -> String {
    cstr(unsafe { ffi::ec_impl_info() })
}

// ── ECF / content_hash ───────────────────────────────────────────────────────

/// Canonical ECF encoding of an entity `{type, data}` where `data` is already the
/// canonical CBOR of the data value (spec §4.1 `ec_encode_ecf`).
pub fn encode_ecf(type_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    call_var(|out, cap, out_len| unsafe {
        ffi::ec_encode_ecf(
            type_bytes.as_ptr(),
            type_bytes.len(),
            data.as_ptr(),
            data.len(),
            out,
            cap,
            out_len,
        )
    })
}

/// content_hash under the default format 0x00 (SHA-256): `0x00 ‖ SHA-256(ECF)`,
/// 33 bytes (spec §4.1 `ec_content_hash`).
pub fn content_hash(type_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; EC_CONTENT_HASH_LEN];
    let rc = unsafe {
        ffi::ec_content_hash(
            type_bytes.as_ptr(),
            type_bytes.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
        )
    };
    if rc == EC_OK {
        Ok(out)
    } else {
        Err(CodecError::from_code(rc))
    }
}

/// content_hash under an explicit format code (spec §4.1a): `varint(code) ‖
/// DIGEST_code(ECF)`. Supported codes = {0x00 SHA-256, 0x01 SHA-384}; any other →
/// `CodecError::Decode` (`unsupported_content_hash_format`) — the conformant
/// "report unsupported rather than emit wrong bytes" branch for synthetic codes.
pub fn content_hash_with_format(
    type_bytes: &[u8],
    data: &[u8],
    format_code: u64,
) -> Result<Vec<u8>> {
    call_var(|out, cap, out_len| unsafe {
        ffi::ec_content_hash_with_format(
            type_bytes.as_ptr(),
            type_bytes.len(),
            data.as_ptr(),
            data.len(),
            format_code,
            out,
            cap,
            out_len,
        )
    })
}

/// A decoded entity, with the original wire bytes preserved for N4 fidelity.
#[derive(Debug, Clone)]
pub struct DecodedEntity {
    pub type_bytes: Vec<u8>,
    pub data: Vec<u8>,
    /// The EXACT original wire bytes of this entity (N4). The host forwards THESE,
    /// never a re-encode of `data`/`type_bytes`.
    pub original: Vec<u8>,
}

/// Decode one entity, running the §3.2 recursive major-type-6 tag scanner (N2):
/// any tag in a `data` region → `CodecError::Decode`. Returns the type/data slices
/// (copied out of the C arena) plus the original-byte span (N4).
pub fn decode_entity(bytes: &[u8]) -> Result<DecodedEntity> {
    let arena = unsafe { ffi::ec_arena_new() };
    if arena.is_null() {
        return Err(CodecError::ArenaExhausted);
    }
    let mut type_ptr: *const u8 = std::ptr::null();
    let mut type_len: usize = 0;
    let mut data_ptr: *const u8 = std::ptr::null();
    let mut data_len: usize = 0;
    let mut orig_ptr: *const u8 = std::ptr::null();
    let mut orig_len: usize = 0;
    let rc = unsafe {
        ffi::ec_decode_entity(
            bytes.as_ptr(),
            bytes.len(),
            arena,
            &mut type_ptr,
            &mut type_len,
            &mut data_ptr,
            &mut data_len,
            &mut orig_ptr,
            &mut orig_len,
        )
    };
    let out = if rc == EC_OK {
        // Copy out of the arena (borrowed until ec_arena_free) / input span.
        let type_bytes = slice_copy(type_ptr, type_len);
        let data = slice_copy(data_ptr, data_len);
        let original = slice_copy(orig_ptr, orig_len);
        Ok(DecodedEntity {
            type_bytes,
            data,
            original,
        })
    } else {
        Err(CodecError::from_code(rc))
    };
    unsafe { ffi::ec_arena_free(arena) };
    out
}

fn slice_copy(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(ptr, len).to_vec() }
}

// ── LEB128 format-code primitives (N1) ───────────────────────────────────────

/// Encode a hash/key format code as LEB128 (spec §3.1 / N1). Codes < 0x80 are a
/// single byte (byte-identical to a fixed field today); ≥ 0x80 extend to 2+ bytes.
pub fn hash_format_code_encode(code: u64) -> Result<Vec<u8>> {
    call_var(|out, cap, out_len| unsafe {
        ffi::ec_hash_format_code_encode(code, out, cap, out_len)
    })
}

/// Decode a LEB128 format code → (code, bytes_consumed).
pub fn hash_format_code_decode(bytes: &[u8]) -> Result<(u64, usize)> {
    let mut code: u64 = 0;
    let mut consumed: usize = 0;
    let rc = unsafe {
        ffi::ec_hash_format_code_decode(bytes.as_ptr(), bytes.len(), &mut code, &mut consumed)
    };
    if rc == EC_OK {
        Ok((code, consumed))
    } else {
        Err(CodecError::from_code(rc))
    }
}

/// Test/differential hook (F6): decode one canonical ECF value and re-emit it
/// through the bare canonical encoder — identity for canonical input, and a real
/// exercise of minimisation + map-key ordering for non-canonical input. NOT a
/// protocol surface; used by the S2 wire-conformance harness for the Class-A
/// (float/int/map_keys/length/nested/primitive/envelope) categories.
pub fn encode_bare_value(input: &[u8]) -> Result<Vec<u8>> {
    call_var(|out, cap, out_len| unsafe {
        ffi::ec_encode_bare_value(input.as_ptr(), input.len(), out, cap, out_len)
    })
}

// ── Peer ID ──────────────────────────────────────────────────────────────────

/// Format a peer-id: `base58( varint(key_type) ‖ varint(hash_type) ‖ digest )`
/// (spec §4.2). Returns the base58 ASCII string.
pub fn peerid_format(key_type: u64, hash_type: u64, digest: &[u8]) -> Result<String> {
    let bytes = call_var(|out, cap, out_len| unsafe {
        ffi::ec_peerid_format(
            key_type,
            hash_type,
            digest.as_ptr(),
            digest.len(),
            out,
            cap,
            out_len,
        )
    })?;
    String::from_utf8(bytes).map_err(|_| CodecError::PeerId)
}

/// Parse a base58 peer-id → (key_type, hash_type, digest).
pub fn peerid_parse(base58: &str) -> Result<(u64, u64, Vec<u8>)> {
    let b = base58.as_bytes();
    let mut key_type: u64 = 0;
    let mut hash_type: u64 = 0;
    let mut digest = vec![0u8; 64];
    let mut digest_len: usize = digest.len();
    let rc = unsafe {
        ffi::ec_peerid_parse(
            b.as_ptr(),
            b.len(),
            &mut key_type,
            &mut hash_type,
            digest.as_mut_ptr(),
            &mut digest_len,
        )
    };
    if rc == EC_OK {
        digest.truncate(digest_len);
        Ok((key_type, hash_type, digest))
    } else {
        Err(CodecError::from_code(rc))
    }
}

// ── Crypto (Ed25519 + SHA) ───────────────────────────────────────────────────

/// SHA-256 (spec §4.3). Infallible in practice; a non-OK code surfaces as an error.
pub fn sha256(data: &[u8]) -> Result<[u8; EC_SHA256_LEN]> {
    let mut out = [0u8; EC_SHA256_LEN];
    let rc = unsafe { ffi::ec_sha256(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    if rc == EC_OK {
        Ok(out)
    } else {
        Err(CodecError::from_code(rc))
    }
}

/// SHA-384 (spec §4.3a, agility) — validated-not-required at the floor.
pub fn sha384(data: &[u8]) -> Result<[u8; EC_SHA384_LEN]> {
    let mut out = [0u8; EC_SHA384_LEN];
    let rc = unsafe { ffi::ec_sha384(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    if rc == EC_OK {
        Ok(out)
    } else {
        Err(CodecError::from_code(rc))
    }
}

/// Ed25519 sign: `priv` is the 32-byte seed (entity-core PEM = base64 of the seed);
/// returns the 64-byte signature over `msg` (spec §4.3).
pub fn ed25519_sign(seed: &[u8], msg: &[u8]) -> Result<[u8; EC_ED25519_SIG_LEN]> {
    if seed.len() != EC_ED25519_SEED_LEN {
        return Err(CodecError::KeyInvalid);
    }
    let mut sig = [0u8; EC_ED25519_SIG_LEN];
    let rc =
        unsafe { ffi::ec_ed25519_sign(seed.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr()) };
    if rc == EC_OK {
        Ok(sig)
    } else {
        Err(CodecError::from_code(rc))
    }
}

/// Ed25519 verify — `true` iff the signature is valid. The host asserts
/// `verified_signer(_)` INTO the Datalog program only on `true` (S3).
pub fn ed25519_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pubkey.len() != EC_ED25519_PUB_LEN || sig.len() != EC_ED25519_SIG_LEN {
        return false;
    }
    let rc =
        unsafe { ffi::ec_ed25519_verify(pubkey.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) };
    rc == EC_OK
}

/// Ed25519 seed → 32-byte public key (RFC 8032). Used to derive the peer's identity
/// public key from the persistent on-disk seed (the `--name` keypair convention).
pub fn ed25519_seed_to_pubkey(seed: &[u8]) -> Result<[u8; EC_ED25519_PUB_LEN]> {
    if seed.len() != EC_ED25519_SEED_LEN {
        return Err(CodecError::KeyInvalid);
    }
    let mut out = [0u8; EC_ED25519_PUB_LEN];
    let rc = unsafe { ffi::ec_ed25519_seed_to_pubkey(seed.as_ptr(), out.as_mut_ptr()) };
    if rc == EC_OK {
        Ok(out)
    } else {
        Err(CodecError::from_code(rc))
    }
}

// ── Crypto agility (Ed448) — validated-not-required ──────────────────────────

/// Ed448 seed → 57-byte public key (RFC 8032). MAY return `CodecError::Internal`
/// if the impl does not implement Ed448 (the floor does not require it).
pub fn ed448_seed_to_pubkey(seed: &[u8]) -> Result<[u8; EC_ED448_PUB_LEN]> {
    if seed.len() != EC_ED448_SEED_LEN {
        return Err(CodecError::KeyInvalid);
    }
    let mut out = [0u8; EC_ED448_PUB_LEN];
    let rc = unsafe { ffi::ec_ed448_seed_to_pubkey(seed.as_ptr(), out.as_mut_ptr()) };
    if rc == EC_OK {
        Ok(out)
    } else {
        Err(CodecError::from_code(rc))
    }
}

/// Ed448 sign (`priv` = 57-byte seed) → 114-byte signature. May be unimplemented.
pub fn ed448_sign(seed: &[u8], msg: &[u8]) -> Result<[u8; EC_ED448_SIG_LEN]> {
    if seed.len() != EC_ED448_SEED_LEN {
        return Err(CodecError::KeyInvalid);
    }
    let mut sig = [0u8; EC_ED448_SIG_LEN];
    let rc =
        unsafe { ffi::ec_ed448_sign(seed.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr()) };
    if rc == EC_OK {
        Ok(sig)
    } else {
        Err(CodecError::from_code(rc))
    }
}

/// Ed448 verify — `true` iff valid (and implemented).
pub fn ed448_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pubkey.len() != EC_ED448_PUB_LEN || sig.len() != EC_ED448_SIG_LEN {
        return false;
    }
    let rc =
        unsafe { ffi::ec_ed448_verify(pubkey.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) };
    rc == EC_OK
}

// ── Envelope verification (§4.4) ─────────────────────────────────────────────

/// Verify an envelope's root hash (spec §4.4). Not corpus-driven (the `envelope`
/// category is `encode_equal`); part of the S3-facing seam.
pub fn envelope_verify_root_hash(envelope: &[u8]) -> Result<()> {
    let rc = unsafe { ffi::ec_envelope_verify_root_hash(envelope.as_ptr(), envelope.len()) };
    if rc == EC_OK {
        Ok(())
    } else {
        Err(CodecError::from_code(rc))
    }
}

// ── Seam-level unit tests (KATs + N1–N4) ─────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// content_hash.1 canonical (v0.8.0 corpus): the empty-entity boundary
    /// `{type:"system/empty", data:{}}` → `0x00 ‖ SHA-256(ECF)`. Pins N3.
    const CONTENT_HASH_1: &str =
        "005f3139e342f5ef35c1e0eb3140c4511c469d604979d20542bc2ab92fd0ca396b";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn provenance_reachable() {
        // Proves the seam links + calls; records the A-DL-003 provenance label.
        let abi = abi_version();
        let info = impl_info();
        assert!(!abi.is_empty() && abi != "<null>", "abi_version: {abi}");
        assert!(info.contains("ecf-c-abi"), "impl_info: {info}");
        eprintln!("C-ABI {abi} / {info}");
    }

    #[test]
    fn sha256_kat() {
        // SHA-256("abc") — NIST known answer.
        let got = sha256(b"abc").unwrap();
        assert_eq!(
            got.to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn sha384_kat() {
        // SHA-384("abc") — NIST known answer (agility, validated-not-required).
        let got = sha384(b"abc").unwrap();
        assert_eq!(
            got.to_vec(),
            hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        );
    }

    #[test]
    fn ed25519_roundtrip() {
        // Deterministic seed → derive pubkey → sign → verify (accept) → tamper (reject).
        let seed = [0u8; 32];
        let pk = ed25519_seed_to_pubkey(&seed).unwrap();
        let msg = b"entity-core datalog seam";
        let sig = ed25519_sign(&seed, msg).unwrap();
        assert!(ed25519_verify(&pk, msg, &sig), "valid sig must verify");
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!ed25519_verify(&pk, msg, &bad), "tampered sig must fail");
    }

    #[test]
    fn signature_1_vector() {
        // v0.8.0 corpus signature.1: seed=0×32, entity {type:"test/v1", data:{x:1}}.
        // ECF({x:1}) data = a1 61 78 01. Proves sign(seed, ECF) is byte-exact.
        let seed = [0u8; 32];
        let ecf = encode_ecf(b"test/v1", &hex("a1617801")).unwrap();
        let sig = ed25519_sign(&seed, &ecf).unwrap();
        assert_eq!(
            sig.to_vec(),
            hex("3f0b5d06636ea267199dc27eb20d8c9b37684d681adc5be43be465819ad643e3b152e5c024bf67ce862699fe439462d7852b029cb125cd917d12a3151529230c")
        );
    }

    #[test]
    fn n1_leb128_format_code() {
        // Allocated codes < 0x80 → single byte; synthetic ≥ 0x80 → multi-byte varint.
        assert_eq!(hash_format_code_encode(0).unwrap(), vec![0x00]);
        assert_eq!(hash_format_code_encode(1).unwrap(), vec![0x01]);
        assert_eq!(hash_format_code_encode(128).unwrap(), vec![0x80, 0x01]);
        assert_eq!(hash_format_code_decode(&[0x00]).unwrap(), (0, 1));
        assert_eq!(hash_format_code_decode(&[0x80, 0x01]).unwrap(), (128, 2));
    }

    #[test]
    fn n2_tag_reject() {
        // tag_reject.1: tag 0 (datetime) inside a data field → MUST reject (§6.3).
        let bytes = hex("a26464617461a1627473c074323032362d30362d30365431323a30303a30305a647479706567746573742f7631");
        assert!(
            decode_entity(&bytes).is_err(),
            "major-type-6 tag in data MUST be rejected"
        );
    }

    #[test]
    fn n3_empty_params_0xa0() {
        // Empty data is the single byte 0xA0 (empty CBOR map). Hashing the empty
        // entity must reproduce content_hash.1 exactly.
        let got = content_hash(b"system/empty", &[0xA0]).unwrap();
        assert_eq!(got, hex(CONTENT_HASH_1));
        // And the ECF of empty data embeds the 0xA0 empty-map byte.
        let ecf = encode_ecf(b"system/empty", &[0xA0]).unwrap();
        assert!(ecf.contains(&0xA0), "ECF must carry the 0xA0 empty map");
    }

    #[test]
    fn n4_entity_fidelity_forward_original() {
        // Encode an entity, decode it, and assert the returned original bytes are
        // byte-identical to the input (never a re-serialization of the decoded form).
        let ecf = encode_ecf(b"test/v1", &hex("a1617801")).unwrap();
        let decoded = decode_entity(&ecf).unwrap();
        assert_eq!(
            decoded.original, ecf,
            "N4: original bytes must be forwarded verbatim"
        );
    }
}
