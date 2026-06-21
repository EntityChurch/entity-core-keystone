//! entity-core-codec-ffi-rust — a conforming implementation of the Entity Codec
//! C-ABI (ffi-generator/c-abi/spec/ENTITY-CODEC-C-ABI-V1.md), ABI 1.1, over
//! spec-data v7.71.
//!
//! Layout:
//!   - `value` / `encode` / `decode` — the hand-written canonical core.
//!   - `api` — safe Rust surface mirroring the §4 ABI; used directly by the
//!     conformance harness (src/bin/conformance_harness.rs).
//!   - the `extern "C"` block — the §4 symbols exported into
//!     libentitycore_codec.{so,a}, each panic-guarded (R6) → int32 error codes.
//!
//! REAL: encode / content_hash(+_with_format) / sha256 / sha384 / ed25519
//! sign+verify+keygen / ed448 sign+verify+keygen+seed→pubkey / peer-id
//! format+parse / LEB128 format-code / decode tag-reject (N2) + N4 type/data
//! spans / envelope verify + find-signature / arena trio / bare-encode hook.
//!
//! AGILITY (C-ABI v1.1, v7.67): SHA-384 (format 0x01) + Ed448 (key_type 0x02)
//! land as validated-not-required exports; the conformance floor stays
//! Ed25519 + SHA-256. Supported content_hash_format codes = {0x00, 0x01};
//! all others → unsupported_content_hash_format (EC_DECODE_ERROR).
//!
//! COVERAGE NOTE: ec_envelope_* and the §4.5 arena trio are NOT driven by any
//! corpus vector (the `envelope` corpus category is encode_equal); they are
//! implemented to the §5.3 schema and covered by unit tests + the cross-impl
//! dlopen differential. See the agility ambiguity-log addendum.

pub mod decode;
pub mod encode;
pub mod value;

/// Safe Rust surface mirroring the ABI. The harness links this (rlib); the FFI
/// block below wraps the same functions.
pub mod api {
    use crate::decode;
    use crate::encode;
    use crate::value::Value;
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
    use sha2::{Digest, Sha256, Sha384};

    /// Ed448 raw lengths (RFC 8032): 57-byte seed, 57-byte public key, 114-byte
    /// signature. SHA-384 digest is 48 bytes.
    pub const ED448_SEED_LEN: usize = 57;
    pub const ED448_PUB_LEN: usize = 57;
    pub const ED448_SIG_LEN: usize = 114;
    pub const SHA384_LEN: usize = 48;

    /// Content-hash format codes that this codec implements (V7 §1.2 seed
    /// table). 0x00 = SHA-256, 0x01 = SHA-384. Everything else is
    /// `unsupported_content_hash_format` (BLAKE3/etc. are v7.67 Phase-3a,
    /// deferred). The framing (LEB128 varint) accepts any code; this set gates
    /// which codes have a digest algorithm bound.
    pub fn content_hash_format_supported(code: u64) -> bool {
        matches!(code, 0 | 1)
    }

    /// Canonical ECF encoding of a value (spec §4.1 `ec_encode_ecf` core).
    pub fn encode_value(v: &Value) -> Vec<u8> {
        encode::encode(v)
    }

    /// SHA-256 (spec §4.3 `ec_sha256`).
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    /// Unsigned LEB128 encode (spec §3.1 / N1 `ec_hash_format_code_encode`).
    pub fn leb128_encode(mut code: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (code & 0x7f) as u8;
            code >>= 7;
            if code != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if code == 0 {
                break;
            }
        }
        out
    }

    /// Unsigned LEB128 decode → (value, bytes_consumed).
    pub fn leb128_decode(bytes: &[u8]) -> Option<(u64, usize)> {
        let mut result: u64 = 0;
        let mut shift = 0;
        for (i, &b) in bytes.iter().enumerate() {
            if shift >= 64 {
                return None;
            }
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some((result, i + 1));
            }
            shift += 7;
        }
        None
    }

    /// content_hash = varint(format_code) ‖ SHA256(ECF({type, data})) (spec §4.1).
    /// `data` is the opaque, already-canonical CBOR of the data field (N4); the
    /// entity hashed is the 2-key map {data, type} (canonically key-sorted).
    pub fn content_hash(type_str: &str, data_bytes: &[u8], format_code: u64) -> Vec<u8> {
        let entity = Value::Map(vec![
            (Value::Text("data".into()), Value::PreEncoded(data_bytes.to_vec())),
            (Value::Text("type".into()), Value::Text(type_str.to_string())),
        ]);
        let digest = sha256(&encode::encode(&entity));
        let mut out = leb128_encode(format_code);
        out.extend_from_slice(&digest);
        out
    }

    /// peer-id format: Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)
    /// (spec §4.2). Bitcoin alphabet (bs58 default).
    pub fn peerid_format(key_type: u64, hash_type: u64, digest: &[u8]) -> String {
        let mut raw = leb128_encode(key_type);
        raw.extend_from_slice(&leb128_encode(hash_type));
        raw.extend_from_slice(digest);
        bs58::encode(raw).into_string()
    }

    /// peer-id parse → (key_type, hash_type, digest).
    pub fn peerid_parse(s: &str) -> Option<(u64, u64, Vec<u8>)> {
        let raw = bs58::decode(s).into_vec().ok()?;
        let (key_type, n1) = leb128_decode(&raw)?;
        let (hash_type, n2) = leb128_decode(&raw[n1..])?;
        let digest = raw[n1 + n2..].to_vec();
        Some((key_type, hash_type, digest))
    }

    /// Deterministic Ed25519 sign over `msg` with a 32-byte seed (= the signing
    /// key bytes per RFC 8032). Spec §4.3 `ec_ed25519_sign`.
    pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(seed);
        sk.sign(msg).to_bytes()
    }

    pub fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        let vk = match VerifyingKey::from_bytes(pubkey) {
            Ok(k) => k,
            Err(_) => return false,
        };
        vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
    }

    /// Decode-entity N2 gate: returns the original bytes on success, errors on
    /// any tag / malformed / indefinite item (spec §4.1, §3.2).
    pub fn decode_entity(bytes: &[u8]) -> Result<&[u8], decode::DecodeError> {
        decode::validate_no_tags(bytes)?;
        Ok(bytes)
    }

    /// Parse arbitrary canonical CBOR back into a `Value` (harness input path).
    pub fn parse_value(bytes: &[u8]) -> Result<Value, decode::DecodeError> {
        decode::decode_value(bytes)
    }

    // ── Crypto agility (C-ABI v1.1, v7.67 Phase 1/2) ──────────────────────────

    /// SHA-384 (spec §4.3a `ec_sha384`; content_hash_format 0x01 digest).
    pub fn sha384(data: &[u8]) -> [u8; SHA384_LEN] {
        let mut h = Sha384::new();
        h.update(data);
        h.finalize().into()
    }

    /// content_hash under an explicit format code (spec §4.1a
    /// `ec_content_hash_with_format`):
    ///   `varint(format_code) ‖ DIGEST_format(ECF({type, data}))`
    /// 0x00 → SHA-256 (33 B), 0x01 → SHA-384 (49 B). Returns `None` for any
    /// unsupported code (`unsupported_content_hash_format`). `data` is the
    /// already-canonical CBOR of the data field (N4), spliced verbatim.
    pub fn content_hash_with_format(
        type_str: &str,
        data_bytes: &[u8],
        format_code: u64,
    ) -> Option<Vec<u8>> {
        if !content_hash_format_supported(format_code) {
            return None;
        }
        let entity = Value::Map(vec![
            (Value::Text("data".into()), Value::PreEncoded(data_bytes.to_vec())),
            (Value::Text("type".into()), Value::Text(type_str.to_string())),
        ]);
        let body = encode::encode(&entity);
        let mut out = leb128_encode(format_code);
        match format_code {
            0 => out.extend_from_slice(&sha256(&body)),
            1 => out.extend_from_slice(&sha384(&body)),
            _ => return None, // unreachable given the guard, kept for totality
        }
        Some(out)
    }

    /// Ed25519 keypair generation from the OS CSPRNG (R2: OsRng, never
    /// ThreadRng). Returns (32-byte seed, 32-byte public key). Not byte-pinned
    /// (random); covered by a round-trip self-test.
    pub fn ed25519_keygen() -> ([u8; 32], [u8; 32]) {
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        (sk.to_bytes(), sk.verifying_key().to_bytes())
    }

    /// Ed25519 seed → 32-byte public key (RFC 8032). Used by the agility harness
    /// to reproduce matrix peer pubkeys deterministically.
    pub fn ed25519_seed_to_pubkey(seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    /// Ed448 seed → 57-byte public key (RFC 8032). Mirrors the reference
    /// cohort's `ed448-goldilocks` derivation. `None` on an invalid seed.
    pub fn ed448_seed_to_pubkey(seed: &[u8; ED448_SEED_LEN]) -> Option<[u8; ED448_PUB_LEN]> {
        let sk = ed448_goldilocks::SigningKey::try_from(&seed[..]).ok()?;
        Some(sk.verifying_key().to_bytes().into())
    }

    /// Deterministic Ed448 sign over `msg` with a 57-byte seed (RFC 8032 pure,
    /// no context). Returns the 114-byte detached signature. `None` on an
    /// invalid seed.
    pub fn ed448_sign(seed: &[u8; ED448_SEED_LEN], msg: &[u8]) -> Option<[u8; ED448_SIG_LEN]> {
        use ed448_goldilocks::signature::Signer;
        let sk = ed448_goldilocks::SigningKey::try_from(&seed[..]).ok()?;
        let sig: ed448_goldilocks::Signature = sk.sign(msg);
        Some(sig.to_bytes())
    }

    /// Verify a 114-byte Ed448 signature against a 57-byte public key.
    pub fn ed448_verify(
        pubkey: &[u8; ED448_PUB_LEN],
        msg: &[u8],
        sig: &[u8; ED448_SIG_LEN],
    ) -> bool {
        use ed448_goldilocks::signature::Verifier;
        let pk = match ed448_goldilocks::VerifyingKey::from_bytes(&(*pubkey).into()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let s = match ed448_goldilocks::Signature::try_from(&sig[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        pk.verify(msg, &s).is_ok()
    }

    /// Ed448 keypair generation from the OS CSPRNG (R2). Returns (57-byte seed,
    /// 57-byte public key). Not byte-pinned; round-trip self-tested.
    pub fn ed448_keygen() -> ([u8; ED448_SEED_LEN], [u8; ED448_PUB_LEN]) {
        use rand::RngCore;
        let mut seed = [0u8; ED448_SEED_LEN];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let pk = ed448_seed_to_pubkey(&seed).expect("57 random bytes is a valid Ed448 seed");
        (seed, pk)
    }

    // ── Envelope verification (spec §4.4) ─────────────────────────────────────
    //
    // NOTE (coverage): no ECF/agility corpus vector drives these two — the
    // `envelope` corpus category is `encode_equal` (encoder tests). They are
    // implemented to the §5.3 envelope schema and covered by the unit tests
    // below + the cross-impl dlopen differential. Logged in the ambiguity log.

    /// Outcome of `ec_envelope_verify_root_hash`.
    #[derive(Debug, PartialEq)]
    pub enum EnvelopeVerify {
        Ok,
        HashMismatch,
        Malformed,
    }

    fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
        map.iter().find_map(|(k, v)| match k {
            Value::Text(t) if t == key => Some(v),
            _ => None,
        })
    }

    /// Decode an envelope, recompute the root entity's content_hash from its
    /// `{type, data}` and compare against the root's declared `content_hash`
    /// (spec §4.4 / §5.3). The declared hash's LEB128 prefix selects the digest
    /// algorithm.
    pub fn envelope_verify_root_hash(bytes: &[u8]) -> EnvelopeVerify {
        let view = match decode::envelope_view(bytes) {
            Ok(v) => v,
            Err(_) => return EnvelopeVerify::Malformed,
        };
        let root_bytes = &bytes[view.root.off..view.root.off + view.root.len];
        let root = match decode::decode_value(root_bytes) {
            Ok(Value::Map(m)) => m,
            _ => return EnvelopeVerify::Malformed,
        };
        let type_str = match map_get(&root, "type") {
            Some(Value::Text(s)) => s.clone(),
            _ => return EnvelopeVerify::Malformed,
        };
        let data = match map_get(&root, "data") {
            Some(v) => v,
            None => return EnvelopeVerify::Malformed,
        };
        let declared = match map_get(&root, "content_hash") {
            Some(Value::Bytes(b)) => b.clone(),
            _ => return EnvelopeVerify::Malformed,
        };
        let fmt = match leb128_decode(&declared) {
            Some((code, _)) => code,
            None => return EnvelopeVerify::Malformed,
        };
        // Canonical input ⇒ re-encoding the decoded data field is identity.
        let data_bytes = encode::encode(data);
        match content_hash_with_format(&type_str, &data_bytes, fmt) {
            Some(computed) if computed == declared => EnvelopeVerify::Ok,
            Some(_) => EnvelopeVerify::HashMismatch,
            None => EnvelopeVerify::Malformed,
        }
    }

    /// Scan an envelope's `included` map for a `system/signature` entity whose
    /// `data.target` equals `target_hash`; return the byte span (offset, len) of
    /// that entity within `bytes` (spec §4.4). `None` if not found / malformed.
    pub fn envelope_find_signature_for(bytes: &[u8], target_hash: &[u8]) -> Option<(usize, usize)> {
        let view = decode::envelope_view(bytes).ok()?;
        for (_kspan, espan) in &view.included {
            let ebytes = &bytes[espan.off..espan.off + espan.len];
            let entity = match decode::decode_value(ebytes) {
                Ok(Value::Map(m)) => m,
                _ => continue,
            };
            let is_sig = matches!(
                map_get(&entity, "type"),
                Some(Value::Text(t)) if t.starts_with("system/signature")
            );
            if !is_sig {
                continue;
            }
            if let Some(Value::Map(data)) = map_get(&entity, "data") {
                if let Some(Value::Bytes(tgt)) = map_get(data, "target") {
                    if tgt.as_slice() == target_hash {
                        return Some((espan.off, espan.len));
                    }
                }
            }
        }
        None
    }
}

// ───────────────────────── C-ABI exports (spec §4) ─────────────────────────
//
// Each fallible export is panic-guarded so no Rust panic crosses the boundary
// (spec §5 rule 6 / R6). Strings are static & null-terminated (§5 rule 4 excpt).

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

pub const EC_OK: i32 = 0;
pub const EC_INVALID_ARGUMENT: i32 = -1;
pub const EC_OUT_OF_SPACE: i32 = -2;
pub const EC_DECODE_ERROR: i32 = -3;
#[allow(dead_code)]
pub const EC_ENCODE_ERROR: i32 = -4;
pub const EC_HASH_MISMATCH: i32 = -5;
pub const EC_SIGNATURE_INVALID: i32 = -6;
#[allow(dead_code)]
pub const EC_KEY_INVALID: i32 = -7;
pub const EC_PEERID_INVALID: i32 = -8;
pub const EC_INTERNAL_ERROR: i32 = -99;

/// Copy `src` into the caller buffer, honoring the OUT_OF_SPACE protocol (§5 rule 2).
unsafe fn write_out(src: &[u8], out_ptr: *mut u8, out_cap: usize, out_len: *mut usize) -> i32 {
    if !out_len.is_null() {
        *out_len = src.len();
    }
    if out_ptr.is_null() || out_cap < src.len() {
        return EC_OUT_OF_SPACE;
    }
    ptr::copy_nonoverlapping(src.as_ptr(), out_ptr, src.len());
    EC_OK
}

#[no_mangle]
pub extern "C" fn ec_encode_ecf(
    type_ptr: *const u8,
    type_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if type_ptr.is_null() || data_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let type_str = unsafe { std::slice::from_raw_parts(type_ptr, type_len) };
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
        let type_text = match std::str::from_utf8(type_str) {
            Ok(s) => s.to_string(),
            Err(_) => return EC_INVALID_ARGUMENT,
        };
        let ecf = encode::encode(&value::Value::Map(vec![
            (value::Value::Text("data".into()), value::Value::PreEncoded(data.to_vec())),
            (value::Value::Text("type".into()), value::Value::Text(type_text)),
        ]));
        unsafe { write_out(&ecf, out_ptr, out_cap, out_len) }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_content_hash(
    type_ptr: *const u8,
    type_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if type_ptr.is_null() || data_ptr.is_null() || out_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let type_bytes = unsafe { std::slice::from_raw_parts(type_ptr, type_len) };
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
        let type_str = match std::str::from_utf8(type_bytes) {
            Ok(s) => s,
            Err(_) => return EC_INVALID_ARGUMENT,
        };
        let h = api::content_hash(type_str, data, 0);
        // common 0x00-code case is 33 bytes (EC_CONTENT_HASH_LEN).
        unsafe { ptr::copy_nonoverlapping(h.as_ptr(), out_ptr, h.len()) };
        EC_OK
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_sha256(data_ptr: *const u8, data_len: usize, out_ptr: *mut u8) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if data_ptr.is_null() || out_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
        let h = api::sha256(data);
        unsafe { ptr::copy_nonoverlapping(h.as_ptr(), out_ptr, 32) };
        EC_OK
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_ed25519_sign(
    priv_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    out_sig: *mut u8,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if priv_ptr.is_null() || msg_ptr.is_null() || out_sig.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let seed_slice = unsafe { std::slice::from_raw_parts(priv_ptr, 32) };
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_slice);
        let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
        let sig = api::ed25519_sign(&seed, msg);
        unsafe { ptr::copy_nonoverlapping(sig.as_ptr(), out_sig, 64) };
        EC_OK
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_ed25519_verify(
    pub_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if pub_ptr.is_null() || msg_ptr.is_null() || sig_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(unsafe { std::slice::from_raw_parts(pub_ptr, 32) });
        let mut sig = [0u8; 64];
        sig.copy_from_slice(unsafe { std::slice::from_raw_parts(sig_ptr, 64) });
        let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
        if api::ed25519_verify(&pk, msg, &sig) {
            EC_OK
        } else {
            EC_SIGNATURE_INVALID
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

/// Ed25519 seed → 32-byte public key (RFC 8032). Spec §4.6 `ec_ed25519_seed_to_pubkey`.
/// Mirrors `ec_ed448_seed_to_pubkey` for the Ed25519 family so a peer whose core
/// crypto is FFI-sourced can derive its identity public key from a persistent
/// on-disk seed (the `--name` keypair convention). Infallible for any 32 bytes.
#[no_mangle]
pub extern "C" fn ec_ed25519_seed_to_pubkey(seed_ptr: *const u8, out_pub: *mut u8) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if seed_ptr.is_null() || out_pub.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(unsafe { std::slice::from_raw_parts(seed_ptr, 32) });
        let pk = api::ed25519_seed_to_pubkey(&seed);
        unsafe { ptr::copy_nonoverlapping(pk.as_ptr(), out_pub, 32) };
        EC_OK
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_peerid_format(
    key_type: u64,
    hash_type: u64,
    digest_ptr: *const u8,
    digest_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if digest_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let digest = unsafe { std::slice::from_raw_parts(digest_ptr, digest_len) };
        let s = api::peerid_format(key_type, hash_type, digest);
        unsafe { write_out(s.as_bytes(), out_ptr, out_cap, out_len) }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_peerid_parse(
    base58_ptr: *const u8,
    base58_len: usize,
    out_key_type: *mut u64,
    out_hash_type: *mut u64,
    out_digest_ptr: *mut u8,
    out_digest_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if base58_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let s = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(base58_ptr, base58_len) }) {
            Ok(s) => s,
            Err(_) => return EC_PEERID_INVALID,
        };
        match api::peerid_parse(s) {
            Some((kt, ht, digest)) => {
                if !out_key_type.is_null() {
                    unsafe { *out_key_type = kt };
                }
                if !out_hash_type.is_null() {
                    unsafe { *out_hash_type = ht };
                }
                unsafe { write_out(&digest, out_digest_ptr, usize::MAX, out_digest_len) }
            }
            None => EC_PEERID_INVALID,
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_hash_format_code_encode(
    code: u64,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let bytes = api::leb128_encode(code);
        unsafe { write_out(&bytes, out_ptr, out_cap, out_len) }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_hash_format_code_decode(
    in_ptr: *const u8,
    in_len: usize,
    out_code: *mut u64,
    out_consumed: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if in_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let bytes = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };
        match api::leb128_decode(bytes) {
            Some((code, consumed)) => {
                if !out_code.is_null() {
                    unsafe { *out_code = code };
                }
                if !out_consumed.is_null() {
                    unsafe { *out_consumed = consumed };
                }
                EC_OK
            }
            None => EC_DECODE_ERROR,
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_decode_entity(
    bytes_ptr: *const u8,
    len: usize,
    _arena: *mut std::ffi::c_void,
    out_type_ptr: *mut *const u8,
    out_type_len: *mut usize,
    out_data_ptr: *mut *const u8,
    out_data_len: *mut usize,
    out_orig_ptr: *mut *const u8,
    out_orig_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if bytes_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let bytes = unsafe { std::slice::from_raw_parts(bytes_ptr, len) };
        // N4 (spec §4.1 option a): all three spans are BORROWED slices of the
        // caller's input — type & data slices + the exact original entity bytes.
        // No arena allocation is needed (this impl decodes by borrowed span);
        // `arena` may be NULL. Tag scan (N2) runs inside entity_spans.
        match decode::entity_spans(bytes) {
            Ok((tspan, dspan)) => {
                unsafe {
                    if !out_type_ptr.is_null() {
                        *out_type_ptr = bytes.as_ptr().add(tspan.off);
                    }
                    if !out_type_len.is_null() {
                        *out_type_len = tspan.len;
                    }
                    if !out_data_ptr.is_null() {
                        *out_data_ptr = bytes.as_ptr().add(dspan.off);
                    }
                    if !out_data_len.is_null() {
                        *out_data_len = dspan.len;
                    }
                    if !out_orig_ptr.is_null() {
                        *out_orig_ptr = bytes.as_ptr();
                    }
                    if !out_orig_len.is_null() {
                        *out_orig_len = bytes.len();
                    }
                }
                EC_OK
            }
            Err(_) => EC_DECODE_ERROR,
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

// --- Introspection (spec §4.6) ---

#[no_mangle]
pub extern "C" fn ec_abi_version() -> *const c_char {
    "1.1\0".as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn ec_impl_info() -> *const c_char {
    "rust 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71\0".as_ptr() as *const c_char
}

// ───────────────────────── Crypto agility (§4.3a, v1.1) ─────────────────────

#[no_mangle]
pub extern "C" fn ec_sha384(data_ptr: *const u8, data_len: usize, out_ptr: *mut u8) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if data_ptr.is_null() || out_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
        let h = api::sha384(data);
        unsafe { ptr::copy_nonoverlapping(h.as_ptr(), out_ptr, api::SHA384_LEN) };
        EC_OK
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

/// content_hash under an explicit format code. Output is variable length
/// (33 B for 0x00, 49 B for 0x01); honors the OUT_OF_SPACE protocol. Unsupported
/// format code → EC_DECODE_ERROR (unsupported_content_hash_format).
#[no_mangle]
pub extern "C" fn ec_content_hash_with_format(
    type_ptr: *const u8,
    type_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    format_code: u64,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if type_ptr.is_null() || data_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let type_bytes = unsafe { std::slice::from_raw_parts(type_ptr, type_len) };
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
        let type_str = match std::str::from_utf8(type_bytes) {
            Ok(s) => s,
            Err(_) => return EC_INVALID_ARGUMENT,
        };
        match api::content_hash_with_format(type_str, data, format_code) {
            Some(h) => unsafe { write_out(&h, out_ptr, out_cap, out_len) },
            None => EC_DECODE_ERROR, // unsupported_content_hash_format
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_ed448_seed_to_pubkey(seed_ptr: *const u8, out_pub: *mut u8) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if seed_ptr.is_null() || out_pub.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let mut seed = [0u8; api::ED448_SEED_LEN];
        seed.copy_from_slice(unsafe { std::slice::from_raw_parts(seed_ptr, api::ED448_SEED_LEN) });
        match api::ed448_seed_to_pubkey(&seed) {
            Some(pk) => {
                unsafe { ptr::copy_nonoverlapping(pk.as_ptr(), out_pub, api::ED448_PUB_LEN) };
                EC_OK
            }
            None => EC_KEY_INVALID,
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_ed448_sign(
    priv_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    out_sig: *mut u8,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if priv_ptr.is_null() || msg_ptr.is_null() || out_sig.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let mut seed = [0u8; api::ED448_SEED_LEN];
        seed.copy_from_slice(unsafe { std::slice::from_raw_parts(priv_ptr, api::ED448_SEED_LEN) });
        let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
        match api::ed448_sign(&seed, msg) {
            Some(sig) => {
                unsafe { ptr::copy_nonoverlapping(sig.as_ptr(), out_sig, api::ED448_SIG_LEN) };
                EC_OK
            }
            None => EC_KEY_INVALID,
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_ed448_verify(
    pub_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if pub_ptr.is_null() || msg_ptr.is_null() || sig_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let mut pk = [0u8; api::ED448_PUB_LEN];
        pk.copy_from_slice(unsafe { std::slice::from_raw_parts(pub_ptr, api::ED448_PUB_LEN) });
        let mut sig = [0u8; api::ED448_SIG_LEN];
        sig.copy_from_slice(unsafe { std::slice::from_raw_parts(sig_ptr, api::ED448_SIG_LEN) });
        let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
        if api::ed448_verify(&pk, msg, &sig) {
            EC_OK
        } else {
            EC_SIGNATURE_INVALID
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_ed448_keygen(out_priv: *mut u8, out_pub: *mut u8) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if out_priv.is_null() || out_pub.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let (seed, pk) = api::ed448_keygen();
        unsafe {
            ptr::copy_nonoverlapping(seed.as_ptr(), out_priv, api::ED448_SEED_LEN);
            ptr::copy_nonoverlapping(pk.as_ptr(), out_pub, api::ED448_PUB_LEN);
        }
        EC_OK
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

// ───────────────── Ed25519 keygen (was first-pass stub) ─────────────────────

#[no_mangle]
pub extern "C" fn ec_ed25519_keygen(out_priv: *mut u8, out_pub: *mut u8) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if out_priv.is_null() || out_pub.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let (seed, pk) = api::ed25519_keygen();
        unsafe {
            ptr::copy_nonoverlapping(seed.as_ptr(), out_priv, 32);
            ptr::copy_nonoverlapping(pk.as_ptr(), out_pub, 32);
        }
        EC_OK
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

// ───────────────────────── Envelope verification (§4.4) ─────────────────────

#[no_mangle]
pub extern "C" fn ec_envelope_verify_root_hash(envelope_ptr: *const u8, envelope_len: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if envelope_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let env = unsafe { std::slice::from_raw_parts(envelope_ptr, envelope_len) };
        match api::envelope_verify_root_hash(env) {
            api::EnvelopeVerify::Ok => EC_OK,
            api::EnvelopeVerify::HashMismatch => EC_HASH_MISMATCH,
            api::EnvelopeVerify::Malformed => EC_DECODE_ERROR,
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

#[no_mangle]
pub extern "C" fn ec_envelope_find_signature_for(
    envelope_ptr: *const u8,
    envelope_len: usize,
    target_hash_ptr: *const u8,
    target_hash_len: usize,
    out_sig_entity_ptr: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if envelope_ptr.is_null() || target_hash_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let env = unsafe { std::slice::from_raw_parts(envelope_ptr, envelope_len) };
        let target = unsafe { std::slice::from_raw_parts(target_hash_ptr, target_hash_len) };
        match api::envelope_find_signature_for(env, target) {
            Some((off, len)) => {
                unsafe {
                    if !out_sig_entity_ptr.is_null() {
                        *out_sig_entity_ptr = env.as_ptr().add(off);
                    }
                    if !out_len.is_null() {
                        *out_len = len;
                    }
                }
                EC_OK
            }
            None => EC_DECODE_ERROR,
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

// ───────────────────────── Arena management (§4.5) ──────────────────────────
//
// This impl decodes by BORROWED span (N4 option a) — type/data/orig are all
// slices of the caller's input, so no arena is allocated by ec_decode_entity.
// The trio is provided for ABI completeness: ec_arena_new returns a real (empty)
// arena handle so callers that pass one get well-defined reset/free behavior.

#[no_mangle]
pub extern "C" fn ec_arena_new() -> *mut std::ffi::c_void {
    // A real heap allocation (not NULL) so the handle is distinguishable and
    // free() is well-defined; this impl stores nothing in it (borrowed spans).
    Box::into_raw(Box::new(())) as *mut std::ffi::c_void
}

#[no_mangle]
pub extern "C" fn ec_arena_reset(_arena: *mut std::ffi::c_void) {
    // Nothing is stored in the arena (borrowed-span decode); reset is a no-op.
}

#[no_mangle]
pub extern "C" fn ec_arena_free(arena: *mut std::ffi::c_void) {
    if !arena.is_null() {
        unsafe { drop(Box::from_raw(arena as *mut ())) };
    }
}

// ───────────────────────── F6: bare-encode test hook ────────────────────────
//
// The shipped ABI only exposes the entity-shaped ec_encode_ecf; the bare
// canonical encoder (the Class-A float/int/length/map_keys core) is not
// otherwise reachable across the ABI boundary, leaving the 5-way differential
// unable to exercise it (finding F6). This test-only hook encodes a single
// canonical ECF value supplied as already-canonical CBOR by round-tripping it
// through decode→encode, proving the encoder core is reachable + canonical.
// It is NOT a protocol surface: it takes canonical CBOR in and returns the
// re-encoded (canonical, identity for canonical input) bytes.
#[no_mangle]
pub extern "C" fn ec_encode_bare_value(
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if in_ptr.is_null() {
            return EC_INVALID_ARGUMENT;
        }
        let input = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };
        match decode::decode_value(input) {
            Ok(v) => {
                let encoded = encode::encode(&v);
                unsafe { write_out(&encoded, out_ptr, out_cap, out_len) }
            }
            Err(_) => EC_DECODE_ERROR,
        }
    }))
    .unwrap_or(EC_INTERNAL_ERROR)
}

// ───────────────────────────── Tests (v1.1) ────────────────────────────────
//
// These cover the surfaces NO corpus vector drives (envelope verify, keygen
// round-trips) plus the agility reject paths. The byte-pinned agility vectors
// (Ed448/SHA-384 positive bytes) are exercised by the conformance harness
// against test-vectors/v0.8.0/agility-vectors-v1.cbor.
#[cfg(test)]
mod v11_tests {
    use crate::api;
    use crate::encode;
    use crate::value::Value;

    // Build a canonical envelope {root: {type,data,content_hash}, included:{}}
    // with a correct SHA-256 root content_hash.
    fn envelope_with_root(type_str: &str, data: Value, hash_override: Option<Vec<u8>>) -> Vec<u8> {
        let data_bytes = encode::encode(&data);
        let ch = hash_override
            .unwrap_or_else(|| api::content_hash_with_format(type_str, &data_bytes, 0).unwrap());
        let root = Value::Map(vec![
            (Value::Text("type".into()), Value::Text(type_str.into())),
            (Value::Text("data".into()), data),
            (Value::Text("content_hash".into()), Value::Bytes(ch)),
        ]);
        let env = Value::Map(vec![
            (Value::Text("root".into()), root),
            (Value::Text("included".into()), Value::Map(vec![])),
        ]);
        encode::encode(&env)
    }

    #[test]
    fn envelope_verify_ok_and_mismatch() {
        let data = Value::Map(vec![(Value::Text("x".into()), Value::Int(1))]);
        let good = envelope_with_root("test/v1", data.clone(), None);
        assert_eq!(api::envelope_verify_root_hash(&good), api::EnvelopeVerify::Ok);

        // Corrupt the declared content_hash → HashMismatch (still 33 bytes,
        // format 0x00, so it parses but won't match).
        let mut bad_hash = vec![0u8; 33];
        bad_hash[0] = 0x00;
        let bad = envelope_with_root("test/v1", data, Some(bad_hash));
        assert_eq!(
            api::envelope_verify_root_hash(&bad),
            api::EnvelopeVerify::HashMismatch
        );
    }

    #[test]
    fn envelope_find_signature() {
        // Root references a target hash; included carries a system/signature
        // entity whose data.target == that hash.
        let target = vec![0xABu8; 33];
        let sig_entity = Value::Map(vec![
            (Value::Text("type".into()), Value::Text("system/signature/v1".into())),
            (
                Value::Text("data".into()),
                Value::Map(vec![
                    (Value::Text("target".into()), Value::Bytes(target.clone())),
                    (Value::Text("sig".into()), Value::Bytes(vec![0x00])),
                ]),
            ),
        ]);
        let root = Value::Map(vec![
            (Value::Text("type".into()), Value::Text("test/v1".into())),
            (Value::Text("data".into()), Value::Map(vec![])),
        ]);
        let env = Value::Map(vec![
            (Value::Text("root".into()), root),
            (
                Value::Text("included".into()),
                Value::Map(vec![(Value::Bytes(target.clone()), sig_entity)]),
            ),
        ]);
        let bytes = encode::encode(&env);
        let found = api::envelope_find_signature_for(&bytes, &target);
        assert!(found.is_some(), "signature entity should be found");
        // Miss on a different target.
        assert!(api::envelope_find_signature_for(&bytes, &[0x01u8; 33]).is_none());
    }

    #[test]
    fn ed25519_keygen_roundtrip() {
        let (seed, pk) = api::ed25519_keygen();
        let msg = b"keygen roundtrip";
        let sig = api::ed25519_sign(&seed, msg);
        assert!(api::ed25519_verify(&pk, msg, &sig));
        let (seed2, _) = api::ed25519_keygen();
        assert_ne!(seed, seed2, "two keygens must differ (OsRng)");
    }

    #[test]
    fn ed448_keygen_roundtrip() {
        let (seed, pk) = api::ed448_keygen();
        let msg = b"ed448 keygen roundtrip";
        let sig = api::ed448_sign(&seed, msg).expect("sign");
        assert!(api::ed448_verify(&pk, msg, &sig));
        assert_eq!(api::ed448_seed_to_pubkey(&seed).unwrap(), pk);
    }

    #[test]
    fn content_hash_format_reject() {
        // 0x00, 0x01 supported; 0x42, 128, 255 unsupported.
        assert!(api::content_hash_with_format("t", &[0x00], 0).is_some());
        assert!(api::content_hash_with_format("t", &[0x00], 1).is_some());
        for bad in [0x42u64, 128, 255] {
            assert!(
                api::content_hash_with_format("t", &[0x00], bad).is_none(),
                "format {bad} must be rejected"
            );
        }
        // SHA-256 form is 33 bytes; SHA-384 form is 49 bytes (1 + 48).
        assert_eq!(api::content_hash_with_format("t", &[0x00], 0).unwrap().len(), 33);
        assert_eq!(api::content_hash_with_format("t", &[0x00], 1).unwrap().len(), 49);
    }
}
