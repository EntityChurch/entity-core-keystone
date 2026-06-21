//! Unit tests for the canonical codec.
//!
//! Covers the conformance invariants N1 (varint framing), N2 (recursive tag
//! rejection), N3 (empty-map = single byte 0xa0) each with a covering case, plus
//! the float ladder, int boundaries, map-key ordering, and round-trips.

use crate::cbor;
use crate::content_hash::content_hash;
use crate::error::CodecError;
use crate::peer_id;
use crate::value::{Key, Value};
use crate::varint;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ── float ladder (Rule 4/4a) ──

#[test]
fn float_specials_and_ladder() {
    assert_eq!(cbor::encode(&Value::Float(0.0)), h("f90000"));
    assert_eq!(cbor::encode(&Value::Float(-0.0)), h("f98000"));
    assert_eq!(cbor::encode(&Value::Float(1.5)), h("f93e00"));
    assert_eq!(cbor::encode(&Value::Float(f64::INFINITY)), h("f97c00"));
    assert_eq!(cbor::encode(&Value::Float(f64::NEG_INFINITY)), h("f9fc00"));
    assert_eq!(cbor::encode(&Value::Float(f64::NAN)), h("f97e00"));
    // f16 max normal vs the value one ulp above that needs f32.
    assert_eq!(cbor::encode(&Value::Float(65504.0)), h("f97bff"));
    assert_eq!(cbor::encode(&Value::Float(65503.0)), h("fa477fdf00"));
    assert_eq!(cbor::encode(&Value::Float(100000.0)), h("fa47c35000"));
    assert_eq!(cbor::encode(&Value::Float(1.1)), h("fb3ff199999999999a"));
}

#[test]
fn float_decode_rejects_nonminimal() {
    // 1.0 as f32 (fa3f800000) is non-minimal — fits in f16.
    assert_eq!(
        cbor::decode(&h("fa3f800000")),
        Err(CodecError::NonMinimalFloat)
    );
    // 1.0 as f64 (fb3ff0000000000000) is non-minimal.
    assert_eq!(
        cbor::decode(&h("fb3ff0000000000000")),
        Err(CodecError::NonMinimalFloat)
    );
}

// ── int boundaries (Rule 1) + full u64 range ──

#[test]
fn int_boundaries() {
    assert_eq!(cbor::encode(&Value::UInt(23)), h("17"));
    assert_eq!(cbor::encode(&Value::UInt(24)), h("1818"));
    assert_eq!(cbor::encode(&Value::UInt(255)), h("18ff"));
    assert_eq!(cbor::encode(&Value::UInt(256)), h("190100"));
    assert_eq!(cbor::encode(&Value::UInt(65536)), h("1a00010000"));
    assert_eq!(
        cbor::encode(&Value::UInt(9223372036854775807)),
        h("1b7fffffffffffffff")
    );
    // full uint64 head form: 2^64-1.
    assert_eq!(
        cbor::encode(&Value::UInt(u64::MAX)),
        h("1bffffffffffffffff")
    );
    assert_eq!(cbor::encode(&Value::NInt(0)), h("20")); // -1
    assert_eq!(cbor::encode(&Value::NInt(23)), h("37")); // -24
                                                         // nint full band: -2^64 = NInt(2^64-1).
    assert_eq!(
        cbor::encode(&Value::NInt(u64::MAX)),
        h("3bffffffffffffffff")
    );
}

#[test]
fn int_decode_rejects_nonminimal() {
    // 0 as 1-byte arg (1800) is non-minimal.
    assert_eq!(cbor::decode(&h("1800")), Err(CodecError::NonMinimalInt));
    // 23 as 2-byte arg.
    assert_eq!(cbor::decode(&h("190017")), Err(CodecError::NonMinimalInt));
}

// ── map-key ordering (Rule 2) ──

#[test]
fn map_key_length_then_lex() {
    // {"aa":2,"z":1} -> z (len-1) before aa (len-2).
    let m = Value::Map(vec![
        (Key::Text("aa".into()), Value::UInt(2)),
        (Key::Text("z".into()), Value::UInt(1)),
    ]);
    assert_eq!(cbor::encode(&m), h("a2617a0162616102"));
    // mixed byte/text keys (map_keys.5): bstr "key" before text "text_key".
    let m2 = Value::Map(vec![
        (Key::Bytes(b"key".to_vec()), Value::UInt(2)),
        (Key::Text("text_key".into()), Value::UInt(1)),
    ]);
    assert_eq!(cbor::encode(&m2), h("a2436b65790268746578745f6b657901"));
}

#[test]
fn map_decode_rejects_unsorted_and_dup() {
    // unsorted: aa(62 6161) then z(61 7a) on the wire — second key sorts before
    // the first, so the decoder must reject as out of canonical order.
    assert_eq!(
        cbor::decode(&h("a262616101617a02")),
        Err(CodecError::UnsortedKeys)
    );
    // duplicate key a/a.
    assert_eq!(
        cbor::decode(&h("a2616101616102")),
        Err(CodecError::DuplicateKey)
    );
}

// ── N3: empty map is the single byte 0xa0 ──

#[test]
fn n3_empty_map_single_byte() {
    assert_eq!(cbor::encode(&Value::Map(vec![])), vec![0xa0]);
    assert_eq!(cbor::encode(&Value::Array(vec![])), vec![0x80]);
}

// ── N2: recursive tag rejection at any depth (§6.3) ──

#[test]
fn n2_tag_rejected_recursively() {
    // bare tag-0 datetime.
    assert!(matches!(
        cbor::decode(&h("c0613a")),
        Err(CodecError::TagRejected)
    ));
    // tag 55799 self-describe wrapper.
    assert_eq!(cbor::decode(&h("d9d9f7a0")), Err(CodecError::TagRejected));
    // tag nested inside a map value.
    assert_eq!(
        cbor::decode(&h("a16174c0613a")),
        Err(CodecError::TagRejected)
    );
}

#[test]
fn indefinite_length_rejected() {
    assert_eq!(cbor::decode(&h("9fff")), Err(CodecError::IndefiniteLength));
    assert_eq!(cbor::decode(&h("bfff")), Err(CodecError::IndefiniteLength));
}

// ── N1: varint framing through the real LEB128 primitive ──

#[test]
fn n1_varint_roundtrip() {
    for v in [0u64, 1, 127, 128, 255, 300, 16384, u64::MAX] {
        let enc = varint::encode(v);
        let (dec, n) = varint::decode(&enc).unwrap();
        assert_eq!(dec, v);
        assert_eq!(n, enc.len());
    }
    // 128 is the first 2-byte varint: 0x80 0x01.
    assert_eq!(varint::encode(128), h("8001"));
}

// ── content_hash (varint || SHA-256(ECF({type,data}))) ──

#[test]
fn content_hash_corpus() {
    // content_hash.1: {type:"system/empty", data:{}}.
    let got = content_hash("system/empty", Value::Map(vec![]), 0);
    assert_eq!(
        got,
        h("005f3139e342f5ef35c1e0eb3140c4511c469d604979d20542bc2ab92fd0ca396b")
    );
    // content_hash.4: format_code 128 -> multi-byte varint prefix.
    let data = Value::Map(vec![(Key::Text("x".into()), Value::UInt(1))]);
    let got4 = content_hash("test/v1", data, 128);
    assert_eq!(
        got4,
        h("800156ff4f3e492cb56a12ace2f0724de332c50e00efa5ff9b0c8edf1898bb9a0329")
    );
}

// ── peer_id round-trip ──

#[test]
fn peer_id_format_parse() {
    let digest = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let s = peer_id::format(1, 1, &digest);
    let parsed = peer_id::parse(&s).unwrap();
    assert_eq!(parsed.key_type, 1);
    assert_eq!(parsed.hash_type, 1);
    assert_eq!(parsed.digest, digest);
    // multi-byte key_type 128.
    let s2 = peer_id::format(128, 1, &digest);
    let p2 = peer_id::parse(&s2).unwrap();
    assert_eq!(p2.key_type, 128);
}

// ── round-trip stability ──

#[test]
fn roundtrip_nested() {
    let v = Value::Map(vec![
        (Key::Text("type".into()), Value::Text("test/v1".into())),
        (
            Key::Text("data".into()),
            Value::Map(vec![
                (Key::Text("a".into()), Value::UInt(1)),
                (Key::Text("b".into()), Value::Text("two".into())),
            ]),
        ),
    ]);
    let enc = cbor::encode(&v);
    let dec = cbor::decode(&enc).unwrap();
    let reenc = cbor::encode(&dec);
    assert_eq!(enc, reenc);
}
