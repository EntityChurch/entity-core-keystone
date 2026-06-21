//! Rust-side ECF conformance harness — the analogue of go's
//! `wire-conformance emit-canonical` (GUIDE-CONFORMANCE §3.1).
//!
//! Reads the canonical-ECF corpus (`conformance-vectors-v1.cbor`, the build
//! artifact every impl loads), runs each vector through THIS crate's codec, and:
//!
//!   * `--out <path>`   writes the per-impl emission file (CBOR map with the
//!     §3.1 shape: impl / impl_version / corpus_version / spec_version /
//!     encode_results / decode_results / decode_codes / errors), byte-comparable
//!     to go's emission.
//!   * default          checks each vector's produced bytes against the corpus's
//!     own locked `canonical` field (the 3-way byte-equality lock) and prints a
//!     PASS/FAIL line per vector + an N/M summary. Exit 1 on any FAIL.
//!
//! Usage:
//!   wire-conformance --input <corpus.cbor> [--out <emission.cbor>] [--json <report.json>]

use std::collections::BTreeMap;
use std::process::ExitCode;

use entity_core_protocol::cbor;
use entity_core_protocol::content_hash::content_hash;
use entity_core_protocol::peer_id;
use entity_core_protocol::signature::sign_entity;
use entity_core_protocol::value::{Key, Value};

const IMPL_NAME: &str = "core-rust";
const IMPL_VERSION: &str = "0.1.0-pre";
const CORPUS_VERSION: &str = "v1";
const SPEC_VERSION: &str = "1.5";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut input = String::new();
    let mut out = String::new();
    let mut json = String::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input = args.get(i).cloned().unwrap_or_default();
            }
            "--out" => {
                i += 1;
                out = args.get(i).cloned().unwrap_or_default();
            }
            "--json" => {
                i += 1;
                json = args.get(i).cloned().unwrap_or_default();
            }
            other => {
                eprintln!("unknown flag: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    if input.is_empty() {
        eprintln!("--input <corpus.cbor> is required");
        return ExitCode::from(2);
    }

    let bytes = match std::fs::read(&input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read corpus: {e}");
            return ExitCode::from(1);
        }
    };

    let corpus = match cbor::decode(&bytes) {
        Ok(Value::Array(v)) => v,
        Ok(_) => {
            eprintln!("corpus is not a top-level array");
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("decode corpus: {e}");
            return ExitCode::from(1);
        }
    };

    let mut encode_results: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut decode_results: BTreeMap<String, bool> = BTreeMap::new();
    let mut decode_codes: BTreeMap<String, String> = BTreeMap::new();
    let mut errors: BTreeMap<String, String> = BTreeMap::new();

    // Self-check against the corpus `canonical` field.
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut fail_ids: Vec<String> = Vec::new();

    for v in &corpus {
        let m = match v {
            Value::Map(m) => m,
            _ => continue,
        };
        let id = match get_text(m, "id") {
            Some(s) => s,
            None => continue,
        };
        let kind = get_text(m, "kind").unwrap_or_default();
        let canonical = get_bytes(m, "canonical");

        match kind.as_str() {
            "encode_equal" => {
                let produced = match encode_vector(&id, m) {
                    Ok(b) => b,
                    Err(e) => {
                        errors.insert(id.clone(), e.clone());
                        eprintln!("FAIL {id}: {e}");
                        fail += 1;
                        fail_ids.push(id.clone());
                        continue;
                    }
                };
                encode_results.insert(id.clone(), produced.clone());
                match &canonical {
                    Some(expected) if expected == &produced => {
                        pass += 1;
                    }
                    Some(expected) => {
                        fail += 1;
                        fail_ids.push(id.clone());
                        eprintln!(
                            "FAIL {id}: bytes differ\n  expected: {}\n  produced: {}",
                            hex(expected),
                            hex(&produced)
                        );
                    }
                    None => {
                        // No expected bytes in corpus; record but don't gate.
                        pass += 1;
                    }
                }
            }
            "decode_reject" => {
                let wire = canonical.clone().unwrap_or_default();
                match cbor::decode(&wire) {
                    Ok(_) => {
                        decode_results.insert(id.clone(), false);
                        errors.insert(id.clone(), "decoder accepted non-canonical input".into());
                        fail += 1;
                        fail_ids.push(id.clone());
                        eprintln!("FAIL {id}: decoder accepted bytes it must reject");
                    }
                    Err(e) => {
                        decode_results.insert(id.clone(), true);
                        decode_codes.insert(id.clone(), e.wire_code().to_string());
                        pass += 1;
                    }
                }
            }
            other => {
                errors.insert(id.clone(), format!("unknown kind: {other}"));
                fail += 1;
                fail_ids.push(id.clone());
            }
        }
    }

    println!("\n=== ECF wire-conformance ({IMPL_NAME}) ===");
    println!("corpus: {input}");
    println!("vectors: {} | PASS {pass} | FAIL {fail}", pass + fail);
    if !fail_ids.is_empty() {
        println!("failed ids: {}", fail_ids.join(", "));
    }

    // Emission file (byte-comparable to go's emit-canonical output).
    if !out.is_empty() {
        let emission = build_emission(&encode_results, &decode_results, &decode_codes, &errors);
        let enc = cbor::encode(&emission);
        if let Err(e) = std::fs::write(&out, &enc) {
            eprintln!("write emission: {e}");
            return ExitCode::from(1);
        }
        println!("emission: wrote {out} ({} bytes)", enc.len());
    }

    if !json.is_empty() {
        let report = build_json(pass, fail, &fail_ids);
        if let Err(e) = std::fs::write(&json, report) {
            eprintln!("write json: {e}");
            return ExitCode::from(1);
        }
    }

    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Re-encode / construct the bytes for an `encode_equal` vector, dispatching by
/// id prefix exactly as the go oracle does.
fn encode_vector(id: &str, m: &[(Key, Value)]) -> std::result::Result<Vec<u8>, String> {
    let input = get(m, "input").ok_or_else(|| "missing input".to_string())?;
    if let Some(rest) = id.strip_prefix("content_hash.") {
        let _ = rest;
        return emit_content_hash(input);
    }
    if id.starts_with("peer_id.") {
        return emit_peer_id(input);
    }
    if id.starts_with("signature.") {
        return emit_signature(input);
    }
    // Class A + envelope.* + nested.* : re-encode the input value tree.
    Ok(cbor::encode(input))
}

fn emit_content_hash(input: &Value) -> std::result::Result<Vec<u8>, String> {
    let m = as_map(input)?;
    let typ = get_text(m, "type").ok_or("content_hash: missing type")?;
    let data = get(m, "data").ok_or("content_hash: missing data")?.clone();
    let format_code = match get(m, "format_code") {
        Some(Value::UInt(n)) => *n,
        Some(_) => return Err("content_hash: format_code must be uint".into()),
        None => 0,
    };
    Ok(content_hash(&typ, data, format_code))
}

fn emit_peer_id(input: &Value) -> std::result::Result<Vec<u8>, String> {
    let m = as_map(input)?;
    let kt = get_uint(m, "key_type").ok_or("peer_id: missing key_type")?;
    let ht = get_uint(m, "hash_type").ok_or("peer_id: missing hash_type")?;
    let digest = get_bytes(m, "digest").ok_or("peer_id: missing digest")?;
    let s = peer_id::format(kt, ht, &digest);
    // Canonical = ECF text-string encoding of the base58 string.
    Ok(cbor::encode(&Value::Text(s)))
}

fn emit_signature(input: &Value) -> std::result::Result<Vec<u8>, String> {
    let m = as_map(input)?;
    let seed = get_bytes(m, "seed").ok_or("signature: missing seed")?;
    if seed.len() != 32 {
        return Err(format!(
            "signature: seed must be 32 bytes, got {}",
            seed.len()
        ));
    }
    let entity = get(m, "entity").ok_or("signature: missing entity")?;
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    Ok(sign_entity(&seed_arr, entity).to_vec())
}

// ───────────────────────── emission + json ─────────────────────────

fn build_emission(
    encode_results: &BTreeMap<String, Vec<u8>>,
    decode_results: &BTreeMap<String, bool>,
    decode_codes: &BTreeMap<String, String>,
    errors: &BTreeMap<String, String>,
) -> Value {
    let mut top: Vec<(Key, Value)> = vec![
        (Key::Text("impl".into()), Value::Text(IMPL_NAME.into())),
        (
            Key::Text("impl_version".into()),
            Value::Text(IMPL_VERSION.into()),
        ),
        (
            Key::Text("corpus_version".into()),
            Value::Text(CORPUS_VERSION.into()),
        ),
        (
            Key::Text("spec_version".into()),
            Value::Text(SPEC_VERSION.into()),
        ),
    ];

    let enc_map = Value::Map(
        encode_results
            .iter()
            .map(|(k, v)| (Key::Text(k.clone()), Value::Bytes(v.clone())))
            .collect(),
    );
    top.push((Key::Text("encode_results".into()), enc_map));

    let dec_map = Value::Map(
        decode_results
            .iter()
            .map(|(k, v)| (Key::Text(k.clone()), Value::Bool(*v)))
            .collect(),
    );
    top.push((Key::Text("decode_results".into()), dec_map));

    let code_map = Value::Map(
        decode_codes
            .iter()
            .map(|(k, v)| (Key::Text(k.clone()), Value::Text(v.clone())))
            .collect(),
    );
    top.push((Key::Text("decode_codes".into()), code_map));

    let err_map = Value::Map(
        errors
            .iter()
            .map(|(k, v)| (Key::Text(k.clone()), Value::Text(v.clone())))
            .collect(),
    );
    top.push((Key::Text("errors".into()), err_map));

    Value::Map(top)
}

fn build_json(pass: usize, fail: usize, fail_ids: &[String]) -> String {
    let ids = fail_ids
        .iter()
        .map(|s| format!("{:?}", s))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{\n  \"impl\": \"{IMPL_NAME}\",\n  \"impl_version\": \"{IMPL_VERSION}\",\n  \"corpus_version\": \"{CORPUS_VERSION}\",\n  \"spec_version\": \"{SPEC_VERSION}\",\n  \"vectors\": {},\n  \"pass\": {pass},\n  \"fail\": {fail},\n  \"failed_ids\": [{ids}]\n}}\n",
        pass + fail
    )
}

// ───────────────────────── value-tree helpers ─────────────────────────

fn get<'a>(m: &'a [(Key, Value)], key: &str) -> Option<&'a Value> {
    m.iter().find_map(|(k, v)| match k {
        Key::Text(s) if s == key => Some(v),
        _ => None,
    })
}

fn get_text(m: &[(Key, Value)], key: &str) -> Option<String> {
    match get(m, key) {
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn get_uint(m: &[(Key, Value)], key: &str) -> Option<u64> {
    match get(m, key) {
        Some(Value::UInt(n)) => Some(*n),
        _ => None,
    }
}

fn get_bytes(m: &[(Key, Value)], key: &str) -> Option<Vec<u8>> {
    match get(m, key) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    }
}

fn as_map(v: &Value) -> std::result::Result<&[(Key, Value)], String> {
    match v {
        Value::Map(m) => Ok(m),
        other => Err(format!("expected map, got {other:?}")),
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}
