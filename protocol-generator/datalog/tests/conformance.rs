//! conformance.rs — S2 wire-conformance gate for the Datalog peer.
//!
//! Drives EVERY vector of the pinned v0.8.0 ECF corpus
//! (protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor) through
//! the `codec_ffi` seam and asserts byte-identity (encode_equal) or rejection
//! (decode_reject). The fixture carries its own cross-blessed `canonical` bytes
//! (Go × Rust × Python 3-way lock), so this is self-contained — no running Go oracle
//! at S2 (the same harness shape the Prolog/OCaml FFI peers use).
//!
//! Per-vector dispatch mirrors the C-ABI conformance harness:
//!   decode_reject        → decode_entity(canonical) MUST error (N2 tag scanner).
//!   encode_equal:
//!     content_hash       → content_hash_with_format(type, raw(data), format_code?).
//!     peer_id            → cbor_text( peerid_format(kt, ht, digest) ).
//!     signature          → ed25519_sign(seed, encode_ecf(type, raw(data))).
//!     everything else    → encode_bare_value( raw(input) )  [decode→re-canonicalise].
//!
//! The `cbor` module here is a HARNESS-ONLY fixture reader — NOT the peer's codec
//! (that is codec_ffi over the C-ABI). It exists only to navigate the fixture and
//! capture each value's raw byte span (needed to re-feed sub-values across the ABI).

use entity_core_protocol_datalog::codec_ffi::{self, CodecError};

// ── Minimal CBOR fixture reader (harness-only) ───────────────────────────────
mod cbor {
    // Harness navigator: the full CBOR value shape is parsed (so raw spans advance
    // correctly), but only a subset of payloads is read out. The unread numeric/bool
    // payloads are retained for completeness + debuggability.
    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    pub enum Val {
        Uint(u64),
        Nint(i128),
        Bytes(Vec<u8>),
        Text(String),
        Array(Vec<Node>),
        Map(Vec<(Node, Node)>),
        Float(f64),
        Bool(bool),
        Null,
        Undefined,
    }

    #[derive(Debug, Clone)]
    pub struct Node {
        pub val: Val,
        /// The exact bytes this value spans in the fixture.
        pub raw: Vec<u8>,
    }

    impl Node {
        pub fn as_text(&self) -> Option<&str> {
            match &self.val {
                Val::Text(s) => Some(s),
                _ => None,
            }
        }
        pub fn as_bytes(&self) -> Option<&[u8]> {
            match &self.val {
                Val::Bytes(b) => Some(b),
                _ => None,
            }
        }
        pub fn as_uint(&self) -> Option<u64> {
            match &self.val {
                Val::Uint(n) => Some(*n),
                _ => None,
            }
        }
        pub fn as_map(&self) -> Option<&[(Node, Node)]> {
            match &self.val {
                Val::Map(p) => Some(p),
                _ => None,
            }
        }
        /// Look up a text-keyed field's value node.
        pub fn field(&self, key: &str) -> Option<&Node> {
            self.as_map()?
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v)
        }
    }

    /// Parse one value at `pos`; return (node, next_pos).
    pub fn parse(b: &[u8], pos: usize) -> (Node, usize) {
        let start = pos;
        let head = b[pos];
        let major = head >> 5;
        let minor = head & 0x1f;
        let mut p = pos + 1;
        let val = match major {
            0 => {
                let (n, np) = arg(b, minor, p);
                p = np;
                Val::Uint(n)
            }
            1 => {
                let (n, np) = arg(b, minor, p);
                p = np;
                Val::Nint(-1 - n as i128)
            }
            2 => {
                let (n, np) = arg(b, minor, p);
                let len = n as usize;
                let bytes = b[np..np + len].to_vec();
                p = np + len;
                Val::Bytes(bytes)
            }
            3 => {
                let (n, np) = arg(b, minor, p);
                let len = n as usize;
                let s = String::from_utf8(b[np..np + len].to_vec()).expect("utf8 text");
                p = np + len;
                Val::Text(s)
            }
            4 => {
                let (n, np) = arg(b, minor, p);
                p = np;
                let mut items = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let (node, np2) = parse(b, p);
                    items.push(node);
                    p = np2;
                }
                Val::Array(items)
            }
            5 => {
                let (n, np) = arg(b, minor, p);
                p = np;
                let mut pairs = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let (k, np_k) = parse(b, p);
                    let (v, np_v) = parse(b, np_k);
                    pairs.push((k, v));
                    p = np_v;
                }
                Val::Map(pairs)
            }
            7 => match minor {
                20 => Val::Bool(false),
                21 => Val::Bool(true),
                22 => Val::Null,
                23 => Val::Undefined,
                25 => {
                    let f = half_to_f64(u16::from_be_bytes([b[p], b[p + 1]]));
                    p += 2;
                    Val::Float(f)
                }
                26 => {
                    let f = f32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) as f64;
                    p += 4;
                    Val::Float(f)
                }
                27 => {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(&b[p..p + 8]);
                    p += 8;
                    Val::Float(f64::from_be_bytes(a))
                }
                other => panic!("unsupported simple/float minor {other}"),
            },
            other => panic!("unsupported major {other}"),
        };
        (
            Node {
                val,
                raw: b[start..p].to_vec(),
            },
            p,
        )
    }

    /// Decode a major-type argument (the value after the head byte).
    fn arg(b: &[u8], minor: u8, p: usize) -> (u64, usize) {
        match minor {
            0..=23 => (minor as u64, p),
            24 => (b[p] as u64, p + 1),
            25 => (u16::from_be_bytes([b[p], b[p + 1]]) as u64, p + 2),
            26 => (
                u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) as u64,
                p + 4,
            ),
            27 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&b[p..p + 8]);
                (u64::from_be_bytes(a), p + 8)
            }
            other => panic!("unsupported arg minor {other}"),
        }
    }

    fn half_to_f64(h: u16) -> f64 {
        let sign = (h >> 15) & 1;
        let exp = (h >> 10) & 0x1f;
        let frac = h & 0x3ff;
        let val = if exp == 0 {
            (frac as f64) * 2f64.powi(-24)
        } else if exp == 0x1f {
            if frac == 0 {
                f64::INFINITY
            } else {
                f64::NAN
            }
        } else {
            (1.0 + (frac as f64) / 1024.0) * 2f64.powi(exp as i32 - 15)
        };
        if sign == 1 {
            -val
        } else {
            val
        }
    }
}

/// CBOR text-string (major 3) encoding of an ASCII string — the canonical form of
/// a peer-id vector's expected bytes.
fn cbor_text_encode(s: &str) -> Vec<u8> {
    let body = s.as_bytes();
    let len = body.len();
    let mut out = if len <= 23 {
        vec![0x60 | len as u8]
    } else if len <= 0xff {
        vec![0x78, len as u8]
    } else {
        vec![0x79, (len >> 8) as u8, (len & 0xff) as u8]
    };
    out.extend_from_slice(body);
    out
}

fn corpus_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor")
}

struct Outcome {
    pass: usize,
    fail: usize,
    failures: Vec<String>,
    notes: Vec<String>,
}

fn category(id: &str) -> &str {
    id.split_once('.').map(|(c, _)| c).unwrap_or(id)
}

#[test]
fn wire_conformance_corpus() {
    let path = corpus_path();
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let (top, consumed) = cbor::parse(&data, 0);
    assert_eq!(consumed, data.len(), "trailing bytes in corpus");
    let items = match &top.val {
        cbor::Val::Array(v) => v,
        _ => panic!("corpus root is not an array"),
    };

    eprintln!(
        "# entity-core-protocol-datalog — S2 wire conformance\n# C-ABI {} / {}\n# corpus: {}",
        codec_ffi::abi_version(),
        codec_ffi::impl_info(),
        path.display()
    );

    let mut o = Outcome {
        pass: 0,
        fail: 0,
        failures: Vec::new(),
        notes: Vec::new(),
    };

    for vec_node in items {
        let id = vec_node.field("id").and_then(|n| n.as_text()).expect("id");
        let kind = vec_node
            .field("kind")
            .and_then(|n| n.as_text())
            .expect("kind");
        let canonical = vec_node
            .field("canonical")
            .and_then(|n| n.as_bytes())
            .expect("canonical")
            .to_vec();

        let result: std::result::Result<(), String> = match kind {
            "decode_reject" => match codec_ffi::decode_entity(&canonical) {
                Err(_) => Ok(()),
                Ok(_) => Err("decode_entity accepted a MUST-reject vector".into()),
            },
            "encode_equal" => drive_encode_equal(id, vec_node, &canonical, &mut o.notes),
            other => Err(format!("unknown kind {other}")),
        };

        match result {
            Ok(()) => o.pass += 1,
            Err(msg) => {
                o.fail += 1;
                o.failures.push(format!("FAIL {id} [{kind}]: {msg}"));
            }
        }
    }

    let total = o.pass + o.fail;
    for n in &o.notes {
        eprintln!("  note: {n}");
    }
    for f in &o.failures {
        eprintln!("  {f}");
    }
    eprintln!("# RESULT: {}/{} PASS", o.pass, total);
    assert_eq!(o.fail, 0, "{} vector(s) failed", o.fail);
    // The pinned v0.8.0 corpus is the 71-vector finalised set.
    assert_eq!(
        total, 71,
        "expected the 71-vector v0.8.0 corpus, saw {total}"
    );
}

fn drive_encode_equal(
    id: &str,
    vec_node: &cbor::Node,
    canonical: &[u8],
    notes: &mut Vec<String>,
) -> std::result::Result<(), String> {
    let input = vec_node.field("input");
    match category(id) {
        "content_hash" => {
            let inp = input.ok_or("content_hash: missing input")?;
            let ty = inp
                .field("type")
                .and_then(|n| n.as_text())
                .ok_or("content_hash: missing type")?;
            let data_raw = inp
                .field("data")
                .map(|n| n.raw.clone())
                .ok_or("content_hash: missing data")?;
            let fc = inp
                .field("format_code")
                .and_then(|n| n.as_uint())
                .unwrap_or(0);
            match codec_ffi::content_hash_with_format(ty.as_bytes(), &data_raw, fc) {
                Ok(got) => bytes_eq(&got, canonical),
                // Synthetic format code (≥ 0x02) unsupported: "report unsupported
                // rather than emit wrong bytes" is a conformant branch (the vector's
                // own note; agility VARINT-MULTIBYTE-1 rejects 128). Count as PASS.
                Err(CodecError::Decode) if fc >= 2 => {
                    notes.push(format!(
                        "{id}: format_code {fc} unsupported → report-unsupported branch (conformant)"
                    ));
                    Ok(())
                }
                Err(e) => Err(format!("content_hash_with_format: {e}")),
            }
        }
        "peer_id" => {
            let inp = input.ok_or("peer_id: missing input")?;
            let kt = inp
                .field("key_type")
                .and_then(|n| n.as_uint())
                .ok_or("peer_id: missing key_type")?;
            let ht = inp
                .field("hash_type")
                .and_then(|n| n.as_uint())
                .ok_or("peer_id: missing hash_type")?;
            let digest = inp
                .field("digest")
                .and_then(|n| n.as_bytes())
                .ok_or("peer_id: missing digest")?;
            let b58 = codec_ffi::peerid_format(kt, ht, digest)
                .map_err(|e| format!("peerid_format: {e}"))?;
            bytes_eq(&cbor_text_encode(&b58), canonical)
        }
        "signature" => {
            let inp = input.ok_or("signature: missing input")?;
            let seed = inp
                .field("seed")
                .and_then(|n| n.as_bytes())
                .ok_or("signature: missing seed")?;
            let entity = inp.field("entity").ok_or("signature: missing entity")?;
            let ty = entity
                .field("type")
                .and_then(|n| n.as_text())
                .ok_or("signature: missing entity.type")?;
            let data_raw = entity
                .field("data")
                .map(|n| n.raw.clone())
                .ok_or("signature: missing entity.data")?;
            let ecf = codec_ffi::encode_ecf(ty.as_bytes(), &data_raw)
                .map_err(|e| format!("encode_ecf: {e}"))?;
            let sig =
                codec_ffi::ed25519_sign(seed, &ecf).map_err(|e| format!("ed25519_sign: {e}"))?;
            bytes_eq(&sig, canonical)
        }
        // Class A + nested/envelope/length/map_keys/primitive/int/float:
        // decode the input value and re-encode canonically.
        _ => {
            let inp = input.ok_or("encode_equal: missing input")?;
            let got = codec_ffi::encode_bare_value(&inp.raw)
                .map_err(|e| format!("encode_bare_value: {e}"))?;
            bytes_eq(&got, canonical)
        }
    }
}

fn bytes_eq(got: &[u8], want: &[u8]) -> std::result::Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!(
            "byte mismatch\n    got:  {}\n    want: {}",
            hexs(got),
            hexs(want)
        ))
    }
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
